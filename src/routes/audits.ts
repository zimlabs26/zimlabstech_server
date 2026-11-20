import express, { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { parseAuditUrl, runCheck, type AuditStatus, type CheckResult } from '../auditcheck.js'
import { db } from '../db.js'
import { captureError } from '../errorlog.js'
import { requireAdmin, requireSuper, requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Auditoria: listado de empresas con lo que se les armo, y un semaforo (verde / amarillo / rojo) que el servidor actualiza
 * a pedido o de forma programada. Cada entrada puede tener tres servicios:
 *  - pagina: la URL de la pagina web.
 *  - CRM y tienda: se auditan por capas; piden la URL del frontend (la web que usa la gente), la URL del servidor y la
 *    ruta de salud de la base de datos (opcional; por defecto /api/health del servidor, que lee y escribe en la base).
 *    NUNCA se guardan claves ni cadenas de conexion.
 * Cada servicio se verifica por separado y el estado general es el peor de los que tiene.
 * Todos los usuarios del CRM ven la lista; solo administradores la editan.
 */

export const auditsRouter = Router()
auditsRouter.use(requireUser)
// Alta y edicion llevan el logo (unos 45 KB como mucho): el limite general de 10 KB no alcanza (ver index.ts).
auditsRouter.use(express.json({ limit: '100kb' }))

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 })

type Kind = 'page' | 'crm' | 'store'
const KINDS: Kind[] = ['page', 'crm', 'store']
type AppKind = 'crm' | 'store'
const APP_KINDS: AppKind[] = ['crm', 'store']

interface AuditRow {
  id: number
  name: string
  status: AuditStatus | null
  logo: string | null
  page_url: string | null
  crm_url: string | null
  crm_app_url: string | null
  crm_db_url: string | null
  store_url: string | null
  store_app_url: string | null
  store_db_url: string | null
  page_result: string | null
  crm_result: string | null
  store_result: string | null
  /** Programacion de esta empresa: cada cuanto se audita sola y cuando fue y sera la proxima. */
  frequency: Frequency
  last_run_at: string | null
  next_run_at: string | null
}

const columns =
  'id, name, status, logo, page_url, crm_url, crm_app_url, crm_db_url, store_url, store_app_url, store_db_url, page_result, crm_result, store_result, frequency, last_run_at, next_run_at'

/** Una capa de un CRM o tienda: su estado (null = no se pudo revisar), sus alertas y lo que tardo en responder. */
interface Layer {
  status: AuditStatus | null
  alerts: string[]
  ms: number | null
}
/** Las tres capas de un CRM o tienda: la web que usa la gente, el servidor y la base de datos. */
interface Layers {
  app: Layer | null
  server: Layer
  db: Layer
}

/** Ultimo resultado guardado de un servicio. */
type StoredResult = CheckResult & { checkedAt: string; layers?: Layers }

/** Direccion principal del servicio: la URL de la pagina, o la del servidor del CRM / tienda. */
const urlOf = (r: AuditRow, kind: Kind) => (kind === 'page' ? r.page_url : kind === 'crm' ? r.crm_url : r.store_url)
/** Frontend (la web que usa la gente) del CRM / tienda. */
const appUrlOf = (r: AuditRow, kind: AppKind) => (kind === 'crm' ? r.crm_app_url : r.store_app_url)
/** Ruta de salud de la base de datos del CRM / tienda (null = la del servidor). */
const dbUrlOf = (r: AuditRow, kind: AppKind) => (kind === 'crm' ? r.crm_db_url : r.store_db_url)
const resultOf = (r: AuditRow, kind: Kind): StoredResult | null => {
  const raw = kind === 'page' ? r.page_result : kind === 'crm' ? r.crm_result : r.store_result
  return raw ? (JSON.parse(raw) as StoredResult) : null
}

/** Un servicio tal como lo ve la web; null si la entrada no lo tiene. */
const toService = (r: AuditRow, kind: Kind) => {
  const url = urlOf(r, kind)
  if (!url) return null
  const res = resultOf(r, kind)
  return {
    /** Pagina: su URL. CRM y tienda: la del servidor. */
    url,
    /** Solo CRM y tienda: el frontend y la ruta de salud de la base de datos (null = la del servidor). */
    appUrl: kind === 'page' ? null : appUrlOf(r, kind),
    dbUrl: kind === 'page' ? null : dbUrlOf(r, kind),
    status: res?.status ?? null,
    /** En CRM y tienda cada alerta lleva el origen: "app:" (frontend) o "srv:" (servidor y base de datos). */
    alerts: res?.alerts ?? [],
    detail: res?.detail ?? '',
    httpStatus: res?.httpStatus ?? null,
    responseMs: res?.responseMs ?? null,
    sslExpiresOn: res?.sslExpiresOn ?? null,
    /** Controles revisados y cuantos salieron bien (null en las verificaciones viejas, de antes de los controles). */
    checks: res?.checks ?? null,
    /** CRM y tienda: el estado de cada capa por separado (null en la pagina y en las verificaciones viejas). */
    layers: res?.layers ?? null,
    checkedAt: res?.checkedAt ?? null,
  }
}

const toAudit = (r: AuditRow) => ({
  id: r.id,
  name: r.name,
  logo: r.logo,
  /** El peor estado de los servicios que ya se verificaron (rojo > amarillo > verde); null si ninguno. */
  status: r.status,
  page: toService(r, 'page'),
  crm: toService(r, 'crm'),
  store: toService(r, 'store'),
  /** Programacion de la empresa: frecuencia, ultima auditoria completa y proxima programada (null si es manual). */
  schedule: { frequency: r.frequency, lastRunAt: r.last_run_at, nextRunAt: r.next_run_at },
})

const idSchema = z.coerce.number().int().positive()

/** CRM o tienda: frontend, servidor y (opcional) ruta de salud de la base de datos. */
const appServiceSchema = z
  .object({
    app: z.string().trim().max(300),
    server: z.string().trim().max(300),
    db: z.string().trim().max(300).nullish(),
  })
  .strict()
  .nullable()

const auditSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    /** URL de la pagina: texto, o null si ese servicio no esta habilitado. */
    page: z.string().trim().max(300).nullable(),
    crm: appServiceSchema,
    store: appServiceSchema,
    /** Logo reducido por la web. undefined = no cambiar, null = quitarlo. Solo PNG, JPEG o WebP (nunca SVG: podria llevar scripts). */
    logo: z
      .string()
      .max(60_000)
      .regex(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/)
      .nullable()
      .optional(),
  })
  .strict()

interface AppInput {
  app: string
  server: string
  db: string | null
}

type Body =
  | { ok: true; name: string; page: string | null; crm: AppInput | null; store: AppInput | null; logo: string | null | undefined }
  | { ok: false; field: string }

/** Valida el cuerpo; devuelve las direcciones normalizadas o el campo que esta mal ("crmApp", "storeServer"...). */
function readBody(body: unknown): Body {
  const parsed = auditSchema.safeParse(body)
  if (!parsed.success) return { ok: false, field: String(parsed.error.issues[0]?.path[0] ?? 'name') }
  const a = parsed.data
  const norm = (raw: string) => parseAuditUrl(raw)?.toString() ?? null

  const page = a.page ? norm(a.page) : null
  if (a.page && !page) return { ok: false, field: 'page' }

  const appInput = (kind: AppKind): AppInput | { field: string } | null => {
    const s = a[kind]
    if (!s) return null
    const app = s.app ? norm(s.app) : null
    const server = s.server ? norm(s.server) : null
    const dbUrl = s.db ? norm(s.db) : null
    if (!app) return { field: `${kind}App` }
    if (!server) return { field: `${kind}Server` }
    if (s.db && !dbUrl) return { field: `${kind}Db` }
    return { app, server, db: dbUrl }
  }
  const crm = appInput('crm')
  if (crm && 'field' in crm) return { ok: false, field: crm.field }
  const store = appInput('store')
  if (store && 'field' in store) return { ok: false, field: store.field }

  if (!page && !crm && !store) return { ok: false, field: 'services' } // hace falta al menos un servicio
  if (a.logo && !logoIsValid(a.logo)) return { ok: false, field: 'logo' }
  return { ok: true, name: a.name, page, crm: crm as AppInput | null, store: store as AppInput | null, logo: a.logo }
}

/** Los bytes tienen que ser de la imagen que dice el tipo (no alcanza con el texto del data URL). */
function logoIsValid(logo: string): boolean {
  const mime = logo.slice(11, logo.indexOf(';'))
  const bytes = Buffer.from(logo.slice(logo.indexOf(',') + 1), 'base64')
  if (mime === 'jpeg') return bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
  if (mime === 'png') return bytes.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
  return bytes.subarray(0, 4).toString('latin1') === 'RIFF' && bytes.subarray(8, 12).toString('latin1') === 'WEBP'
}

const RANK: Record<AuditStatus, number> = { red: 3, yellow: 2, green: 1 }
const worstOf = (list: AuditStatus[]): AuditStatus | null => list.reduce<AuditStatus | null>((w, s) => (!w || RANK[s] > RANK[w] ? s : w), null)

/** Estado general de una entrada: el peor de los servicios que tiene resultado. */
function overallStatus(r: AuditRow): AuditStatus | null {
  return worstOf(
    KINDS.filter((kind) => urlOf(r, kind))
      .map((kind) => resultOf(r, kind)?.status)
      .filter((s): s is AuditStatus => !!s),
  )
}

/** Junta el resultado del frontend y el del servidor (con su base de datos) en uno solo, marcando de donde viene cada alerta. */
function merge(app: CheckResult | null, server: CheckResult): CheckResult & { layers: Layers } {
  const parts: { tag: string; r: CheckResult }[] = [...(app ? [{ tag: 'app', r: app }] : []), { tag: 'srv', r: server }]
  const ssl = parts.map((p) => p.r.sslExpiresOn).filter((d): d is string => !!d).sort()[0] ?? null

  // Estado de cada capa: rojo si tiene una alerta grave, amarillo si solo avisos, verde si ninguna.
  const layerOf = (r: CheckResult, alerts: string[]): Layer => ({
    status: alerts.some((a) => r.severe.includes(a)) ? 'red' : alerts.length ? 'yellow' : 'green',
    alerts,
    ms: r.responseMs,
  })
  const DB_ALERTS = ['db_failed', 'no_db_check']
  const serverAlerts = server.alerts.filter((a) => !DB_ALERTS.includes(a))
  // La base de datos se revisa a traves de la ruta de salud del servidor: si el servidor ni responde, no se pudo revisar.
  const cannotReach = ['dns', 'refused', 'timeout', 'unreachable', 'blocked', 'ssl_invalid', 'health_failed', 'no_health', 'http_5xx']
  const dbAlerts = server.alerts.filter((a) => DB_ALERTS.includes(a))
  const dbStatus: AuditStatus | null = server.alerts.includes('db_failed')
    ? 'red'
    : server.alerts.includes('no_db_check')
      ? 'yellow'
      : server.alerts.some((a) => cannotReach.includes(a))
        ? null
        : 'green'
  const layers: Layers = {
    app: app ? layerOf(app, app.alerts) : null,
    server: layerOf(server, serverAlerts),
    db: { status: dbStatus, alerts: dbAlerts, ms: null },
  }
  return {
    layers,
    status: worstOf(parts.map((p) => p.r.status)) ?? 'red',
    alerts: parts.flatMap((p) => p.r.alerts.map((alert) => `${p.tag}:${alert}`)),
    detail: parts.map((p) => p.r.detail).join(' | '),
    httpStatus: server.httpStatus,
    responseMs: server.responseMs,
    sslExpiresOn: ssl,
    checks: { passed: parts.reduce((n, p) => n + p.r.checks.passed, 0), total: parts.reduce((n, p) => n + p.r.checks.total, 0) },
    severe: parts.flatMap((p) => p.r.severe.map((alert) => `${p.tag}:${alert}`)),
  }
}

/** Todo lo que identifica a lo auditado de un servicio: si cambia, el resultado viejo ya no vale. */
const signature = (r: AuditRow, kind: Kind) =>
  kind === 'page' ? String(r.page_url) : [urlOf(r, kind), appUrlOf(r, kind), dbUrlOf(r, kind)].join('|')

/**
 * Verifica los servicios de una entrada (todos, o solo `only`) y guarda cada resultado. Nunca lanza: un fallo de la
 * verificacion es un resultado (rojo).
 */
export async function runAudit(id: number, only: Kind[] = KINDS): Promise<void> {
  for (const kind of only) {
    const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow | undefined
    if (!row) return
    const url = urlOf(row, kind)
    if (!url) continue
    const before = signature(row, kind)
    try {
      let result: CheckResult
      if (kind === 'page') result = await runCheck(url, 'page')
      else {
        // CRM y tienda por capas: frontend (la web que usa la gente) y servidor con su base de datos.
        const app = appUrlOf(row, kind)
        const [appResult, serverResult] = await Promise.all([app ? runCheck(app, 'app') : null, runCheck(url, 'crm', dbUrlOf(row, kind))])
        result = merge(appResult, serverResult)
      }
      db.transaction(() => {
        const current = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow | undefined
        // Puede haberse borrado o cambiado la direccion mientras se consultaba: en ese caso el resultado ya no vale.
        if (!current || signature(current, kind) !== before) return
        const stored: StoredResult = { ...result, checkedAt: new Date().toISOString() }
        db.prepare(`UPDATE audits SET ${kind}_result = ? WHERE id = ?`).run(JSON.stringify(stored), id)
        const updated = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow
        db.prepare('UPDATE audits SET status = ? WHERE id = ?').run(overallStatus(updated), id)
      })()
    } catch (error) {
      captureError(error, { kind: 'server', message: 'No se pudo verificar una entrada de auditoria', alert: false })
    }
  }
  // Una auditoria completa (todos sus servicios) anota la fecha y deja programada la proxima de esa empresa.
  if (only.length === KINDS.length) {
    const cur = db.prepare('SELECT frequency FROM audits WHERE id = ?').get(id) as { frequency: Frequency } | undefined
    if (cur) {
      const now = Date.now()
      db.prepare('UPDATE audits SET last_run_at = ?, next_run_at = ? WHERE id = ?').run(new Date(now).toISOString(), nextRunFrom(cur.frequency, now), id)
    }
  }
  emit('audits')
}

/* ---------- Auditar todo y programacion ---------- */

export const FREQUENCIES = ['manual', 'daily', 'weekly', 'biweekly', 'monthly'] as const
type Frequency = (typeof FREQUENCIES)[number]

/** Cada cuanto se audita todo solo (el mes son 30 dias). `manual` no tiene intervalo: nunca corre solo. */
const INTERVAL_MS: Record<Exclude<Frequency, 'manual'>, number> = {
  daily: 86_400_000,
  weekly: 7 * 86_400_000,
  biweekly: 15 * 86_400_000,
  monthly: 30 * 86_400_000,
}

const nextRunFrom = (frequency: Frequency, from = Date.now()) =>
  frequency === 'manual' ? null : new Date(from + INTERVAL_MS[frequency]).toISOString()

/** Mientras corre una auditoria de todo (a pedido o programada): solo una a la vez. */
let running = false
export const isAuditRunning = () => running

/**
 * Audita todos los servicios de todas las empresas, de a una entrada (para no abrir decenas de conexiones juntas).
 * Devuelve false si ya habia una corriendo. Al terminar anota la fecha y deja programada la proxima (si hay programacion).
 */
export async function runAllAudits(): Promise<boolean> {
  if (running) return false
  running = true
  emit('audits') // las pantallas abiertas pasan a "auditando..."
  try {
    const ids = db.prepare('SELECT id FROM audits ORDER BY id').all() as { id: number }[]
    for (const { id } of ids) await runAudit(id)
  } finally {
    running = false
    emit('audits')
  }
  return true
}

/**
 * Lo llama el reloj del servidor cada tanto: audita las empresas a las que ya les toca segun SU programacion.
 * Una empresa con programacion nueva y sin fecha todavia solo recibe su primera fecha (no se audita de golpe).
 */
let ticking = false
export async function tickAuditSchedule(): Promise<void> {
  if (ticking || running) return
  ticking = true
  try {
    const rows = db.prepare(`SELECT id, frequency, next_run_at FROM audits WHERE frequency != 'manual'`).all() as {
      id: number
      frequency: Frequency
      next_run_at: string | null
    }[]
    for (const r of rows) {
      if (!r.next_run_at) {
        db.prepare('UPDATE audits SET next_run_at = ? WHERE id = ?').run(nextRunFrom(r.frequency), r.id)
      } else if (Date.parse(r.next_run_at) <= Date.now()) {
        await runAudit(r.id)
      }
    }
  } catch (error) {
    captureError(error, { kind: 'server', message: 'No se pudo correr la auditoria programada', alert: false })
  } finally {
    ticking = false
  }
}

/* ---------- Listar (todos) ---------- */

auditsRouter.get('/', (_req, res) => {
  const rows = db.prepare(`SELECT ${columns} FROM audits ORDER BY name COLLATE NOCASE`).all() as unknown as AuditRow[]
  res.json({ audits: rows.map(toAudit), running })
})

/** Programar la auditoria de UNA empresa (todos los administradores). La proxima se cuenta desde ahora. */
auditsRouter.put('/:id/schedule', requireAdmin, sameOrigin, limiter, (req, res) => {
  const id = idSchema.safeParse(req.params.id)
  const body = z.object({ frequency: z.enum(FREQUENCIES) }).strict().safeParse(req.body)
  if (!id.success || !body.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('UPDATE audits SET frequency = ?, next_run_at = ? WHERE id = ?').run(body.data.frequency, nextRunFrom(body.data.frequency), id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.json({ audit: toAudit(row) })
})

/** Auditar todo ahora: responde enseguida y el avance llega por tiempo real. */
auditsRouter.post('/run-all', requireAdmin, sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }), (_req, res) => {
  if (running) {
    res.status(409).json({ error: 'already_running' })
    return
  }
  res.status(202).json({ running: true })
  void runAllAudits()
})

/* ---------- Crear / editar / borrar / verificar (administradores) ---------- */

/** Valores de las columnas de direcciones segun lo que llego (el mismo orden que `ADDRESS_COLUMNS`). */
function addressValues(b: Extract<Body, { ok: true }>): (string | null)[] {
  return [
    (b.page ?? b.crm?.server ?? b.store?.server)!, // `url`, obligatoria desde antes: la primera direccion que haya
    b.page ? 1 : 0, b.crm ? 1 : 0 /* is_page, is_crm */,
    b.page, b.crm?.server ?? null, b.crm?.app ?? null, b.crm?.db ?? null,
    b.store?.server ?? null, b.store?.app ?? null, b.store?.db ?? null,
  ] as (string | null)[]
}
const ADDRESS_COLUMNS = ['url', 'is_page', 'is_crm', 'page_url', 'crm_url', 'crm_app_url', 'crm_db_url', 'store_url', 'store_app_url', 'store_db_url']

// Agregar, editar y borrar empresas es solo del super admin; auditar y programar es de todos los administradores.
auditsRouter.post('/', requireSuper, sameOrigin, limiter, (req, res) => {
  const body = readBody(req.body)
  if (!body.ok) {
    res.status(400).json({ error: 'invalid_input', field: body.field })
    return
  }
  const user = res.locals.user as SessionUser
  const cols = ['name', ...ADDRESS_COLUMNS, 'logo', 'created_by']
  const id = Number(
    db
      .prepare(`INSERT INTO audits (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
      .run(body.name, ...addressValues(body), body.logo ?? null, user.id).lastInsertRowid,
  )
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.status(201).json({ audit: toAudit(row) })
  void runAudit(id) // primera verificacion en segundo plano: el resultado llega por tiempo real
})

auditsRouter.put('/:id', requireSuper, sameOrigin, limiter, (req, res) => {
  const id = idSchema.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const body = readBody(req.body)
  if (!body.ok) {
    res.status(400).json({ error: 'invalid_input', field: body.field })
    return
  }
  const before = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow | undefined
  if (!before) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  // Un servicio con direccion nueva (o recien habilitado) pierde su resultado y se verifica de nuevo; si se deshabilita, se borra.
  const nextSignature: Record<Kind, string> = {
    page: String(body.page),
    crm: body.crm ? [body.crm.server, body.crm.app, body.crm.db].join('|') : 'null||',
    store: body.store ? [body.store.server, body.store.app, body.store.db].join('|') : 'null||',
  }
  const same = (kind: Kind) => {
    const was = signature(before, kind)
    return was === nextSignature[kind] || (!urlOf(before, kind) && nextSignature[kind].startsWith('null'))
  }
  const changed = KINDS.filter((kind) => !same(kind))
  db.transaction(() => {
    db.prepare(`UPDATE audits SET name = ?, ${ADDRESS_COLUMNS.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(body.name, ...addressValues(body), id.data)
    for (const kind of changed) db.prepare(`UPDATE audits SET ${kind}_result = NULL WHERE id = ?`).run(id.data)
    // Logo: sin el campo no se toca; con null se quita; con una imagen se reemplaza.
    if (body.logo !== undefined) db.prepare('UPDATE audits SET logo = ? WHERE id = ?').run(body.logo, id.data)
    const now = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
    db.prepare('UPDATE audits SET status = ? WHERE id = ?').run(overallStatus(now), id.data)
  })()
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.json({ audit: toAudit(row) })
  const toRun = changed.filter((kind) => urlOf(row, kind))
  if (toRun.length) void runAudit(id.data, toRun)
})

auditsRouter.delete('/:id', requireSuper, sameOrigin, limiter, (req, res) => {
  const id = idSchema.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('DELETE FROM audits WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('audits', { exceptCid: res.locals.cid })
  res.status(204).end()
})

/** Verificar ahora: responde enseguida y el resultado llega por tiempo real. */
auditsRouter.post('/:id/check', requireAdmin, sameOrigin, limiter, (req, res) => {
  const id = idSchema.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!db.prepare('SELECT 1 FROM audits WHERE id = ?').get(id.data)) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.status(202).end()
  void runAudit(id.data)
})
