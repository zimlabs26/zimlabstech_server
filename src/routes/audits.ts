import express, { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { parseAuditUrl, runCheck, type AuditStatus, type CheckResult } from '../auditcheck.js'
import { db } from '../db.js'
import { captureError } from '../errorlog.js'
import { requireAdmin, requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Auditoria: listado de paginas y CRM que arma el equipo, con un semaforo (verde / amarillo / rojo) que el servidor
 * actualiza solo (ver `checkAllAudits`) o a pedido. Cada entrada puede tener los dos servicios: la URL de la pagina y/o la
 * direccion del servidor del CRM; cada uno se verifica por separado y el estado general es el peor de los dos.
 * Todos los usuarios del CRM ven la lista; solo administradores la editan.
 */

export const auditsRouter = Router()
auditsRouter.use(requireUser)
// Alta y edicion llevan el logo (unos 45 KB como mucho): el limite general de 10 KB no alcanza (ver index.ts).
auditsRouter.use(express.json({ limit: '100kb' }))

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 })

type Kind = 'page' | 'crm'
const KINDS: Kind[] = ['page', 'crm']

interface AuditRow {
  id: number
  name: string
  status: AuditStatus | null
  logo: string | null
  page_url: string | null
  crm_url: string | null
  page_result: string | null
  crm_result: string | null
}

const columns = 'id, name, status, logo, page_url, crm_url, page_result, crm_result'

/** Ultimo resultado guardado de un servicio (sin el estado `url`, que va aparte). */
type StoredResult = CheckResult & { checkedAt: string }

const urlOf = (r: AuditRow, kind: Kind) => (kind === 'page' ? r.page_url : r.crm_url)
const resultOf = (r: AuditRow, kind: Kind): StoredResult | null => {
  const raw = kind === 'page' ? r.page_result : r.crm_result
  return raw ? (JSON.parse(raw) as StoredResult) : null
}

/** Un servicio tal como lo ve la web; null si la entrada no lo tiene. */
const toService = (r: AuditRow, kind: Kind) => {
  const url = urlOf(r, kind)
  if (!url) return null
  const res = resultOf(r, kind)
  return {
    url,
    status: res?.status ?? null,
    alerts: res?.alerts ?? [],
    detail: res?.detail ?? '',
    httpStatus: res?.httpStatus ?? null,
    responseMs: res?.responseMs ?? null,
    sslExpiresOn: res?.sslExpiresOn ?? null,
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
})

const idSchema = z.coerce.number().int().positive()

const auditSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    /** URL de la pagina y direccion del servidor del CRM: texto, o null / vacio si ese servicio no esta habilitado. */
    page: z.string().trim().max(300).nullable(),
    crm: z.string().trim().max(300).nullable(),
    /** Logo reducido por la web. undefined = no cambiar, null = quitarlo. Solo PNG, JPEG o WebP (nunca SVG: podria llevar scripts). */
    logo: z
      .string()
      .max(60_000)
      .regex(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/)
      .nullable()
      .optional(),
  })
  .strict()

/** Valida el cuerpo; devuelve las direcciones normalizadas o el campo que esta mal. */
function readBody(body: unknown):
  | { ok: true; name: string; page: string | null; crm: string | null; logo: string | null | undefined }
  | { ok: false; field: string } {
  const parsed = auditSchema.safeParse(body)
  if (!parsed.success) return { ok: false, field: String(parsed.error.issues[0]?.path[0] ?? 'name') }
  const a = parsed.data
  const normalize = (raw: string | null) => (raw ? (parseAuditUrl(raw)?.toString() ?? false) : null)
  const page = normalize(a.page)
  const crm = normalize(a.crm)
  if (page === false) return { ok: false, field: 'page' }
  if (crm === false) return { ok: false, field: 'crm' }
  if (!page && !crm) return { ok: false, field: 'services' } // hace falta al menos un servicio
  if (a.logo && !logoIsValid(a.logo)) return { ok: false, field: 'logo' }
  return { ok: true, name: a.name, page, crm, logo: a.logo }
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

/** Estado general de una entrada: el peor de los servicios que tiene resultado. */
function overallStatus(r: AuditRow): AuditStatus | null {
  let worst: AuditStatus | null = null
  for (const kind of KINDS) {
    if (!urlOf(r, kind)) continue
    const s = resultOf(r, kind)?.status
    if (s && (!worst || RANK[s] > RANK[worst])) worst = s
  }
  return worst
}

/**
 * Verifica los servicios de una entrada (los dos, o solo `only`) y guarda cada resultado. Nunca lanza: un fallo de la
 * verificacion es un resultado (rojo).
 */
export async function runAudit(id: number, only: Kind[] = KINDS): Promise<void> {
  for (const kind of only) {
    const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow | undefined
    if (!row) return
    const url = urlOf(row, kind)
    if (!url) continue
    try {
      const result = await runCheck(url)
      db.transaction(() => {
        const current = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow | undefined
        // Puede haberse borrado o cambiado la direccion mientras se consultaba: en ese caso el resultado ya no vale.
        if (!current || urlOf(current, kind) !== url) return
        const stored: StoredResult = { ...result, checkedAt: new Date().toISOString() }
        db.prepare(`UPDATE audits SET ${kind}_result = ? WHERE id = ?`).run(JSON.stringify(stored), id)
        const updated = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow
        db.prepare('UPDATE audits SET status = ? WHERE id = ?').run(overallStatus(updated), id)
      })()
    } catch (error) {
      captureError(error, { kind: 'server', message: 'No se pudo verificar una entrada de auditoria', alert: false })
    }
  }
  emit('audits')
}

/** Verifica todas las entradas, de a una (para no abrir decenas de conexiones juntas). Lo llama el reloj del servidor. */
export async function checkAllAudits(): Promise<void> {
  const ids = db.prepare('SELECT id FROM audits ORDER BY id').all() as { id: number }[]
  for (const { id } of ids) await runAudit(id)
}

/* ---------- Listar (todos) ---------- */

auditsRouter.get('/', (_req, res) => {
  const rows = db.prepare(`SELECT ${columns} FROM audits ORDER BY name COLLATE NOCASE`).all() as unknown as AuditRow[]
  res.json({ audits: rows.map(toAudit) })
})

/* ---------- Crear / editar / borrar / verificar (administradores) ---------- */

auditsRouter.post('/', requireAdmin, sameOrigin, limiter, (req, res) => {
  const body = readBody(req.body)
  if (!body.ok) {
    res.status(400).json({ error: 'invalid_input', field: body.field })
    return
  }
  const user = res.locals.user as SessionUser
  const id = Number(
    db
      .prepare('INSERT INTO audits (name, url, is_page, is_crm, page_url, crm_url, logo, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(body.name, (body.page ?? body.crm)!, body.page ? 1 : 0, body.crm ? 1 : 0, body.page, body.crm, body.logo ?? null, user.id)
      .lastInsertRowid,
  )
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.status(201).json({ audit: toAudit(row) })
  void runAudit(id) // primera verificacion en segundo plano: el resultado llega por tiempo real
})

auditsRouter.put('/:id', requireAdmin, sameOrigin, limiter, (req, res) => {
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
  const changed = KINDS.filter((kind) => urlOf(before, kind) !== (kind === 'page' ? body.page : body.crm))
  db.transaction(() => {
    db.prepare(
      'UPDATE audits SET name = ?, url = ?, is_page = ?, is_crm = ?, page_url = ?, crm_url = ? WHERE id = ?',
    ).run(body.name, (body.page ?? body.crm)!, body.page ? 1 : 0, body.crm ? 1 : 0, body.page, body.crm, id.data)
    for (const kind of changed) db.prepare(`UPDATE audits SET ${kind}_result = NULL WHERE id = ?`).run(id.data)
    // Logo: sin el campo no se toca; con null se quita; con una imagen se reemplaza.
    if (body.logo !== undefined) db.prepare('UPDATE audits SET logo = ? WHERE id = ?').run(body.logo, id.data)
    const now = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
    db.prepare('UPDATE audits SET status = ? WHERE id = ?').run(overallStatus(now), id.data)
  })()
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.json({ audit: toAudit(row) })
  if (changed.length) void runAudit(id.data, changed)
})

auditsRouter.delete('/:id', requireAdmin, sameOrigin, limiter, (req, res) => {
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
