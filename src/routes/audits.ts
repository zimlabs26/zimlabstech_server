import express, { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { parseAuditUrl, runCheck, type AuditStatus } from '../auditcheck.js'
import { db } from '../db.js'
import { captureError } from '../errorlog.js'
import { requireAdmin, requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Auditoria: listado de paginas y CRM que arma el equipo, con un semaforo (verde / amarillo / rojo) que el servidor
 * actualiza solo (ver `checkAllAudits`) o a pedido. Todos los usuarios del CRM ven la lista; solo administradores la editan.
 */

export const auditsRouter = Router()
auditsRouter.use(requireUser)
// Alta y edicion llevan el logo (unos 45 KB como mucho): el limite general de 10 KB no alcanza (ver index.ts).
auditsRouter.use(express.json({ limit: '100kb' }))

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 })

interface AuditRow {
  id: number
  name: string
  url: string
  is_page: 0 | 1
  is_crm: 0 | 1
  status: AuditStatus | null
  alerts: string
  detail: string
  http_status: number | null
  response_ms: number | null
  ssl_expires_on: string | null
  checked_at: string | null
  logo: string | null
}

const columns = 'id, name, url, is_page, is_crm, status, alerts, detail, http_status, response_ms, ssl_expires_on, checked_at, logo'

const toAudit = (r: AuditRow) => ({
  id: r.id,
  name: r.name,
  url: r.url,
  /** Un servicio es una pagina o un CRM (los que se cargaron como ambos antes, se muestran como CRM). */
  type: (r.is_crm === 1 ? 'crm' : 'page') as 'page' | 'crm',
  logo: r.logo,
  status: r.status,
  alerts: JSON.parse(r.alerts) as string[],
  detail: r.detail,
  httpStatus: r.http_status,
  responseMs: r.response_ms,
  sslExpiresOn: r.ssl_expires_on,
  checkedAt: r.checked_at,
})

const idSchema = z.coerce.number().int().positive()

const auditSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    url: z
      .string()
      .trim()
      .min(1)
      .max(300)
      .transform((value) => parseAuditUrl(value)?.toString() ?? null)
      .refine((value): value is string => value !== null),
    type: z.enum(['page', 'crm']),
    /** Logo reducido por la web. undefined = no cambiar, null = quitarlo. Solo PNG, JPEG o WebP (nunca SVG: podria llevar scripts). */
    logo: z
      .string()
      .max(60_000)
      .regex(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/)
      .nullable()
      .optional(),
  })
  .strict()

/** Los bytes tienen que ser de la imagen que dice el tipo (no alcanza con el texto del data URL). */
function logoIsValid(logo: string): boolean {
  const mime = logo.slice(11, logo.indexOf(';'))
  const bytes = Buffer.from(logo.slice(logo.indexOf(',') + 1), 'base64')
  if (mime === 'jpeg') return bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
  if (mime === 'png') return bytes.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
  return bytes.subarray(0, 4).toString('latin1') === 'RIFF' && bytes.subarray(8, 12).toString('latin1') === 'WEBP'
}

/** Verifica una entrada y guarda el resultado. Nunca lanza: un fallo de la verificacion es un resultado (rojo). */
export async function runAudit(id: number): Promise<void> {
  const row = db.prepare('SELECT url FROM audits WHERE id = ?').get(id) as { url: string } | undefined
  if (!row) return
  try {
    const r = await runCheck(row.url)
    // Puede haberse borrado o cambiado la direccion mientras se consultaba: en ese caso el resultado ya no vale.
    db.prepare(
      `UPDATE audits SET status = ?, alerts = ?, detail = ?, http_status = ?, response_ms = ?, ssl_expires_on = ?,
         checked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ? AND url = ?`,
    ).run(r.status, JSON.stringify(r.alerts), r.detail, r.httpStatus, r.responseMs, r.sslExpiresOn, id, row.url)
  } catch (error) {
    captureError(error, { kind: 'server', message: 'No se pudo verificar una entrada de auditoria', alert: false })
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
  const parsed = auditSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'name')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }
  const a = parsed.data
  if (a.logo && !logoIsValid(a.logo)) {
    res.status(400).json({ error: 'invalid_input', field: 'logo' })
    return
  }
  const user = res.locals.user as SessionUser
  const id = Number(
    db
      .prepare('INSERT INTO audits (name, url, is_page, is_crm, logo, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .run(a.name, a.url, a.type === 'page' ? 1 : 0, a.type === 'crm' ? 1 : 0, a.logo ?? null, user.id).lastInsertRowid,
  )
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.status(201).json({ audit: toAudit(row) })
  void runAudit(id) // primera verificacion en segundo plano: el resultado llega por tiempo real
})

auditsRouter.put('/:id', requireAdmin, sameOrigin, limiter, (req, res) => {
  const id = idSchema.safeParse(req.params.id)
  const parsed = auditSchema.safeParse(req.body)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'name')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }
  const a = parsed.data
  if (a.logo && !logoIsValid(a.logo)) {
    res.status(400).json({ error: 'invalid_input', field: 'logo' })
    return
  }
  const before = db.prepare('SELECT url FROM audits WHERE id = ?').get(id.data) as { url: string } | undefined
  if (!before) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  const changedUrl = before.url !== a.url
  db.transaction(() => {
    db.prepare(
      changedUrl
        ? `UPDATE audits SET name = ?, url = ?, is_page = ?, is_crm = ?, status = NULL, alerts = '[]', detail = '',
             http_status = NULL, response_ms = NULL, ssl_expires_on = NULL, checked_at = NULL WHERE id = ?`
        : 'UPDATE audits SET name = ?, url = ?, is_page = ?, is_crm = ? WHERE id = ?',
    ).run(a.name, a.url, a.type === 'page' ? 1 : 0, a.type === 'crm' ? 1 : 0, id.data)
    // Logo: sin el campo no se toca; con null se quita; con una imagen se reemplaza.
    if (a.logo !== undefined) db.prepare('UPDATE audits SET logo = ? WHERE id = ?').run(a.logo, id.data)
  })()
  const row = db.prepare(`SELECT ${columns} FROM audits WHERE id = ?`).get(id.data) as unknown as AuditRow
  emit('audits', { exceptCid: res.locals.cid })
  res.json({ audit: toAudit(row) })
  if (changedUrl) void runAudit(id.data)
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
