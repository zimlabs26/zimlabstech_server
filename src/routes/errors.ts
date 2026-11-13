import { Router } from 'express'
import { z } from 'zod'
import { getSessionUser } from '../auth/sessions.js'
import { config } from '../config.js'
import { db } from '../db.js'
import { recordError } from '../errorlog.js'
import { requireSuper, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'

export const errorsRouter = Router()

/* ---------- Recibir errores de la web (publico: tambien fallan la pantalla de ingreso y el cambio de clave) ---------- */

// Tope por IP para que nadie pueda inundar el registro. Las filas totales tambien estan acotadas (errorlog.ts).
const reportLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 })

const reportSchema = z.object({
  kind: z.enum(['js_error', 'promise', 'render', 'network']),
  message: z.string().trim().min(1).max(500),
  detail: z.string().max(4000).optional(),
  path: z.string().max(200).optional(),
})

errorsRouter.post('/', sameOrigin, reportLimiter, (req, res) => {
  const parsed = reportSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  // Si hay sesion abierta se anota de quien es el error (solo el correo), para poder consultarle que hacia.
  const user = getSessionUser(req.cookies?.[config.cookieName])
  const recorded = recordError({
    source: 'web',
    kind: parsed.data.kind,
    message: parsed.data.message,
    detail: parsed.data.detail,
    path: parsed.data.path,
    userEmail: user?.email,
    userAgent: req.get('user-agent') ?? '',
  })
  res.status(201).json({ ref: recorded?.ref ?? null })
})

/* ---------- Ver y limpiar (solo el super admin) ---------- */

interface ErrorRow {
  id: number
  source: 'server' | 'web'
  kind: string
  message: string
  detail: string
  path: string
  method: string
  status: number | null
  user_email: string
  user_agent: string
  ref: string
  count: number
  first_seen: string
  last_seen: string
}

errorsRouter.get('/', requireSuper, (req, res) => {
  const query = z
    .object({
      source: z.enum(['server', 'web']).optional(),
      q: z.string().trim().max(100).optional(),
      limit: z.coerce.number().int().min(1).max(200).default(100),
      offset: z.coerce.number().int().min(0).default(0),
    })
    .safeParse(req.query)
  if (!query.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { source, q, limit, offset } = query.data
  const like = q ? `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%` : null
  const where = [
    source ? 'source = @source' : '1=1',
    like ? `(message LIKE @like ESCAPE '\\' OR path LIKE @like ESCAPE '\\' OR ref LIKE @like ESCAPE '\\')` : '1=1',
  ].join(' AND ')
  // better-sqlite3 solo acepta los parametros con nombre que la consulta usa.
  const params: Record<string, string> = {}
  if (source) params.source = source
  if (like) params.like = like

  const rows = db
    .prepare(`SELECT * FROM error_log WHERE ${where} ORDER BY last_seen DESC LIMIT ${limit} OFFSET ${offset}`)
    .all(params) as ErrorRow[]
  const total = (db.prepare(`SELECT COUNT(*) AS n FROM error_log WHERE ${where}`).get(params) as { n: number }).n
  const counts = db.prepare('SELECT source, COUNT(*) AS n FROM error_log GROUP BY source').all() as { source: string; n: number }[]

  res.json({
    errors: rows.map((r) => ({
      id: r.id,
      source: r.source,
      kind: r.kind,
      message: r.message,
      detail: r.detail,
      path: r.path,
      method: r.method,
      status: r.status,
      userEmail: r.user_email,
      userAgent: r.user_agent,
      ref: r.ref,
      count: r.count,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    })),
    total,
    counts: { server: counts.find((c) => c.source === 'server')?.n ?? 0, web: counts.find((c) => c.source === 'web')?.n ?? 0 },
  })
})

const idParam = z.coerce.number().int().positive()

errorsRouter.delete('/:id', sameOrigin, requireSuper, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('DELETE FROM error_log WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.status(204).end()
})

// Vaciar todo el registro.
errorsRouter.delete('/', sameOrigin, requireSuper, (_req, res) => {
  db.prepare('DELETE FROM error_log').run()
  res.status(204).end()
})
