import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { db } from '../db.js'
import { requireAdmin, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

export const tasksRouter = Router()

// Las tareas las ven y gestionan todos los administradores, y nadie mas.
tasksRouter.use(requireAdmin)

const statuses = ['todo', 'doing', 'done'] as const
type Status = (typeof statuses)[number]

interface TaskRow {
  id: number
  title: string
  description: string
  status: Status
  position: number
  created_at: string
  updated_at: string
  /** NULL solo en las tareas anteriores a la regla "cada tarea tiene cliente". */
  client_id: number | null
  client_name: string | null
}

const select = `
  SELECT t.id, t.title, t.description, t.status, t.position, t.created_at, t.updated_at, t.client_id, c.name AS client_name
  FROM tasks t LEFT JOIN clients c ON c.id = t.client_id`
const GAP = 1024 // separacion entre tarjetas vecinas
const MIN_GAP = 1e-3 // por debajo de esto se renumera la columna

const toTask = (r: TaskRow) => ({
  id: r.id,
  title: r.title,
  description: r.description,
  status: r.status,
  position: r.position,
  clientId: r.client_id,
  clientName: r.client_name,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
})

// Mover una tarjeta es frecuente: limite generoso pero acotado.
const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 })

const idParam = z.coerce.number().int().positive()

const findTask = (id: number) => db.prepare(`${select} WHERE t.id = ?`).get(id) as TaskRow | undefined

const clientExists = (id: number) => db.prepare('SELECT 1 FROM clients WHERE id = ?').get(id) !== undefined

/* ---------- Listar ---------- */

// Tope de seguridad: un tablero con mas de 500 tarjetas pide archivar, no seguir creciendo.
tasksRouter.get('/', (_req, res) => {
  const rows = db.prepare(`${select} ORDER BY t.position LIMIT 500`).all() as TaskRow[]
  res.json({ tasks: rows.map(toTask) })
})

/* ---------- Crear (siempre al final de "Pendiente") ---------- */

const createSchema = z.object({
  title: z.string().trim().min(1).max(120),
  // El cliente es opcional (null = tarea interna); si viene, debe existir (se verifica en cada ruta).
  clientId: z.number().int().positive().nullish().transform((v) => v ?? null),
  description: z
    .string()
    .trim()
    .max(2000)
    .optional()
    .transform((v) => v ?? ''),
})

tasksRouter.post('/', sameOrigin, writeLimiter, (req, res) => {
  const parsed = createSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'title')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  if (parsed.data.clientId !== null && !clientExists(parsed.data.clientId)) {
    res.status(400).json({ error: 'invalid_input', field: 'clientId' })
    return
  }

  const user = res.locals.user as SessionUser
  const last = db.prepare(`SELECT MAX(position) AS m FROM tasks WHERE status = 'todo'`).get() as { m: number | null }

  const result = db
    .prepare(
      `INSERT INTO tasks (title, description, client_id, status, position, created_by) VALUES (?, ?, ?, 'todo', ?, ?)`,
    )
    .run(parsed.data.title, parsed.data.description, parsed.data.clientId, (last.m ?? 0) + GAP, user.id)

  emit('tasks', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(201).json({ task: toTask(findTask(Number(result.lastInsertRowid))!) })
})

/* ---------- Editar titulo, descripcion y cliente (no toca el lugar en el tablero) ---------- */

tasksRouter.put('/:id', sameOrigin, writeLimiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  const parsed = createSchema.safeParse(req.body)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'title')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  if (parsed.data.clientId !== null && !clientExists(parsed.data.clientId)) {
    res.status(400).json({ error: 'invalid_input', field: 'clientId' })
    return
  }

  const result = db
    .prepare(
      `UPDATE tasks SET title = ?, description = ?, client_id = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`,
    )
    .run(parsed.data.title, parsed.data.description, parsed.data.clientId, id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('tasks', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ task: toTask(findTask(id.data)!) })
})

/* ---------- Mover (cambiar de columna y/o de lugar) ---------- */

const moveSchema = z.object({
  status: z.enum(statuses),
  // La tarjeta queda justo ANTES de esta; sin valor, al final de la columna.
  beforeId: z.number().int().positive().nullable().optional(),
})

/** Si dos vecinas quedaron casi pegadas, se renumera toda la columna (raro: hace falta partir ~40 veces el mismo hueco). */
function rebalanceIfNeeded(status: Status): { id: number; position: number }[] | undefined {
  const rows = db.prepare('SELECT id, position FROM tasks WHERE status = ? ORDER BY position').all(status) as {
    id: number
    position: number
  }[]

  const tight = rows.some((r, i) => i > 0 && r.position - rows[i - 1].position < MIN_GAP)
  if (!tight) return undefined

  const update = db.prepare('UPDATE tasks SET position = ? WHERE id = ?')
  const renumbered = rows.map((r, i) => ({ id: r.id, position: (i + 1) * GAP }))
  for (const r of renumbered) update.run(r.position, r.id)
  return renumbered
}

tasksRouter.put('/:id/move', sameOrigin, writeLimiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  const body = moveSchema.safeParse(req.body)
  if (!id.success || !body.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  if (!findTask(id.data)) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  const { status, beforeId } = body.data

  const move = db.transaction(() => {
    const before =
      beforeId && beforeId !== id.data
        ? (db.prepare('SELECT position FROM tasks WHERE id = ? AND status = ?').get(beforeId, status) as
            | { position: number }
            | undefined)
        : undefined

    let position: number
    if (before) {
      // Entre la vecina anterior y la que queda despues: el punto medio.
      const prev = db
        .prepare('SELECT MAX(position) AS p FROM tasks WHERE status = ? AND id != ? AND position < ?')
        .get(status, id.data, before.position) as { p: number | null }
      position = prev.p === null ? before.position - GAP : (prev.p + before.position) / 2
    } else {
      // Sin vecina valida (o la columna cambio mientras tanto): al final.
      const last = db
        .prepare('SELECT MAX(position) AS m FROM tasks WHERE status = ? AND id != ?')
        .get(status, id.data) as { m: number | null }
      position = (last.m ?? 0) + GAP
    }

    db.prepare(`UPDATE tasks SET status = ?, position = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`).run(
      status,
      position,
      id.data,
    )
    return rebalanceIfNeeded(status)
  })

  const positions = move()
  emit('tasks', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ task: toTask(findTask(id.data)!), positions })
})

/* ---------- Eliminar ---------- */

tasksRouter.delete('/:id', sameOrigin, writeLimiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const result = db.prepare('DELETE FROM tasks WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('tasks', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
