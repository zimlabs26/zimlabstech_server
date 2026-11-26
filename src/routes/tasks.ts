import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { db } from '../db.js'
import { requireAdmin, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

export const tasksRouter = Router()

// Las tareas compartidas las ven y gestionan todos los administradores. Las privadas (owner_id) solo su dueño: cada
// consulta de este archivo filtra con VISIBLE, y una tarea ajena responde 404 como si no existiera.
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
  /** NULL en las internas, en las privadas y en las anteriores a la regla "cada tarea tiene cliente". */
  client_id: number | null
  client_name: string | null
  /** Dueño de una tarea privada; NULL = tablero compartido. */
  owner_id: number | null
}

const select = `
  SELECT t.id, t.title, t.description, t.status, t.position, t.created_at, t.updated_at, t.client_id, c.name AS client_name, t.owner_id
  FROM tasks t LEFT JOIN clients c ON c.id = t.client_id`
/** Condicion de visibilidad (un parametro: el id de quien consulta). */
const VISIBLE = '(t.owner_id IS NULL OR t.owner_id = ?)'
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
  private: r.owner_id !== null,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
})

// Mover una tarjeta es frecuente: limite generoso pero acotado.
const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 })

const idParam = z.coerce.number().int().positive()

const userOf = (res: { locals: Record<string, unknown> }) => (res.locals.user as SessionUser).id

const findTask = (id: number, userId: number) => db.prepare(`${select} WHERE t.id = ? AND ${VISIBLE}`).get(id, userId) as TaskRow | undefined

const clientExists = (id: number) => db.prepare('SELECT 1 FROM clients WHERE id = ?').get(id) !== undefined

/** Una tarea privada solo le importa a su dueño; el resto de los cambios se avisa a todos los administradores. */
const notify = (res: { locals: Record<string, unknown> }, userId: number, onlyOwner: boolean) =>
  emit('tasks', onlyOwner ? { userId, exceptCid: res.locals.cid as string } : { adminsOnly: true, exceptCid: res.locals.cid as string })

/* ---------- Listar ---------- */

// Tope de seguridad: un tablero con mas de 500 tarjetas pide archivar, no seguir creciendo.
tasksRouter.get('/', (_req, res) => {
  const rows = db.prepare(`${select} WHERE ${VISIBLE} ORDER BY t.position LIMIT 500`).all(userOf(res)) as TaskRow[]
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
  // Privada: personal, solo la ve quien la crea y no lleva cliente.
  private: z.boolean().optional().default(false),
})

tasksRouter.post('/', sameOrigin, writeLimiter, (req, res) => {
  const parsed = createSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'title')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  const isPrivate = parsed.data.private
  const clientId = isPrivate ? null : parsed.data.clientId
  if (clientId !== null && !clientExists(clientId)) {
    res.status(400).json({ error: 'invalid_input', field: 'clientId' })
    return
  }

  const userId = userOf(res)
  const last = db.prepare(`SELECT MAX(position) AS m FROM tasks t WHERE t.status = 'todo' AND ${VISIBLE}`).get(userId) as { m: number | null }

  const result = db
    .prepare(
      `INSERT INTO tasks (title, description, client_id, status, position, created_by, owner_id) VALUES (?, ?, ?, 'todo', ?, ?, ?)`,
    )
    .run(parsed.data.title, parsed.data.description, clientId, (last.m ?? 0) + GAP, userId, isPrivate ? userId : null)

  notify(res, userId, isPrivate)
  res.status(201).json({ task: toTask(findTask(Number(result.lastInsertRowid), userId)!) })
})

/* ---------- Editar titulo, descripcion, cliente y privacidad (no toca el lugar en el tablero) ---------- */

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

  const userId = userOf(res)
  const before = findTask(id.data, userId)
  if (!before) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  const isPrivate = parsed.data.private
  const clientId = isPrivate ? null : parsed.data.clientId
  if (clientId !== null && !clientExists(clientId)) {
    res.status(400).json({ error: 'invalid_input', field: 'clientId' })
    return
  }

  db.prepare(
    `UPDATE tasks SET title = ?, description = ?, client_id = ?, owner_id = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`,
  ).run(parsed.data.title, parsed.data.description, clientId, isPrivate ? userId : null, id.data)

  // Si pasa de compartida a privada (o al reves) los demas administradores tambien tienen que enterarse.
  notify(res, userId, isPrivate && before.owner_id !== null)
  res.json({ task: toTask(findTask(id.data, userId)!) })
})

/* ---------- Mover (cambiar de columna y/o de lugar) ---------- */

const moveSchema = z.object({
  status: z.enum(statuses),
  // La tarjeta queda justo ANTES de esta; sin valor, al final de la columna.
  beforeId: z.number().int().positive().nullable().optional(),
})

/**
 * Si dos vecinas quedaron casi pegadas, se renumera toda la columna (raro: hace falta partir ~40 veces el mismo hueco).
 * Solo se renumeran las tarjetas que esta persona ve: asi nunca se tocan ni se devuelven las privadas de otra.
 */
function rebalanceIfNeeded(status: Status, userId: number): { id: number; position: number }[] | undefined {
  const rows = db.prepare(`SELECT t.id, t.position FROM tasks t WHERE t.status = ? AND ${VISIBLE} ORDER BY t.position`).all(status, userId) as {
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

  const userId = userOf(res)
  const current = findTask(id.data, userId)
  if (!current) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  const { status, beforeId } = body.data

  const move = db.transaction(() => {
    const before =
      beforeId && beforeId !== id.data
        ? (db.prepare(`SELECT t.position FROM tasks t WHERE t.id = ? AND t.status = ? AND ${VISIBLE}`).get(beforeId, status, userId) as
            | { position: number }
            | undefined)
        : undefined

    let position: number
    if (before) {
      // Entre la vecina anterior y la que queda despues: el punto medio.
      const prev = db
        .prepare(`SELECT MAX(t.position) AS p FROM tasks t WHERE t.status = ? AND t.id != ? AND t.position < ? AND ${VISIBLE}`)
        .get(status, id.data, before.position, userId) as { p: number | null }
      position = prev.p === null ? before.position - GAP : (prev.p + before.position) / 2
    } else {
      // Sin vecina valida (o la columna cambio mientras tanto): al final.
      const last = db
        .prepare(`SELECT MAX(t.position) AS m FROM tasks t WHERE t.status = ? AND t.id != ? AND ${VISIBLE}`)
        .get(status, id.data, userId) as { m: number | null }
      position = (last.m ?? 0) + GAP
    }

    db.prepare(`UPDATE tasks SET status = ?, position = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`).run(
      status,
      position,
      id.data,
    )
    return rebalanceIfNeeded(status, userId)
  })

  const positions = move()
  // Una renumeracion puede haber movido tarjetas compartidas: en ese caso los demas tambien deben refrescar.
  notify(res, userId, current.owner_id !== null && !positions)
  res.json({ task: toTask(findTask(id.data, userId)!), positions })
})

/* ---------- Eliminar ---------- */

tasksRouter.delete('/:id', sameOrigin, writeLimiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const userId = userOf(res)
  const current = findTask(id.data, userId)
  if (!current) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  db.prepare('DELETE FROM tasks WHERE id = ?').run(id.data)
  notify(res, userId, current.owner_id !== null)
  res.status(204).end()
})
