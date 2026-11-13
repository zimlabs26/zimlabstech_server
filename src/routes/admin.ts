import { Router } from 'express'
import { z } from 'zod'
import { hashPassword } from '../auth/password.js'
import { accountBlock, deleteUserSessions, type SessionUser } from '../auth/sessions.js'
import { config } from '../config.js'
import { db } from '../db.js'
import { sendAdminCreatedNotice, sendWelcomeEmail } from '../mailer.js'
import { requireAdmin, requireSuper, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit, endConnections } from '../realtime.js'

export const adminRouter = Router()

// Todo lo de este router es solo para administradores.
adminRouter.use(requireAdmin)

interface AdminRow {
  id: number
  email: string
  created_at: string
  is_super: number
  banned: number
  suspended_until: number | null
  avatar_at: number | null
  totp_enabled: number
}

const adminColumns = 'id, email, created_at, is_super, banned, suspended_until, avatar_at, totp_enabled'

const toAdmin = (r: AdminRow) => {
  const block = accountBlock(r)
  return {
    id: r.id,
    email: r.email,
    createdAt: r.created_at,
    isSuper: r.is_super === 1,
    // URL de su foto (con version para el cache) o null si no subio ninguna.
    avatar: r.avatar_at ? `/api/admin/admins/${r.id}/avatar?v=${r.avatar_at}` : null,
    // 'active' | 'suspended' (hasta `suspendedUntil`) | 'banned' (permanente)
    status: block ? block.kind : ('active' as const),
    suspendedUntil: block?.kind === 'suspended' ? block.until : null,
    // Tiene activada la verificacion en dos pasos (solo se informa si esta o no: nunca el secreto).
    twofa: r.totp_enabled === 1,
  }
}

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 })

const email = z.string().trim().toLowerCase().email().max(254)
// Cuenta con acceso total: contrasena larga obligatoria.
const password = z.string().min(12).max(128)

const findAdmin = (id: number) =>
  db
    .prepare(`SELECT ${adminColumns} FROM users WHERE id = ? AND role = 'admin'`)
    .get(id) as AdminRow | undefined

function invalidField(error: z.ZodError): 'email' | 'password' {
  return error.issues[0]?.path[0] === 'password' ? 'password' : 'email'
}

/* ---------- Listar ---------- */

adminRouter.get('/admins', (_req, res) => {
  const rows = db
    .prepare(`SELECT ${adminColumns} FROM users WHERE role = 'admin' ORDER BY is_super DESC, id`)
    .all() as AdminRow[]
  res.json({ admins: rows.map(toAdmin) })
})

/* ---------- Foto de cada administrador (la lista del panel Admin las muestra) ---------- */

// Este router ya exige ser administrador, asi que solo ellos ven estas fotos. La URL lleva la version.
adminRouter.get('/admins/:id/avatar', (req, res) => {
  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const row = db.prepare(`SELECT avatar FROM users WHERE id = ? AND role = 'admin'`).get(id.data) as
    | { avatar: string | null }
    | undefined
  const match = row?.avatar?.match(/^data:(image\/(?:jpeg|png|webp));base64,(.+)$/)
  if (!match) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.set({ 'Content-Type': match[1], 'Cache-Control': 'private, max-age=31536000, immutable' })
  res.send(Buffer.from(match[2], 'base64'))
})

/* ---------- Crear ---------- */

adminRouter.post('/admins', sameOrigin, limiter, async (req, res) => {
  const parsed = z.object({ email, password }).safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: invalidField(parsed.error) })
    return
  }

  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(parsed.data.email)) {
    res.status(409).json({ error: 'email_taken' })
    return
  }

  const hash = await hashPassword(parsed.data.password)
  const result = db
    // must_change_password = 1: la contrasena la elige quien crea la cuenta, asi que en el primer ingreso se debe cambiar.
    .prepare(`INSERT INTO users (email, password_hash, role, must_change_password) VALUES (?, ?, 'admin', 1)`)
    .run(parsed.data.email, hash)

  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid })
  // Aviso al nuevo usuario con su contrasena temporal; si el correo falla, la cuenta igual queda creada.
  const creator = res.locals.user as SessionUser
  const superRow = db.prepare('SELECT email FROM users WHERE is_super = 1').get() as { email: string } | undefined
  const [mailStatus] = await Promise.all([
    sendWelcomeEmail(parsed.data.email, parsed.data.password),
    // Constancia para el super admin (sin la contrasena).
    superRow ? sendAdminCreatedNotice(superRow.email, parsed.data.email, creator.email) : Promise.resolve(false),
  ])
  res.status(201).json({ admin: toAdmin(findAdmin(Number(result.lastInsertRowid))!), emailSent: mailStatus === 'sent', mailStatus })
})

/* ---------- Editar ---------- */

// Solo el super admin edita, y nunca su propia cuenta: el perfil propio se cambia en
// Configuracion (PUT /api/auth/profile, que pide la contrasena actual).
adminRouter.put('/admins/:id', sameOrigin, limiter, async (req, res) => {
  const caller = res.locals.user as SessionUser

  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const target = findAdmin(id.data)
  if (!target) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  if (!caller.isSuper || target.id === caller.id) {
    res.status(403).json({ error: 'forbidden' })
    return
  }

  const parsed = z
    .object({ email: email.optional(), password: password.optional() })
    .strict()
    .refine((v) => v.email !== undefined || v.password !== undefined)
    .safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: invalidField(parsed.error) })
    return
  }

  const { email: newEmail, password: newPassword } = parsed.data

  if (newEmail && newEmail !== target.email) {
    if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id != ?').get(newEmail, target.id)) {
      res.status(409).json({ error: 'email_taken' })
      return
    }
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, target.id)
  }

  if (newPassword) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(newPassword), target.id)
    // La clave cambio: se cierran las sesiones abiertas de esa cuenta
    // (si alguien cambia la suya, conserva la sesion actual).
    deleteUserSessions(target.id, target.id === caller.id ? req.cookies?.[config.cookieName] : undefined)
  }

  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid })
  emit('profile', { userId: target.id }) // si le cambiaron el correo, sus pestanas abiertas lo reflejan
  res.json({ admin: toAdmin(findAdmin(target.id)!) })
})

/* ---------- Habilitar / suspender / banear (solo el super admin) ---------- */

// 'suspended' dura `minutes` (hasta un ano); 'banned' es permanente; 'active' vuelve a habilitar la cuenta.
const statusSchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('active') }).strict(),
  z.object({ mode: z.literal('banned') }).strict(),
  z.object({ mode: z.literal('suspended'), minutes: z.number().int().min(1).max(525_600) }).strict(),
])

adminRouter.put('/admins/:id/status', requireSuper, sameOrigin, limiter, (req, res) => {
  const caller = res.locals.user as SessionUser

  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  const parsed = statusSchema.safeParse(req.body)
  if (!id.success || !parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const target = findAdmin(id.data)
  if (!target) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  // Nadie bloquea al super admin ni a si mismo: el CRM nunca se queda sin dueno.
  if (target.is_super === 1 || target.id === caller.id) {
    res.status(403).json({ error: 'forbidden' })
    return
  }

  const change = parsed.data
  if (change.mode === 'active') {
    db.prepare('UPDATE users SET banned = 0, suspended_until = NULL WHERE id = ?').run(target.id)
  } else if (change.mode === 'banned') {
    db.prepare('UPDATE users SET banned = 1, suspended_until = NULL WHERE id = ?').run(target.id)
    deleteUserSessions(target.id)
  } else {
    db.prepare('UPDATE users SET banned = 0, suspended_until = ? WHERE id = ?').run(
      Date.now() + change.minutes * 60_000,
      target.id,
    )
    // Se la saca de inmediato: sus sesiones abiertas se cierran.
    deleteUserSessions(target.id)
  }

  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ admin: toAdmin(findAdmin(target.id)!) })
})

/* ---------- Eliminar (solo el super admin) ---------- */

adminRouter.delete('/admins/:id', requireSuper, sameOrigin, limiter, (req, res) => {
  const caller = res.locals.user as SessionUser

  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const target = findAdmin(id.data)
  if (!target) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  // El super admin no se puede eliminar (ni a si mismo): el CRM nunca se queda sin dueno.
  if (target.is_super === 1 || target.id === caller.id) {
    res.status(403).json({ error: 'forbidden' })
    return
  }

  // Sus sesiones se borran en cascada; los clientes que creo se conservan (created_by queda en NULL).
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id)
  // Sus pestanas abiertas salen al login al instante (las sesiones se borraron en cascada).
  endConnections({ userId: target.id })
  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
