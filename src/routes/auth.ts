import express, { Router, type Response } from 'express'
import { z } from 'zod'
import { burnTime, hashPassword, verifyPassword } from '../auth/password.js'
import {
  accountBlock,
  clearSessionCookie,
  createSession,
  deleteSession,
  deleteUserSessionById,
  deleteUserSessions,
  getSessionUser,
  listUserSessions,
  setSessionCookie,
} from '../auth/sessions.js'
import {
  checkSecondFactor,
  closeTicket,
  failTicket,
  generateRecoveryCodes,
  issueTicket,
  remainingRecoveryCodes,
  ticketUser,
} from '../auth/twofa.js'
import { config } from '../config.js'
import { db, type UserRow } from '../db.js'
import { newSecret, otpauthUri, verifyTotp } from '../totp.js'
import { sameOrigin } from '../middleware/guards.js'
import { failureLimiter, rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

const email = z.string().trim().toLowerCase().email().max(254)

// No hay registro publico: el acceso al CRM lo crea un administrador (scripts/users.ts).
// En el login no se revela la politica de contrasenas: solo se acota el largo.
const loginSchema = z.object({ email, password: z.string().min(1).max(128) })

// Pedidos de gestion de la cuenta (2FA, perfil). Los intentos con codigo o clave incorrectos se limitan aparte
// (twofaFailuresByUser), asi que este tope solo evita abusos y no debe cortar a quien prueba la pantalla.
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 })

// Login: tope general de pedidos por IP (protege la CPU del hash de contrasenas) y limites aparte por intentos fallidos.
const loginFloodLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 })
const loginFailuresByIp = failureLimiter({ windowMs: 15 * 60 * 1000, max: 20 })
const loginFailuresByPair = failureLimiter({ windowMs: 15 * 60 * 1000, max: 8 })

function invalidInput(res: Response, error: z.ZodError): void {
  const field = error.issues[0]?.path[0]
  res.status(400).json({ error: 'invalid_input', field: field === 'password' ? 'password' : 'email' })
}

export const authRouter = Router()

authRouter.get('/me', (req, res) => {
  res.json({ user: getSessionUser(req.cookies?.[config.cookieName]) })
})

authRouter.post('/login', sameOrigin, loginFloodLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body)
  if (!parsed.success) return invalidInput(res, parsed.error)

  const { email: address, password } = parsed.data

  // Solo cuentan los intentos fallidos: entrar bien nunca gasta cupo. Se frena por IP (muchas cuentas distintas) y por
  // correo + IP (adivinar una contrasena), y quien tiene el cupo agotado ni siquiera llega a comprobar la contrasena.
  const ipKey = req.ip ?? 'unknown'
  const pairKey = `${address}|${ipKey}`
  const wait = Math.max(loginFailuresByIp.blockedFor(ipKey), loginFailuresByPair.blockedFor(pairKey))
  if (wait > 0) {
    res.setHeader('Retry-After', wait)
    res.status(429).json({ error: 'rate_limited' })
    return
  }
  const fail = () => {
    loginFailuresByIp.fail(ipKey)
    loginFailuresByPair.fail(pairKey)
    res.status(401).json({ error: 'invalid_credentials' })
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(address) as UserRow | undefined

  if (!user) {
    await burnTime(password)
    return fail()
  }

  if (!(await verifyPassword(password, user.password_hash))) return fail()

  // Entrar bien limpia el contador de ESTE correo desde ESTA IP. El de la IP sola no se limpia: asi una cuenta
  // valida no sirve para reiniciar el freno mientras se prueban otras.
  loginFailuresByPair.reset(pairKey)

  // Con la contrasena correcta se avisa por que no puede entrar (antes no: asi no se revela que la cuenta existe).
  const block = accountBlock(user)
  if (block) {
    res.status(403).json(
      block.kind === 'banned' ? { error: 'account_banned' } : { error: 'account_suspended', until: block.until },
    )
    return
  }

  // Con 2FA activado la contrasena sola no abre sesion: se entrega un ticket y falta confirmar el codigo.
  if (user.totp_enabled === 1) {
    res.json({ twofaRequired: true, ticket: issueTicket(user.id) })
    return
  }

  const token = createSession(user.id, req.get('user-agent'))
  setSessionCookie(res, token)
  // Un dispositivo nuevo aparece al instante en "Sesiones activas" de las demas pestanas de la cuenta.
  emit('sessions', { userId: user.id })
  res.json({ user: getSessionUser(token) })
})

/* ---------- Verificacion en dos pasos (2FA) ---------- */

// Intentos fallidos del segundo paso: por IP y por cuenta (asi un atacante que ya tiene la contrasena no puede probar
// codigos sin limite pidiendo tickets nuevos).
const twofaFailuresByIp = failureLimiter({ windowMs: 15 * 60 * 1000, max: 30 })
const twofaFailuresByUser = failureLimiter({ windowMs: 15 * 60 * 1000, max: 10 })

const codeField = z.string().trim().min(1).max(32)

// Segundo paso del login: ticket + codigo de la app (6 digitos) o de recuperacion. Recien aca se abre la sesion.
authRouter.post('/login/2fa', sameOrigin, loginFloodLimiter, (req, res) => {
  const parsed = z.object({ ticket: z.string().min(10).max(100), code: codeField }).safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { ticket, code } = parsed.data

  const userId = ticketUser(ticket)
  if (userId === null) {
    res.status(401).json({ error: 'invalid_ticket' })
    return
  }
  const ipKey = req.ip ?? 'unknown'
  const userKey = `u${userId}`
  const wait = Math.max(twofaFailuresByIp.blockedFor(ipKey), twofaFailuresByUser.blockedFor(userKey))
  if (wait > 0) {
    res.setHeader('Retry-After', wait)
    res.status(429).json({ error: 'rate_limited' })
    return
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as UserRow | undefined
  if (!user || user.totp_enabled !== 1) {
    closeTicket(ticket)
    res.status(401).json({ error: 'invalid_ticket' })
    return
  }
  const block = accountBlock(user)
  if (block) {
    closeTicket(ticket)
    res.status(403).json(
      block.kind === 'banned' ? { error: 'account_banned' } : { error: 'account_suspended', until: block.until },
    )
    return
  }

  const method = checkSecondFactor(user, code)
  if (!method) {
    twofaFailuresByIp.fail(ipKey)
    twofaFailuresByUser.fail(userKey)
    failTicket(ticket)
    res.status(401).json({ error: 'invalid_code' })
    return
  }

  closeTicket(ticket)
  twofaFailuresByUser.reset(userKey)
  const token = createSession(user.id, req.get('user-agent'))
  setSessionCookie(res, token)
  emit('sessions', { userId: user.id })
  // Si entro con un codigo de recuperacion se avisa cuantos quedan (para que genere nuevos antes de quedarse sin ninguno).
  res.json({ user: getSessionUser(token), ...(method === 'recovery' ? { recoveryLeft: remainingRecoveryCodes(user.id) } : {}) })
})

/** Sesion abierta + datos de la cuenta, o null (la respuesta de error ya se envio). */
function sessionAccount(req: express.Request, res: Response): { token: unknown; row: UserRow } | null {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return null
  }
  if (session.mustChangePassword) {
    res.status(403).json({ error: 'password_change_required' })
    return null
  }
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(session.id) as UserRow | undefined
  if (!row) {
    res.status(401).json({ error: 'unauthorized' })
    return null
  }
  return { token, row }
}

/** Para desactivar o regenerar codigos: contrasena actual + un codigo (de la app o de recuperacion). */
async function confirmIdentity(
  res: Response,
  row: UserRow,
  body: { password: string; code: string },
): Promise<boolean> {
  const userKey = `u${row.id}`
  const wait = twofaFailuresByUser.blockedFor(userKey)
  if (wait > 0) {
    res.setHeader('Retry-After', wait)
    res.status(429).json({ error: 'rate_limited' })
    return false
  }
  if (!(await verifyPassword(body.password, row.password_hash))) {
    twofaFailuresByUser.fail(userKey)
    res.status(403).json({ error: 'wrong_password' })
    return false
  }
  if (!checkSecondFactor(row, body.code)) {
    twofaFailuresByUser.fail(userKey)
    res.status(400).json({ error: 'invalid_code' })
    return false
  }
  twofaFailuresByUser.reset(userKey)
  return true
}

const confirmSchema = z.object({ password: z.string().min(1).max(128), code: codeField })

// Estado: cuantos codigos de recuperacion quedan sin usar.
authRouter.get('/2fa', (req, res) => {
  const account = sessionAccount(req, res)
  if (!account) return
  res.json({ enabled: account.row.totp_enabled === 1, recoveryLeft: account.row.totp_enabled === 1 ? remainingRecoveryCodes(account.row.id) : 0 })
})

// Paso 1 de la activacion: se crea el secreto y se devuelve para mostrarlo como QR. Todavia no protege nada.
authRouter.post('/2fa/setup', sameOrigin, authLimiter, (req, res) => {
  const account = sessionAccount(req, res)
  if (!account) return
  if (account.row.totp_enabled === 1) {
    res.status(409).json({ error: 'already_enabled' })
    return
  }
  const secret = newSecret()
  db.prepare('UPDATE users SET totp_secret = ?, totp_last_step = NULL WHERE id = ?').run(secret, account.row.id)
  res.json({ secret, uri: otpauthUri(secret, account.row.email) })
})

// Paso 2: se confirma con un codigo de la app. Recien aca queda activado y se entregan los codigos de recuperacion.
authRouter.post('/2fa/enable', sameOrigin, authLimiter, (req, res) => {
  const account = sessionAccount(req, res)
  if (!account) return
  const parsed = z.object({ code: codeField }).safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { row } = account
  if (row.totp_enabled === 1) {
    res.status(409).json({ error: 'already_enabled' })
    return
  }
  if (!row.totp_secret) {
    res.status(400).json({ error: 'setup_required' })
    return
  }
  const step = verifyTotp(row.totp_secret, parsed.data.code.replace(/\s/g, ''), null)
  if (step === null) {
    res.status(400).json({ error: 'invalid_code' })
    return
  }
  db.prepare('UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?').run(step, row.id)
  const recoveryCodes = generateRecoveryCodes(row.id)
  emit('profile', { userId: row.id })
  res.json({ recoveryCodes, user: getSessionUser(account.token) })
})

// Desactivar: exige la contrasena y un codigo, asi una sesion abandonada no alcanza para quitar la proteccion.
authRouter.post('/2fa/disable', sameOrigin, authLimiter, async (req, res) => {
  const account = sessionAccount(req, res)
  if (!account) return
  const parsed = confirmSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { row } = account
  if (row.totp_enabled !== 1) {
    res.status(409).json({ error: 'not_enabled' })
    return
  }
  if (!(await confirmIdentity(res, row, parsed.data))) return

  db.transaction(() => {
    db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = NULL WHERE id = ?').run(row.id)
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(row.id)
  })()
  emit('profile', { userId: row.id })
  res.json({ user: getSessionUser(account.token) })
})

// Codigos de recuperacion nuevos (los anteriores dejan de servir).
authRouter.post('/2fa/recovery', sameOrigin, authLimiter, async (req, res) => {
  const account = sessionAccount(req, res)
  if (!account) return
  const parsed = confirmSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { row } = account
  if (row.totp_enabled !== 1) {
    res.status(409).json({ error: 'not_enabled' })
    return
  }
  if (!(await confirmIdentity(res, row, parsed.data))) return
  res.json({ recoveryCodes: generateRecoveryCodes(row.id) })
})

// Preferencias del usuario con sesion abierta: se guardan en su cuenta y lo acompanan en cualquier dispositivo.
const preferencesSchema = z
  .object({ lang: z.enum(['en', 'es']).optional(), theme: z.enum(['light', 'dark']).optional() })
  .strict()
  .refine((v) => v.lang !== undefined || v.theme !== undefined)

authRouter.put('/preferences', sameOrigin, (req, res) => {
  const user = getSessionUser(req.cookies?.[config.cookieName])
  if (!user) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }

  const parsed = preferencesSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  // Solo cambia lo enviado; lo demas se conserva.
  const lang = parsed.data.lang ?? user.lang
  const theme = parsed.data.theme ?? user.theme
  db.prepare('UPDATE users SET lang = ?, theme = ? WHERE id = ?').run(lang, theme, user.id)

  // Idioma y tema viajan con la cuenta: los demas dispositivos los toman al instante.
  emit('profile', { userId: user.id, exceptCid: res.locals.cid })
  res.json({ user: { ...user, lang, theme } })
})

// Perfil propio: correo y contrasena. Exige la contrasena actual, asi una sesion abandonada
// no basta para quedarse con la cuenta. Es el unico lugar donde alguien edita su propia cuenta.
const profileSchema = z
  .object({
    currentPassword: z.string().min(1).max(128),
    email: email.optional(),
    newPassword: z.string().min(12).max(128).optional(),
  })
  .strict()
  .refine((v) => v.email !== undefined || v.newPassword !== undefined)

authRouter.put('/profile', sameOrigin, authLimiter, async (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }

  const parsed = profileSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = parsed.error.issues[0]?.path[0]
    res.status(400).json({
      error: 'invalid_input',
      field: field === 'newPassword' ? 'newPassword' : field === 'currentPassword' ? 'currentPassword' : 'email',
    })
    return
  }

  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(session.id) as UserRow | undefined
  if (!row || !(await verifyPassword(parsed.data.currentPassword, row.password_hash))) {
    res.status(403).json({ error: 'wrong_password' })
    return
  }

  const { email: newEmail, newPassword } = parsed.data

  if (newEmail && newEmail !== row.email) {
    if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id != ?').get(newEmail, row.id)) {
      res.status(409).json({ error: 'email_taken' })
      return
    }
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, row.id)
  }

  if (newPassword) {
    // La nueva debe ser otra: sobre todo en el primer ingreso, donde reemplaza a la contrasena inicial.
    if (newPassword === parsed.data.currentPassword) {
      res.status(400).json({ error: 'invalid_input', field: 'newPassword' })
      return
    }
    // must_change_password = 0: la marca de primer ingreso se borra para siempre al elegir una contrasena propia.
    db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(
      await hashPassword(newPassword),
      row.id,
    )
    // Cierra las demas sesiones de la cuenta; esta se conserva.
    deleteUserSessions(row.id, token)
  }

  emit('profile', { userId: row.id, exceptCid: res.locals.cid })
  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid }) // el correo se ve en la lista de administradores
  res.json({ user: getSessionUser(token) })
})

/* ---------- Datos de perfil: nombre, apellido y foto (no tocan las credenciales: no piden contrasena) ---------- */

const nameField = z
  .string()
  .trim()
  .max(60)
  .transform((v) => (v ? v : null))
const detailsSchema = z.object({ firstName: nameField, lastName: nameField }).strict()
const profileLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 })

authRouter.put('/profile/details', sameOrigin, profileLimiter, (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  const parsed = detailsSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  db.prepare('UPDATE users SET first_name = ?, last_name = ? WHERE id = ?').run(
    parsed.data.firstName,
    parsed.data.lastName,
    session.id,
  )
  emit('profile', { userId: session.id, exceptCid: res.locals.cid })
  res.json({ user: getSessionUser(token) })
})

// La foto llega ya reducida por la web (unos 256 px). Solo JPEG, PNG o WebP: se comprueba tambien la firma de los
// bytes, y nunca se acepta SVG (podria llevar scripts).
const AVATAR_MAX_CHARS = 150_000
const avatarSchema = z
  .object({
    avatar: z
      .string()
      .max(AVATAR_MAX_CHARS)
      .regex(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/)
      .nullable(),
  })
  .strict()

function imageMatches(mime: string, bytes: Buffer): boolean {
  if (mime === 'jpeg') return bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
  if (mime === 'png') return bytes.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
  return bytes.subarray(0, 4).toString('latin1') === 'RIFF' && bytes.subarray(8, 12).toString('latin1') === 'WEBP'
}

authRouter.put('/avatar', sameOrigin, profileLimiter, express.json({ limit: '200kb' }), (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  const parsed = avatarSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const { avatar } = parsed.data
  if (avatar) {
    const mime = avatar.slice(11, avatar.indexOf(';'))
    if (!imageMatches(mime, Buffer.from(avatar.slice(avatar.indexOf(',') + 1), 'base64'))) {
      res.status(400).json({ error: 'invalid_input' })
      return
    }
  }
  db.prepare('UPDATE users SET avatar = ?, avatar_at = ? WHERE id = ?').run(avatar, avatar ? Date.now() : null, session.id)
  emit('profile', { userId: session.id, exceptCid: res.locals.cid })
  emit('admins', { adminsOnly: true, exceptCid: res.locals.cid }) // la foto se ve en la lista de administradores
  res.json({ user: getSessionUser(token) })
})

// La foto se sirve como imagen normal (no dentro del JSON de /me, que se pide en cada pagina). La URL lleva la version.
authRouter.get('/avatar', (req, res) => {
  const session = getSessionUser(req.cookies?.[config.cookieName])
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  const row = db.prepare('SELECT avatar FROM users WHERE id = ?').get(session.id) as { avatar: string | null } | undefined
  const match = row?.avatar?.match(/^data:(image\/(?:jpeg|png|webp));base64,(.+)$/)
  if (!match) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.set({ 'Content-Type': match[1], 'Cache-Control': 'private, max-age=31536000, immutable' })
  res.send(Buffer.from(match[2], 'base64'))
})

/* ---------- Sesiones activas: ver donde esta abierta la cuenta y cerrar las que no se reconocen ---------- */

authRouter.get('/sessions', (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  res.json({ sessions: listUserSessions(session.id, token) })
})

// "Cerrar las demas": conserva solo la sesion actual.
authRouter.delete('/sessions', sameOrigin, profileLimiter, (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  deleteUserSessions(session.id, token)
  res.json({ sessions: listUserSessions(session.id, token) })
})

authRouter.delete('/sessions/:id', sameOrigin, profileLimiter, (req, res) => {
  const token = req.cookies?.[config.cookieName]
  const session = getSessionUser(token)
  if (!session) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  const id = z.string().regex(/^[a-f0-9]{64}$/).safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  // La sesion actual se cierra con "Cerrar sesion", no desde esta lista.
  if (listUserSessions(session.id, token).some((s) => s.current && s.id === id.data)) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!deleteUserSessionById(session.id, id.data)) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('sessions', { userId: session.id, exceptCid: res.locals.cid })
  res.status(204).end()
})

authRouter.post('/logout', sameOrigin, (req, res) => {
  const who = getSessionUser(req.cookies?.[config.cookieName])
  deleteSession(req.cookies?.[config.cookieName])
  // Los demas dispositivos de la cuenta ven desaparecer esa sesion de la lista.
  if (who) emit('sessions', { userId: who.id })
  clearSessionCookie(res)
  res.status(204).end()
})
