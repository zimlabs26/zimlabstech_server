import { Router, type Request, type Response } from 'express'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { z } from 'zod'
import { verifyPassword } from '../auth/password.js'
import { relyingParty, saveChallenge, takeChallenge } from '../auth/passkeys.js'
import { accountBlock, createSession, getSessionUser, setSessionCookie } from '../auth/sessions.js'
import { config } from '../config.js'
import { db, type UserRow } from '../db.js'
import { sameOrigin } from '../middleware/guards.js'
import { failureLimiter, rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Entrar con huella (passkeys). Es un acceso alternativo a la contrasena en los dispositivos que lo tienen: la
 * huella (o el rostro / PIN) se verifica en el propio equipo, que firma el desafio del servidor. La clave privada
 * no sale del dispositivo. Como exige verificacion del usuario (algo que tiene + algo que es), reemplaza tambien
 * al codigo 2FA. Registrar o quitar una huella pide la contrasena.
 */

export const passkeysRouter = Router()

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 })
const failuresByIp = failureLimiter({ windowMs: 15 * 60 * 1000, max: 20 })

interface PasskeyRow {
  id: string
  user_id: number
  public_key: Buffer
  counter: number
  transports: string | null
  name: string
  created_at: string
  last_used_at: string | null
}

const parseTransports = (value: string | null): AuthenticatorTransport[] | undefined => {
  if (!value) return undefined
  try {
    return JSON.parse(value) as AuthenticatorTransport[]
  } catch {
    return undefined
  }
}

/** Datos de la cuenta con sesion abierta, o null (la respuesta de error ya se envio). */
function account(req: Request, res: Response): UserRow | null {
  const session = getSessionUser(req.cookies?.[config.cookieName])
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
  return row
}

const toInfo = (p: PasskeyRow) => ({ id: p.id, name: p.name, createdAt: p.created_at, lastUsedAt: p.last_used_at })

const listFor = (userId: number) =>
  (db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at DESC').all(userId) as PasskeyRow[]).map(toInfo)

/* ---------- Gestion (con sesion abierta) ---------- */

passkeysRouter.get('/passkeys', (req, res) => {
  const row = account(req, res)
  if (!row) return
  res.json({ passkeys: listFor(row.id) })
})

const passwordSchema = z.object({ password: z.string().min(1).max(128) })

// Paso 1: pide la contrasena y entrega el desafio para que el dispositivo cree la clave.
passkeysRouter.post('/passkeys/register/options', sameOrigin, limiter, async (req, res) => {
  const row = account(req, res)
  if (!row) return
  const rp = relyingParty(req)
  const parsed = passwordSchema.safeParse(req.body)
  if (!rp || !parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!(await verifyPassword(parsed.data.password, row.password_hash))) {
    res.status(403).json({ error: 'wrong_password' })
    return
  }

  const existing = db.prepare('SELECT id, transports FROM passkeys WHERE user_id = ?').all(row.id) as Pick<
    PasskeyRow,
    'id' | 'transports'
  >[]
  const options = await generateRegistrationOptions({
    rpName: 'Zim Labs CRM',
    rpID: rp.rpID,
    userName: row.email,
    userID: new TextEncoder().encode(`u${row.id}`),
    attestationType: 'none',
    // Para no registrar dos veces el mismo dispositivo.
    excludeCredentials: existing.map((p) => ({ id: p.id, transports: parseTransports(p.transports) })),
    authenticatorSelection: {
      // Solo el lector del propio equipo (huella, rostro, PIN): no llaves externas ni el telefono por QR.
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'required',
    },
  })
  res.json({ options, key: saveChallenge(options.challenge, row.id) })
})

const registerVerifySchema = z.object({
  key: z.string().min(10).max(64),
  name: z.string().trim().max(60).optional(),
  response: z.record(z.string(), z.unknown()),
})

// Paso 2: verifica lo que firmo el dispositivo y guarda la clave publica.
passkeysRouter.post('/passkeys/register/verify', sameOrigin, limiter, async (req, res) => {
  const row = account(req, res)
  if (!row) return
  const rp = relyingParty(req)
  const parsed = registerVerifySchema.safeParse(req.body)
  const pendingChallenge = parsed.success ? takeChallenge(parsed.data.key) : null
  if (!rp || !parsed.success || !pendingChallenge || pendingChallenge.userId !== row.id) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: parsed.data.response as unknown as RegistrationResponseJSON,
      expectedChallenge: pendingChallenge.challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      requireUserVerification: true,
    })
  } catch {
    res.status(400).json({ error: 'verification_failed' })
    return
  }
  if (!verification.verified) {
    res.status(400).json({ error: 'verification_failed' })
    return
  }

  const { credential } = verification.registrationInfo
  db.prepare('INSERT OR IGNORE INTO passkeys (id, user_id, public_key, counter, transports, name) VALUES (?, ?, ?, ?, ?, ?)').run(
    credential.id,
    row.id,
    Buffer.from(credential.publicKey),
    credential.counter,
    credential.transports ? JSON.stringify(credential.transports) : null,
    parsed.data.name || 'Dispositivo',
  )
  emit('profile', { userId: row.id })
  res.json({ passkeys: listFor(row.id) })
})

// Quitar una huella: pide la contrasena (una sesion abandonada no alcanza).
passkeysRouter.delete('/passkeys/:id', sameOrigin, limiter, async (req, res) => {
  const row = account(req, res)
  if (!row) return
  const id = z.string().min(1).max(512).safeParse(req.params.id)
  const body = passwordSchema.safeParse(req.body)
  if (!id.success || !body.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!(await verifyPassword(body.data.password, row.password_hash))) {
    res.status(403).json({ error: 'wrong_password' })
    return
  }
  const removed = db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(id.data, row.id).changes > 0
  if (!removed) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('profile', { userId: row.id })
  res.json({ passkeys: listFor(row.id) })
})

/* ---------- Ingreso con huella (sin sesion) ---------- */

// El dispositivo elige la clave por su cuenta (no hace falta escribir el correo).
passkeysRouter.post('/login/passkey/options', sameOrigin, limiter, async (req, res) => {
  const rp = relyingParty(req)
  if (!rp) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const options = await generateAuthenticationOptions({ rpID: rp.rpID, userVerification: 'required' })
  res.json({ options, key: saveChallenge(options.challenge, null) })
})

const loginVerifySchema = z.object({
  key: z.string().min(10).max(64),
  response: z.record(z.string(), z.unknown()),
})

passkeysRouter.post('/login/passkey/verify', sameOrigin, limiter, async (req, res) => {
  const rp = relyingParty(req)
  const parsed = loginVerifySchema.safeParse(req.body)
  if (!rp || !parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const ipKey = req.ip ?? 'unknown'
  const wait = failuresByIp.blockedFor(ipKey)
  if (wait > 0) {
    res.setHeader('Retry-After', wait)
    res.status(429).json({ error: 'rate_limited' })
    return
  }
  const fail = () => {
    failuresByIp.fail(ipKey)
    res.status(401).json({ error: 'invalid_credentials' })
  }

  const pendingChallenge = takeChallenge(parsed.data.key)
  const response = parsed.data.response as unknown as AuthenticationResponseJSON
  if (!pendingChallenge || typeof response.id !== 'string') return fail()

  const passkey = db.prepare('SELECT * FROM passkeys WHERE id = ?').get(response.id) as PasskeyRow | undefined
  if (!passkey) return fail()

  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: pendingChallenge.challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      requireUserVerification: true,
      credential: {
        id: passkey.id,
        publicKey: new Uint8Array(passkey.public_key),
        counter: passkey.counter,
        transports: parseTransports(passkey.transports),
      },
    })
  } catch {
    return fail()
  }
  if (!verification.verified) return fail()

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(passkey.user_id) as UserRow | undefined
  if (!user) return fail()
  const block = accountBlock(user)
  if (block) {
    res.status(403).json(block.kind === 'banned' ? { error: 'account_banned' } : { error: 'account_suspended', until: block.until })
    return
  }

  db.prepare("UPDATE passkeys SET counter = ?, last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").run(
    verification.authenticationInfo.newCounter,
    passkey.id,
  )
  const token = createSession(user.id, req.get('user-agent'))
  setSessionCookie(res, token)
  emit('sessions', { userId: user.id })
  res.json({ user: getSessionUser(token) })
})
