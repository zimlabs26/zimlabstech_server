import { createHash, randomBytes } from 'node:crypto'
import { db, type UserRow } from '../db.js'
import { verifyTotp } from '../totp.js'

/**
 * Segundo paso del login (2FA). Con la contrasena correcta de una cuenta con 2FA NO se abre sesion: se entrega un
 * "ticket" de corta vida y la sesion recien se crea al confirmar el codigo. Los tickets viven en memoria (se pierden
 * al reiniciar el servidor: solo hay que volver a poner la contrasena).
 */

const TICKET_MS = 5 * 60 * 1000
const MAX_ATTEMPTS = 5

const tickets = new Map<string, { userId: number; exp: number; attempts: number }>()

function purge(now = Date.now()): void {
  for (const [key, ticket] of tickets) if (ticket.exp <= now) tickets.delete(key)
}

export function issueTicket(userId: number): string {
  purge()
  const token = randomBytes(24).toString('base64url')
  tickets.set(token, { userId, exp: Date.now() + TICKET_MS, attempts: 0 })
  return token
}

/** Usuario al que pertenece un ticket vigente (sin gastar un intento), o null. */
export function ticketUser(token: string): number | null {
  const ticket = tickets.get(token)
  if (!ticket) return null
  if (ticket.exp <= Date.now()) {
    tickets.delete(token)
    return null
  }
  return ticket.userId
}

/** Un codigo equivocado gasta un intento; al quinto el ticket se anula y hay que volver a poner la contrasena. */
export function failTicket(token: string): void {
  const ticket = tickets.get(token)
  if (!ticket) return
  ticket.attempts += 1
  if (ticket.attempts >= MAX_ATTEMPTS) tickets.delete(token)
}

export const closeTicket = (token: string): void => void tickets.delete(token)

/* ---------- Codigos de recuperacion ---------- */

// Sin 0/1/i/l/o: no se confunden al copiarlos a mano.
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'

const normalize = (code: string): string => code.toLowerCase().replace(/[^a-z0-9]/g, '')
const hash = (code: string): string => createHash('sha256').update(normalize(code)).digest('hex')

/** Reemplaza los codigos de recuperacion de la cuenta por 8 nuevos y los devuelve (esta es la unica vez que se ven). */
export function generateRecoveryCodes(userId: number, count = 8): string[] {
  const codes = Array.from({ length: count }, () => {
    let text = ''
    for (const byte of randomBytes(10)) text += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length]
    return `${text.slice(0, 5)}-${text.slice(5)}`
  })
  db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId)
    const insert = db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)')
    for (const code of codes) insert.run(userId, hash(code))
  })()
  return codes
}

export const remainingRecoveryCodes = (userId: number): number =>
  (db.prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId) as { n: number }).n

/**
 * Comprueba el segundo factor: el codigo de 6 digitos de la app o un codigo de recuperacion (que se gasta al usarlo).
 * Devuelve cual fue o null si no coincide.
 */
export function checkSecondFactor(
  user: Pick<UserRow, 'id' | 'totp_secret' | 'totp_last_step'>,
  input: string,
): 'totp' | 'recovery' | null {
  const compact = input.replace(/\s/g, '')

  if (/^\d{6}$/.test(compact)) {
    if (!user.totp_secret) return null
    const step = verifyTotp(user.totp_secret, compact, user.totp_last_step)
    if (step === null) return null
    // Guarda el paso usado: el mismo codigo no vale una segunda vez.
    db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id)
    return 'totp'
  }

  if (normalize(input).length === 10) {
    const used = db
      .prepare(
        `UPDATE recovery_codes SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
      )
      .run(user.id, hash(input))
    if (used.changes > 0) return 'recovery'
  }
  return null
}
