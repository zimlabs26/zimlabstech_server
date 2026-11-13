import type { Request } from 'express'
import { randomBytes } from 'node:crypto'
import { config } from '../config.js'

/**
 * Passkeys (WebAuthn): entrar con la huella, el rostro o el PIN del dispositivo. El "relying party" (rpID) es el
 * dominio desde el que se abre la web; se toma del encabezado Origin, que solo se acepta si esta en WEB_ORIGIN.
 * Los desafios viven en memoria (5 minutos, un solo uso): si el servidor reinicia, se vuelve a tocar el boton.
 */

const CHALLENGE_MS = 5 * 60 * 1000

interface Pending {
  challenge: string
  userId: number | null
  exp: number
}

const pending = new Map<string, Pending>()

function purge(now = Date.now()): void {
  for (const [key, value] of pending) if (value.exp <= now) pending.delete(key)
}

/** Guarda un desafio y devuelve la clave para recuperarlo al verificar. */
export function saveChallenge(challenge: string, userId: number | null): string {
  purge()
  const key = randomBytes(18).toString('base64url')
  pending.set(key, { challenge, userId, exp: Date.now() + CHALLENGE_MS })
  return key
}

/** Consume el desafio (sirve una sola vez). */
export function takeChallenge(key: unknown): Pending | null {
  if (typeof key !== 'string') return null
  const found = pending.get(key)
  pending.delete(key)
  if (!found || found.exp <= Date.now()) return null
  return found
}

/** Origen y dominio de la web que hace el pedido, o null si el origen no esta permitido. */
export function relyingParty(req: Request): { origin: string; rpID: string } | null {
  const origin = req.get('origin')
  if (!origin || !config.webOrigins.includes(origin)) return null
  try {
    return { origin, rpID: new URL(origin).hostname }
  } catch {
    return null
  }
}
