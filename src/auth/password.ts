import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

// Parametros de scrypt (OWASP: N=2^17 con r=8, p=1). Cada hash usa ~128 MB de memoria mientras se calcula.
// Los hashes ya guardados con parametros mas livianos siguen sirviendo (cada hash trae los suyos) y se actualizan solos
// al proximo inicio de sesion (ver needsRehash).
const N = 131072
const R = 8
const P = 1
const KEYLEN = 64

function derive(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEYLEN, { N: n, r, p, maxmem: 256 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    )
  })
}

/** El hash guardado usa parametros mas livianos que los actuales: conviene recalcularlo cuando se conoce la contrasena. */
export function needsRehash(stored: string): boolean {
  const [scheme, n, r, p] = stored.split('$')
  return scheme === 'scrypt' && (Number(n) < N || Number(r) < R || Number(p) < P)
}

/** Devuelve `scrypt$N$r$p$salt$hash` (salt y hash en base64). */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const key = await derive(password, salt, N, R, P)
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, n, r, p, salt, hash] = stored.split('$')
  if (scheme !== 'scrypt' || !n || !r || !p || !salt || !hash) return false

  const expected = Buffer.from(hash, 'base64')
  const key = await derive(password, Buffer.from(salt, 'base64'), Number(n), Number(r), Number(p))
  return key.length === expected.length && timingSafeEqual(key, expected)
}

/**
 * Hash falso para gastar el mismo tiempo cuando el correo no existe,
 * asi la respuesta no delata si la cuenta existe.
 */
let dummy: Promise<string> | undefined
export async function burnTime(password: string): Promise<void> {
  dummy ??= hashPassword('not-a-real-password')
  await verifyPassword(password, await dummy)
}
