import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * Codigos de un solo uso basados en el tiempo (TOTP, RFC 6238): los mismos que generan Google Authenticator, Authy,
 * Microsoft Authenticator, etc. SHA-1, 6 digitos, cambian cada 30 segundos.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const STEP_SECONDS = 30

export function base32Encode(buf: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '')
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of clean) {
    const index = ALPHABET.indexOf(ch)
    if (index < 0) throw new Error('Secreto base32 invalido')
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** Secreto nuevo de 160 bits (el largo que recomienda el estandar), en base32 para que lo lea la app. */
export const newSecret = (): string => base32Encode(randomBytes(20))

/** Codigo HOTP (RFC 4226) para un contador. */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const hash = createHmac('sha1', secret).update(message).digest()
  const offset = hash[hash.length - 1] & 0xf
  const binary =
    ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3]
  return String(binary % 10 ** digits).padStart(digits, '0')
}

export const currentStep = (now = Date.now()): number => Math.floor(now / 1000 / STEP_SECONDS)

const sameText = (a: string, b: string): boolean => {
  const x = Buffer.from(a)
  const y = Buffer.from(b)
  return x.length === y.length && timingSafeEqual(x, y)
}

/**
 * Comprueba un codigo de 6 digitos. Admite el paso anterior y el siguiente (relojes un poco desfasados) y rechaza
 * cualquier paso menor o igual a `lastStep`, asi un mismo codigo no sirve dos veces. Devuelve el paso que coincidio.
 */
export function verifyTotp(secretBase32: string, code: string, lastStep: number | null, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null
  let secret: Buffer
  try {
    secret = base32Decode(secretBase32)
  } catch {
    return null
  }
  const base = currentStep(now)
  for (const delta of [0, -1, 1]) {
    const step = base + delta
    if (lastStep !== null && step <= lastStep) continue
    if (sameText(hotp(secret, step), code)) return step
  }
  return null
}

/** Direccion otpauth:// que se muestra como QR para que la app guarde la cuenta. */
export function otpauthUri(secret: string, account: string, issuer = 'ZimLabs'): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP_SECONDS}`
}
