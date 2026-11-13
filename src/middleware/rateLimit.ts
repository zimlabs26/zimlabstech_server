import type { NextFunction, Request, Response } from 'express'

interface Options {
  windowMs: number
  max: number
}

/**
 * Limitador de intentos FALLIDOS (para el login). A diferencia de `rateLimit`, un acceso correcto no gasta cupo:
 * solo se cuentan los fallos. El estado vive en memoria (suficiente para un solo proceso).
 */
export function failureLimiter({ windowMs, max }: Options) {
  const hits = new Map<string, { count: number; resetAt: number }>()

  setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of hits) if (entry.resetAt <= now) hits.delete(key)
  }, windowMs).unref()

  return {
    /** Segundos que faltan para poder reintentar; 0 = permitido. */
    blockedFor(key: string): number {
      const entry = hits.get(key)
      if (!entry || entry.resetAt <= Date.now() || entry.count < max) return 0
      return Math.ceil((entry.resetAt - Date.now()) / 1000)
    },
    fail(key: string): void {
      const now = Date.now()
      const entry = hits.get(key)
      if (!entry || entry.resetAt <= now) hits.set(key, { count: 1, resetAt: now + windowMs })
      else entry.count += 1
    },
    reset(key: string): void {
      hits.delete(key)
    },
  }
}

/** Limitador simple en memoria, por IP. Suficiente para un solo proceso. */
export function rateLimit({ windowMs, max }: Options) {
  const hits = new Map<string, { count: number; resetAt: number }>()

  setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of hits) if (entry.resetAt <= now) hits.delete(key)
  }, windowMs).unref()

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip ?? 'unknown'
    const now = Date.now()
    const entry = hits.get(key)

    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs })
      next()
      return
    }

    entry.count += 1
    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.resetAt - now) / 1000))
      res.status(429).json({ error: 'rate_limited' })
      return
    }
    next()
  }
}
