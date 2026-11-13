import crypto from 'node:crypto'
import { config } from './config.js'
import { db } from './db.js'
import { sendErrorAlert } from './mailer.js'

/**
 * Registro de errores del CRM (servidor y web). Reglas:
 *  - Nunca lanza: registrar un error no puede causar otro.
 *  - Enmascara contrasenas, tokens y claves antes de guardar; nunca recibe el cuerpo de las peticiones.
 *  - Los errores iguales se agrupan (misma `fingerprint`) y solo suben el contador.
 *  - Los errores graves del servidor avisan por correo al super admin, con tope para no llenar la casilla.
 */

export interface ErrorInput {
  source: 'server' | 'web'
  kind: string
  message: string
  detail?: string
  path?: string
  method?: string
  status?: number | null
  userEmail?: string
  userAgent?: string
}

export interface Recorded {
  ref: string
  fingerprint: string
  count: number
  isNew: boolean
}

const MAX_ROWS = 1000

/** Quita de un texto lo que no debe quedar guardado: valores de contrasenas, tokens, claves y cadenas opacas largas. */
export function redact(text: string): string {
  return text
    .replace(/\b(Bearer|Basic)\s+[\w.~+/=-]+/gi, '$1 [oculto]')
    .replace(
      /(password|passwd|pass|pwd|token|secret|authorization|cookie|api[_-]?key|access[_-]?token|signature)(["']?\s*[:=]\s*)(["']?)[^\s"',;&}]+/gi,
      '$1$2$3[oculto]',
    )
    .replace(/\b(?:APP_USR|TEST)-[\w-]{8,}/g, '[oculto]')
    .replace(/[A-Za-z0-9_-]{40,}/g, '[oculto]')
}

const clip = (text: string, max: number) => (text.length > max ? `${text.slice(0, max - 1)}…` : text)

/** Ruta sin query (puede llevar datos) y con el hash de la pantalla del CRM. */
const cleanPath = (p: string) => clip(p.replace(/\?[^#]*/, ''), 200)

function fingerprintOf(input: ErrorInput): string {
  const firstFrame = (input.detail ?? '').split('\n').find((l) => /\bat\b|\.js:|\.ts:/.test(l)) ?? ''
  const normalize = (s: string) => s.replace(/0x[0-9a-f]+/gi, '#').replace(/\d+/g, '#').trim()
  return crypto
    .createHash('sha1')
    .update([input.source, input.kind, normalize(input.message), normalize(firstFrame)].join('|'))
    .digest('hex')
}

const newRef = () => crypto.randomBytes(4).toString('hex').toUpperCase()

export function recordError(input: ErrorInput): Recorded | null {
  try {
    const clean = {
      source: input.source,
      kind: clip(input.kind, 40),
      message: clip(redact(input.message || 'Error sin mensaje'), 500),
      detail: clip(redact(input.detail ?? ''), 4000),
      path: cleanPath(input.path ?? ''),
      method: clip(input.method ?? '', 10),
      status: input.status ?? null,
      userEmail: clip(input.userEmail ?? '', 254),
      userAgent: clip(input.userAgent ?? '', 200),
    }
    const fingerprint = fingerprintOf(clean)
    const ref = newRef()
    const now = new Date().toISOString()

    const existing = db.prepare('SELECT count FROM error_log WHERE fingerprint = ?').get(fingerprint) as { count: number } | undefined
    if (existing) {
      db.prepare(
        `UPDATE error_log SET count = count + 1, last_seen = ?, ref = ?, path = ?, method = ?, status = ?, user_email = ?, user_agent = ? WHERE fingerprint = ?`,
      ).run(now, ref, clean.path, clean.method, clean.status, clean.userEmail, clean.userAgent, fingerprint)
      return { ref, fingerprint, count: existing.count + 1, isNew: false }
    }

    db.prepare(
      `INSERT INTO error_log (fingerprint, source, kind, message, detail, path, method, status, user_email, user_agent, ref, first_seen, last_seen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(fingerprint, clean.source, clean.kind, clean.message, clean.detail, clean.path, clean.method, clean.status, clean.userEmail, clean.userAgent, ref, now, now)
    // Tope de filas: se descartan las mas viejas.
    db.prepare(`DELETE FROM error_log WHERE id IN (SELECT id FROM error_log ORDER BY last_seen DESC LIMIT -1 OFFSET ${MAX_ROWS})`).run()
    return { ref, fingerprint, count: 1, isNew: true }
  } catch (error) {
    console.error('[errorlog] no se pudo registrar un error:', (error as Error).message)
    return null
  }
}

/* ---------- Aviso por correo al super admin ---------- */

const ALERT_EVERY_MS = 30 * 60 * 1000 // un aviso por tipo de error cada 30 minutos
const ALERT_MAX_PER_HOUR = 6 // y nunca mas de 6 por hora en total
const lastAlert = new Map<string, number>()
let alertsThisHour: number[] = []

function maybeAlert(recorded: Recorded, input: ErrorInput): void {
  try {
    const now = Date.now()
    if (now - (lastAlert.get(recorded.fingerprint) ?? 0) < ALERT_EVERY_MS) return
    alertsThisHour = alertsThisHour.filter((t) => now - t < 60 * 60 * 1000)
    if (alertsThisHour.length >= ALERT_MAX_PER_HOUR) return

    const superRow = db.prepare('SELECT email FROM users WHERE is_super = 1').get() as { email: string } | undefined
    if (!superRow) return
    lastAlert.set(recorded.fingerprint, now)
    alertsThisHour.push(now)
    void sendErrorAlert(superRow.email, {
      ref: recorded.ref,
      kind: input.kind,
      message: clip(redact(input.message), 300),
      path: cleanPath(`${input.method ?? ''} ${input.path ?? ''}`.trim()),
      count: recorded.count,
      panelUrl: `${config.publicUrl}/crm`,
    }).catch(() => undefined)
  } catch {
    /* un aviso nunca debe romper nada */
  }
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value).slice(0, 1500)
  } catch {
    return String(value)
  }
}

/** Registra un error del servidor (una excepcion) y, si es grave, avisa al super admin. Devuelve el codigo de referencia. */
export function captureError(
  error: unknown,
  ctx: { kind: string; message?: string; path?: string; method?: string; status?: number; userEmail?: string; alert?: boolean },
): string | null {
  const err = error instanceof Error ? error : new Error(typeof error === 'string' ? error : 'Error desconocido')
  const body = (error as { body?: unknown }).body
  const detail = [err.stack ?? '', body !== undefined ? `Respuesta: ${safeJson(body)}` : ''].filter(Boolean).join('\n')
  const input: ErrorInput = {
    source: 'server',
    kind: ctx.kind,
    message: ctx.message ?? err.message,
    detail,
    path: ctx.path,
    method: ctx.method,
    status: ctx.status ?? null,
    userEmail: ctx.userEmail,
  }
  console.error(`[error] ${ctx.kind}: ${input.message}`)
  const recorded = recordError(input)
  if (recorded && ctx.alert !== false) maybeAlert(recorded, input)
  return recorded?.ref ?? null
}
