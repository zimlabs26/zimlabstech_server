import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import type { TLSSocket } from 'node:tls'

/**
 * Verificacion de una pagina o CRM desde el servidor: una consulta HTTP(S) y un semaforo.
 *  - red:    no responde, el certificado no es valido, o responde con error (4xx/5xx).
 *  - yellow: responde bien pero con alertas (lenta, certificado por vencer, sin https, redirige a otro sitio...).
 *  - green:  todo bien.
 * El servidor consulta direcciones que cargan los administradores: se bloquean las redes internas (SSRF) tanto al guardar
 * como al conectar (la IP se valida cuando se resuelve el nombre, asi un DNS cambiante no sirve para saltear el control).
 */

export type AuditStatus = 'green' | 'yellow' | 'red'

export interface CheckResult {
  status: AuditStatus
  /** Codigos de alerta o de error (la web los traduce). */
  alerts: string[]
  /** Resumen corto: "HTTP 200 · 412 ms" o el motivo del fallo. */
  detail: string
  httpStatus: number | null
  responseMs: number | null
  /** AAAA-MM-DD del vencimiento del certificado, si es https. */
  sslExpiresOn: string | null
}

const TIMEOUT_MS = 8_000
const SLOW_MS = 3_000
const SSL_WARN_DAYS = 14
const MAX_REDIRECTS = 3

/** Direcciones que nunca se consultan: loopback, redes privadas, link-local, CGNAT, multicast y reservadas. */
export function isPrivateAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    )
  }
  const v = ip.toLowerCase()
  if (v.startsWith('::ffff:')) {
    const rest = v.slice(7)
    return net.isIPv4(rest) ? isPrivateAddress(rest) : true
  }
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('ff')
}

/** Valida y normaliza lo que escribio la persona: solo http/https, sin usuario ni clave y sin IP interna. */
export function parseAuditUrl(raw: string): URL | null {
  const text = raw.trim()
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    if (url.username || url.password) return null
    const host = url.hostname.replace(/^\[|\]$/g, '')
    if (!host || host === 'localhost' || (net.isIP(host) && isPrivateAddress(host))) return null
    if (!net.isIP(host) && !host.includes('.')) return null
    return url
  } catch {
    return null
  }
}

/** `lookup` propio: resuelve el nombre y se niega a conectar si alguna direccion es interna. */
const safeLookup = ((hostname: string, options: { family?: number; all?: boolean }, callback: (...args: unknown[]) => void) => {
  dns.lookup(hostname, { family: options.family, all: true }, (error, addresses) => {
    if (error) return callback(error)
    if (!addresses.length || addresses.some((a) => isPrivateAddress(a.address))) {
      return callback(Object.assign(new Error('Direccion no permitida'), { code: 'EBLOCKED' }))
    }
    if (options.all) return callback(null, addresses)
    callback(null, addresses[0].address, addresses[0].family)
  })
}) as unknown as net.LookupFunction

interface Hop {
  status: number
  location: string | null
  ms: number
  certExpires: Date | null
}

function request(url: URL): Promise<Hop> {
  return new Promise((resolve, reject) => {
    const host = url.hostname.replace(/^\[|\]$/g, '')
    if (net.isIP(host) && isPrivateAddress(host)) return reject(Object.assign(new Error('Direccion no permitida'), { code: 'EBLOCKED' }))
    const started = Date.now()
    const lib = url.protocol === 'https:' ? https : http
    const req = lib.request(
      url,
      { method: 'GET', lookup: safeLookup, timeout: TIMEOUT_MS, headers: { 'user-agent': 'ZimlabsAudit/1.0', accept: '*/*' } },
      (res) => {
        const ms = Date.now() - started
        let certExpires: Date | null = null
        if (url.protocol === 'https:') {
          const validTo = (res.socket as TLSSocket).getPeerCertificate?.()?.valid_to
          if (validTo) certExpires = new Date(validTo)
        }
        res.resume() // el cuerpo no importa
        resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? null, ms, certExpires })
        req.destroy()
      },
    )
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })))
    req.on('error', reject)
    req.end()
  })
}

const CERT_ERRORS = new Set([
  'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_NOT_YET_VALID', 'CERT_UNTRUSTED',
])

/** Codigo de error de red a un codigo de alerta propio. */
function errorCode(error: unknown): string {
  const code = String((error as { code?: unknown })?.code ?? '')
  if (CERT_ERRORS.has(code)) return 'ssl_invalid'
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'dns'
  if (code === 'ECONNREFUSED') return 'refused'
  if (code === 'ETIMEDOUT' || code === 'ECONNRESET') return 'timeout'
  if (code === 'EBLOCKED') return 'blocked'
  return 'unreachable'
}

const day = (d: Date) => d.toISOString().slice(0, 10)

export async function runCheck(rawUrl: string): Promise<CheckResult> {
  const fail = (code: string, detail: string): CheckResult => ({
    status: 'red', alerts: [code], detail, httpStatus: null, responseMs: null, sslExpiresOn: null,
  })
  const first = parseAuditUrl(rawUrl)
  if (!first) return fail('blocked', 'Direccion no valida')

  let url = first
  let redirects = 0
  let hop: Hop
  try {
    for (;;) {
      hop = await request(url)
      if (hop.status >= 300 && hop.status < 400 && hop.location && redirects < MAX_REDIRECTS) {
        const next = parseAuditUrl(new URL(hop.location, url).toString())
        if (!next) return fail('blocked', 'Redirige a una direccion no permitida')
        url = next
        redirects++
        continue
      }
      break
    }
  } catch (error) {
    const code = errorCode(error)
    return fail(code, String((error as { code?: unknown })?.code ?? (error as Error)?.message ?? code).slice(0, 80))
  }

  const alerts: string[] = []
  let red = false
  if (hop.status >= 500) {
    red = true
    alerts.push('http_5xx')
  } else if (hop.status === 401 || hop.status === 403) {
    alerts.push('auth_required') // responde, pero pide credenciales: no se puede ver si funciona
  } else if (hop.status >= 400) {
    red = true
    alerts.push('http_4xx')
  } else if (hop.status >= 300) {
    alerts.push('redirect_loop')
  }
  if (hop.ms > SLOW_MS) alerts.push('slow')
  if (url.protocol === 'http:') alerts.push('no_https')
  if (redirects > 0 && url.hostname !== first.hostname) alerts.push('redirect_host')
  if (hop.certExpires) {
    const daysLeft = Math.floor((hop.certExpires.getTime() - Date.now()) / 86_400_000)
    if (daysLeft <= SSL_WARN_DAYS) alerts.push('ssl_expiring')
  }

  return {
    status: red ? 'red' : alerts.length ? 'yellow' : 'green',
    alerts,
    detail: `HTTP ${hop.status} · ${hop.ms} ms`,
    httpStatus: hop.status,
    responseMs: hop.ms,
    sslExpiresOn: hop.certExpires ? day(hop.certExpires) : null,
  }
}
