import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import type { TLSSocket } from 'node:tls'
import zlib from 'node:zlib'

/**
 * Auditoria de una pagina o del servidor de un CRM: no alcanza con que el link responda, se revisa que FUNCIONE.
 *  - Pagina: responde, velocidad, https y certificado, redireccion de http a https, titulo y contenido de la pagina,
 *    que no muestre un error del servidor, que sea apta para celular, que sus scripts, estilos e imagenes carguen, que no
 *    mezcle contenido http en una pagina https, cabeceras de seguridad, compresion, robots.txt y sitemap.xml.
 *  - CRM: responde, velocidad, https y certificado, que su ruta de salud (/api/health) funcione, cabeceras de seguridad
 *    y redireccion de http a https.
 * Resultado: semaforo.
 *  - red:    no responde, certificado invalido, error del servidor o algo esencial roto (scripts, estilos, ruta de salud).
 *  - yellow: funciona pero con alertas (lento, sin https, certificado por vencer, falta algo recomendable...).
 *  - green:  todo bien.
 * El servidor consulta direcciones que cargan los administradores: se bloquean las redes internas (SSRF) tanto al guardar
 * como al conectar (la IP se valida cuando se resuelve el nombre, asi un DNS cambiante no sirve para saltear el control).
 * Lo mismo vale para cada direccion que sale del contenido de la pagina (scripts, estilos, imagenes): solo las del mismo sitio.
 */

export type AuditStatus = 'green' | 'yellow' | 'red'
/** page = pagina web comun · crm = servidor de un CRM o tienda (salud y base de datos) · app = el frontend de un CRM o tienda. */
export type AuditKind = 'page' | 'crm' | 'app'

export interface CheckResult {
  status: AuditStatus
  /** Codigos de alerta o de error (la web los traduce). */
  alerts: string[]
  /** Resumen corto y sin idioma: "HTTP 200 · 412 ms" o el motivo del fallo. */
  detail: string
  httpStatus: number | null
  responseMs: number | null
  /** AAAA-MM-DD del vencimiento del certificado, si es https. */
  sslExpiresOn: string | null
  /** Controles revisados y cuantos salieron bien. */
  checks: { passed: number; total: number }
}

const TIMEOUT_MS = 8_000
const SLOW_MS = 3_000
const SSL_WARN_DAYS = 14
const MAX_REDIRECTS = 3
/** Lo que se lee de una respuesta (comprimida): lo demas se descarta. */
const MAX_BODY = 400_000
const MAX_DECODED = 1_500_000
const MAX_ASSETS = 8

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
  /** Hasta que llegan las cabeceras de la respuesta. */
  ms: number
  certExpires: Date | null
  headers: http.IncomingHttpHeaders
  /** Cuerpo ya descomprimido (solo si se pidio); vacio si no se pidio o no se pudo leer entero. */
  body: string
}

function decode(buf: Buffer, encoding: string | undefined): string {
  try {
    const opts = { maxOutputLength: MAX_DECODED }
    if (encoding === 'gzip') return zlib.gunzipSync(buf, opts).toString('utf8')
    if (encoding === 'br') return zlib.brotliDecompressSync(buf, opts).toString('utf8')
    if (encoding === 'deflate') return zlib.inflateSync(buf, opts).toString('utf8')
    return encoding && encoding !== 'identity' ? '' : buf.toString('utf8')
  } catch {
    return '' // cortado a la mitad o roto: no se juzga el contenido
  }
}

function request(url: URL, wantBody = false): Promise<Hop> {
  return new Promise((resolve, reject) => {
    const host = url.hostname.replace(/^\[|\]$/g, '')
    if (net.isIP(host) && isPrivateAddress(host)) return reject(Object.assign(new Error('Direccion no permitida'), { code: 'EBLOCKED' }))
    const started = Date.now()
    const lib = url.protocol === 'https:' ? https : http
    const req = lib.request(
      url,
      {
        method: 'GET',
        lookup: safeLookup,
        timeout: TIMEOUT_MS,
        headers: {
          'user-agent': 'ZimlabsAudit/1.0',
          accept: wantBody ? 'text/html,application/json;q=0.9,*/*;q=0.8' : '*/*',
          'accept-encoding': 'gzip, br',
        },
      },
      (res) => {
        const ms = Date.now() - started
        let certExpires: Date | null = null
        if (url.protocol === 'https:') {
          const validTo = (res.socket as TLSSocket).getPeerCertificate?.()?.valid_to
          if (validTo) certExpires = new Date(validTo)
        }
        const hop = (body: string): Hop => ({
          status: res.statusCode ?? 0,
          location: res.headers.location ?? null,
          ms,
          certExpires,
          headers: res.headers,
          body,
        })
        if (!wantBody) {
          res.resume() // el cuerpo no importa
          resolve(hop(''))
          req.destroy()
          return
        }
        const chunks: Buffer[] = []
        let size = 0
        let cut = false
        res.on('data', (chunk: Buffer) => {
          size += chunk.length
          if (size > MAX_BODY) {
            cut = true
            res.destroy()
            return
          }
          chunks.push(chunk)
        })
        const finish = () => resolve(hop(cut ? '' : decode(Buffer.concat(chunks), res.headers['content-encoding'])))
        res.on('end', finish)
        res.on('close', () => !res.complete && finish())
        res.on('error', finish)
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

const fail = (code: string, detail: string): CheckResult => ({
  status: 'red', alerts: [code], detail, httpStatus: null, responseMs: null, sslExpiresOn: null, checks: { passed: 0, total: 1 },
})

/** Direcciones del mismo sitio que la pagina necesita para funcionar: scripts y estilos (esenciales) e imagenes. */
function assetsOf(html: string, base: URL): { url: URL; critical: boolean }[] {
  const found = new Map<string, boolean>()
  const add = (raw: string | undefined, critical: boolean) => {
    if (!raw || /^(data|blob|javascript|mailto|tel):/i.test(raw)) return
    try {
      const u = new URL(raw, base)
      if (u.host !== base.host || (u.protocol !== 'http:' && u.protocol !== 'https:')) return
      u.hash = ''
      const key = u.toString()
      found.set(key, (found.get(key) ?? false) || critical)
    } catch {
      /* direccion mal escrita en la pagina: se ignora */
    }
  }
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1], true)
  for (const m of html.matchAll(/<link\b[^>]*\brel=["']?stylesheet["']?[^>]*\bhref=["']([^"']+)["']/gi)) add(m[1], true)
  for (const m of html.matchAll(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']?stylesheet["']?/gi)) add(m[1], true)
  for (const m of html.matchAll(/<img\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1], false)
  return [...found.entries()]
    .sort((a, b) => Number(b[1]) - Number(a[1])) // primero lo esencial
    .slice(0, MAX_ASSETS)
    .map(([u, critical]) => ({ url: new URL(u), critical }))
}

const textOf = (html: string) =>
  html.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()

/**
 * `healthUrl`: solo para el servidor de un CRM o tienda (`crm`): ruta de salud de la base de datos si no es la de siempre
 * (/api/health del mismo servidor). Nunca se guardan claves ni cadenas de conexion: la base se revisa por esa ruta.
 */
export async function runCheck(rawUrl: string, kind: AuditKind = 'page', healthUrl?: string | null): Promise<CheckResult> {
  const first = parseAuditUrl(rawUrl)
  if (!first) return fail('blocked', 'Direccion no valida')
  const customHealth = healthUrl ? parseAuditUrl(healthUrl) : null
  if (healthUrl && !customHealth) return fail('blocked', 'Direccion de la base de datos no valida')

  let url = first
  let redirects = 0
  let hop: Hop
  try {
    for (;;) {
      hop = await request(url, true)
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

  /** Cada control: si salio bien, y si no, que alerta deja y si es grave (rojo) o solo un aviso (amarillo). */
  const checks: { ok: boolean; alert?: string; red?: boolean }[] = []
  const check = (ok: boolean, alert?: string, red = false) => checks.push({ ok, alert, red })

  // Lo que se pide aparte, todo a la vez: ruta de salud del CRM, o robots, sitemap, subida de http a https y archivos de la pagina.
  const httpTwin = new URL(url)
  httpTwin.protocol = 'http:'
  httpTwin.port = ''
  const settle = <T>(p: Promise<T>) => p.catch(() => null)
  const isHtml = /html/i.test(String(hop.headers['content-type'] ?? ''))
  const assets = kind !== 'crm' && hop.status < 400 && hop.body && isHtml ? assetsOf(hop.body, url) : []
  const [health, robots, sitemap, twin, assetResults] = await Promise.all([
    kind === 'crm' ? settle(request(customHealth ?? new URL('/api/health', url), true)) : null,
    kind === 'page' ? settle(request(new URL('/robots.txt', url))) : null,
    kind === 'page' ? settle(request(new URL('/sitemap.xml', url))) : null,
    url.protocol === 'https:' ? settle(request(new URL('/', httpTwin))) : null,
    Promise.all(assets.map(async (a) => ({ critical: a.critical, ok: !!(await settle(request(a.url)).then((h) => h && h.status < 400)) }))),
  ])

  /* ---- Funciona: responde ---- */
  const healthOk = kind === 'crm' && !!health && health.status >= 200 && health.status < 300
  // El servidor de un CRM puede no tener nada en la raiz (404): si su ruta de salud responde, esta bien.
  const rootOk = hop.status < 400 || (kind === 'crm' && hop.status < 500 && healthOk)
  if (hop.status >= 500) check(false, 'http_5xx', true)
  else if (hop.status === 401 || hop.status === 403) check(false, 'auth_required')
  else if (hop.status >= 400 && !rootOk) check(false, 'http_4xx', true)
  else if (hop.status >= 300 && hop.status < 400) check(false, 'redirect_loop')
  else check(true)

  check(hop.ms <= SLOW_MS, 'slow')
  check(url.protocol === 'https:', 'no_https')
  if (hop.certExpires) check(Math.floor((hop.certExpires.getTime() - Date.now()) / 86_400_000) > SSL_WARN_DAYS, 'ssl_expiring')
  check(!(redirects > 0 && url.hostname !== first.hostname), 'redirect_host')

  const reachable = hop.status < 400 && rootOk
  if (kind === 'crm') {
    /* ---- CRM: su ruta de salud y su base de datos ---- */
    // La ruta de salud del CRM lee y escribe en su base de datos y lo informa: { ok, db: { ok, ms } }.
    let dbState: 'ok' | 'failed' | 'unknown' = 'unknown'
    if (health) {
      try {
        const info = JSON.parse(health.body) as { db?: { ok?: unknown } }
        if (info?.db?.ok === true) dbState = 'ok'
        else if (info?.db?.ok === false) dbState = 'failed'
      } catch {
        /* no es el JSON de un CRM de Zimlabs: la base queda sin informar */
      }
    }
    if (!health) check(false, 'health_failed', true)
    else if (health.status === 404) check(false, 'no_health')
    else if (dbState === 'failed') {
      check(true) // el servidor contesta...
      check(false, 'db_failed', true) // ...pero su base de datos no
    } else {
      check(healthOk, 'health_failed', true)
      if (healthOk) check(dbState === 'ok', 'no_db_check') // un servidor viejo no informa el estado de su base de datos
    }
  } else if (reachable && hop.body && isHtml) {
    /* ---- Pagina: el contenido ---- */
    const html = hop.body
    check(/<title[^>]*>\s*[^<\s][^<]*<\/title>/i.test(html), 'no_title')
    const text = textOf(html)
    check(html.length >= 300 && text.length >= 20, 'empty_page', true)
    check(!/(application error|internal server error|bad gateway|service unavailable|fatal error|stack trace|cannot get \/|error establishing a database connection)/i.test(text.slice(0, 3000)), 'error_page', true)
    check(/<meta[^>]+name=["']viewport["']/i.test(html), 'no_viewport')
    if (url.protocol === 'https:') check(!/<(?:script|img|link|iframe)\b[^>]*\b(?:src|href)=["']http:\/\//i.test(html), 'mixed_content')
    if (assetResults.length) {
      const broken = assetResults.filter((r) => !r.ok)
      check(broken.length === 0, 'broken_assets', broken.some((r) => r.critical))
    }
    // robots.txt y sitemap.xml son de una pagina publica: el frontend de un CRM o tienda no los necesita.
    if (kind === 'page') {
      check(!!robots && robots.status === 200, 'no_robots')
      check(!!sitemap && sitemap.status === 200, 'no_sitemap')
    }
    const encoding = String(hop.headers['content-encoding'] ?? '')
    if (hop.body.length > 4_000) check(/gzip|br|deflate/.test(encoding), 'no_compression')
  }

  /* ---- Seguridad (https) y subida de http a https: los dos tipos ---- */
  if (url.protocol === 'https:' && reachable) {
    check(!!hop.headers['strict-transport-security'], 'no_hsts')
    check(!!hop.headers['x-content-type-options'] && !!(hop.headers['x-frame-options'] || /frame-ancestors/i.test(String(hop.headers['content-security-policy'] ?? ''))), 'no_security_headers')
    // Si nadie escucha en http (error), esta bien: no hay nada que redirigir.
    if (twin) check(twin.status >= 300 && twin.status < 400 && /^https:/i.test(twin.location ?? ''), 'no_https_redirect')
  }

  const failed = checks.filter((c) => !c.ok)
  return {
    status: failed.some((c) => c.red) ? 'red' : failed.length ? 'yellow' : 'green',
    alerts: [...new Set(failed.map((c) => c.alert).filter((a): a is string => !!a))],
    detail: `HTTP ${hop.status} · ${hop.ms} ms`,
    httpStatus: hop.status,
    responseMs: hop.ms,
    sslExpiresOn: hop.certExpires ? day(hop.certExpires) : null,
    checks: { passed: checks.length - failed.length, total: checks.length },
  }
}
