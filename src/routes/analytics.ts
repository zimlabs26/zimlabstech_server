import crypto from 'node:crypto'
import { Router } from 'express'
import { z } from 'zod'
import { config } from '../config.js'
import { captureError } from '../errorlog.js'
import { requireAdmin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'

/**
 * Analiticas de la web (Google Analytics 4). El navegador nunca habla con Google: este servidor consulta la API de datos
 * de GA4 con una cuenta de servicio y le devuelve al CRM solo los numeros ya resumidos. Solo administradores.
 * Sin GA_PROPERTY_ID / GA_CLIENT_EMAIL / GA_PRIVATE_KEY la ruta responde { configured: false } y el CRM explica que falta.
 */

export const analyticsRouter = Router()
analyticsRouter.use(requireAdmin)

const querySchema = z.object({ days: z.coerce.number().pipe(z.union([z.literal(7), z.literal(28), z.literal(90)])).default(28) })

const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly'
const b64url = (input: Buffer | string) => Buffer.from(input).toString('base64url')

let token: { value: string; expires: number } | null = null

/** Token de acceso de la cuenta de servicio (JWT firmado con RS256, valido una hora; se reutiliza hasta poco antes de vencer). */
async function accessToken(): Promise<string> {
  if (token && token.expires - Date.now() > 60_000) return token.value
  const now = Math.floor(Date.now() / 1000)
  const unsigned = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(
    JSON.stringify({ iss: config.gaClientEmail, scope: SCOPE, aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }),
  )}`
  const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), config.gaPrivateKey).toString('base64url')
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }),
  })
  if (!res.ok) throw new Error(`GA token ${res.status}`)
  const json = (await res.json()) as { access_token: string; expires_in: number }
  token = { value: json.access_token, expires: Date.now() + json.expires_in * 1000 }
  return token.value
}

type Row = { dimensionValues?: { value: string }[]; metricValues?: { value: string }[] }
type Report = { rows?: Row[] }

async function ga(method: 'runReport' | 'runRealtimeReport', body: unknown): Promise<Report> {
  const res = await fetch(`https://analyticsdata.googleapis.com/v1beta/properties/${config.gaPropertyId}:${method}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${await accessToken()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`GA ${method} ${res.status}: ${(await res.text()).slice(0, 300)}`)
  return (await res.json()) as Report
}

const num = (row: Row | undefined, i: number) => Number(row?.metricValues?.[i]?.value ?? 0)
const dim = (row: Row, i = 0) => row.dimensionValues?.[i]?.value ?? ''
const metrics = (...names: string[]) => names.map((name) => ({ name }))

export type AnalyticsData = {
  configured: true
  days: number
  /** Personas con la web abierta ahora mismo (ultimos 30 minutos). */
  realtime: number
  totals: { users: number; newUsers: number; sessions: number; pageviews: number; engagementRate: number; avgSeconds: number }
  /** Una fila por dia (AAAA-MM-DD). */
  daily: { date: string; users: number; sessions: number; pageviews: number }[]
  pages: { path: string; views: number; users: number }[]
  sources: { name: string; sessions: number }[]
  countries: { name: string; users: number }[]
  devices: { name: string; users: number }[]
  fetchedAt: string
}

const cache = new Map<number, { at: number; data: AnalyticsData }>()
const TTL = 5 * 60_000

async function load(days: number): Promise<AnalyticsData> {
  const dateRanges = [{ startDate: `${days - 1}daysAgo`, endDate: 'today' }]
  const top = (dimension: string, metric: string, limit: number) => ({
    dateRanges,
    dimensions: [{ name: dimension }],
    metrics: metrics(metric),
    orderBys: [{ metric: { metricName: metric }, desc: true }],
    limit,
  })
  const [totals, daily, pages, sources, countries, devices, live] = await Promise.all([
    ga('runReport', { dateRanges, metrics: metrics('activeUsers', 'newUsers', 'sessions', 'screenPageViews', 'engagementRate', 'averageSessionDuration') }),
    ga('runReport', {
      dateRanges,
      dimensions: [{ name: 'date' }],
      metrics: metrics('activeUsers', 'sessions', 'screenPageViews'),
      orderBys: [{ dimension: { dimensionName: 'date' } }],
    }),
    ga('runReport', {
      dateRanges,
      dimensions: [{ name: 'pagePath' }],
      metrics: metrics('screenPageViews', 'activeUsers'),
      orderBys: [{ metric: { metricName: 'screenPageViews' }, desc: true }],
      limit: 8,
    }),
    ga('runReport', top('sessionDefaultChannelGroup', 'sessions', 8)),
    ga('runReport', top('country', 'activeUsers', 8)),
    ga('runReport', top('deviceCategory', 'activeUsers', 4)),
    ga('runRealtimeReport', { metrics: metrics('activeUsers') }),
  ])
  const t = totals.rows?.[0]
  return {
    configured: true,
    days,
    realtime: num(live.rows?.[0], 0),
    totals: { users: num(t, 0), newUsers: num(t, 1), sessions: num(t, 2), pageviews: num(t, 3), engagementRate: num(t, 4), avgSeconds: num(t, 5) },
    daily: (daily.rows ?? []).map((r) => {
      const d = dim(r)
      return { date: `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}`, users: num(r, 0), sessions: num(r, 1), pageviews: num(r, 2) }
    }),
    pages: (pages.rows ?? []).map((r) => ({ path: dim(r), views: num(r, 0), users: num(r, 1) })),
    sources: (sources.rows ?? []).map((r) => ({ name: dim(r), sessions: num(r, 0) })),
    countries: (countries.rows ?? []).map((r) => ({ name: dim(r), users: num(r, 0) })),
    devices: (devices.rows ?? []).map((r) => ({ name: dim(r), users: num(r, 0) })),
    fetchedAt: new Date().toISOString(),
  }
}

analyticsRouter.get('/', rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  if (!config.gaPropertyId || !config.gaClientEmail || !config.gaPrivateKey) {
    res.json({ configured: false })
    return
  }
  const parsed = querySchema.safeParse(req.query)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const days = parsed.data.days
  const hit = cache.get(days)
  if (hit && Date.now() - hit.at < TTL) {
    res.json(hit.data)
    return
  }
  try {
    const data = await load(days)
    cache.set(days, { at: Date.now(), data })
    res.json(data)
  } catch (error) {
    // Google no contesta o rechaza las credenciales: se registra y, si hay datos viejos, se muestran esos.
    captureError(error, { kind: 'analytics', path: req.path, method: req.method, status: 502 })
    if (hit) res.json(hit.data)
    else res.status(502).json({ error: 'analytics_unavailable' })
  }
})
