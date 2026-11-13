import crypto from 'node:crypto'
import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import {
  classify,
  devices,
  featureIds,
  haveNeedUnsure,
  maintenanceInterest,
  prefIds,
  recordScale,
  securityIds,
  tabIds,
  timelines,
  toolIds,
  userScale,
  type BriefAnswers,
} from '../briefs.js'
import { db } from '../db.js'
import { requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/** Cuanto dura un enlace sin completar. */
const LINK_DAYS = 30

const newToken = () => crypto.randomBytes(18).toString('base64url') // 144 bits: no se puede adivinar

interface FormRow {
  id: number
  token: string
  client_id: number
  status: 'pending' | 'submitted'
  answers: string | null
  result: string | null
  created_at: string
  expires_at: string
  submitted_at: string | null
  client_name: string
  client_company: string | null
}

const select = `SELECT f.id, f.token, f.client_id, f.status, f.answers, f.result, f.created_at, f.expires_at, f.submitted_at,
  c.name AS client_name, c.company AS client_company
  FROM forms f JOIN clients c ON c.id = f.client_id`

const parse = <T>(text: string | null): T | null => {
  if (!text) return null
  try {
    return JSON.parse(text) as T
  } catch {
    return null
  }
}

const toForm = (r: FormRow, withAnswers: boolean) => ({
  id: r.id,
  token: r.token,
  clientId: r.client_id,
  clientName: r.client_name,
  company: r.client_company,
  status: r.status,
  expired: r.status === 'pending' && r.expires_at < new Date().toISOString(),
  result: parse(r.result),
  answers: withAnswers ? parse(r.answers) : undefined,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  submittedAt: r.submitted_at,
})

/* ---------- Equipo (con sesion): crear enlaces, ver respuestas ---------- */

export const formsRouter = Router()
formsRouter.use(requireUser)

formsRouter.get('/', (_req, res) => {
  const rows = db.prepare(`${select} ORDER BY f.id DESC LIMIT 200`).all() as FormRow[]
  res.json({ forms: rows.map((r) => toForm(r, false)) })
})

formsRouter.get('/:id', (req, res) => {
  const row = db.prepare(`${select} WHERE f.id = ?`).get(Number(req.params.id)) as FormRow | undefined
  if (!row) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.json({ form: toForm(row, true) })
})

formsRouter.post('/', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 60 }), (req, res) => {
  const parsed = z.object({ clientId: z.number().int().positive() }).safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: 'clientId' })
    return
  }
  if (!db.prepare('SELECT 1 FROM clients WHERE id = ?').get(parsed.data.clientId)) {
    res.status(404).json({ error: 'client_not_found', field: 'clientId' })
    return
  }
  const user = res.locals.user as SessionUser
  const expires = new Date(Date.now() + LINK_DAYS * 86_400_000).toISOString()
  const result = db
    .prepare('INSERT INTO forms (token, client_id, expires_at, created_by) VALUES (?, ?, ?, ?)')
    .run(newToken(), parsed.data.clientId, expires, user.id)
  const row = db.prepare(`${select} WHERE f.id = ?`).get(Number(result.lastInsertRowid)) as FormRow
  emit('forms', { exceptCid: res.locals.cid })
  res.status(201).json({ form: toForm(row, false) })
})

formsRouter.delete('/:id', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 120 }), (req, res) => {
  const info = db.prepare('DELETE FROM forms WHERE id = ?').run(Number(req.params.id))
  if (!info.changes) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('forms', { exceptCid: res.locals.cid })
  res.json({ ok: true })
})

/* ---------- Publico (el cliente, con el enlace): ver el formulario y enviarlo ---------- */

export const briefRouter = Router()

const find = (token: string) =>
  token.length >= 16 && token.length <= 64
    ? (db.prepare(`${select} WHERE f.token = ?`).get(token) as FormRow | undefined)
    : undefined

// Mismo limite para ver y enviar: alcanza para uso normal y frena el barrido de enlaces.
briefRouter.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 60 }))

briefRouter.get('/:token', (req, res) => {
  const row = find(req.params.token)
  if (!row) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  const state = row.status === 'submitted' ? 'submitted' : row.expires_at < new Date().toISOString() ? 'expired' : 'open'
  // Solo el primer nombre, para saludar. Nada mas del cliente sale por esta ruta.
  res.json({ state, name: row.client_name.trim().split(/\s+/)[0] ?? '' })
})

const text = (max: number) => z.string().trim().max(max).default('')
const keys = <T extends object>(o: T) => Object.keys(o) as [keyof T & string, ...(keyof T & string)[]]

/** Lista de opciones tildadas (sin repetir, sin pasarse del total posible). */
const picks = <T extends [string, ...string[]]>(values: T) => z.array(z.enum(values)).max(values.length).default([])
/** "Agregar otro": hasta 10 cosas escritas a mano, de hasta 80 letras cada una (las vacias se descartan). */
const extras = z
  .array(z.string().trim().max(80))
  .max(10)
  .default([])
  .transform((list) => list.filter(Boolean))

const answersSchema = z
  .object({
    business: text(1000),
    goals: text(1000),
    features: picks(featureIds),
    tabs: picks(tabIds),
    security: picks(securityIds),
    prefs: picks(prefIds),
    tools: picks(toolIds),
    featuresExtra: extras,
    languagesExtra: extras,
    tabsExtra: extras,
    securityExtra: extras,
    prefsExtra: extras,
    toolsExtra: extras,
    users: z.enum(keys(userScale)),
    records: z.enum(keys(recordScale)),
    migrate: z.boolean().default(false),
    devices: z.array(z.enum(devices)).max(devices.length).default([]),
    branding: z.enum(haveNeedUnsure).default('unsure'),
    domain: z.enum(haveNeedUnsure).default('unsure'),
    maintenance: z.enum(maintenanceInterest).default('maybe'),
    timeline: z.enum(timelines).default('flexible'),
    budget: text(100),
    notes: text(1000),
  })
  // Hay que haber marcado o escrito algo: un formulario vacio no dice que necesita.
  .refine(
    (v) =>
      v.features.length + v.tabs.length + v.security.length + v.prefs.length + v.tools.length +
        v.featuresExtra.length + v.languagesExtra.length + v.tabsExtra.length + v.securityExtra.length + v.prefsExtra.length + v.toolsExtra.length > 0,
    { path: ['features'] },
  )

briefRouter.post('/:token', sameOrigin, (req, res) => {
  const row = find(req.params.token)
  if (!row) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  if (row.status === 'submitted') {
    res.status(409).json({ error: 'already_submitted' })
    return
  }
  if (row.expires_at < new Date().toISOString()) {
    res.status(410).json({ error: 'expired' })
    return
  }
  const parsed = answersSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: String(parsed.error.issues[0]?.path[0] ?? 'features') })
    return
  }
  const d = parsed.data
  const answers: BriefAnswers = {
    ...d,
    features: [...new Set(d.features)],
    tabs: [...new Set(d.tabs)],
    security: [...new Set(d.security)],
    prefs: [...new Set(d.prefs)],
    tools: [...new Set(d.tools)],
    devices: [...new Set(d.devices)],
  }
  const result = classify(answers)
  // El UPDATE solo pasa si sigue pendiente: dos envios a la vez no se pisan.
  const info = db
    .prepare(
      "UPDATE forms SET status = 'submitted', answers = ?, result = ?, submitted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ? AND status = 'pending'",
    )
    .run(JSON.stringify(answers), JSON.stringify(result), row.id)
  if (!info.changes) {
    res.status(409).json({ error: 'already_submitted' })
    return
  }
  emit('forms')
  res.json({ ok: true })
})
