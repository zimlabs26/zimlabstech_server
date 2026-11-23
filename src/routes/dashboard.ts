import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { db } from '../db.js'
import { captureError } from '../errorlog.js'
import { mpEnabled } from '../mercadopago.js'
import { canRetry, getMpSummary, isStale, isSyncing, startSync, type MpSummary } from '../mpreports.js'
import { requireAdmin, requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { adjustmentsByMonth, getGoal, getPipeline, setGoal } from '../pipeline.js'
import { emit } from '../realtime.js'
import { costsForMonth, type ExpenseRow } from './expenses.js'

export const dashboardRouter = Router()

// Cualquier usuario con sesion ve lo de clientes; pagos y debitos son solo para administradores.
dashboardRouter.use(requireUser)

type Currency = 'ARS' | 'USD'
const DAY = 24 * 60 * 60 * 1000
const isoDay = (d: Date) => d.toISOString().slice(0, 10)

const money = (rows: { currency: Currency; total: number }[]): Record<Currency, number> => {
  const out: Record<Currency, number> = { ARS: 0, USD: 0 }
  for (const r of rows) out[r.currency] = r.total
  return out
}

/** Una sola respuesta con todo lo que dibuja el dashboard. Importes en centavos. */
dashboardRouter.get('/', (_req, res) => {
  const user = res.locals.user as SessionUser

  /* ---------- Clientes (todos los usuarios) ---------- */

  const byCategory: Record<string, number> = { bronze: 0, silver: 0, gold: 0, diamond: 0 }
  let total = 0
  // Las estadisticas cuentan clientes de verdad: los posibles clientes (prospect = 1) quedan afuera.
  for (const r of db.prepare('SELECT category, COUNT(*) AS n FROM clients WHERE prospect = 0 GROUP BY category').all() as { category: string; n: number }[]) {
    byCategory[r.category] = r.n
    total += r.n
  }
  const byPlan: Record<string, number> = { static: 0, server: 0, crmb: 0, crmf: 0, none: 0 }
  for (const r of db.prepare('SELECT maintenance_plan AS plan, COUNT(*) AS n FROM clients WHERE prospect = 0 GROUP BY maintenance_plan').all() as {
    plan: string | null
    n: number
  }[]) {
    byPlan[r.plan ?? 'none'] = r.n
  }
  const clients = { total, byCategory, byPlan }

  if (user.role !== 'admin') {
    res.json({ clients })
    return
  }

  /* ---------- Debitos automaticos ---------- */

  const debits = { none: 0, pending: 0, authorized: 0, paused: 0 }
  let withDebit = 0
  for (const r of db
    .prepare(`SELECT status, COUNT(DISTINCT client_id) AS n FROM subscriptions WHERE status != 'cancelled' GROUP BY status`)
    .all() as { status: 'pending' | 'authorized' | 'paused'; n: number }[]) {
    debits[r.status] = r.n
    withDebit += r.n
  }
  debits.none = Math.max(0, total - withDebit)

  /* ---------- Plata ---------- */

  const now = new Date()
  const today = isoDay(now)
  const month = today.slice(0, 7)

  const collectedMonth = money(
    db
      .prepare(`SELECT currency, SUM(amount) AS total FROM payments WHERE status = 'paid' AND substr(paid_at, 1, 7) = ? GROUP BY currency`)
      .all(month) as { currency: Currency; total: number }[],
  )
  const pending = money(
    db.prepare(`SELECT currency, SUM(amount) AS total FROM payments WHERE status = 'pending' GROUP BY currency`).all() as {
      currency: Currency
      total: number
    }[],
  )
  const overdue = money(
    db
      .prepare(`SELECT currency, SUM(amount) AS total FROM payments WHERE status = 'pending' AND due_date < ? GROUP BY currency`)
      .all(today) as { currency: Currency; total: number }[],
  )
  // Ingreso mensual recurrente: lo que cobran por mes los debitos activos (siempre en pesos).
  const mrr = (db.prepare(`SELECT COALESCE(SUM(amount), 0) AS total FROM subscriptions WHERE status = 'authorized'`).get() as { total: number }).total
  const counts = db
    .prepare(
      `SELECT SUM(CASE WHEN rejected = 1 THEN 1 ELSE 0 END) AS rejected,
              SUM(CASE WHEN due_date < ? THEN 1 ELSE 0 END) AS overdue
       FROM payments WHERE status = 'pending'`,
    )
    .get(today) as { rejected: number | null; overdue: number | null }

  /* ---------- Proximos cobros (30 dias) ---------- */

  const horizon = isoDay(new Date(now.getTime() + 30 * DAY))
  const next = db
    .prepare(
      `SELECT s.next_payment_date AS date, s.amount, c.name AS clientName
       FROM subscriptions s JOIN clients c ON c.id = s.client_id
       WHERE s.status = 'authorized' AND s.next_payment_date BETWEEN ? AND ?
       ORDER BY s.next_payment_date, s.id LIMIT 8`,
    )
    .all(today, horizon) as { date: string; amount: number; clientName: string }[]

  /* ---------- Cobrado por mes (ultimos 6, en pesos) ---------- */

  const months: string[] = []
  for (let i = 5; i >= 0; i--) {
    months.push(isoDay(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1))).slice(0, 7))
  }
  const paidBy = new Map(
    (
      db
        .prepare(
          `SELECT substr(paid_at, 1, 7) AS m, SUM(amount) AS total FROM payments
           WHERE status = 'paid' AND currency = 'ARS' AND substr(paid_at, 1, 7) BETWEEN ? AND ? GROUP BY m`,
        )
        .all(months[0], months[5]) as { m: string; total: number }[]
    ).map((r) => [r.m, r.total]),
  )
  const dueBy = new Map(
    (
      db
        .prepare(
          `SELECT substr(due_date, 1, 7) AS m, SUM(amount) AS total FROM payments
           WHERE currency = 'ARS' AND substr(due_date, 1, 7) BETWEEN ? AND ? GROUP BY m`,
        )
        .all(months[0], months[5]) as { m: string; total: number }[]
    ).map((r) => [r.m, r.total]),
  )
  // Costos fijos cargados por el equipo: se restan de lo cobrado para mostrar la ganancia o la perdida de cada mes.
  const expenseRows = db
    .prepare('SELECT id, name, amount, frequency, start_month, end_month, note FROM expenses')
    .all() as unknown as ExpenseRow[]
  const mpIncome = getMpSummary()?.income ?? {}
  // Plata que entro a Mercado Pago pero no es ganancia (aportes de los socios, dinero que entro y salio): se resta de ese mes.
  const adjustments = adjustmentsByMonth()
  const incomeOf = (m: string, fallback: number) => Math.max(0, (mpIncome[m] ?? fallback) - (adjustments[m] ?? 0))
  const monthly = months.map((m) => ({
    month: m,
    // Los ingresos salen de los reportes de Mercado Pago (todo lo que entro: pagos y transferencias); sin datos, de los pagos del CRM.
    paid: incomeOf(m, paidBy.get(m) ?? 0),
    expected: dueBy.get(m) ?? 0,
    costs: costsForMonth(expenseRows, m),
  }))
  const costsMonth = costsForMonth(expenseRows, month)
  const collectedNow = incomeOf(month, collectedMonth.ARS)

  /* ---------- Objetivo anual y pipeline ---------- */

  const year = now.getUTCFullYear()
  // Cobrado en el ano (ya sin los ajustes): de los reportes de Mercado Pago, y de los pagos del CRM en los meses que no estan en ellos.
  const crmYear = new Map(
    (
      db
        .prepare(`SELECT substr(paid_at, 1, 7) AS m, SUM(amount) AS total FROM payments WHERE status = 'paid' AND currency = 'ARS' AND substr(paid_at, 1, 4) = ? GROUP BY m`)
        .all(String(year)) as { m: string; total: number }[]
    ).map((r) => [r.m, r.total]),
  )
  let collectedYear = 0
  for (let i = 1; i <= now.getUTCMonth() + 1; i++) {
    const m = `${year}-${String(i).padStart(2, '0')}`
    collectedYear += incomeOf(m, crmYear.get(m) ?? 0)
  }
  const goal = { year, amount: getGoal(year), collectedYear }

  /* ---------- Requiere atencion ---------- */

  // Links de debito generados hace 3 dias o mas que el cliente todavia no activo.
  const cutoff = new Date(now.getTime() - 3 * DAY).toISOString()
  const staleLinks = (
    db
      .prepare(
        `SELECT c.id, c.name, s.created_at AS createdAt FROM subscriptions s JOIN clients c ON c.id = s.client_id
         WHERE s.status = 'pending' AND s.created_at < ? ORDER BY s.created_at LIMIT 5`,
      )
      .all(cutoff) as { id: number; name: string; createdAt: string }[]
  ).map((r) => ({ id: r.id, name: r.name, days: Math.floor((now.getTime() - Date.parse(r.createdAt)) / DAY) }))

  // Clientes con plan a los que todavia no se les puede generar el debito (falta correo, costo o esta en dolares).
  const notReady = (
    db
      .prepare(
        `SELECT c.id, c.name, c.email, c.maintenance_price AS price FROM clients c
         WHERE c.maintenance_plan IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM subscriptions s WHERE s.client_id = c.id AND s.status != 'cancelled')
           AND (c.email IS NULL OR c.email = '' OR c.maintenance_price IS NULL OR c.maintenance_price <= 0 OR c.maintenance_currency != 'ARS')
         ORDER BY c.id DESC LIMIT 5`,
      )
      .all() as { id: number; name: string; email: string | null; price: number | null }[]
  ).map((r) => ({
    id: r.id,
    name: r.name,
    missing: !r.email ? 'email' : !r.price || r.price <= 0 ? 'price' : 'currency',
  }))

  res.json({
    clients,
    admin: {
      goal,
      pipeline: getPipeline(),
      debits,
      // Resultado del mes (en pesos): lo cobrado menos los costos fijos. Puede ser negativo (perdida).
      money: { collectedMonth: { ...collectedMonth, ARS: collectedNow }, pending, overdue, mrr, costsMonth, resultMonth: collectedNow - costsMonth },
      counts: { rejected: counts.rejected ?? 0, overdue: counts.overdue ?? 0 },
      next,
      monthly,
      attention: { staleLinks, notReady },
    },
  })
})

/* ---------- Saldo de la cuenta de Mercado Pago ---------- */

type BalanceReply =
  | { status: 'ok'; balance: { available: number; unavailable: number; total: number; currency: string }; asOf: string; updatedAt: string; refreshing: boolean }
  | { status: 'syncing' | 'disabled' | 'error' }

const toReply = (s: MpSummary): BalanceReply => ({
  status: 'ok',
  balance: { available: s.balance, unavailable: 0, total: s.balance, currency: 'ARS' },
  asOf: s.asOf,
  updatedAt: s.updatedAt,
  refreshing: isSyncing(),
})

/**
 * Saldo disponible, leido de los reportes de Mercado Pago. Un reporte tarda varios minutos, asi que se actualiza en
 * segundo plano: la primera vez no hay datos (status "syncing") y despues se refresca solo cada 6 horas.
 * Es solo lectura: nunca mueve plata.
 */
dashboardRouter.get('/balance', requireAdmin, (_req, res) => {
  if (!mpEnabled()) {
    res.json({ status: 'disabled' } satisfies BalanceReply)
    return
  }
  const summary = getMpSummary()
  if (isStale(summary) && canRetry()) startSync()
  if (summary) {
    res.json(toReply(summary))
    return
  }
  res.json({ status: isSyncing() || canRetry() ? 'syncing' : 'error' } satisfies BalanceReply)
})

/* ---------- Objetivo anual ---------- */

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 240 })

/** Objetivo del ano en curso, en centavos de ARS. 0 = sin objetivo. */
dashboardRouter.put('/goal', requireAdmin, sameOrigin, limiter, (req, res) => {
  const parsed = z.object({ amount: z.number().int().min(0).max(100_000_000_000_00) }).safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: 'amount' })
    return
  }
  const year = new Date().getUTCFullYear()
  setGoal(year, parsed.data.amount)
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ goal: { year, amount: getGoal(year) } })
})

/* ---------- Ajustes de ingresos ---------- */

interface AdjustmentRow {
  id: number
  month: string
  amount: number
  note: string
}

const toAdjustment = (r: AdjustmentRow) => ({ id: r.id, month: r.month, amount: r.amount, note: r.note })

const adjustmentSchema = z.object({
  month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/),
  /** Centavos de ARS. */
  amount: z.number().int().positive().max(100_000_000_000_00),
  note: z.string().trim().max(300).optional(),
})

/** Dinero que entro a Mercado Pago y no es ganancia (aportes, plata que entro y salio). Se resta de los ingresos de su mes. */
dashboardRouter.get('/adjustments', requireAdmin, (_req, res) => {
  const rows = db.prepare('SELECT id, month, amount, note FROM income_adjustments ORDER BY month DESC, id DESC LIMIT 500').all() as unknown as AdjustmentRow[]
  res.json({ adjustments: rows.map(toAdjustment) })
})

dashboardRouter.post('/adjustments', requireAdmin, sameOrigin, limiter, (req, res) => {
  const parsed = adjustmentSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: String(parsed.error.issues[0]?.path[0] ?? 'amount') })
    return
  }
  const a = parsed.data
  const user = res.locals.user as SessionUser
  const result = db.prepare('INSERT INTO income_adjustments (month, amount, note, created_by) VALUES (?, ?, ?, ?)').run(a.month, a.amount, a.note ?? '', user.id)
  const row = db.prepare('SELECT id, month, amount, note FROM income_adjustments WHERE id = ?').get(Number(result.lastInsertRowid)) as unknown as AdjustmentRow
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(201).json({ adjustment: toAdjustment(row) })
})

dashboardRouter.delete('/adjustments/:id', requireAdmin, sameOrigin, limiter, (req, res) => {
  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('DELETE FROM income_adjustments WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
