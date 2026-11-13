import { Router } from 'express'
import { z } from 'zod'
import { db } from '../db.js'
import { requireAdmin } from '../middleware/guards.js'

export const paymentsRouter = Router()

// Los pagos los ven solo los administradores. Son de SOLO LECTURA: los crea y los marca como cobrados el debito
// automatico de Mercado Pago (billing.ts), nadie los carga ni los edita a mano.
paymentsRouter.use(requireAdmin)

const statuses = ['pending', 'paid'] as const
const currencies = ['ARS', 'USD'] as const
type Status = (typeof statuses)[number]
type Currency = (typeof currencies)[number]

interface PaymentRow {
  id: number
  client_id: number
  client_name: string
  concept: string
  amount: number
  currency: Currency
  due_date: string
  status: Status
  paid_at: string | null
  method: 'manual' | 'mercadopago' | null
  rejected: 0 | 1
  created_at: string
}

const select = `
  SELECT p.id, p.client_id, c.name AS client_name, p.concept, p.amount, p.currency, p.due_date, p.status,
         p.paid_at, p.method, p.rejected, p.created_at
  FROM payments p JOIN clients c ON c.id = p.client_id`

const toPayment = (r: PaymentRow) => ({
  id: r.id,
  clientId: r.client_id,
  clientName: r.client_name,
  concept: r.concept,
  amount: r.amount,
  currency: r.currency,
  dueDate: r.due_date,
  status: r.status,
  paidAt: r.paid_at,
  method: r.method,
  /** El banco rechazo el ultimo intento de cobro (sigue pendiente; Mercado Pago reintenta). */
  rejected: r.rejected === 1,
  createdAt: r.created_at,
})

/** Fecha de hoy (AAAA-MM-DD, UTC): lo pendiente con fecha anterior esta vencido. */
const today = () => new Date().toISOString().slice(0, 10)

/* ---------- Listar ---------- */

const listSchema = z.object({
  status: z.enum(statuses).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
})

paymentsRouter.get('/', (req, res) => {
  const parsed = listSchema.safeParse(req.query)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { status, limit, offset } = parsed.data

  // Pendientes: el que vence primero arriba. Pagados: el mas reciente arriba.
  const where = status ? 'WHERE p.status = ?' : ''
  const order = status === 'paid' ? 'p.paid_at DESC, p.id DESC' : 'p.due_date ASC, p.id ASC'
  const rows = db
    .prepare(`${select} ${where} ORDER BY ${order} LIMIT ? OFFSET ?`)
    .all(...(status ? [status] : []), limit + 1, offset) as PaymentRow[]
  const hasMore = rows.length > limit

  // Totales por moneda (nunca se suman pesos con dolares).
  const now = today()
  const sums = db
    .prepare(
      `SELECT currency, status, COUNT(*) AS n, SUM(amount) AS total,
              SUM(CASE WHEN status = 'pending' AND due_date < ? THEN 1 ELSE 0 END) AS overdue,
              SUM(CASE WHEN status = 'pending' AND due_date < ? THEN amount ELSE 0 END) AS overdue_total
       FROM payments GROUP BY currency, status`,
    )
    .all(now, now) as { currency: Currency; status: Status; n: number; total: number; overdue: number; overdue_total: number }[]

  const counts = { all: 0, pending: 0, paid: 0, overdue: 0 }
  const totals: Record<Currency, { pending: number; paid: number; overdue: number }> = {
    ARS: { pending: 0, paid: 0, overdue: 0 },
    USD: { pending: 0, paid: 0, overdue: 0 },
  }
  for (const s of sums) {
    counts.all += s.n
    counts[s.status] += s.n
    counts.overdue += s.overdue
    totals[s.currency][s.status] += s.total
    totals[s.currency].overdue += s.overdue_total
  }

  res.json({
    payments: (hasMore ? rows.slice(0, limit) : rows).map(toPayment),
    nextOffset: hasMore ? offset + limit : null,
    counts,
    totals,
  })
})
