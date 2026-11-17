import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { db } from '../db.js'
import { requireAdmin, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Costos fijos del negocio. Solo administradores. Importes en centavos de ARS.
 * El dashboard los resta de lo cobrado (ver `costsForMonth`) para mostrar ganancias y perdidas.
 */

export const expensesRouter = Router()
expensesRouter.use(requireAdmin)

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 240 })

export type ExpenseFrequency = 'monthly' | 'yearly' | 'once'

export interface ExpenseRow {
  id: number
  name: string
  amount: number
  frequency: ExpenseFrequency
  start_month: string
  end_month: string | null
  note: string
}

const columns = 'id, name, amount, frequency, start_month, end_month, note'

const toExpense = (r: ExpenseRow) => ({
  id: r.id,
  name: r.name,
  amount: r.amount,
  frequency: r.frequency,
  startMonth: r.start_month,
  endMonth: r.end_month,
  note: r.note,
})

/**
 * Cuanto pesa un costo en un mes (AAAA-MM), en centavos.
 *  - monthly: el importe completo cada mes entre inicio y fin.
 *  - yearly:  un doceavo por mes (se reparte el anio para que la ganancia no dé saltos).
 *  - once:    el importe completo solo en su mes.
 */
export function costsForMonth(rows: ExpenseRow[], month: string): number {
  let total = 0
  for (const e of rows) {
    if (e.frequency === 'once') {
      if (e.start_month === month) total += e.amount
      continue
    }
    if (e.start_month > month || (e.end_month !== null && e.end_month < month)) continue
    total += e.frequency === 'yearly' ? Math.round(e.amount / 12) : e.amount
  }
  return total
}

const month = z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/)

const expenseSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    /** Centavos de ARS. */
    amount: z.number().int().positive().max(100_000_000_000_00),
    frequency: z.enum(['monthly', 'yearly', 'once']),
    startMonth: month,
    endMonth: month.nullable().optional(),
    note: z.string().trim().max(300).optional(),
  })
  .refine((e) => e.frequency === 'once' || !e.endMonth || e.endMonth >= e.startMonth, { path: ['endMonth'] })

const idParam = z.coerce.number().int().positive()

function bad(res: import('express').Response, issues: z.ZodIssue[]): void {
  res.status(400).json({ error: 'invalid_input', field: String(issues[0]?.path[0] ?? 'name') })
}

expensesRouter.get('/', (_req, res) => {
  const rows = db.prepare(`SELECT ${columns} FROM expenses ORDER BY start_month DESC, id DESC LIMIT 1000`).all() as unknown as ExpenseRow[]
  res.json({ expenses: rows.map(toExpense) })
})

expensesRouter.post('/', sameOrigin, limiter, (req, res) => {
  const parsed = expenseSchema.safeParse(req.body)
  if (!parsed.success) return bad(res, parsed.error.issues)
  const e = parsed.data
  const user = res.locals.user as SessionUser
  const result = db
    .prepare('INSERT INTO expenses (name, amount, frequency, start_month, end_month, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(e.name, e.amount, e.frequency, e.startMonth, e.frequency === 'once' ? null : (e.endMonth ?? null), e.note ?? '', user.id)
  const row = db.prepare(`SELECT ${columns} FROM expenses WHERE id = ?`).get(Number(result.lastInsertRowid)) as unknown as ExpenseRow
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(201).json({ expense: toExpense(row) })
})

expensesRouter.put('/:id', sameOrigin, limiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  const parsed = expenseSchema.safeParse(req.body)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!parsed.success) return bad(res, parsed.error.issues)
  const e = parsed.data
  const result = db
    .prepare('UPDATE expenses SET name = ?, amount = ?, frequency = ?, start_month = ?, end_month = ?, note = ? WHERE id = ?')
    .run(e.name, e.amount, e.frequency, e.startMonth, e.frequency === 'once' ? null : (e.endMonth ?? null), e.note ?? '', id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  const row = db.prepare(`SELECT ${columns} FROM expenses WHERE id = ?`).get(id.data) as unknown as ExpenseRow
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ expense: toExpense(row) })
})

expensesRouter.delete('/:id', sameOrigin, limiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('DELETE FROM expenses WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
