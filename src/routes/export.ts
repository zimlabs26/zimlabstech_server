import { Router } from 'express'
import { z } from 'zod'
import { db } from '../db.js'
import { requireAdmin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { createZip } from '../zip.js'

export const exportRouter = Router()

// Llevarse datos es cosa de administradores.
exportRouter.use(requireAdmin)

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 })

const datasets = ['clients', 'payments', 'debits', 'tasks'] as const
type Dataset = (typeof datasets)[number]
type Lang = 'es' | 'en'

const MAX_ROWS = 50_000

/** Cada celda va entre comillas. Las que empiezan con = + - @ se neutralizan: Excel las ejecutaria como formulas. */
function csvCell(value: string | number | null | undefined): string {
  const text = value === null || value === undefined ? '' : String(value)
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
  return `"${safe.replace(/"/g, '""')}"`
}

/** Importe en centavos -> "15000,50" (es) o "15000.50" (en), sin separador de miles para que Excel lo tome como numero. */
const money = (cents: number | null, lang: Lang): string => {
  if (cents === null || cents === undefined) return ''
  const text = (cents / 100).toFixed(2)
  return lang === 'es' ? text.replace('.', ',') : text
}

const labels = {
  es: {
    clients: ['Nombre', 'Empresa', 'Correo', 'Telefono', 'Plan', 'Categoria', 'Costo mensual', 'Moneda', 'Notas', 'Creado'],
    payments: ['Cliente', 'Concepto', 'Monto', 'Moneda', 'Vencimiento', 'Estado', 'Fecha de cobro', 'Metodo', 'Creado'],
    debits: ['Cliente', 'Estado', 'Monto mensual', 'Proximo cobro', 'ID de Mercado Pago', 'Creado'],
    tasks: ['Titulo', 'Descripcion', 'Estado', 'Cliente', 'Creada', 'Actualizada'],
    files: { clients: 'clientes', payments: 'pagos', debits: 'debitos', tasks: 'tareas', backup: 'copia-zimlabs' },
    status: {
      paid: 'Pagado', pending: 'Pendiente', overdue: 'Vencido', rejected: 'Rechazado',
      authorized: 'Activo', paused: 'En pausa', cancelled: 'Cancelado', awaiting: 'Esperando tarjeta',
      todo: 'Por hacer', doing: 'En curso', done: 'Hecha',
    },
    method: { mercadopago: 'Mercado Pago', manual: 'Manual' },
  },
  en: {
    clients: ['Name', 'Company', 'Email', 'Phone', 'Plan', 'Category', 'Monthly cost', 'Currency', 'Notes', 'Created'],
    payments: ['Client', 'Concept', 'Amount', 'Currency', 'Due date', 'Status', 'Paid on', 'Method', 'Created'],
    debits: ['Client', 'Status', 'Monthly amount', 'Next charge', 'Mercado Pago ID', 'Created'],
    tasks: ['Title', 'Description', 'Status', 'Client', 'Created', 'Updated'],
    files: { clients: 'clients', payments: 'payments', debits: 'debits', tasks: 'tasks', backup: 'zimlabs-backup' },
    status: {
      paid: 'Paid', pending: 'Pending', overdue: 'Overdue', rejected: 'Rejected',
      authorized: 'Active', paused: 'Paused', cancelled: 'Cancelled', awaiting: 'Awaiting card',
      todo: 'To do', doing: 'Doing', done: 'Done',
    },
    method: { mercadopago: 'Mercado Pago', manual: 'Manual' },
  },
} as const

type Row = (string | number | null)[]

function rowsFor(dataset: Dataset, lang: Lang): Row[] {
  const l = labels[lang]
  switch (dataset) {
    case 'clients':
      return (
        db
          .prepare(
            `SELECT name, company, email, phone, maintenance_plan AS plan, category, maintenance_price AS price,
                    maintenance_currency AS currency, notes, created_at AS createdAt
             FROM clients ORDER BY id DESC LIMIT ?`,
          )
          .all(MAX_ROWS) as Record<string, string | number | null>[]
      ).map((r) => [r.name, r.company, r.email, r.phone, r.plan, r.category, r.price === null ? '' : money(r.price as number, lang), r.currency, r.notes, r.createdAt])

    case 'payments': {
      const today = new Date().toISOString().slice(0, 10)
      return (
        db
          .prepare(
            `SELECT c.name AS client, p.concept, p.amount, p.currency, p.due_date AS dueDate, p.status, p.rejected,
                    p.paid_at AS paidAt, p.method, p.created_at AS createdAt
             FROM payments p JOIN clients c ON c.id = p.client_id ORDER BY p.due_date DESC, p.id DESC LIMIT ?`,
          )
          .all(MAX_ROWS) as Record<string, string | number | null>[]
      ).map((r) => {
        const state =
          r.status === 'paid' ? l.status.paid : r.rejected === 1 ? l.status.rejected : (r.dueDate as string) < today ? l.status.overdue : l.status.pending
        const method = r.method ? (l.method[r.method as 'mercadopago' | 'manual'] ?? r.method) : ''
        return [r.client, r.concept, money(r.amount as number, lang), r.currency, r.dueDate, state, r.paidAt, method, r.createdAt]
      })
    }

    case 'debits':
      return (
        db
          .prepare(
            `SELECT c.name AS client, s.status, s.amount, s.next_payment_date AS next, s.mp_id AS mpId, s.created_at AS createdAt
             FROM subscriptions s JOIN clients c ON c.id = s.client_id ORDER BY s.id DESC LIMIT ?`,
          )
          .all(MAX_ROWS) as Record<string, string | number | null>[]
      ).map((r) => {
        const status = r.status === 'pending' ? l.status.awaiting : (l.status[r.status as 'authorized' | 'paused' | 'cancelled'] ?? r.status)
        return [r.client, status, money(r.amount as number, lang), r.next, r.mpId, r.createdAt]
      })

    case 'tasks':
      return (
        db
          .prepare(
            `SELECT t.title, t.description, t.status, c.name AS client, t.created_at AS createdAt, t.updated_at AS updatedAt
             FROM tasks t LEFT JOIN clients c ON c.id = t.client_id ORDER BY t.id DESC LIMIT ?`,
          )
          .all(MAX_ROWS) as Record<string, string | number | null>[]
      ).map((r) => [r.title, r.description, l.status[r.status as 'todo' | 'doing' | 'done'] ?? r.status, r.client, r.createdAt, r.updatedAt])
  }
}

/** CSV completo de un conjunto de datos. BOM al inicio: Excel reconoce las tildes (UTF-8). */
function csvFor(dataset: Dataset, lang: Lang): Buffer {
  const lines = [labels[lang][dataset].map((h) => csvCell(h)).join(','), ...rowsFor(dataset, lang).map((row) => row.map(csvCell).join(','))]
  return Buffer.from(`﻿${lines.join('\r\n')}\r\n`, 'utf8')
}

const querySchema = z.object({ sets: z.string().max(100), lang: z.enum(['es', 'en']).default('es') })

/**
 * GET /api/export?sets=clients,payments&lang=es
 * Un solo conjunto = un CSV. Varios (o todos) = un ZIP con un CSV de cada uno (sirve como copia de seguridad).
 */
exportRouter.get('/', limiter, (req, res) => {
  const parsed = querySchema.safeParse(req.query)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const requested = new Set(parsed.data.sets.split(',').map((s) => s.trim()).filter(Boolean))
  if (requested.size === 0 || [...requested].some((s) => !(datasets as readonly string[]).includes(s))) {
    res.status(400).json({ error: 'invalid_input', field: 'sets' })
    return
  }

  const chosen = datasets.filter((d) => requested.has(d))
  const { lang } = parsed.data
  const day = new Date().toISOString().slice(0, 10)
  const names = labels[lang].files

  res.set({ 'Cache-Control': 'no-store' })
  if (chosen.length === 1) {
    res.set({
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${names[chosen[0]]}-${day}.csv"`,
    })
    res.send(csvFor(chosen[0], lang))
    return
  }

  const zip = createZip(chosen.map((d) => ({ name: `${names[d]}.csv`, data: csvFor(d, lang) })))
  res.set({
    'Content-Type': 'application/zip',
    'Content-Disposition': `attachment; filename="${names.backup}-${day}.zip"`,
  })
  res.send(zip)
})
