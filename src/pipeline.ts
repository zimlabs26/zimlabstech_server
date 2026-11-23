import { db } from './db.js'

/**
 * Pipeline comercial: en que estado esta cada cliente y cuanta plata hay en cada estado, para compararla con el
 * objetivo anual. Importes en centavos.
 *
 * Estados (del mas avanzado al menos):
 *  - client:   al menos un servicio contratado.
 *  - proposal: hay una propuesta enviada y todavia nada contratado.
 *  - prospect: posible cliente (pidio cotizacion o todavia no se le envio propuesta).
 *  - rejected: todos sus servicios fueron rechazados.
 * Un cliente cuenta UNA vez, en su estado mas avanzado. La plata, en cambio, se cuenta por servicio (cada servicio
 * pesa en el estado que tiene), asi un cliente con un servicio contratado y otro en propuesta suma en los dos.
 */

export const PIPELINE_STATES = ['client', 'proposal', 'prospect', 'rejected'] as const
export type PipelineState = (typeof PIPELINE_STATES)[number]

const rank: Record<PipelineState, number> = { client: 3, proposal: 2, prospect: 1, rejected: 0 }

export interface Pipeline {
  /** Clientes por estado. */
  counts: Record<PipelineState, number>
  /** Valor anual de los servicios por estado, en pesos. */
  value: Record<PipelineState, number>
  /** Lo mismo para servicios cotizados en dolares (no se mezcla con pesos): solo para avisar que existen. */
  valueUsd: Record<PipelineState, number>
}

interface ServiceRow {
  client_id: number
  prospect: number
  product: string | null
  status: PipelineState | null
  price: number | null
  currency: 'ARS' | 'USD' | null
  discount_percent: number | null
  discount_months: number | null
}

const zero = (): Record<PipelineState, number> => ({ client: 0, proposal: 0, prospect: 0, rejected: 0 })

/**
 * Valor de un servicio en un ano. Un proyecto es un pago unico. Un mantenimiento es mensual: se multiplica por 12 y, si
 * tiene descuento, los primeros `discount_months` meses (o todo el ano si no tiene fin) se cobran con el descuento.
 */
export function annualValue(s: { product: string; price: number; discount_percent: number; discount_months: number | null }): number {
  if (!s.product.startsWith('maint_')) return s.price
  const months = s.discount_months === null ? 12 : Math.min(12, s.discount_months)
  const discounted = Math.round((s.price * (100 - s.discount_percent)) / 100)
  return discounted * months + s.price * (12 - months)
}

export function getPipeline(): Pipeline {
  const rows = db
    .prepare(
      `SELECT c.id AS client_id, c.prospect, s.product, s.status, s.price, s.currency, s.discount_percent, s.discount_months
       FROM clients c LEFT JOIN client_services s ON s.client_id = c.id`,
    )
    .all() as unknown as ServiceRow[]

  const counts = zero()
  const value = zero()
  const valueUsd = zero()
  const stateOf = new Map<number, PipelineState>()

  for (const r of rows) {
    // Cliente sin servicios cargados: vale lo que dice su ficha (posible cliente o cliente).
    const own: PipelineState = r.status ?? (r.prospect === 1 ? 'prospect' : 'client')
    const current = stateOf.get(r.client_id)
    if (!current || rank[own] > rank[current]) stateOf.set(r.client_id, own)

    if (r.status && r.product && r.price !== null) {
      const annual = annualValue({ product: r.product, price: r.price, discount_percent: r.discount_percent ?? 0, discount_months: r.discount_months })
      if (r.currency === 'USD') valueUsd[r.status] += annual
      else value[r.status] += annual
    }
  }
  for (const state of stateOf.values()) counts[state]++
  return { counts, value, valueUsd }
}

/* ---------- Objetivo anual ---------- */

const goalKey = (year: number) => `annual_goal:${year}`

/** Objetivo anual de un ano en centavos de ARS (0 = todavia no se cargo). */
export function getGoal(year: number): number {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(goalKey(year)) as { value: string } | undefined
  const n = row ? Number(row.value) : 0
  return Number.isFinite(n) && n > 0 ? n : 0
}

export function setGoal(year: number, amount: number): void {
  if (amount <= 0) {
    db.prepare('DELETE FROM app_settings WHERE key = ?').run(goalKey(year))
    return
  }
  db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(goalKey(year), String(amount))
}

/* ---------- Ajustes de ingresos ---------- */

/** Lo que hay que restar a los ingresos de cada mes (AAAA-MM), en centavos. */
export function adjustmentsByMonth(): Record<string, number> {
  const out: Record<string, number> = {}
  for (const r of db.prepare('SELECT month, SUM(amount) AS total FROM income_adjustments GROUP BY month').all() as { month: string; total: number }[]) {
    out[r.month] = r.total
  }
  return out
}
