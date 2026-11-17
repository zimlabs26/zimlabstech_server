import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { db } from '../db.js'
import { requireAdmin, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'

/**
 * Precios y promociones de la web.
 *  - Lista de precios: cada producto tiene un precio por defecto (el de la web) que se puede cambiar desde el CRM.
 *  - Promociones: un descuento en porcentaje sobre los productos elegidos, con fechas opcionales y un interruptor.
 *    La web muestra el precio de lista tachado y el precio con descuento (si varias promociones afectan al mismo
 *    producto gana la de mayor porcentaje: no se acumulan).
 * Importes en centavos de ARS.
 */

export const PRODUCTS = ['landing', 'page', 'crmb', 'crmf', 'store', 'app', 'maint_store', 'maint_crm'] as const
export type Product = (typeof PRODUCTS)[number]

/** Precios de lista por defecto: los mismos que trae la web si nadie los cambia desde el CRM. */
export const DEFAULT_PRICE: Record<Product, number> = {
  landing: 51_243_000,
  page: 69_658_200,
  crmb: 92_478_000,
  crmf: 123_460_000,
  store: 82_315_000,
  app: 71_865_000,
  maint_store: 9_568_200,
  maint_crm: 12_398_300,
}

interface PromoRow {
  id: number
  name: string
  percent: number
  products: string
  starts_on: string | null
  ends_on: string | null
  active: 0 | 1
}

const toPromo = (r: PromoRow) => ({
  id: r.id,
  name: r.name,
  percent: r.percent,
  products: JSON.parse(r.products) as Product[],
  startsOn: r.starts_on,
  endsOn: r.ends_on,
  active: r.active === 1,
})

/** Hoy en Argentina (UTC-3, sin horario de verano) como AAAA-MM-DD: una promocion "hasta el 31" dura todo el 31. */
const todayAr = () => new Date(Date.now() - 3 * 3600_000).toISOString().slice(0, 10)

const basePrices = (): Record<Product, number> => {
  const out = { ...DEFAULT_PRICE }
  for (const r of db.prepare('SELECT product, amount FROM price_overrides').all() as { product: Product; amount: number }[]) {
    if (r.product in out) out[r.product] = r.amount
  }
  return out
}

/** Precio de lista y precio final de cada producto, con la promocion vigente (si hay). */
export function effectivePrices() {
  const base = basePrices()
  const today = todayAr()
  const promos = (db.prepare('SELECT * FROM promotions WHERE active = 1').all() as unknown as PromoRow[])
    .map(toPromo)
    .filter((p) => (!p.startsOn || p.startsOn <= today) && (!p.endsOn || today <= p.endsOn))

  const out = {} as Record<Product, { base: number; final: number; percent?: number; promo?: string; endsOn?: string | null }>
  for (const product of PRODUCTS) {
    const best = promos.filter((p) => p.products.includes(product)).sort((a, b) => b.percent - a.percent)[0]
    // El precio final se redondea a pesos enteros.
    const final = best ? Math.round((base[product] * (100 - best.percent)) / 10_000) * 100 : base[product]
    out[product] = best ? { base: base[product], final, percent: best.percent, promo: best.name, endsOn: best.endsOn } : { base: base[product], final: base[product] }
  }
  return out
}

/* ---------- Publico: lo que muestra la web ---------- */

export const pricingRouter = Router()

pricingRouter.get('/', (_req, res) => {
  // Un minuto de cache: los cambios del CRM se ven casi al instante y la web no pega al servidor en cada visita.
  res.set('Cache-Control', 'public, max-age=60')
  res.json({ prices: effectivePrices() })
})

/* ---------- Administracion (CRM) ---------- */

export const promotionsRouter = Router()
promotionsRouter.use(requireAdmin)

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 240 })
const date = z.string().regex(/^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/)
const idParam = z.coerce.number().int().positive()

const promoSchema = z
  .object({
    name: z.string().trim().min(1).max(80),
    percent: z.number().int().min(1).max(90),
    products: z.array(z.enum(PRODUCTS)).min(1).max(PRODUCTS.length),
    startsOn: date.nullable().optional(),
    endsOn: date.nullable().optional(),
    active: z.boolean().default(true),
  })
  .refine((p) => !p.startsOn || !p.endsOn || p.endsOn >= p.startsOn, { path: ['endsOn'] })

const bad = (res: import('express').Response, issues: z.ZodIssue[]) =>
  res.status(400).json({ error: 'invalid_input', field: String(issues[0]?.path[0] ?? 'name') })

function snapshot() {
  const base = basePrices()
  const custom = new Set((db.prepare('SELECT product FROM price_overrides').all() as { product: string }[]).map((r) => r.product))
  return {
    products: PRODUCTS.map((product) => ({ product, amount: base[product], defaultAmount: DEFAULT_PRICE[product], custom: custom.has(product) })),
    promotions: (db.prepare('SELECT * FROM promotions ORDER BY active DESC, id DESC LIMIT 200').all() as unknown as PromoRow[]).map(toPromo),
    effective: effectivePrices(),
  }
}

promotionsRouter.get('/', (_req, res) => {
  res.json(snapshot())
})

/** Cambia precios de lista. `null` = volver al precio por defecto de la web. */
promotionsRouter.put('/prices', sameOrigin, limiter, (req, res) => {
  const parsed = z
    .object({ prices: z.record(z.enum(PRODUCTS), z.number().int().min(100).max(100_000_000_00).nullable()) })
    .safeParse(req.body)
  if (!parsed.success) return bad(res, parsed.error.issues)
  db.transaction(() => {
    for (const [product, amount] of Object.entries(parsed.data.prices)) {
      if (amount === null || amount === DEFAULT_PRICE[product as Product]) {
        db.prepare('DELETE FROM price_overrides WHERE product = ?').run(product)
      } else {
        db.prepare(
          "INSERT INTO price_overrides (product, amount) VALUES (?, ?) ON CONFLICT(product) DO UPDATE SET amount = excluded.amount, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        ).run(product, amount)
      }
    }
  })()
  res.json(snapshot())
})

promotionsRouter.post('/', sameOrigin, limiter, (req, res) => {
  const parsed = promoSchema.safeParse(req.body)
  if (!parsed.success) return bad(res, parsed.error.issues)
  const p = parsed.data
  const user = res.locals.user as SessionUser
  db.prepare('INSERT INTO promotions (name, percent, products, starts_on, ends_on, active, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    p.name,
    p.percent,
    JSON.stringify([...new Set(p.products)]),
    p.startsOn ?? null,
    p.endsOn ?? null,
    p.active ? 1 : 0,
    user.id,
  )
  res.status(201).json(snapshot())
})

promotionsRouter.put('/:id', sameOrigin, limiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  const parsed = promoSchema.safeParse(req.body)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!parsed.success) return bad(res, parsed.error.issues)
  const p = parsed.data
  const result = db
    .prepare('UPDATE promotions SET name = ?, percent = ?, products = ?, starts_on = ?, ends_on = ?, active = ? WHERE id = ?')
    .run(p.name, p.percent, JSON.stringify([...new Set(p.products)]), p.startsOn ?? null, p.endsOn ?? null, p.active ? 1 : 0, id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.json(snapshot())
})

promotionsRouter.delete('/:id', sameOrigin, limiter, (req, res) => {
  const id = idParam.safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const result = db.prepare('DELETE FROM promotions WHERE id = ?').run(id.data)
  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  res.json(snapshot())
})
