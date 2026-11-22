import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { discounted, liveSubscription, toDebit } from '../billing.js'
import { clientCode, clientSearchText, db, fillClientCodes, normalizeText } from '../db.js'
import { captureError } from '../errorlog.js'
import { mpEnabled, updatePreapprovalAmount } from '../mercadopago.js'
import { requireUser, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

export const clientsRouter = Router()

// Cualquier usuario con sesion puede ver y crear clientes.
clientsRouter.use(requireUser)

const categories = ['bronze', 'silver', 'gold', 'diamond'] as const
type Category = (typeof categories)[number]

// Planes de mantenimiento (los mismos de la web) y la categoria que le corresponde a cada uno.
// Sin plan, el cliente queda en bronce. La categoria NUNCA llega desde el cliente HTTP: siempre se calcula aca.
const plans = ['static', 'server', 'crmb', 'crmf'] as const
type Plan = (typeof plans)[number]
const categoryOfPlan: Record<Plan, Category> = { static: 'bronze', server: 'silver', crmb: 'gold', crmf: 'diamond' }
export const categoryFor = (plan: Plan | null): Category => (plan ? categoryOfPlan[plan] : 'bronze')

interface ClientRow {
  id: number
  name: string
  email: string | null
  phone: string | null
  company: string | null
  notes: string | null
  category: Category
  maintenance_plan: Plan | null
  maintenance_price: number | null
  maintenance_currency: 'ARS' | 'USD'
  prospect: 0 | 1
  country: string | null
  tax_id: string | null
  code: string | null
  created_at: string
}

const columns =
  'id, name, email, phone, company, notes, category, maintenance_plan, maintenance_price, maintenance_currency, prospect, country, tax_id, code, created_at'

/** Paises que se pueden elegir: Latinoamerica y Estados Unidos (codigo ISO de 2 letras). */
const countries = ['AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC', 'SV', 'GT', 'HT', 'HN', 'MX', 'NI', 'PA', 'PY', 'PE', 'PR', 'UY', 'VE', 'US'] as const

/** Lo que se le vende a un cliente: los proyectos y los mantenimientos de la tabla de precios. */
const serviceProducts = ['landing', 'page', 'crmb', 'crmf', 'store', 'app', 'maint_page', 'maint_store', 'maint_crmb', 'maint_crm'] as const
type ServiceProduct = (typeof serviceProducts)[number]
/** Estado de cada servicio: posible cliente, propuesta enviada, cliente o rechazado. */
const serviceStatuses = ['prospect', 'proposal', 'client', 'rejected'] as const

/** Mantenimiento contratado -> plan del cliente (de ahi salen su categoria y el precio del debito automatico). */
export const planOfService: Partial<Record<ServiceProduct, Plan>> = { maint_page: 'static', maint_store: 'server', maint_crmb: 'crmb', maint_crm: 'crmf' }
export const planRank: Record<Plan, number> = { static: 1, server: 2, crmb: 3, crmf: 4 }

interface ServiceRow {
  client_id: number
  product: ServiceProduct
  status: (typeof serviceStatuses)[number]
  price: number
  currency: 'ARS' | 'USD'
  discount_percent: number
  discount_months: number | null
}

const toService = (s: ServiceRow) => ({
  product: s.product,
  status: s.status,
  /** Precio de lista (centavos). */
  price: s.price,
  currency: s.currency,
  discountPercent: s.discount_percent,
  /** Meses que dura el descuento (null = todo el periodo). */
  discountMonths: s.discount_months,
  /** Precio con el descuento aplicado, en centavos. */
  finalPrice: s.discount_percent ? discounted(s.price, s.discount_percent) : s.price,
})

/** Servicios de varios clientes en una sola consulta. */
function servicesByClient(ids: number[]): Map<number, ReturnType<typeof toService>[]> {
  const out = new Map<number, ReturnType<typeof toService>[]>()
  if (!ids.length) return out
  const rows = db
    .prepare(
      `SELECT client_id, product, status, price, currency, discount_percent, discount_months FROM client_services
       WHERE client_id IN (${ids.map(() => '?').join(',')}) ORDER BY id`,
    )
    .all(...ids) as unknown as ServiceRow[]
  for (const r of rows) out.set(r.client_id, [...(out.get(r.client_id) ?? []), toService(r)])
  return out
}

const toClient = (r: ClientRow, services = servicesByClient([r.id]).get(r.id) ?? []) => {
  const sub = liveSubscription(r.id)
  return {
  /** Codigo de cliente: 3 letras de la empresa y el numero (PAN0007). */
  code: r.code,
  country: r.country,
  /** CUIL/CUIT (solo Argentina), como XX-XXXXXXXX-X. */
  taxId: r.tax_id,
  services,
  /** Debito automatico vigente (null = no tiene). `link` solo mientras espera que el cliente ingrese su tarjeta. */
  debit: sub ? toDebit(sub) : null,
  id: r.id,
  name: r.name,
  email: r.email,
  phone: r.phone,
  company: r.company,
  notes: r.notes,
  category: r.category,
  plan: r.maintenance_plan,
  /** Costo cotizado en centavos (null = sin cotizar). */
  price: r.maintenance_price,
  currency: r.maintenance_currency,
  /** Posible cliente: pidio una cotizacion pero todavia no es cliente. */
  prospect: r.prospect === 1,
  createdAt: r.created_at,
  }
}

/* ---------- Listar: paginado, con busqueda y filtro en el servidor ---------- */

const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(20),
  // Paginacion por cursor: "los que tengan id menor a este". No se salta ni repite filas aunque se creen nuevas.
  cursor: z.coerce.number().int().positive().optional(),
  q: z.string().trim().max(100).optional(),
  category: z.enum(categories).optional(),
  /** Solo clientes o solo posibles clientes (sin esto, todos). */
  kind: z.enum(['client', 'prospect']).optional(),
})

/** Escapa % _ \ para que lo que escribe el usuario se busque literal dentro de LIKE. */
const escapeLike = (term: string) => term.replace(/[\\%_]/g, '\\$&')

clientsRouter.get('/', (req, res) => {
  const parsed = listSchema.safeParse(req.query)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const { limit, cursor, q, category, kind } = parsed.data

  // Cada palabra debe aparecer (en cualquier orden y en cualquier campo). Maximo 8 palabras.
  const terms = normalizeText(q ?? '')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 8)
  const searchSql = terms.map(() => `search_text LIKE ? ESCAPE '\\'`).join(' AND ')
  const searchParams = terms.map((t) => `%${escapeLike(t)}%`)

  const whereQuery = searchSql ? `WHERE ${searchSql}` : ''

  // Contadores por tipo (cliente / posible cliente): respetan la busqueda pero NO el tipo elegido.
  const kindRows = db
    .prepare(`SELECT prospect, COUNT(*) AS n FROM clients ${whereQuery} GROUP BY prospect`)
    .all(...searchParams) as { prospect: 0 | 1; n: number }[]
  const kinds = { all: 0, client: 0, prospect: 0 }
  for (const g of kindRows) {
    kinds[g.prospect === 1 ? 'prospect' : 'client'] = g.n
    kinds.all += g.n
  }

  // Busqueda + tipo (constantes, no vienen de afuera): la base de los contadores por categoria y de la lista.
  const baseConditions = [...(searchSql ? [searchSql] : []), ...(kind ? [`prospect = ${kind === 'prospect' ? 1 : 0}`] : [])]
  const baseWhere = baseConditions.length ? `WHERE ${baseConditions.join(' AND ')}` : ''

  // Contadores por categoria: respetan la busqueda y el tipo pero NO el filtro de categoria (asi los chips siempre informan).
  const grouped = db
    .prepare(`SELECT category, COUNT(*) AS n FROM clients ${baseWhere} GROUP BY category`)
    .all(...searchParams) as { category: Category; n: number }[]
  const counts = { all: 0, bronze: 0, silver: 0, gold: 0, diamond: 0 }
  for (const g of grouped) {
    counts[g.category] = g.n
    counts.all += g.n
  }
  const total = category ? counts[category] : counts.all

  // Pagina: se piden limit + 1 filas; si llega la extra, hay mas.
  const conditions = [...baseConditions, ...(category ? ['category = ?'] : []), ...(cursor ? ['id < ?'] : [])]
  const params: unknown[] = [...searchParams, ...(category ? [category] : []), ...(cursor ? [cursor] : [])]

  const rows = db
    .prepare(
      `SELECT ${columns} FROM clients ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`,
    )
    .all(...params, limit + 1) as ClientRow[]

  const hasMore = rows.length > limit
  const page = hasMore ? rows.slice(0, limit) : rows

  const servicesOf = servicesByClient(page.map((r) => r.id))
  res.json({
    clients: page.map((r) => toClient(r, servicesOf.get(r.id) ?? [])),
    nextCursor: hasMore ? page[page.length - 1].id : null,
    total,
    counts,
    kinds,
  })
})

/* ---------- Crear ---------- */

// Texto opcional: vacio = sin dato (NULL).
const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .optional()
    .transform((v) => (v ? v : null))

const clientSchema = z.object({
  name: z.string().trim().min(1).max(120),
  company: optionalText(120),
  email: z
    .string()
    .trim()
    .toLowerCase()
    .max(254)
    .optional()
    .transform((v) => (v ? v : null))
    .pipe(z.string().email().nullable()),
  phone: optionalText(40),
  notes: optionalText(2000),
  plan: z.enum(plans).nullish().transform((v) => v ?? null),
  // Centavos enteros. Sin plan no hay costo que guardar.
  price: z.number().int().min(0).max(100_000_000_00).nullish().transform((v) => v ?? null),
  currency: z.enum(['ARS', 'USD']).default('ARS'),
  /** Posible cliente (todavia no es cliente). El equipo lo marca o lo desmarca (por ejemplo al convertirlo en cliente). */
  prospect: z.boolean().default(false),
  country: z.enum(countries).nullish().transform((v) => v ?? null),
  /** CUIL/CUIT: opcional y solo para Argentina (con otro pais se ignora). */
  taxId: z.string().trim().max(20).nullish().transform((v) => v || null),
  /**
   * Servicios del cliente con su estado, precio y descuento. Si llegan, de ahi se calculan el plan de mantenimiento, su
   * precio y si es un posible cliente (ver `derive`); si no llegan (importacion de CSV), valen los campos de arriba.
   */
  services: z
    .array(
      z.object({
        product: z.enum(serviceProducts),
        status: z.enum(serviceStatuses),
        /** Precio de lista, en centavos (el que figura en la tabla de precios). */
        price: z.number().int().min(0).max(100_000_000_00),
        currency: z.enum(['ARS', 'USD']).default('ARS'),
        discountPercent: z.number().int().min(0).max(90).default(0),
        /** Meses que dura el descuento; vacio = todo el periodo. */
        discountMonths: z.number().int().min(1).max(120).nullish().transform((v) => v ?? null),
      }),
    )
    .max(10)
    .optional(),
}).superRefine((c, ctx) => {
  if (c.services && new Set(c.services.map((s) => s.product)).size !== c.services.length) {
    ctx.addIssue({ code: 'custom', path: ['services'], message: 'duplicated_service' })
  }
  if (c.country === 'AR' && c.taxId && !normalizeCuil(c.taxId)) {
    ctx.addIssue({ code: 'custom', path: ['taxId'], message: 'invalid_cuil' })
  }
})

/** CUIL/CUIT con 11 digitos y un prefijo valido; devuelve XX-XXXXXXXX-X, o null si no lo es. */
function normalizeCuil(raw: string): string | null {
  const d = raw.replace(/\D/g, '')
  if (d.length !== 11 || !['20', '23', '24', '25', '26', '27', '30', '33', '34'].includes(d.slice(0, 2))) return null
  return `${d.slice(0, 2)}-${d.slice(2, 10)}-${d.slice(10)}`
}

/**
 * Lo que de los servicios sale para la ficha del cliente: el plan de mantenimiento contratado (el mas alto si hay mas de
 * uno), su precio de lista y si el cliente sigue siendo un posible cliente (ninguno de sus servicios esta en "cliente").
 * Sin servicios (importacion de CSV) valen los campos viejos tal cual llegan.
 */
function derive(c: z.infer<typeof clientSchema>): { plan: Plan | null; price: number | null; currency: 'ARS' | 'USD'; prospect: boolean } {
  if (!c.services) return { plan: c.plan, price: c.plan ? c.price : null, currency: c.currency, prospect: c.prospect }
  let plan: Plan | null = null
  let price: number | null = null
  let currency: 'ARS' | 'USD' = 'ARS'
  for (const s of c.services) {
    const p = s.status === 'client' ? planOfService[s.product] : undefined
    if (p && (!plan || planRank[p] > planRank[plan])) {
      plan = p
      price = s.price
      currency = s.currency
    }
  }
  return { plan, price, currency, prospect: !c.services.some((s) => s.status === 'client') }
}

/** Reemplaza los servicios del cliente por los que llegan. Va dentro de la transaccion que guarda al cliente. */
function saveServices(clientId: number, services: NonNullable<z.infer<typeof clientSchema>['services']>): void {
  db.prepare('DELETE FROM client_services WHERE client_id = ?').run(clientId)
  const insert = db.prepare(
    'INSERT INTO client_services (client_id, product, status, price, currency, discount_percent, discount_months) VALUES (?, ?, ?, ?, ?, ?, ?)',
  )
  for (const s of services) {
    // Solo los mantenimientos (que se cobran todos los meses) llevan descuento; un proyecto se vende a su precio de lista.
    // Todos los servicios pueden llevar descuento; los meses solo tienen sentido en los mantenimientos (se cobran todos los meses).
    const percent = s.discountPercent
    insert.run(clientId, s.product, s.status, s.price, s.currency, percent, percent && s.product.startsWith('maint_') ? s.discountMonths : null)
  }
}

clientsRouter.post('/', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 120 }), (req, res) => {
  const parsed = clientSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'name')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  const user = res.locals.user as SessionUser
  const c = parsed.data
  const d = derive(c)
  const taxId = c.country === 'AR' && c.taxId ? normalizeCuil(c.taxId) : null
  const newId = db.transaction(() => {
    const result = db
      .prepare(
        'INSERT INTO clients (name, email, phone, company, notes, maintenance_plan, maintenance_price, maintenance_currency, category, search_text, created_by, prospect, country, tax_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        c.name, c.email, c.phone, c.company, c.notes, d.plan, d.price, d.currency,
        categoryFor(d.plan), clientSearchText(c), user.id, d.prospect ? 1 : 0, c.country, taxId,
      )
    const clientId = Number(result.lastInsertRowid)
    // El codigo lleva el numero de cliente, que recien se conoce al insertar; tambien se puede buscar por el.
    const code = clientCode(c.country, clientId)
    db.prepare('UPDATE clients SET code = ?, search_text = search_text || ? WHERE id = ?').run(code, ` ${code.toLowerCase()}`, clientId)
    if (c.services) saveServices(clientId, c.services)
    return clientId
  })()

  const row = db.prepare(`SELECT ${columns} FROM clients WHERE id = ?`).get(newId) as ClientRow

  emit('clients', { exceptCid: res.locals.cid })
  res.status(201).json({ client: toClient(row) })
})

/* ---------- Editar ---------- */

clientsRouter.put('/:id', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 240 }), async (req, res) => {
  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  const parsed = clientSchema.safeParse(req.body)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'name')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  const c = parsed.data
  const d = derive(c)
  const newPrice = d.plan ? d.price : null
  const taxId = c.country === 'AR' && c.taxId ? normalizeCuil(c.taxId) : null
  // El codigo es el del pais (3 letras) y el numero interno: si se cambia el pais, el codigo se corrige.
  const newCode = clientCode(c.country, id.data)

  /* Con debito automatico vigente, el precio del mantenimiento es el monto que Mercado Pago cobra cada mes.
     Si cambia (por ejemplo un aumento), se actualiza PRIMERO en Mercado Pago: si eso falla no se toca nada aca,
     asi el CRM y Mercado Pago nunca quedan con montos distintos. */
  const sub = liveSubscription(id.data)
  /** Lo que se cobra hoy por un precio normal dado: con la promocion vigente lleva su descuento. */
  const chargeNow = (price: number) => (sub?.promo_percent && !sub.promo_ended ? discounted(price, sub.promo_percent) : price)
  let debitAmountChanged = false
  if (sub) {
    // El debito cobra un importe fijo en pesos: no se puede quitar el precio ni pasarlo a dolares mientras exista.
    if (!newPrice || newPrice <= 0 || d.currency !== 'ARS') {
      res.status(409).json({ error: 'debit_price_locked' })
      return
    }
    // Con promocion, `amount` es lo que se cobra hoy (con descuento) y el precio del cliente es el valor normal.
    const listPrice = sub.full_amount ?? sub.amount
    if (newPrice !== listPrice) {
      if (!mpEnabled()) {
        res.status(503).json({ error: 'mp_disabled' })
        return
      }
      try {
        await updatePreapprovalAmount(sub.mp_id, chargeNow(newPrice) / 100)
      } catch (error) {
        captureError(error, { kind: 'mercadopago', message: 'No se pudo actualizar el monto de la suscripcion en Mercado Pago', path: req.path, method: req.method })
        res.status(502).json({ error: 'mp_error' })
        return
      }
      debitAmountChanged = true
    }
  }

  const result = db.transaction(() => {
    const updated = db
      .prepare(
        'UPDATE clients SET name = ?, email = ?, phone = ?, company = ?, notes = ?, maintenance_plan = ?, maintenance_price = ?, maintenance_currency = ?, category = ?, search_text = ?, prospect = ?, country = ?, tax_id = ?, code = ? WHERE id = ?',
      )
      .run(
        c.name, c.email, c.phone, c.company, c.notes, d.plan, newPrice, d.currency,
        categoryFor(d.plan), clientSearchText({ ...c, code: newCode }), d.prospect ? 1 : 0, c.country, taxId, newCode, id.data,
      )
    if (updated.changes > 0 && c.services) saveServices(id.data, c.services)
    if (debitAmountChanged && sub && newPrice) {
      const charge = chargeNow(newPrice)
      db.prepare('UPDATE subscriptions SET amount = ?, full_amount = CASE WHEN full_amount IS NULL THEN NULL ELSE ? END WHERE id = ?').run(
        charge,
        newPrice,
        sub.id,
      )
      // El proximo cobro (todavia pendiente) pasa al monto nuevo; lo ya cobrado queda como historial.
      db.prepare(`UPDATE payments SET amount = ? WHERE subscription_id = ? AND status = 'pending'`).run(charge, sub.id)
    }
    return updated
  })()

  if (result.changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  const row = db.prepare(`SELECT ${columns} FROM clients WHERE id = ?`).get(id.data) as ClientRow
  emit('clients', { exceptCid: res.locals.cid })
  if (debitAmountChanged) emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.json({ client: toClient(row), ...(debitAmountChanged ? { debitUpdated: true } : {}) })
})

/* ---------- Exportar a CSV (copia de seguridad / planillas) ---------- */

const csvHeaders = {
  es: ['Nombre', 'Empresa', 'Correo', 'Telefono', 'Plan', 'Categoria', 'Notas', 'Creado'],
  en: ['Name', 'Company', 'Email', 'Phone', 'Plan', 'Category', 'Notes', 'Created'],
} as const

/** Cada celda va entre comillas. Las que empiezan con = + - @ se neutralizan: Excel las ejecutaria como formulas. */
function csvCell(value: string | null): string {
  const text = value ?? ''
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
  return `"${safe.replace(/"/g, '""')}"`
}

clientsRouter.get('/export', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }), (req, res) => {
  // Llevarse todos los clientes es cosa de administradores.
  if ((res.locals.user as SessionUser).role !== 'admin') {
    res.status(403).json({ error: 'forbidden' })
    return
  }
  const lang = req.query.lang === 'en' ? 'en' : 'es'

  const rows = db
    .prepare(`SELECT ${columns} FROM clients ORDER BY id DESC LIMIT 50000`)
    .all() as ClientRow[]
  const lines = [
    csvHeaders[lang].map((h) => csvCell(h)).join(','),
    ...rows.map((r) =>
      [r.name, r.company, r.email, r.phone, r.maintenance_plan, r.category, r.notes, r.created_at]
        .map((v) => csvCell(v))
        .join(','),
    ),
  ]

  const day = new Date().toISOString().slice(0, 10)
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="clients-${day}.csv"`,
    'Cache-Control': 'no-store',
  })
  // BOM al inicio: Excel reconoce las tildes (UTF-8).
  res.send(`﻿${lines.join('\r\n')}\r\n`)
})

/* ---------- Importar desde un CSV: vista previa y confirmacion ---------- */

const importSchema = z.object({ rows: z.array(z.unknown()).min(1).max(500), dryRun: z.boolean().default(true) })

// La web lee el CSV y manda las filas ya armadas. Con dryRun solo cuenta (vista previa); sin dryRun inserta todo junto.
// Cada fila pasa por las MISMAS reglas que un cliente creado a mano. Los repetidos (mismo correo, o mismo nombre y
// empresa si no hay correo) se omiten, tanto los que ya existen como los repetidos dentro del archivo.
clientsRouter.post('/import', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }), (req, res) => {
  const user = res.locals.user as SessionUser
  if (user.role !== 'admin') {
    res.status(403).json({ error: 'forbidden' })
    return
  }
  const body = importSchema.safeParse(req.body)
  if (!body.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  const byEmail = db.prepare('SELECT 1 FROM clients WHERE lower(email) = ?')
  const byName = db.prepare(`SELECT 1 FROM clients WHERE lower(name) = ? AND lower(coalesce(company, '')) = ?`)
  const seen = new Set<string>()
  const valid: z.infer<typeof clientSchema>[] = []
  const invalid: { row: number; field: string }[] = []
  let duplicates = 0

  body.data.rows.forEach((raw, index) => {
    const parsed = clientSchema.safeParse(raw)
    if (!parsed.success) {
      invalid.push({ row: index + 1, field: String(parsed.error.issues[0]?.path[0] ?? 'name') })
      return
    }
    const c = parsed.data
    const key = c.email ?? `${normalizeText(c.name)}|${normalizeText(c.company ?? '')}`
    const exists = c.email ? byEmail.get(c.email) : byName.get(c.name.toLowerCase(), (c.company ?? '').toLowerCase())
    if (seen.has(key) || exists) {
      duplicates++
      return
    }
    seen.add(key)
    valid.push(c)
  })

  if (!body.data.dryRun && valid.length > 0) {
    const insert = db.prepare(
      'INSERT INTO clients (name, email, phone, company, notes, maintenance_plan, maintenance_price, maintenance_currency, category, search_text, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    db.transaction(() => {
      for (const c of valid) {
        insert.run(c.name, c.email, c.phone, c.company, c.notes, c.plan, c.plan ? c.price : null, c.currency, categoryFor(c.plan), clientSearchText(c), user.id)
      }
    })()
    fillClientCodes() // los importados tambien reciben su codigo
    // Sin exceptCid: la pestana que importo tampoco sabe que cambio la lista, asi que tambien se entera.
    emit('clients')
  }

  res.json({
    dryRun: body.data.dryRun,
    total: body.data.rows.length,
    valid: valid.length,
    duplicates,
    invalidCount: invalid.length,
    invalid: invalid.slice(0, 20),
  })
})

/* ---------- Eliminar ---------- */

// Cualquier usuario del CRM (todos son administradores) puede eliminar clientes, igual que crearlos o editarlos.
// Se borra todo lo del cliente en cascada: sus pagos (el historial), sus tareas, sus formularios y sus suscripciones.
// Unica condicion: con debito automatico vigente primero hay que cancelarlo (si no, Mercado Pago seguiria cobrando).
clientsRouter.delete('/:id', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 120 }), (req, res) => {
  const id = z.coerce.number().int().positive().safeParse(req.params.id)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }

  if (liveSubscription(id.data)) {
    res.status(409).json({ error: 'client_has_subscription' })
    return
  }

  // payments y tasks apuntan al cliente con ON DELETE RESTRICT: se borran primero. subscriptions y forms caen solas.
  const changes = db.transaction(() => {
    db.prepare('DELETE FROM payments WHERE client_id = ?').run(id.data)
    db.prepare('DELETE FROM tasks WHERE client_id = ?').run(id.data)
    return db.prepare('DELETE FROM clients WHERE id = ?').run(id.data).changes
  })()
  if (changes === 0) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  emit('clients', { exceptCid: res.locals.cid })
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  emit('tasks', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
