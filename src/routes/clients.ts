import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { discounted, liveSubscription, toDebit } from '../billing.js'
import { clientSearchText, db, normalizeText } from '../db.js'
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
const categoryFor = (plan: Plan | null): Category => (plan ? categoryOfPlan[plan] : 'bronze')

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
  created_at: string
}

const columns =
  'id, name, email, phone, company, notes, category, maintenance_plan, maintenance_price, maintenance_currency, prospect, created_at'

const toClient = (r: ClientRow) => {
  const sub = liveSubscription(r.id)
  return {
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

  res.json({
    clients: page.map(toClient),
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
})

clientsRouter.post('/', sameOrigin, rateLimit({ windowMs: 15 * 60 * 1000, max: 120 }), (req, res) => {
  const parsed = clientSchema.safeParse(req.body)
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? 'name')
    res.status(400).json({ error: 'invalid_input', field })
    return
  }

  const user = res.locals.user as SessionUser
  const c = parsed.data
  const result = db
    .prepare(
      'INSERT INTO clients (name, email, phone, company, notes, maintenance_plan, maintenance_price, maintenance_currency, category, search_text, created_by, prospect) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      c.name, c.email, c.phone, c.company, c.notes, c.plan, c.plan ? c.price : null, c.currency,
      categoryFor(c.plan), clientSearchText(c), user.id, c.prospect ? 1 : 0,
    )

  const row = db
    .prepare(`SELECT ${columns} FROM clients WHERE id = ?`)
    .get(Number(result.lastInsertRowid)) as ClientRow

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
  const newPrice = c.plan ? c.price : null

  /* Con debito automatico vigente, el precio del mantenimiento es el monto que Mercado Pago cobra cada mes.
     Si cambia (por ejemplo un aumento), se actualiza PRIMERO en Mercado Pago: si eso falla no se toca nada aca,
     asi el CRM y Mercado Pago nunca quedan con montos distintos. */
  const sub = liveSubscription(id.data)
  /** Lo que se cobra hoy por un precio normal dado: con la promocion vigente lleva su descuento. */
  const chargeNow = (price: number) => (sub?.promo_percent && !sub.promo_ended ? discounted(price, sub.promo_percent) : price)
  let debitAmountChanged = false
  if (sub) {
    // El debito cobra un importe fijo en pesos: no se puede quitar el precio ni pasarlo a dolares mientras exista.
    if (!newPrice || newPrice <= 0 || c.currency !== 'ARS') {
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
        'UPDATE clients SET name = ?, email = ?, phone = ?, company = ?, notes = ?, maintenance_plan = ?, maintenance_price = ?, maintenance_currency = ?, category = ?, search_text = ?, prospect = ? WHERE id = ?',
      )
      .run(
        c.name, c.email, c.phone, c.company, c.notes, c.plan, newPrice, c.currency,
        categoryFor(c.plan), clientSearchText(c), c.prospect ? 1 : 0, id.data,
      )
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
  emit('forms', { exceptCid: res.locals.cid })
  res.status(204).end()
})
