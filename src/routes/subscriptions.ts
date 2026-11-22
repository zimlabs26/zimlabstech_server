import { Router } from 'express'
import { z } from 'zod'
import type { SessionUser } from '../auth/sessions.js'
import { discounted, liveSubscription, toDebit, type SubscriptionRow } from '../billing.js'
import { db } from '../db.js'
import { captureError } from '../errorlog.js'
import { cancelPreapproval, createPreapproval, MpError, mpEnabled } from '../mercadopago.js'
import { requireAdmin, sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'
import { categoryFor, planOfService, planRank } from './clients.js'

export const subscriptionsRouter = Router()

// El debito automatico lo gestionan solo los administradores.
subscriptionsRouter.use(requireAdmin)

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 })
const clientId = z.coerce.number().int().positive()

interface ClientRow {
  id: number
  name: string
  email: string | null
  maintenance_plan: string | null
  maintenance_price: number | null
  maintenance_currency: 'ARS' | 'USD'
}

/** Mantenimiento del que sale el importe del debito: el cliente (o el que esta por serlo) con el plan mas alto. */
interface MaintenanceService {
  product: string
  status: string
  price: number
  currency: 'ARS' | 'USD'
}

/**
 * El mantenimiento que se cobra por debito automatico. Sale de los SERVICIOS del cliente (un servicio recien agregado
 * queda como "posible cliente" o "propuesta" y igual se puede activar). Prefiere el que ya es "cliente" y, entre
 * varios, el de plan mas alto. Los rechazados no cuentan.
 */
function maintenanceOf(clientId: number): MaintenanceService | undefined {
  const rows = db
    .prepare(
      `SELECT product, status, price, currency FROM client_services
       WHERE client_id = ? AND product LIKE 'maint\\_%' ESCAPE '\\' AND status != 'rejected'`,
    )
    .all(clientId) as unknown as MaintenanceService[]
  const rank = (s: MaintenanceService) => (s.status === 'client' ? 10 : 0) + (planRank[planOfService[s.product as keyof typeof planOfService]!] ?? 0)
  return rows.sort((a, b) => rank(b) - rank(a))[0]
}

/* ---------- Activar: crea la suscripcion y devuelve el link para el cliente ---------- */

subscriptionsRouter.post('/', sameOrigin, limiter, async (req, res) => {
  // Promocion opcional: `percent`% de descuento los primeros `promoMonths` cobros, valor normal despues y baja a los
  // `termMonths`. Si los meses de descuento son todos los del periodo, el descuento dura todo el contrato.
  const promoSchema = z
    .object({
      percent: z.number().int().min(1).max(90),
      promoMonths: z.number().int().min(1).max(120),
      /** Solo lo manda la web vieja; la nueva manda `termMonths` aparte. */
      termMonths: z.number().int().min(2).max(120).optional(),
    })
  // `termMonths`: el periodo (contrato) en cobros; al cumplirse la suscripcion se da de baja. Sin el, no tiene fin.
  const body = z
    .object({ clientId, promo: promoSchema.optional(), termMonths: z.number().int().min(2).max(120).optional() })
    .refine((b) => {
      const term = b.termMonths ?? b.promo?.termMonths
      return !b.promo || !term || b.promo.promoMonths <= term
    }, { path: ['promo'] })
    .safeParse(req.body)
  if (!body.success) {
    const first = body.error.issues[0]?.path[0]
    const field = first === 'promo' || first === 'termMonths' ? 'promo' : undefined
    res.status(400).json({ error: 'invalid_input', ...(field ? { field } : {}) })
    return
  }
  const promo = body.data.promo
  const termMonths = body.data.termMonths ?? promo?.termMonths ?? null
  if (!mpEnabled()) {
    res.status(503).json({ error: 'mp_disabled' })
    return
  }

  const client = db
    .prepare('SELECT id, name, email, maintenance_plan, maintenance_price, maintenance_currency FROM clients WHERE id = ?')
    .get(body.data.clientId) as ClientRow | undefined
  if (!client) {
    res.status(404).json({ error: 'not_found' })
    return
  }
  // Mercado Pago necesita el correo del cliente y un importe en pesos. Se avisa cual campo falta.
  if (!client.email) {
    res.status(400).json({ error: 'invalid_input', field: 'email' })
    return
  }
  // El importe sale del servicio de mantenimiento; sin servicios cargados (clientes viejos) valen los campos del cliente.
  const service = maintenanceOf(client.id)
  const listCents = service ? service.price : client.maintenance_plan ? client.maintenance_price : null
  const currency = service ? service.currency : client.maintenance_currency
  if (!listCents || listCents <= 0) {
    res.status(400).json({ error: 'invalid_input', field: 'price' })
    return
  }
  if (currency !== 'ARS') {
    res.status(400).json({ error: 'invalid_input', field: 'currency' })
    return
  }

  const existing = liveSubscription(client.id)
  if (existing) {
    // Esperando la tarjeta: se reutiliza el mismo link. Ya activo (o pausado): no hay nada que crear.
    if (existing.status === 'pending' && existing.init_point) {
      res.json({ debit: toDebit(existing) })
      return
    }
    res.status(409).json({ error: 'already_active' })
    return
  }

  // Con promocion se cobra el importe con descuento y el valor normal queda guardado para cuando termine.
  const fullCents = listCents
  const firstCents = promo ? discounted(fullCents, promo.percent) : fullCents
  if (firstCents <= 0) {
    res.status(400).json({ error: 'invalid_input', field: 'promo' })
    return
  }

  try {
    const pre = await createPreapproval({
      reason: `Mantenimiento mensual - ${client.name}`.slice(0, 200),
      externalReference: `client-${client.id}`,
      payerEmail: client.email,
      amount: firstCents / 100,
    })
    if (!pre.init_point) throw new Error('Mercado Pago no devolvio el link de activacion')

    const user = res.locals.user as SessionUser
    db.transaction(() => {
      db.prepare(
        `INSERT INTO subscriptions (client_id, mp_id, status, amount, init_point, created_by, full_amount, promo_percent, promo_months, term_months)
         VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        client.id, pre.id, firstCents, pre.init_point, user.id,
        promo ? fullCents : null, promo?.percent ?? null, promo?.promoMonths ?? null, termMonths,
      )
      // Activar el debito es cerrar la venta del mantenimiento: el servicio pasa a "cliente" y la ficha toma su plan y precio
      // (asi despues se puede editar al cliente sin que el debito quede sin precio).
      const plan = service ? planOfService[service.product as keyof typeof planOfService] : undefined
      if (service && plan && service.status !== 'client') {
        db.prepare(`UPDATE client_services SET status = 'client' WHERE client_id = ? AND product = ?`).run(client.id, service.product)
        db.prepare(
          `UPDATE clients SET maintenance_plan = ?, maintenance_price = ?, maintenance_currency = ?, category = ?, prospect = 0 WHERE id = ?`,
        ).run(plan, service.price, service.currency, categoryFor(plan), client.id)
      }
    })()

    emit('clients', { exceptCid: res.locals.cid })
    const row = liveSubscription(client.id) as SubscriptionRow
    res.status(201).json({ debit: toDebit(row) })
  } catch (error) {
    // El detalle (por ejemplo "payer_email invalido") queda en el log; a la web solo llega un codigo.
    // Suele ser un dato del cliente (correo no valido): se registra pero no avisa por correo.
    captureError(error, { kind: 'mercadopago', message: 'No se pudo crear la suscripcion en Mercado Pago', path: req.path, method: req.method, alert: false })
    // Si el rechazo es por el comprador (correo invalido o de otro sitio / no es de prueba), se avisa que revise el correo.
    const reason = error instanceof MpError ? JSON.stringify(error.body) : ''
    const payerProblem = /payer|different site|test users/i.test(reason)
    // El motivo (mensaje de Mercado Pago o del error de red) va solo a administradores; nunca incluye credenciales.
    const body = error instanceof MpError ? (error.body as { message?: unknown } | null) : null
    const detail = String(
      error instanceof MpError ? (body?.message ?? `HTTP ${error.status}`) : error instanceof Error ? error.message : 'error',
    ).slice(0, 200)
    res.status(502).json({ error: 'mp_error', detail, ...(payerProblem ? { field: 'email' } : {}) })
  }
})

/* ---------- Cancelar ---------- */

subscriptionsRouter.delete('/:clientId', sameOrigin, limiter, async (req, res) => {
  const id = clientId.safeParse(req.params.clientId)
  if (!id.success) {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  const sub = liveSubscription(id.data)
  if (!sub) {
    res.status(404).json({ error: 'not_found' })
    return
  }

  // `?local=1`: la persona confirmo que ya la cancelo en Mercado Pago por su cuenta (ver mp_no_access abajo);
  // en ese caso solo se da de baja en el CRM, sin llamar a Mercado Pago.
  const localOnly = req.query.local === '1'

  if (!localOnly) {
    try {
      await cancelPreapproval(sub.mp_id)
    } catch (error) {
      if (error instanceof MpError && (error.status === 401 || error.status === 403)) {
        // El token no tiene acceso a esta suscripcion: la creo otra cuenta o aplicacion de Mercado Pago.
        // Se avisa con un codigo propio para que el CRM ofrezca marcarla como cancelada si ya se hizo a mano.
        captureError(error, { kind: 'mercadopago', message: 'El token de Mercado Pago no tiene acceso a la suscripcion', path: req.path, method: req.method })
        res.status(409).json({ error: 'mp_no_access' })
        return
      }
      // Si ya no existe en Mercado Pago igual se cancela aca; cualquier otro error se informa.
      if (!(error instanceof MpError && error.status === 404)) {
        captureError(error, { kind: 'mercadopago', message: 'No se pudo cancelar la suscripcion en Mercado Pago', path: req.path, method: req.method })
        res.status(502).json({ error: 'mp_error' })
        return
      }
    }
  }

  db.transaction(() => {
    db.prepare(`UPDATE subscriptions SET status = 'cancelled' WHERE id = ?`).run(sub.id)
    // Lo cobrado queda como historial; lo pendiente deja de ser deuda.
    db.prepare(`DELETE FROM payments WHERE subscription_id = ? AND status = 'pending'`).run(sub.id)
  })()

  emit('clients', { exceptCid: res.locals.cid })
  emit('payments', { adminsOnly: true, exceptCid: res.locals.cid })
  res.status(204).end()
})
