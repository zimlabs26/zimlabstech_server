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

/* ---------- Activar: crea la suscripcion y devuelve el link para el cliente ---------- */

subscriptionsRouter.post('/', sameOrigin, limiter, async (req, res) => {
  // Promocion opcional: `percent`% de descuento los primeros `promoMonths` cobros, valor normal despues y baja a los `termMonths`.
  const promoSchema = z
    .object({
      percent: z.number().int().min(1).max(90),
      promoMonths: z.number().int().min(1).max(120),
      termMonths: z.number().int().min(2).max(120),
    })
    .refine((p) => p.promoMonths < p.termMonths)
  const body = z.object({ clientId, promo: promoSchema.optional() }).safeParse(req.body)
  if (!body.success) {
    const field = body.error.issues[0]?.path[0] === 'promo' ? 'promo' : undefined
    res.status(400).json({ error: 'invalid_input', ...(field ? { field } : {}) })
    return
  }
  const promo = body.data.promo
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
  if (!client.maintenance_plan || !client.maintenance_price || client.maintenance_price <= 0) {
    res.status(400).json({ error: 'invalid_input', field: 'price' })
    return
  }
  if (client.maintenance_currency !== 'ARS') {
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
  const fullCents = client.maintenance_price
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
    db.prepare(
      `INSERT INTO subscriptions (client_id, mp_id, status, amount, init_point, created_by, full_amount, promo_percent, promo_months, term_months)
       VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      client.id, pre.id, firstCents, pre.init_point, user.id,
      promo ? fullCents : null, promo?.percent ?? null, promo?.promoMonths ?? null, promo?.termMonths ?? null,
    )

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
