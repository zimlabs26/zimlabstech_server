import { db } from './db.js'
import { captureError } from './errorlog.js'
import {
  cancelPreapproval,
  getAuthorizedPayment,
  getPreapproval,
  listAuthorizedPayments,
  MpError,
  mpEnabled,
  updatePreapprovalAmount,
  type AuthorizedPayment,
} from './mercadopago.js'
import { emit } from './realtime.js'

/**
 * Logica del debito automatico: mantiene al dia las suscripciones y los pagos del CRM segun lo que informa Mercado Pago.
 * Nada de aca se llama desde la web: lo disparan el webhook, la conciliacion diaria y la creacion de la suscripcion.
 * Toda la informacion se vuelve a pedir a la API de Mercado Pago (nunca se confia en el cuerpo del aviso).
 */

export type SubscriptionStatus = 'pending' | 'authorized' | 'paused' | 'cancelled'

export interface SubscriptionRow {
  id: number
  client_id: number
  mp_id: string
  status: SubscriptionStatus
  amount: number
  init_point: string | null
  next_payment_date: string | null
  /** Valor normal (centavos) cuando hay promocion; NULL si no la hay. `amount` es lo que se cobra hoy. */
  full_amount: number | null
  promo_percent: number | null
  promo_months: number | null
  /** Cantidad de cobros en total: al cumplirse, la suscripcion se da de baja. NULL = sin fin. */
  term_months: number | null
  promo_ended: 0 | 1
}

const columns =
  'id, client_id, mp_id, status, amount, init_point, next_payment_date, full_amount, promo_percent, promo_months, term_months, promo_ended'

/** Precio con descuento, en pesos enteros (centavos multiplo de 100), igual que el de las promociones de la lista. */
export const discounted = (fullCents: number, percent: number): number => Math.round((fullCents * (100 - percent)) / 10_000) * 100
/** Pausa entre suscripciones durante la conciliacion. */
const RECONCILE_PAUSE_MS = 1500
const nowSql = `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`

/** Lo que ve la web del debito de un cliente: el estado y, mientras espera la tarjeta, el link para activarlo. */
export const toDebit = (s: SubscriptionRow) => ({
  status: s.status,
  link: s.status === 'pending' ? s.init_point : null,
  nextPaymentDate: s.next_payment_date,
  /** Promocion y plazo (null = sin ninguno de los dos). Importes en centavos. */
  promo:
    s.term_months || s.promo_percent
      ? {
          percent: s.promo_percent,
          promoMonths: s.promo_months,
          termMonths: s.term_months,
          ended: s.promo_ended === 1,
          amount: s.amount,
          fullAmount: s.full_amount ?? s.amount,
        }
      : null,
})

/** Suscripcion vigente (no cancelada) de un cliente. */
export const liveSubscription = (clientId: number): SubscriptionRow | undefined =>
  db
    .prepare(`SELECT ${columns} FROM subscriptions WHERE client_id = ? AND status != 'cancelled' ORDER BY id DESC LIMIT 1`)
    .get(clientId) as SubscriptionRow | undefined

const byMpId = (mpId: string) =>
  db.prepare(`SELECT ${columns} FROM subscriptions WHERE mp_id = ?`).get(mpId) as SubscriptionRow | undefined

/** Crea el cobro PENDIENTE del proximo vencimiento (si todavia no existe): asi "Pagos" muestra lo que viene. */
function ensurePending(sub: SubscriptionRow): void {
  if (sub.status !== 'authorized' || !sub.next_payment_date) return
  const client = db.prepare('SELECT maintenance_plan FROM clients WHERE id = ?').get(sub.client_id) as
    | { maintenance_plan: string | null }
    | undefined
  if (!client) return
  // El indice unico (suscripcion, vencimiento) hace que repetir esto sea inofensivo.
  db.prepare(
    `INSERT OR IGNORE INTO payments (client_id, concept, amount, currency, due_date, subscription_id)
     VALUES (?, ?, ?, 'ARS', ?, ?)`,
  ).run(sub.client_id, client.maintenance_plan ?? '', sub.amount, sub.next_payment_date, sub.id)
}

/** Trae el estado actual de la suscripcion en Mercado Pago y lo refleja en el CRM. */
export async function syncSubscription(mpId: string): Promise<void> {
  if (!byMpId(mpId)) return // no es de este CRM
  const pre = await getPreapproval(mpId)
  const next = pre.next_payment_date?.slice(0, 10) ?? null

  db.transaction(() => {
    const sub = byMpId(mpId)
    if (!sub) return
    db.prepare('UPDATE subscriptions SET status = ?, next_payment_date = ?, init_point = COALESCE(?, init_point) WHERE id = ?').run(
      pre.status,
      next,
      pre.init_point ?? null,
      sub.id,
    )
    if (pre.status === 'cancelled') {
      // Sin suscripcion no hay cobro que esperar: lo pendiente deja de ser deuda.
      db.prepare(`DELETE FROM payments WHERE subscription_id = ? AND status = 'pending'`).run(sub.id)
    } else {
      ensurePending({ ...sub, status: pre.status, next_payment_date: next })
    }
  })()

  // Un fallo aca no debe perder la sincronizacion: la conciliacion de cada hora lo reintenta.
  try {
    await applySchedule(mpId)
  } catch (error) {
    captureError(error, { kind: 'mercadopago', message: 'No se pudo aplicar la promocion o el plazo de la suscripcion' })
  }

  emit('payments', { adminsOnly: true })
  emit('clients')
}

/**
 * Promocion y plazo de la suscripcion, segun los cobros APROBADOS (no segun fechas: si un cobro se rechaza o se atrasa,
 * el mes promocional no se pierde).
 *  - Al cumplirse `promo_months` cobros: el monto vuelve al valor normal (en Mercado Pago y en el CRM).
 *  - Al cumplirse `term_months` cobros: la suscripcion se cancela y lo pendiente deja de ser deuda.
 * Es idempotente: si Mercado Pago falla, no se toca nada aca y se reintenta en la proxima sincronizacion.
 */
async function applySchedule(mpId: string): Promise<void> {
  const sub = byMpId(mpId)
  if (!sub || sub.status !== 'authorized' || !mpEnabled()) return
  const paid = (
    db.prepare(`SELECT COUNT(*) AS n FROM payments WHERE subscription_id = ? AND status = 'paid'`).get(sub.id) as { n: number }
  ).n

  if (sub.term_months && paid >= sub.term_months) {
    await cancelPreapproval(sub.mp_id)
    db.transaction(() => {
      db.prepare(`UPDATE subscriptions SET status = 'cancelled' WHERE id = ?`).run(sub.id)
      db.prepare(`DELETE FROM payments WHERE subscription_id = ? AND status = 'pending'`).run(sub.id)
    })()
    return
  }

  if (sub.promo_percent && sub.promo_months && sub.full_amount && !sub.promo_ended && paid >= sub.promo_months) {
    await updatePreapprovalAmount(sub.mp_id, sub.full_amount / 100)
    db.transaction(() => {
      db.prepare('UPDATE subscriptions SET amount = ?, promo_ended = 1 WHERE id = ?').run(sub.full_amount, sub.id)
      // El proximo cobro (ya pendiente) pasa al valor normal; lo cobrado queda como historial.
      db.prepare(`UPDATE payments SET amount = ? WHERE subscription_id = ? AND status = 'pending'`).run(sub.full_amount, sub.id)
    })()
  }
}

/** Registra un cobro de la suscripcion (aprobado o rechazado) en "Pagos". No consulta nada a Mercado Pago. */
function applyAuthorizedPayment(sub: SubscriptionRow, ap: AuthorizedPayment): void {
  const ref = String(ap.id)
  const outcome = ap.payment?.status
  const due = (ap.debit_date ?? '').slice(0, 10)
  const cents = Math.round(ap.transaction_amount * 100)

  db.transaction(() => {
    // Mercado Pago repite los avisos: un cobro ya registrado no se vuelve a tocar.
    if (db.prepare('SELECT 1 FROM payments WHERE provider_ref = ?').get(ref)) return

    // El pendiente que corresponde: el de vencimiento mas cercano a la fecha del cobro, y solo si esta a 10 dias o menos.
    // Asi el primer cobro nunca se asigna al pendiente del mes siguiente (que puede existir si el aviso de activacion
    // llego despues del cobro): en ese caso se registra con la fecha real del cobro.
    const target = db
      .prepare(
        `SELECT id FROM payments WHERE subscription_id = ? AND status = 'pending'
           AND ABS(julianday(due_date) - julianday(COALESCE(NULLIF(?, ''), due_date))) <= 10
         ORDER BY ABS(julianday(due_date) - julianday(COALESCE(NULLIF(?, ''), due_date))) LIMIT 1`,
      )
      .get(sub.id, due, due) as { id: number } | undefined

    if (outcome === 'approved') {
      const amount = cents > 0 ? cents : sub.amount
      if (target) {
        db.prepare(
          `UPDATE payments SET status = 'paid', paid_at = ${nowSql}, method = 'mercadopago', provider_ref = ?, amount = ?, rejected = 0
           WHERE id = ?`,
        ).run(ref, amount, target.id)
      } else if (/^\d{4}-\d{2}-\d{2}$/.test(due)) {
        const plan = db.prepare('SELECT maintenance_plan FROM clients WHERE id = ?').get(sub.client_id) as
          | { maintenance_plan: string | null }
          | undefined
        db.prepare(
          `INSERT OR IGNORE INTO payments (client_id, concept, amount, currency, due_date, status, paid_at, method, provider_ref, subscription_id)
           VALUES (?, ?, ?, 'ARS', ?, 'paid', ${nowSql}, 'mercadopago', ?, ?)`,
        ).run(sub.client_id, plan?.maintenance_plan ?? '', amount, due, ref, sub.id)
      }
    } else if (outcome === 'rejected' && target) {
      db.prepare('UPDATE payments SET rejected = 1 WHERE id = ?').run(target.id)
    }
  })()
}

/** Un cobro avisado por el webhook: se marca en "Pagos" y se programa el siguiente. */
export async function settleAuthorizedPayment(authorizedId: string): Promise<void> {
  const ap = await getAuthorizedPayment(authorizedId)
  const sub = byMpId(ap.preapproval_id)
  if (!sub) return // no es de este CRM

  applyAuthorizedPayment(sub, ap)
  // Actualiza la proxima fecha y deja programado el pendiente del mes siguiente.
  await syncSubscription(sub.mp_id)
}

/**
 * Conciliacion de respaldo (al arrancar y cada hora): si se perdio algun aviso, se leen los cobros de cada suscripcion
 * vigente directamente en Mercado Pago y el CRM queda igual que si los avisos hubieran llegado.
 */
export async function reconcile(): Promise<void> {
  if (!mpEnabled()) return
  const subs = db.prepare(`SELECT mp_id FROM subscriptions WHERE status IN ('pending', 'authorized', 'paused')`).all() as {
    mp_id: string
  }[]
  for (const [i, s] of subs.entries()) {
    // Cada suscripcion hace dos consultas a Mercado Pago: se espacian para no pasar su limite de pedidos (429).
    if (i > 0) await new Promise((resolve) => setTimeout(resolve, RECONCILE_PAUSE_MS))
    try {
      // Primero los cobros (del mas viejo al mas nuevo) y despues el estado: asi cada cobro cae en su fecha y el
      // pendiente del mes siguiente se crea al final.
      const sub = byMpId(s.mp_id)
      if (sub) {
        const charges = (await listAuthorizedPayments(s.mp_id)).sort((a, b) => (a.debit_date ?? '').localeCompare(b.debit_date ?? ''))
        for (const ap of charges) applyAuthorizedPayment(sub, ap)
      }
      await syncSubscription(s.mp_id)
    } catch (error) {
      if (error instanceof MpError && error.status === 429) {
        // Mercado Pago pide frenar: insistir con el resto solo empeora el bloqueo. Se corta y la proxima ronda retoma.
        captureError(error, { kind: 'mercadopago', message: 'Mercado Pago limito los pedidos: la conciliacion se reintenta en la proxima ronda' })
        return
      }
      captureError(error, { kind: 'mercadopago', message: 'Conciliacion de Mercado Pago fallida para una suscripcion' })
    }
  }
}
