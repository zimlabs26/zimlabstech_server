import { db } from './db.js'
import { captureError } from './errorlog.js'
import { mailEnabled, sendChargePaid, sendChargeReminder, type ChargeInfo, type MailStatus } from './mailer.js'

/**
 * Avisos por correo al cliente sobre su debito automatico, todos los meses:
 *  - Una semana antes del cobro: "el <fecha> se va a cobrar <importe>".
 *  - El dia del cobro, cuando Mercado Pago lo confirma: "el cobro se realizo correctamente".
 * Cada aviso se manda UNA sola vez por cobro (tabla billing_notices): se "reserva" antes de enviar, asi dos pasadas
 * simultaneas no duplican el correo, y si el envio falla la reserva se libera para reintentar en la proxima pasada.
 * Un cobro rechazado no genera aviso de cobro realizado.
 */

const DAY = 86_400_000
const ZONE = 'America/Argentina/Buenos_Aires'
/** Los recordatorios salen de dia (hora de Argentina), no de madrugada. */
const REMINDER_FROM_HOUR = 9

const dateAr = (ms: number) => new Date(ms).toLocaleDateString('en-CA', { timeZone: ZONE })
const hourAr = () => Number(new Date().toLocaleString('en-US', { timeZone: ZONE, hour: 'numeric', hour12: false })) % 24

interface Row {
  id: number
  amount: number
  due_date: string
  paid_at: string | null
  concept: string
  name: string
  email: string
}

const SELECT = `SELECT p.id, p.amount, p.due_date, p.paid_at, p.concept, c.name, c.email
  FROM payments p
  JOIN subscriptions s ON s.id = p.subscription_id
  JOIN clients c ON c.id = p.client_id`

// Estricto a proposito: sin comas, punto y coma, comillas ni <>, para que un dato mal cargado nunca se lea como VARIOS
// destinatarios ni como un encabezado de correo.
const hasEmail = (r: Row) => /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/.test((r.email ?? '').trim())

/** Reserva el aviso, lo envia y, si fallo, libera la reserva. */
async function deliver(rows: Row[], kind: 'reminder' | 'paid', send: (to: string, c: ChargeInfo) => Promise<MailStatus>, dateOf: (r: Row) => string): Promise<void> {
  const claim = db.prepare('INSERT OR IGNORE INTO billing_notices (payment_id, kind) VALUES (?, ?)')
  const release = db.prepare('DELETE FROM billing_notices WHERE payment_id = ? AND kind = ?')
  for (const r of rows) {
    if (!hasEmail(r)) continue
    if (Number(claim.run(r.id, kind).changes) !== 1) continue // otro proceso ya lo tomo o ya se envio
    const status = await send(r.email.trim(), { clientName: r.name, plan: r.concept, amount: r.amount, date: dateOf(r) })
    if (status !== 'sent') release.run(r.id, kind)
  }
}

let running = false

/** Envia los avisos que correspondan ahora. Seguro de llamar muchas veces: no repite ni se pisa. No lanza. */
export async function sendBillingNotices(): Promise<void> {
  if (!mailEnabled || running) return
  running = true
  try {
    const now = Date.now()
    const today = dateAr(now)

    // Una semana antes: cobros pendientes de suscripciones activas que vencen dentro de los proximos 7 dias.
    if (hourAr() >= REMINDER_FROM_HOUR) {
      const reminders = db
        .prepare(
          `${SELECT}
           WHERE p.status = 'pending' AND s.status = 'authorized' AND p.due_date > ? AND p.due_date <= ?
             AND NOT EXISTS (SELECT 1 FROM billing_notices n WHERE n.payment_id = p.id AND n.kind = 'reminder')
           ORDER BY p.due_date`,
        )
        .all(today, dateAr(now + 7 * DAY)) as unknown as Row[]
      await deliver(reminders, 'reminder', sendChargeReminder, (r) => r.due_date)
    }

    // El dia del cobro: cobros confirmados en los ultimos 2 dias (no se avisa por cobros viejos).
    const paid = db
      .prepare(
        `${SELECT}
         WHERE p.status = 'paid' AND p.paid_at >= ?
           AND NOT EXISTS (SELECT 1 FROM billing_notices n WHERE n.payment_id = p.id AND n.kind = 'paid')
         ORDER BY p.paid_at`,
      )
      .all(new Date(now - 2 * DAY).toISOString()) as unknown as Row[]
    await deliver(paid, 'paid', sendChargePaid, (r) => (r.paid_at ? dateAr(Date.parse(r.paid_at)) : r.due_date))
  } catch (error) {
    captureError(error, { kind: 'mail', message: 'No se pudieron enviar los avisos de cobro a los clientes', alert: false })
  } finally {
    running = false
  }
}
