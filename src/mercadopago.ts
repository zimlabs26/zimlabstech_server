import crypto from 'node:crypto'
import { config } from './config.js'

/**
 * Cliente minimo de la API de Mercado Pago (Suscripciones). Solo se usa desde el servidor: el Access Token nunca
 * llega a la web. Sin MP_ACCESS_TOKEN el debito automatico queda desactivado.
 */

const API = 'https://api.mercadopago.com'

export const mpEnabled = (): boolean => config.mpAccessToken !== ''

/** Respuesta de error de Mercado Pago (el detalle solo se registra en el log del servidor, nunca se muestra). */
export class MpError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`Mercado Pago respondio ${status}`)
  }
}

async function mp<T>(method: 'GET' | 'POST' | 'PUT', path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${config.mpAccessToken}`,
      'Content-Type': 'application/json',
      // Reintentar una creacion con la misma clave no la duplica.
      ...(method === 'POST' ? { 'X-Idempotency-Key': crypto.randomUUID() } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  })
  const text = await res.text()
  let data: unknown = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    /* respuesta sin JSON */
  }
  if (!res.ok) throw new MpError(res.status, data)
  return data as T
}

export type PreapprovalStatus = 'pending' | 'authorized' | 'paused' | 'cancelled'

export interface Preapproval {
  id: string
  status: PreapprovalStatus
  init_point?: string
  /** Fecha ISO del proximo cobro. */
  next_payment_date?: string
  auto_recurring?: { transaction_amount?: number }
}

export interface AuthorizedPayment {
  id: number
  preapproval_id: string
  /** scheduled = programado, processed = cobrado o rechazado (ver `payment`), recycling = reintentando, cancelled. */
  status: string
  transaction_amount: number
  debit_date?: string
  payment?: { id?: number; status?: string; status_detail?: string }
}

export const getPreapproval = (id: string): Promise<Preapproval> =>
  mp<Preapproval>('GET', `/preapproval/${encodeURIComponent(id)}`)

export const getAuthorizedPayment = (id: string): Promise<AuthorizedPayment> =>
  mp<AuthorizedPayment>('GET', `/authorized_payments/${encodeURIComponent(id)}`)

/** Todos los cobros (aprobados, rechazados y programados) de una suscripcion. Sirve para la conciliacion. */
export const listAuthorizedPayments = async (preapprovalId: string): Promise<AuthorizedPayment[]> =>
  (await mp<{ results?: AuthorizedPayment[] }>('GET', `/authorized_payments/search?preapproval_id=${encodeURIComponent(preapprovalId)}`))
    .results ?? []

/** Crea una suscripcion mensual SIN tarjeta: queda "pending" y devuelve el link donde el cliente la ingresa en Mercado Pago. */
export const createPreapproval = (input: {
  reason: string
  externalReference: string
  payerEmail: string
  /** En pesos (no en centavos). */
  amount: number
}): Promise<Preapproval> =>
  mp<Preapproval>('POST', '/preapproval', {
    reason: input.reason,
    external_reference: input.externalReference,
    payer_email: input.payerEmail,
    back_url: `${config.publicUrl}/crm`,
    status: 'pending',
    auto_recurring: {
      frequency: 1,
      frequency_type: 'months',
      transaction_amount: input.amount,
      currency_id: 'ARS',
    },
  })

export const cancelPreapproval = (id: string): Promise<Preapproval> =>
  mp<Preapproval>('PUT', `/preapproval/${encodeURIComponent(id)}`, { status: 'cancelled' })

/**
 * Valida la firma que Mercado Pago agrega a cada aviso (cabecera x-signature = "ts=...,v1=...").
 * v1 es el HMAC-SHA256 (con la clave secreta del webhook) de "id:<data.id>;request-id:<x-request-id>;ts:<ts>;".
 */
export function verifySignature(xSignature: string | undefined, xRequestId: string | undefined, dataId: string): boolean {
  if (!config.mpWebhookSecret || !xSignature) return false

  const parts = new Map<string, string>()
  for (const piece of xSignature.split(',')) {
    const i = piece.indexOf('=')
    if (i > 0) parts.set(piece.slice(0, i).trim(), piece.slice(i + 1).trim())
  }
  const ts = parts.get('ts')
  const v1 = parts.get('v1')
  if (!ts || !v1) return false

  // Segun la documentacion, un id alfanumerico se firma en minusculas.
  const id = /^[a-z0-9]+$/i.test(dataId) ? dataId.toLowerCase() : dataId
  const manifest = `${id ? `id:${id};` : ''}${xRequestId ? `request-id:${xRequestId};` : ''}ts:${ts};`
  const expected = Buffer.from(crypto.createHmac('sha256', config.mpWebhookSecret).update(manifest).digest('hex'))
  const received = Buffer.from(v1)
  return expected.length === received.length && crypto.timingSafeEqual(expected, received)
}

/**
 * Cambia el monto de una suscripcion existente (PUT /preapproval/{id}): los proximos cobros salen por el monto nuevo.
 * El cliente conserva su tarjeta. Importe en pesos (no en centavos).
 */
export const updatePreapprovalAmount = (id: string, amount: number): Promise<Preapproval> =>
  mp<Preapproval>('PUT', `/preapproval/${encodeURIComponent(id)}`, {
    auto_recurring: { transaction_amount: amount, currency_id: 'ARS' },
  })

/** Saldo de la cuenta de Mercado Pago en centavos. `available` es lo que se puede retirar o usar ya. */
export interface AccountBalance {
  available: number
  unavailable: number
  total: number
  currency: string
}

let accountId: number | null = null

/**
 * Consulta el saldo de la cuenta duena del Access Token. Mercado Pago no documenta este endpoint y lo habilita solo
 * para algunas cuentas y aplicaciones: sin permiso responde 401/403 (MpError) y el dashboard muestra que no esta disponible.
 */
export async function getAccountBalance(): Promise<AccountBalance> {
  if (accountId === null) accountId = (await mp<{ id: number }>('GET', '/users/me')).id
  const b = await mp<{
    currency_id?: string
    total_amount?: number
    available_balance?: number
    unavailable_balance?: number
  }>('GET', `/users/${accountId}/mercadopago_account/balance`)
  const cents = (n: number | undefined) => Math.round((n ?? 0) * 100)
  return {
    available: cents(b.available_balance),
    unavailable: cents(b.unavailable_balance),
    total: cents(b.total_amount ?? (b.available_balance ?? 0) + (b.unavailable_balance ?? 0)),
    currency: b.currency_id ?? 'ARS',
  }
}
