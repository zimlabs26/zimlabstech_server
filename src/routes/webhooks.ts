import { Router } from 'express'
import { settleAuthorizedPayment, syncSubscription } from '../billing.js'
import { captureError } from '../errorlog.js'
import { MpError, verifySignature } from '../mercadopago.js'
import { rateLimit } from '../middleware/rateLimit.js'

export const webhooksRouter = Router()

const limiter = rateLimit({ windowMs: 60 * 1000, max: 120 })

/**
 * Avisos de Mercado Pago. Es publica (Mercado Pago no tiene sesion), asi que TODO aviso debe traer una firma valida
 * (clave secreta del webhook). Aun con firma valida, el estado real se vuelve a pedir a la API de Mercado Pago.
 */
webhooksRouter.post('/mercadopago', limiter, async (req, res) => {
  const dataId = String(req.query['data.id'] ?? (req.body as { data?: { id?: unknown } } | undefined)?.data?.id ?? '')
  const type = String(req.query.type ?? (req.body as { type?: unknown } | undefined)?.type ?? '')

  if (!verifySignature(req.get('x-signature'), req.get('x-request-id'), dataId)) {
    res.status(401).json({ error: 'invalid_signature' })
    return
  }
  // Solo ids con forma de id de Mercado Pago: nada raro llega a la URL que se consulta.
  if (!/^[\w-]{1,64}$/.test(dataId)) {
    res.sendStatus(200)
    return
  }

  try {
    if (type === 'subscription_preapproval') await syncSubscription(dataId)
    else if (type === 'subscription_authorized_payment') await settleAuthorizedPayment(dataId)
    // Otros tipos (pagos sueltos, etc.) no se usan: se confirman para que no los reenvie.
    res.sendStatus(200)
  } catch (error) {
    // 404 / 400: el id no existe (por ejemplo la simulacion del panel de Mercado Pago). Reintentar no sirve.
    if (error instanceof MpError && (error.status === 404 || error.status === 400)) {
      res.sendStatus(200)
      return
    }
    captureError(error, { kind: 'mercadopago', message: 'Aviso de Mercado Pago no procesado', path: req.path, method: req.method })
    // 500: Mercado Pago reintenta mas tarde.
    res.sendStatus(500)
  }
})
