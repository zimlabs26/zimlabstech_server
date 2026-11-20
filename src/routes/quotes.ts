import { Router } from 'express'
import { z } from 'zod'
import { config } from '../config.js'
import { clientSearchText, db, fillClientCodes } from '../db.js'
import { sendSalesNotice } from '../mailer.js'
import { sameOrigin } from '../middleware/guards.js'
import { rateLimit } from '../middleware/rateLimit.js'
import { emit } from '../realtime.js'

/**
 * Pedido de cotizacion desde la web publica: crea un POSIBLE CLIENTE en el CRM. No hay sesion (lo usa cualquier
 * visitante), asi que se cuida de otra forma: tope de pedidos por IP, campo trampa para robots y limites de largo.
 * El cliente queda sin plan ni categoria (bronce) y sin usuario creador; el equipo lo ve en Clientes con la nota
 * "Posible cliente" y lo que pidio cotizar.
 */

export const quotesRouter = Router()

const optional = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .optional()
    .transform((v) => (v ? v : null))

const quoteSchema = z.object({
  name: z.string().trim().min(2).max(120),
  company: optional(120),
  email: z.string().trim().toLowerCase().max(254).pipe(z.string().email()),
  phone: optional(40),
  /** Lo que quiere cotizar, en palabras (por ejemplo "CRM completo" o el resumen de un plan a medida). */
  interest: optional(600),
  /** Campo trampa: las personas no lo ven ni lo completan, los robots si. */
  website: z.string().max(200).optional(),
})

// Pocos pedidos por IP y hora: alcanza para uso normal y frena el relleno de la lista de clientes.
quotesRouter.post('/', sameOrigin, rateLimit({ windowMs: 60 * 60 * 1000, max: 8 }), (req, res) => {
  const parsed = quoteSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_input', field: String(parsed.error.issues[0]?.path[0] ?? 'name') })
    return
  }
  const q = parsed.data

  // Un robot que llena el campo trampa recibe el mismo "ok" que una persona, pero no se guarda nada.
  if (q.website) {
    res.status(201).json({ ok: true })
    return
  }

  const notes = ['Posible cliente: pidió avanzar con un proyecto desde la web.', q.interest ? `Eligió: ${q.interest}` : null]
    .filter(Boolean)
    .join('\n')
  const client = { name: q.name, company: q.company, email: q.email, phone: q.phone, notes }

  // Un posible cliente (prospect = 1): el equipo lo ve en Clientes con lo que pidio cotizar.
  db.prepare(
    "INSERT INTO clients (name, email, phone, company, notes, category, search_text, created_by, prospect) VALUES (?, ?, ?, ?, ?, 'bronze', ?, NULL, 1)",
  ).run(client.name, client.email, client.phone, client.company, client.notes, clientSearchText(client))
  fillClientCodes() // el posible cliente recibe su codigo (XXX hasta que se le elija el pais, y su numero)

  emit('clients')

  // Aviso a ventas. No se espera la respuesta del correo (puede tardar): el pedido ya quedo guardado en el CRM y
  // sendSalesNotice nunca lanza; si el correo falla, queda en el registro del servidor.
  void sendSalesNotice(config.salesEmail, { name: q.name, company: q.company, email: q.email, phone: q.phone, interest: q.interest })

  // La web ya no lleva a la persona al formulario de necesidades: se le avisa que el equipo la va a contactar.
  res.status(201).json({ ok: true })
})
