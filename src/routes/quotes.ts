import crypto from 'node:crypto'
import { Router } from 'express'
import { z } from 'zod'
import { clientSearchText, db } from '../db.js'
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

/** Cuanto dura el enlace al formulario de necesidades (lo mismo que los que genera el equipo). */
const FORM_DAYS = 30

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

  const notes = ['Posible cliente: pidió una cotización desde la web.', q.interest ? `Quiere cotizar: ${q.interest}` : null]
    .filter(Boolean)
    .join('\n')
  const client = { name: q.name, company: q.company, email: q.email, phone: q.phone, notes }

  // Un posible cliente (prospect = 1) con su formulario de necesidades ya creado: despues de dejar sus datos la
  // persona pasa a ese formulario para contar que necesita y el equipo sepa como cotizarlo.
  const token = crypto.randomBytes(18).toString('base64url') // 144 bits, igual que los enlaces que genera el equipo
  const expires = new Date(Date.now() + FORM_DAYS * 86_400_000).toISOString()
  db.transaction(() => {
    const created = db
      .prepare(
        "INSERT INTO clients (name, email, phone, company, notes, category, search_text, created_by, prospect) VALUES (?, ?, ?, ?, ?, 'bronze', ?, NULL, 1)",
      )
      .run(client.name, client.email, client.phone, client.company, client.notes, clientSearchText(client))
    db.prepare('INSERT INTO forms (token, client_id, expires_at, created_by) VALUES (?, ?, ?, NULL)').run(
      token,
      Number(created.lastInsertRowid),
      expires,
    )
  })()

  emit('clients')
  emit('forms')
  res.status(201).json({ ok: true, token })
})
