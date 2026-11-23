import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import nodemailer from 'nodemailer'
import { config } from './config.js'

export const mailEnabled = Boolean(config.mailUser && config.mailPass)

const transporter = mailEnabled
  ? nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user: config.mailUser, pass: config.mailPass },
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 12000,
    })
  : null

/** Resultado de un envio: 'sent' o el motivo (sin datos sensibles) para poder orientar a quien administra. */
export type MailStatus = 'sent' | 'not_configured' | 'auth' | 'connection' | 'error'

function failure(what: string, error: unknown): MailStatus {
  const e = error as { code?: string; responseCode?: number }
  const connection = ['ETIMEDOUT', 'ECONNECTION', 'ESOCKET', 'ECONNREFUSED', 'ENOTFOUND', 'EDNS', 'EAI_AGAIN']
  const status: MailStatus =
    e.code === 'EAUTH' || e.responseCode === 535 ? 'auth' : connection.includes(e.code ?? '') ? 'connection' : 'error'
  // Solo el tipo de fallo: el mensaje original puede incluir datos de la conexion.
  console.error(`[mail] no se pudo enviar ${what}: ${status} (${e.code ?? 'sin codigo'}${e.responseCode ? ` ${e.responseCode}` : ''})`)
  return status
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

/* ---------- Plantilla comun de los correos ---------- */

const C = {
  page: '#eef0f4',
  card: '#ffffff',
  head: '#0b0c0f',
  accent: '#2f6bff',
  text: '#14161a',
  muted: '#5b6270',
  panel: '#f5f6f9',
  line: '#e3e6ec',
  noteBg: '#eef3ff',
  warnBg: '#fff6e5',
  warn: '#d98a00',
}
const FONT = "-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

/** El logo viaja dentro del correo (imagen incrustada): se ve aunque el cliente bloquee imagenes externas. */
const LOGO_CID = 'zimlabs-logo'
const logoPath = fileURLToPath(new URL('../assets/mail-logo.png', import.meta.url))
let logoBuffer: Buffer | null | undefined
function logo(): Buffer | null {
  if (logoBuffer === undefined) {
    try {
      logoBuffer = fs.readFileSync(logoPath)
    } catch {
      logoBuffer = null // sin archivo, el correo sale igual pero sin imagen
    }
  }
  return logoBuffer
}
const attachments = () => {
  const buffer = logo()
  return buffer ? [{ filename: 'zimlabs.png', content: buffer, cid: LOGO_CID, contentDisposition: 'inline' as const }] : []
}

const h1 = (text: string) =>
  `<h1 style="margin:0 0 14px;font-family:${FONT};font-size:26px;line-height:1.25;font-weight:700;color:${C.text};letter-spacing:-0.01em">${escapeHtml(text)}</h1>`

const p = (html: string, muted = false) =>
  `<p style="margin:0 0 18px;font-family:${FONT};font-size:15px;line-height:1.65;color:${muted ? C.muted : C.text}">${html}</p>`

/** Tarjeta con datos "etiqueta / valor". `mono` marca los valores que se leen como codigo (contrasenas, codigos). */
function panel(rows: { label: string; value: string; mono?: boolean }[]): string {
  const cells = rows
    .map(
      (r, i) => `
        <tr>
          <td style="padding:${i === 0 ? '18px' : '4px'} 22px ${i === rows.length - 1 ? '18px' : '4px'}">
            <div style="font-family:${FONT};font-size:11px;font-weight:600;letter-spacing:0.12em;text-transform:uppercase;color:${C.muted};margin:0 0 6px">${escapeHtml(r.label)}</div>
            ${
              r.mono
                ? `<div style="display:inline-block;font-family:${MONO};font-size:17px;letter-spacing:0.04em;color:${C.text};background:${C.card};border:1px solid ${C.line};border-radius:8px;padding:9px 14px">${escapeHtml(r.value)}</div>`
                : `<div style="font-family:${FONT};font-size:15px;line-height:1.5;color:${C.text};font-weight:600;word-break:break-word">${escapeHtml(r.value)}</div>`
            }
          </td>
        </tr>`,
    )
    .join('')
  return `
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px;background:${C.panel};border:1px solid ${C.line};border-radius:12px">${cells}</table>`
}

/** Boton "a prueba de clientes de correo" (tabla con fondo) y el enlace en texto por si el boton no anda. */
function button(url: string, label: string): string {
  return `
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 14px"><tr>
      <td align="center" bgcolor="${C.accent}" style="border-radius:10px;background:${C.accent}">
        <a href="${escapeHtml(url)}" style="display:inline-block;padding:14px 30px;font-family:${FONT};font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:10px">${escapeHtml(label)}</a>
      </td>
    </tr></table>
    <p style="margin:0 0 26px;font-family:${FONT};font-size:12px;line-height:1.5;color:${C.muted}">Si el botón no funciona, copiá este enlace en tu navegador:<br /><a href="${escapeHtml(url)}" style="color:${C.accent};word-break:break-all">${escapeHtml(url)}</a></p>`
}

/** Recuadro de aviso con una barra de color a la izquierda. */
function note(html: string, tone: 'info' | 'warn' = 'info'): string {
  const bar = tone === 'warn' ? C.warn : C.accent
  const bg = tone === 'warn' ? C.warnBg : C.noteBg
  return `
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px"><tr>
      <td style="background:${bg};border-left:4px solid ${bar};border-radius:8px;padding:14px 18px;font-family:${FONT};font-size:14px;line-height:1.6;color:${C.text}">${html}</td>
    </tr></table>`
}

/** Marco comun: cabecera oscura con el logo, franja azul, contenido y pie. */
function layout(opts: { preheader: string; title: string; body: string; footer?: string }): string {
  const hasLogo = logo() !== null
  const year = new Date().getFullYear()
  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="light" />
  <title>${escapeHtml(opts.title)}</title>
</head>
<body style="margin:0;padding:0;background:${C.page}">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;font-size:1px;line-height:1px">${escapeHtml(opts.preheader)}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${C.page}">
    <tr><td align="center" style="padding:32px 12px">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:${C.card};border:1px solid ${C.line};border-radius:16px;overflow:hidden">
        <tr><td bgcolor="${C.head}" style="background:${C.head};padding:26px 32px">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            ${hasLogo ? `<td style="padding-right:16px;vertical-align:middle"><img src="cid:${LOGO_CID}" width="56" height="56" alt="Zimlabs" style="display:block;width:56px;height:56px;border:0;border-radius:14px" /></td>` : ''}
            <td style="vertical-align:middle">
              <div style="font-family:${FONT};font-size:20px;font-weight:700;letter-spacing:0.24em;color:#ffffff">ZIMLABS</div>
              <div style="font-family:${FONT};font-size:11px;font-weight:500;letter-spacing:0.32em;color:#8b93a3;margin-top:5px">TECHNOLOGIES</div>
            </td>
          </tr></table>
        </td></tr>
        <tr><td bgcolor="${C.accent}" style="height:4px;line-height:4px;font-size:0;background:${C.accent}">&nbsp;</td></tr>
        <tr><td style="padding:38px 32px 10px">${opts.body}</td></tr>
        <tr><td style="padding:6px 32px 30px">
          <div style="border-top:1px solid ${C.line};padding-top:20px;font-family:${FONT};font-size:12px;line-height:1.6;color:${C.muted}">
            ${opts.footer ?? 'Este mensaje se envió automáticamente desde el CRM de Zimlabs Technologies. No respondas a este correo.'}
          </div>
        </td></tr>
      </table>
      <div style="padding:18px 12px 0;font-family:${FONT};font-size:12px;color:#8b93a3">© ${year} Zimlabs Technologies</div>
    </td></tr>
  </table>
</body>
</html>`
}

const now = () => new Date().toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires', dateStyle: 'long', timeStyle: 'short' })

/* ---------- Correos ---------- */

/**
 * Constancia para el super admin: quien dio de alta una cuenta nueva y cuando. Nunca incluye la contrasena.
 * No lanza: un fallo de correo no debe impedir el alta.
 */
export async function sendAdminCreatedNotice(to: string, newEmail: string, createdBy: string): Promise<boolean> {
  if (!transporter) return false
  const when = `${now()} (hora de Argentina)`
  const adminUrl = `${config.publicUrl}/crm#admin`

  const text = [
    'Hola,',
    '',
    'Se dio de alta una cuenta nueva de administrador en el CRM.',
    '',
    `Cuenta nueva: ${newEmail}`,
    `Creada por: ${createdBy}`,
    `Fecha: ${when}`,
    '',
    'Esta cuenta tiene acceso total al CRM. Si no reconocés este alta, suspendé o eliminá la cuenta desde el panel Admin:',
    adminUrl,
  ].join('\n')

  const html = layout({
    preheader: `Se creó la cuenta ${newEmail}. Constancia de seguridad.`,
    title: 'Alta de una cuenta nueva',
    body: [
      h1('Se dio de alta una cuenta nueva'),
      p('Te enviamos esta constancia porque se creó una cuenta de administrador en el CRM.'),
      panel([
        { label: 'Cuenta nueva', value: newEmail },
        { label: 'Creada por', value: createdBy },
        { label: 'Fecha', value: when },
      ]),
      note('<strong>Esta cuenta tiene acceso total al CRM.</strong> Si no reconocés este alta, suspendé o eliminá la cuenta desde el panel Admin.', 'warn'),
      button(adminUrl, 'Abrir el panel Admin'),
    ].join(''),
  })

  try {
    await transporter.sendMail({
      from: { name: config.mailFromName, address: config.mailUser },
      to,
      subject: `Alta de una cuenta nueva: ${newEmail}`,
      text,
      html,
      attachments: attachments(),
    })
    return true
  } catch (error) {
    failure('la constancia de alta', error)
    return false
  }
}

/**
 * Aviso al super admin de un error grave del servidor. Solo lleva un resumen ya enmascarado (sin pila ni datos de
 * personas); el detalle completo esta en el registro de errores del CRM. No lanza.
 */
export async function sendErrorAlert(
  to: string,
  info: { ref: string; kind: string; message: string; path: string; count: number; panelUrl: string },
): Promise<boolean> {
  if (!transporter) return false
  const when = `${now()} (hora de Argentina)`
  const logUrl = `${info.panelUrl}#settings`
  const rows = [
    { label: 'Código de referencia', value: info.ref, mono: true },
    { label: 'Tipo', value: info.kind },
    { label: 'Mensaje', value: info.message },
    { label: 'Dónde', value: info.path || '-' },
    { label: 'Veces que ocurrió', value: String(info.count) },
    { label: 'Fecha', value: when },
  ]
  const text = [
    'Se registró un error en el servidor del CRM.',
    '',
    ...rows.map((r) => `${r.label}: ${r.value}`),
    '',
    `Detalle completo: ${logUrl} > Errores`,
    'Para no llenar tu casilla, este mismo error no vuelve a avisar por 30 minutos.',
  ].join('\n')

  const html = layout({
    preheader: `Error en el servidor (${info.ref}): ${info.message}`,
    title: 'Error en el servidor del CRM',
    body: [
      h1('Error en el servidor del CRM'),
      p('Se registró un fallo. Este es el resumen; el detalle técnico completo está en el registro de errores del CRM.'),
      panel(rows),
      button(logUrl, 'Ver el registro de errores'),
      note('Para no llenar tu casilla, este mismo error no vuelve a avisar por 30 minutos.'),
    ].join(''),
  })

  try {
    await transporter.sendMail({
      from: { name: config.mailFromName, address: config.mailUser },
      to,
      subject: `[CRM] Error en el servidor (${info.ref})`,
      text,
      html,
      attachments: attachments(),
    })
    return true
  } catch (error) {
    failure('el aviso de error', error)
    return false
  }
}

/**
 * Avisa a una cuenta nueva que fue dada de alta e incluye su contrasena temporal.
 * Devuelve true si el correo salio; nunca lanza (un fallo de correo no debe impedir el alta) y nunca registra la clave.
 */
export async function sendWelcomeEmail(to: string, tempPassword: string): Promise<MailStatus> {
  if (!transporter) {
    console.error('[mail] no se envia el aviso de alta: faltan las variables MAIL_USER y MAIL_PASS en el servidor')
    return 'not_configured'
  }
  const loginUrl = `${config.publicUrl}/login`

  const text = [
    'Hola,',
    '',
    'Te dimos de alta en el CRM de Zimlabs Technologies.',
    '',
    `Ingresá en: ${loginUrl}`,
    `Correo: ${to}`,
    `Contraseña temporal: ${tempPassword}`,
    '',
    'Al iniciar sesión por primera vez, el sistema te va a pedir que la cambies por una propia.',
    'Si no esperabas este mensaje, ignoralo y avisanos.',
  ].join('\n')

  const html = layout({
    preheader: 'Tu cuenta del CRM ya está lista. Ingresá con tu contraseña temporal.',
    title: 'Tu acceso al CRM',
    body: [
      h1('Te damos la bienvenida al CRM'),
      p('Hola, creamos tu cuenta en el CRM de <strong>Zimlabs Technologies</strong>. Con estos datos ya podés ingresar:'),
      panel([
        { label: 'Correo', value: to },
        { label: 'Contraseña temporal', value: tempPassword, mono: true },
      ]),
      button(loginUrl, 'Iniciar sesión'),
      note('<strong>Por seguridad, vas a tener que cambiar esta contraseña</strong> por una propia la primera vez que ingreses. Hasta entonces no vas a poder usar el CRM.'),
      p('No compartas este correo con nadie. Si no esperabas este mensaje, ignoralo o avisanos.', true),
    ].join(''),
  })

  try {
    await transporter.sendMail({
      from: { name: config.mailFromName, address: config.mailUser },
      to,
      subject: `Tu acceso al CRM de ${config.mailFromName}`,
      text,
      html,
      attachments: attachments(),
    })
    return 'sent'
  } catch (error) {
    return failure('el aviso de alta', error)
  }
}

/* ---------- Avisos del debito automatico al cliente ---------- */

const PLAN_NAMES: Record<string, string> = {
  static: 'Cuidado de web estática',
  server: 'Cuidado de web interactiva',
  crmb: 'Cuidado de CRM básico',
  crmf: 'Cuidado de CRM completo',
}

export interface ChargeInfo {
  clientName: string
  /** Codigo del plan de mantenimiento (concepto del cobro). */
  plan: string
  /** Centavos de ARS. */
  amount: number
  /** AAAA-MM-DD */
  date: string
}

const peso = (cents: number) => new Intl.NumberFormat('es-AR', { style: 'currency', currency: 'ARS' }).format(cents / 100)
const longDate = (iso: string) => new Date(`${iso}T12:00:00`).toLocaleDateString('es-AR', { dateStyle: 'long' })
const clean = (s: string) => s.replace(/[\r\n]+/g, ' ')

async function sendToClient(to: string, subject: string, text: string, html: string, what: string): Promise<MailStatus> {
  if (!transporter) return 'not_configured'
  try {
    await transporter.sendMail({
      from: { name: config.mailFromName, address: config.mailUser },
      to,
      // Si el cliente responde, le llega a ventas.
      replyTo: config.salesEmail,
      subject,
      text,
      html,
      attachments: attachments(),
    })
    return 'sent'
  } catch (error) {
    return failure(what, error)
  }
}

const clientFooter = () =>
  `Este es un aviso automático de ${escapeHtml(config.mailFromName)} sobre tu débito automático de Mercado Pago. Si tenés dudas, respondé este correo o escribinos a <a href="mailto:${escapeHtml(config.salesEmail)}" style="color:${C.accent}">${escapeHtml(config.salesEmail)}</a>.`

/** Una semana antes: avisa que se va a hacer el cobro del debito automatico. */
export function sendChargeReminder(to: string, c: ChargeInfo): Promise<MailStatus> {
  const plan = PLAN_NAMES[c.plan] ?? 'Mantenimiento'
  const date = longDate(c.date)
  const text = [
    `Hola ${clean(c.clientName)},`,
    '',
    `Te avisamos que el ${date} se va a realizar el cobro de tu débito automático.`,
    '',
    `Servicio: ${plan}`,
    `Importe: ${peso(c.amount)}`,
    `Fecha del cobro: ${date}`,
    '',
    'Se descuenta solo de la tarjeta que registraste en Mercado Pago. No tenés que hacer nada; solo asegurate de tener saldo disponible.',
    `Si tenés dudas, escribinos a ${config.salesEmail}.`,
  ].join('\n')

  const html = layout({
    preheader: `El ${date} se cobra tu débito automático de ${peso(c.amount)}.`,
    title: 'Aviso de cobro próximo',
    body: [
      h1('Se acerca tu próximo cobro'),
      p(`Hola ${escapeHtml(c.clientName)}, te avisamos con una semana de anticipación que se va a realizar el cobro de tu <strong>débito automático</strong>.`),
      panel([
        { label: 'Servicio', value: plan },
        { label: 'Importe', value: peso(c.amount) },
        { label: 'Fecha del cobro', value: date },
      ]),
      note('Se descuenta solo de la tarjeta que registraste en Mercado Pago. <strong>No tenés que hacer nada</strong>; solo asegurate de tener saldo disponible ese día.'),
    ].join(''),
    footer: clientFooter(),
  })
  return sendToClient(to, `Aviso: el ${date} se realizará el cobro de tu débito automático`, text, html, 'el aviso de cobro próximo')
}

/** El dia del cobro: confirma que se hizo correctamente. */
export function sendChargePaid(to: string, c: ChargeInfo): Promise<MailStatus> {
  const plan = PLAN_NAMES[c.plan] ?? 'Mantenimiento'
  const date = longDate(c.date)
  const text = [
    `Hola ${clean(c.clientName)},`,
    '',
    'El cobro de tu débito automático se realizó correctamente. ¡Gracias!',
    '',
    `Servicio: ${plan}`,
    `Importe cobrado: ${peso(c.amount)}`,
    `Fecha: ${date}`,
    '',
    `Si tenés dudas, escribinos a ${config.salesEmail}.`,
  ].join('\n')

  const html = layout({
    preheader: `Cobro realizado correctamente: ${peso(c.amount)}.`,
    title: 'Cobro realizado',
    body: [
      h1('Cobro realizado correctamente'),
      p(`Hola ${escapeHtml(c.clientName)}, el cobro de tu <strong>débito automático</strong> se realizó con éxito. ¡Gracias!`),
      panel([
        { label: 'Servicio', value: plan },
        { label: 'Importe cobrado', value: peso(c.amount) },
        { label: 'Fecha', value: date },
      ]),
      p('El próximo cobro te lo vamos a avisar con una semana de anticipación.', true),
    ].join(''),
    footer: clientFooter(),
  })
  return sendToClient(to, 'Cobro realizado correctamente', text, html, 'el aviso de cobro realizado')
}

/**
 * Aviso a ventas: alguien dejo sus datos en la web para contratar un plan. El Reply-To es la persona, asi que
 * responder el correo le escribe directo. No lanza: un fallo de correo no debe impedir que el pedido quede en el CRM.
 */
export async function sendSalesNotice(
  to: string,
  lead: { name: string; company: string | null; email: string; phone: string | null; interest: string | null },
): Promise<MailStatus> {
  if (!transporter) {
    console.error('[mail] no se envia el aviso a ventas: faltan las variables MAIL_USER y MAIL_PASS en el servidor')
    return 'not_configured'
  }
  const when = `${now()} (hora de Argentina)`
  const crmUrl = `${config.publicUrl}/crm#clients`
  const rows = [
    { label: 'Nombre', value: lead.name },
    ...(lead.company ? [{ label: 'Empresa', value: lead.company }] : []),
    { label: 'Correo', value: lead.email },
    ...(lead.phone ? [{ label: 'Teléfono', value: lead.phone }] : []),
    { label: 'Eligió', value: lead.interest ?? 'Consulta general' },
    { label: 'Fecha', value: when },
  ]
  const text = [
    'Llegó un pedido nuevo desde la web.',
    '',
    ...rows.map((r) => `${r.label}: ${r.value}`),
    '',
    'Quedó cargado como posible cliente en el CRM:',
    crmUrl,
    'Podés responder este correo: le llega directo a la persona.',
  ].join('\n')

  const html = layout({
    preheader: `${lead.name} quiere avanzar con un proyecto: ${lead.interest ?? 'consulta general'}`,
    title: 'Nuevo pedido desde la web',
    body: [
      h1('Nuevo pedido desde la web'),
      p('Alguien dejó sus datos en <strong>zimlabstech.com</strong> para avanzar con un proyecto. Hay que contactarlo para darle una propuesta.'),
      panel(rows),
      note('Quedó cargado como <strong>posible cliente</strong> en el CRM. Podés responder este correo: le llega directo a la persona.'),
      button(crmUrl, 'Ver en el CRM'),
    ].join(''),
    footer: 'Aviso automático de la web de Zimlabs Technologies.',
  })

  try {
    await transporter.sendMail({
      from: { name: config.mailFromName, address: config.mailUser },
      to,
      replyTo: { name: lead.name.replace(/[\r\n]+/g, ' '), address: lead.email },
      // Sin saltos de linea: el nombre viene de un formulario publico.
      subject: `Nuevo pedido de proyecto: ${lead.name.replace(/[\r\n]+/g, ' ')}`,
      text,
      html,
      attachments: attachments(),
    })
    return 'sent'
  } catch (error) {
    return failure('el aviso a ventas', error)
  }
}
