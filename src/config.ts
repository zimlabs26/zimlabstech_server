import 'dotenv/config'
import path from 'node:path'

const isProd = process.env.NODE_ENV === 'production'

/**
 * Limpia una direccion cargada en el panel del hosting (comillas, espacios, barra final) y la valida.
 * Devuelve solo el origen ("https://dominio") o '' si no es una URL http(s) valida.
 */
const cleanOrigin = (value: string | undefined): string => {
  const text = (value ?? '').trim().replace(/^["'`]+|["'`]+$/g, '').trim()
  try {
    const url = new URL(text)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : ''
  } catch {
    return ''
  }
}

export const config = {
  isProd,
  port: Number(process.env.PORT ?? 3000),
  /**
   * Origenes permitidos para las peticiones con cookies (la web). Admite varios separados por comas, por ejemplo
   * "https://zimerman.greenlimetech.com,https://zimerman-web.vercel.app" mientras convivan dos direcciones.
   */
  webOrigins: (process.env.WEB_ORIGIN ?? 'http://localhost:7777')
    .split(',')
    .map((o) => o.trim().replace(/\/$/, ''))
    .filter(Boolean),
  /** Carpeta con la web compilada (el contenido de web/dist). Si no existe, el servidor solo responde la API. */
  staticDir: process.env.STATIC_DIR ?? path.join(process.cwd(), 'public'),
  dbPath: process.env.DB_PATH ?? path.join(process.cwd(), 'data', 'app.db'),
  /**
   * Cuantos proxies hay delante del servidor (Render pone uno; si ademas la web de Vercel reenvia /api, son dos).
   * Sin esto, detras de un proxy todas las peticiones parecen venir de la misma IP y el limite de intentos se
   * comparte entre todos. En desarrollo no hay proxy (0).
   */
  trustProxy: Number(process.env.TRUST_PROXY ?? (isProd ? 1 : 0)),
  /** Mercado Pago. Sin token el debito automatico queda desactivado (el resto del CRM funciona igual). */
  mpAccessToken: process.env.MP_ACCESS_TOKEN?.trim() ?? '',
  mpWebhookSecret: process.env.MP_WEBHOOK_SECRET?.trim() ?? '',
  // Adonde vuelve el cliente desde Mercado Pago. Si PUBLIC_URL falta o es invalida se usa la direccion de la web (WEB_ORIGIN).
  publicUrl:
    cleanOrigin(process.env.PUBLIC_URL) ||
    cleanOrigin((process.env.WEB_ORIGIN ?? '').split(',')[0]) ||
    'http://localhost:7777',
  /** Correo saliente por Gmail (contrasena de aplicacion, sin espacios). Sin estos datos no se envian avisos. */
  mailUser: process.env.MAIL_USER?.trim() ?? '',
  mailPass: (process.env.MAIL_PASS ?? '').replace(/\s+/g, ''),
  mailFromName: process.env.MAIL_FROM_NAME?.trim() || 'Zim Labs',
  cookieName: 'zsid',
  sessionDays: 7,
} as const
