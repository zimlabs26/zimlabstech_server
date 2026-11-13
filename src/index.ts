// Debe ir primero: hace que un error dentro de una ruta asincrona llegue al manejador de errores (Express 4 no lo hace solo).
import 'express-async-errors'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import express, { type NextFunction, type Request, type Response } from 'express'
import helmet from 'helmet'
import { purgeExpiredSessions, sessionIdOf, type SessionUser } from './auth/sessions.js'
import { bootstrapSuperAdmin } from './bootstrap.js'
import { config } from './config.js'
import './db.js'
import { captureError } from './errorlog.js'
import { requireUser } from './middleware/guards.js'
import { openConnection } from './realtime.js'
import { adminRouter } from './routes/admin.js'
import { authRouter } from './routes/auth.js'
import { passkeysRouter } from './routes/passkeys.js'
import { quotesRouter } from './routes/quotes.js'
import { clientsRouter } from './routes/clients.js'
import { dashboardRouter } from './routes/dashboard.js'
import { errorsRouter } from './routes/errors.js'
import { briefRouter, formsRouter } from './routes/forms.js'
import { exportRouter } from './routes/export.js'
import { reconcile } from './billing.js'
import { paymentsRouter } from './routes/payments.js'
import { subscriptionsRouter } from './routes/subscriptions.js'
import { tasksRouter } from './routes/tasks.js'
import { webhooksRouter } from './routes/webhooks.js'
import { inlineScriptHashes, mountSite } from './site.js'

const app = express()

// Detras de Render (y de la web de Vercel) la IP real viene en X-Forwarded-For: se confia solo en esa cantidad de proxies.
if (config.trustProxy > 0) app.set('trust proxy', config.trustProxy)

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        // Los scripts en linea de las paginas (tema antes del primer dibujo) se permiten por su hash, no en general.
        'script-src': ["'self'", ...inlineScriptHashes()],
        // Ninguna pagina se muestra dentro de otra (ni de este mismo sitio): evita el clickjacking.
        'frame-ancestors': ["'none'"],
        // blob: para la vista previa del recorte de la foto de perfil.
        'img-src': ["'self'", 'data:', 'blob:'],
        // En desarrollo (http://localhost) el navegador no debe forzar https.
        'upgrade-insecure-requests': config.isProd ? [] : null,
      },
    },
  }),
)
// Mismo criterio para navegadores viejos que no leen frame-ancestors.
app.use((_req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY')
  // La web no usa camara, microfono, ubicacion ni pagos del navegador: se cortan por si alguien inyectara algo.
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=()')
  next()
})
// Las respuestas de la API llevan datos de clientes y de sesion: ningun navegador ni proxy debe guardarlas.
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store')
  next()
})
app.use(cors({ origin: config.webOrigins, credentials: true }))
// La foto de perfil (ya reducida) tiene su propio limite en routes/auth.ts; la importacion de clientes lleva muchas
// filas y admite hasta 1 MB. Todo lo demas, 10 KB.
const smallJson = express.json({ limit: '10kb' })
const importJson = express.json({ limit: '1mb' })
app.use((req, res, next) => {
  if (req.path === '/api/auth/avatar') return next()
  return (req.path === '/api/clients/import' ? importJson : smallJson)(req, res, next)
})
app.use(cookieParser())

// Cada pestana del CRM se identifica con un id propio (cabecera X-Client-Id): el servidor no le devuelve el aviso
// de un cambio que ella misma origino, porque ya lo refleja sola.
app.use((req, res, next) => {
  res.locals.cid = String(req.get('x-client-id') ?? '').slice(0, 64)
  next()
})

app.get('/api/health', (_req, res) => {
  res.json({ ok: true })
})

// Tiempo real: la conexion queda abierta y el servidor avisa cuando algo cambia (ver realtime.ts).
app.get('/api/events', requireUser, (req, res) => {
  const user = res.locals.user as SessionUser
  openConnection(res, {
    userId: user.id,
    role: user.role,
    sessionId: sessionIdOf(req.cookies?.[config.cookieName]),
    cid: String(req.query.cid ?? '').slice(0, 64),
  })
})

app.use('/api/auth', authRouter)
app.use('/api/auth', passkeysRouter)
app.use('/api/admin', adminRouter)
app.use('/api/clients', clientsRouter)
app.use('/api/forms', formsRouter)
// Publico: el cliente completa su formulario con un enlace (token de 144 bits; ver routes/forms.ts).
app.use('/api/brief', briefRouter)
// Publico: pedido de cotizacion desde la web (crea un posible cliente; limitado por IP).
app.use('/api/quotes', quotesRouter)
app.use('/api/dashboard', dashboardRouter)
app.use('/api/export', exportRouter)
app.use('/api/errors', errorsRouter)
app.use('/api/tasks', tasksRouter)
app.use('/api/payments', paymentsRouter)
app.use('/api/subscriptions', subscriptionsRouter)
// Publico (lo llama Mercado Pago): cada aviso se valida con la firma del webhook.
app.use('/api/webhooks', webhooksRouter)

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'not_found' })
})

// La web (si esta la carpeta public/) se entrega desde aqui: mismo origen que la API.
mountSite(app)

// Nunca se filtra el detalle del error al cliente: solo un codigo de referencia para buscarlo en el registro de errores.
app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  // Pedidos mal formados: no son un fallo del servidor, se contestan con un 4xx claro y no se registran como error.
  const known = err as { type?: string; status?: number; statusCode?: number }
  if (known.type === 'entity.parse.failed') {
    res.status(400).json({ error: 'invalid_input' })
    return
  }
  if (known.type === 'entity.too.large') {
    res.status(413).json({ error: 'payload_too_large' })
    return
  }
  const clientStatus = known.status ?? known.statusCode
  if (typeof clientStatus === 'number' && clientStatus >= 400 && clientStatus < 500) {
    res.status(clientStatus).json({ error: 'invalid_input' })
    return
  }

  const user = res.locals.user as SessionUser | undefined
  const ref = captureError(err, { kind: 'http_500', path: req.path, method: req.method, status: 500, userEmail: user?.email })
  if (res.headersSent) return
  res.status(500).json({ error: 'server_error', ref })
})

// Fallos fuera de una peticion (una promesa sin atender, una excepcion suelta): se registran y el servidor sigue en pie.
process.on('unhandledRejection', (reason) => {
  captureError(reason, { kind: 'unhandled_rejection' })
})
process.on('uncaughtException', (error) => {
  captureError(error, { kind: 'uncaught_exception' })
})

purgeExpiredSessions()
// Hosting sin consola: si la base esta vacia, crea el super admin desde las variables BOOTSTRAP_SUPER_* (ver bootstrap.ts).
void bootstrapSuperAdmin()
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref()
// Debito automatico: conciliacion de respaldo con Mercado Pago (por si se perdio algun aviso): al arrancar y cada hora.
setTimeout(() => void reconcile(), 30_000).unref()
setInterval(() => void reconcile(), 60 * 60 * 1000).unref()

app.listen(config.port, () => {
  console.log(`Server escuchando en http://localhost:${config.port}`)
})
