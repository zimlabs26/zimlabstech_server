import type { NextFunction, Request, Response } from 'express'
import { getSessionUser, type SessionUser } from '../auth/sessions.js'
import { config } from '../config.js'

/** Rechaza peticiones que cambian estado y vienen de otro origen (defensa extra contra CSRF). */
export function sameOrigin(req: Request, res: Response, next: NextFunction): void {
  const origin = req.get('origin')
  if (origin && !config.webOrigins.includes(origin)) {
    res.status(403).json({ error: 'forbidden' })
    return
  }
  next()
}

/** Exige sesion abierta. El usuario queda en `res.locals.user`. */
export function requireUser(req: Request, res: Response, next: NextFunction): void {
  const user = getSessionUser(req.cookies?.[config.cookieName])
  if (!user) {
    res.status(401).json({ error: 'unauthorized' })
    return
  }
  // Primer ingreso: hasta cambiar la contrasena inicial no hay acceso a nada del CRM (clientes, tareas, administracion
  // ni tiempo real). Las rutas de /api/auth (perfil, contrasena, salir) no pasan por aca y siguen disponibles.
  if (user.mustChangePassword) {
    res.status(403).json({ error: 'password_change_required' })
    return
  }
  res.locals.user = user
  next()
}

/** Exige ser el super admin (solo existe uno). */
export function requireSuper(req: Request, res: Response, next: NextFunction): void {
  requireAdmin(req, res, () => {
    if (!(res.locals.user as SessionUser).isSuper) {
      res.status(403).json({ error: 'forbidden' })
      return
    }
    next()
  })
}

/** Exige sesion abierta Y rol de administrador. La autorizacion se decide siempre aqui, nunca en la web. */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  requireUser(req, res, () => {
    if ((res.locals.user as SessionUser).role !== 'admin') {
      res.status(403).json({ error: 'forbidden' })
      return
    }
    next()
  })
}
