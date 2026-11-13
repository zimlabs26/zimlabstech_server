import type { Response } from 'express'
import { createHash, randomBytes } from 'node:crypto'
import { config } from '../config.js'
import { db, type Lang, type Role, type Theme } from '../db.js'
import { endConnections } from '../realtime.js'

const DAY_MS = 24 * 60 * 60 * 1000
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex')

export interface SessionUser {
  id: number
  email: string
  role: Role
  lang: Lang | null
  theme: Theme | null
  /** El unico super admin: puede eliminar y editar a cualquier administrador. */
  isSuper: boolean
  firstName: string | null
  lastName: string | null
  /** URL de la foto (con version para el cache) o null si no subio ninguna. */
  avatar: string | null
  /** Primer ingreso: hasta que cambie la contrasena inicial no puede usar el CRM. */
  mustChangePassword: boolean
  /** Tiene activada la verificacion en dos pasos (2FA). */
  twofa: boolean
}

/** Crea una sesion nueva y devuelve el token (solo viaja en la cookie; en la BD queda su hash). */
export function createSession(userId: number, userAgent?: string | null): string {
  const token = randomBytes(32).toString('base64url')
  db.prepare('INSERT INTO sessions (id, user_id, expires_at, user_agent) VALUES (?, ?, ?, ?)').run(
    sha256(token),
    userId,
    Date.now() + config.sessionDays * DAY_MS,
    userAgent ? userAgent.slice(0, 200) : null,
  )
  return token
}

/** Por que una cuenta no puede entrar: baneo permanente o suspension temporal (con el momento en que termina). */
export type AccountBlock = { kind: 'banned' } | { kind: 'suspended'; until: number }

/** null = la cuenta esta habilitada. */
export function accountBlock(row: { banned: number; suspended_until: number | null }, now = Date.now()): AccountBlock | null {
  if (row.banned === 1) return { kind: 'banned' }
  if (row.suspended_until !== null && row.suspended_until > now) return { kind: 'suspended', until: row.suspended_until }
  return null
}

export interface SessionInfo {
  /** Identificador de la sesion (el hash del token: sirve para cerrarla, no para iniciar sesion). */
  id: string
  userAgent: string | null
  createdAt: string
  /** La sesion desde la que se esta pidiendo la lista. */
  current: boolean
}

/** Sesiones abiertas de un usuario (las vencidas no se listan), la actual primero. */
export function listUserSessions(userId: number, token: unknown): SessionInfo[] {
  const currentId = typeof token === 'string' ? sha256(token) : ''
  const rows = db
    .prepare(
      'SELECT id, user_agent AS userAgent, created_at AS createdAt FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC',
    )
    .all(userId, Date.now()) as Omit<SessionInfo, 'current'>[]
  return rows.map((r) => ({ ...r, current: r.id === currentId })).sort((a, b) => Number(b.current) - Number(a.current))
}

/** Cierra UNA sesion del usuario (nunca la de otra persona: el id se busca junto con el dueno). */
export function deleteUserSessionById(userId: number, id: string): boolean {
  const removed = db.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').run(id, userId).changes > 0
  // Ese dispositivo se entera al instante y vuelve al login.
  if (removed) endConnections({ userId, sessionId: id })
  return removed
}

export function getSessionUser(token: unknown): SessionUser | null {
  if (typeof token !== 'string' || token.length === 0 || token.length > 128) return null

  const row = db
    .prepare(
      // La foto NO se lee aca (esta consulta corre en cada peticion): solo si existe y de cuando es.
      `SELECT u.id AS id, u.email AS email, u.role AS role, u.lang AS lang, u.theme AS theme, u.is_super AS isSuper,
              u.first_name AS firstName, u.last_name AS lastName, u.avatar_at AS avatarAt,
              u.must_change_password AS mustChange, u.totp_enabled AS totp
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = ? AND s.expires_at > ?
          AND u.banned = 0 AND (u.suspended_until IS NULL OR u.suspended_until <= ?)`,
    )
    // Una cuenta baneada o suspendida no tiene sesion valida, aunque el token siga vigente (se aplica al instante).
    .get(sha256(token), Date.now(), Date.now()) as
    | (Omit<SessionUser, 'isSuper' | 'avatar' | 'mustChangePassword' | 'twofa'> & {
        isSuper: number
        avatarAt: number | null
        mustChange: number
        totp: number
      })
    | undefined

  if (!row) return null
  const { avatarAt, mustChange, totp, ...rest } = row
  return {
    ...rest,
    isSuper: row.isSuper === 1,
    avatar: avatarAt ? `/api/auth/avatar?v=${avatarAt}` : null,
    mustChangePassword: mustChange === 1,
    twofa: totp === 1,
  }
}

/** Identificador publico de una sesion (el hash del token). Sirve para reconocerla, no para iniciar sesion. */
export const sessionIdOf = (token: unknown): string => (typeof token === 'string' ? sha256(token) : '')

/** Cierra todas las sesiones de un usuario (menos la de `exceptToken`, si se indica). */
export function deleteUserSessions(userId: number, exceptToken?: unknown): void {
  if (typeof exceptToken === 'string' && exceptToken) {
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').run(userId, sha256(exceptToken))
    endConnections({ userId, exceptSessionId: sha256(exceptToken) })
  } else {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId)
    endConnections({ userId })
  }
}

export function deleteSession(token: unknown): void {
  if (typeof token !== 'string') return
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sha256(token))
  endConnections({ sessionId: sha256(token) })
}

export function purgeExpiredSessions(): void {
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now())
}

export function setSessionCookie(res: Response, token: string): void {
  res.cookie(config.cookieName, token, {
    httpOnly: true, // inaccesible desde JavaScript (mitiga robo por XSS)
    sameSite: 'lax', // no se envia en peticiones cruzadas (mitiga CSRF)
    secure: config.isProd, // solo HTTPS en produccion
    path: '/',
    maxAge: config.sessionDays * DAY_MS,
  })
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(config.cookieName, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.isProd,
    path: '/',
  })
}
