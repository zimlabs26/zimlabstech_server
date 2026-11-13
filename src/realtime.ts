import type { Response } from 'express'
import type { Role } from './db.js'

/**
 * Tiempo real con Server-Sent Events: cada pestana del CRM mantiene UNA conexion abierta y el servidor le avisa
 * cuando algo cambia. Los avisos NO llevan datos (solo "cambio esto"): la pestana vuelve a pedir lo que le interesa
 * por la API normal, que ya comprueba los permisos. Asi nunca se filtra informacion por este canal.
 */

export type RealtimeType =
  | 'clients' // cambio la lista de clientes
  | 'forms' // cambio la lista de formularios de relevamiento
  | 'tasks' // cambio el tablero de tareas (solo administradores)
  | 'payments' // cambio la lista de pagos (solo administradores)
  | 'admins' // cambio la lista de administradores (solo administradores)
  | 'profile' // cambio el perfil, el idioma o el tema de la cuenta
  | 'sessions' // cambiaron las sesiones abiertas de la cuenta
  | 'session-ended' // esta sesion se cerro (cuenta suspendida, baneada, eliminada o sesion revocada)

interface Connection {
  res: Response
  userId: number
  role: Role
  /** Hash de la cookie de sesion (no es el token: no sirve para iniciar sesion). */
  sessionId: string
  /** Identificador de la pestana: quien origina un cambio no recibe su propio aviso. */
  cid: string
}

const connections = new Set<Connection>()

/** Conexiones abiertas por cuenta: pasado este limite se cierra la mas vieja (evita acumular conexiones). */
const MAX_PER_USER = 8

function send(conn: Connection, type: RealtimeType): void {
  try {
    conn.res.write(`data: ${JSON.stringify({ type })}\n\n`)
  } catch {
    connections.delete(conn)
  }
}

/** Registra una conexion SSE ya autenticada y deja la respuesta abierta. */
export function openConnection(
  res: Response,
  info: { userId: number; role: Role; sessionId: string; cid: string },
): void {
  res.status(200).set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // evita que un proxy junte los mensajes
  })
  res.flushHeaders()
  // Si la conexion se corta, el navegador reintenta a los 3 s por su cuenta.
  res.write('retry: 3000\n\n')

  const conn: Connection = { res, ...info }
  const mine = [...connections].filter((c) => c.userId === info.userId)
  if (mine.length >= MAX_PER_USER) {
    mine[0].res.end()
    connections.delete(mine[0])
  }
  connections.add(conn)
  send(conn, 'profile') // al conectar, la pestana se pone al dia (por si se perdio algo mientras estaba desconectada)

  res.on('close', () => connections.delete(conn))
}

interface EmitOptions {
  /** Solo a las pestanas de esta cuenta. */
  userId?: number
  /** Solo a administradores. */
  adminsOnly?: boolean
  /** No avisar a la pestana que origino el cambio (ya se actualizo sola). */
  exceptCid?: string
}

/** Avisa a las pestanas conectadas que algo cambio. */
export function emit(type: RealtimeType, options: EmitOptions = {}): void {
  for (const conn of connections) {
    if (options.userId !== undefined && conn.userId !== options.userId) continue
    if (options.adminsOnly && conn.role !== 'admin') continue
    if (options.exceptCid && conn.cid === options.exceptCid) continue
    send(conn, type)
  }
}

/** Cierra las conexiones de sesiones que dejaron de ser validas, avisandoles antes para que vuelvan al login. */
export function endConnections(match: { userId?: number; sessionId?: string; exceptSessionId?: string }): void {
  for (const conn of [...connections]) {
    if (match.userId !== undefined && conn.userId !== match.userId) continue
    if (match.sessionId !== undefined && conn.sessionId !== match.sessionId) continue
    if (match.exceptSessionId !== undefined && conn.sessionId === match.exceptSessionId) continue
    send(conn, 'session-ended')
    conn.res.end()
    connections.delete(conn)
  }
}

// Un comentario cada 25 s mantiene viva la conexion (proxies y navegadores cierran las inactivas).
setInterval(() => {
  for (const conn of connections) {
    try {
      conn.res.write(': ping\n\n')
    } catch {
      connections.delete(conn)
    }
  }
}, 25_000).unref()
