import { hashPassword } from './auth/password.js'
import { db } from './db.js'

/**
 * Primera cuenta en hosting SIN consola (por ejemplo el plan gratis de Render, que no tiene Shell).
 *
 * Si la base esta VACIA y estan definidas BOOTSTRAP_SUPER_EMAIL y BOOTSTRAP_SUPER_PASSWORD, se crea el super admin.
 * Si ya hay alguna cuenta no hace nada (por eso es seguro dejar las variables puestas, aunque conviene borrarlas
 * despues del primer arranque: la contrasena no deberia quedar guardada en el panel del hosting).
 */
export async function bootstrapSuperAdmin(): Promise<void> {
  const email = process.env.BOOTSTRAP_SUPER_EMAIL?.trim().toLowerCase()
  const password = process.env.BOOTSTRAP_SUPER_PASSWORD
  if (!email || !password) return

  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }
  if (n > 0) return

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    console.error('BOOTSTRAP_SUPER_EMAIL no es un correo valido: no se creo ninguna cuenta.')
    return
  }
  if (password.length < 12 || password.length > 128) {
    console.error('BOOTSTRAP_SUPER_PASSWORD debe tener entre 12 y 128 caracteres: no se creo ninguna cuenta.')
    return
  }

  // La contrasena inicial viaja por una variable de entorno: en el primer ingreso se obliga a cambiarla.
  db.prepare(`INSERT INTO users (email, password_hash, role, is_super, must_change_password) VALUES (?, ?, 'admin', 1, 1)`).run(
    email,
    await hashPassword(password),
  )
  console.log(`Super admin creado: ${email}. Borra BOOTSTRAP_SUPER_PASSWORD de las variables de entorno.`)
}
