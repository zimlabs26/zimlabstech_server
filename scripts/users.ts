/**
 * Administracion de cuentas de acceso al CRM. No existe registro publico:
 * las cuentas solo se crean desde aqui, con acceso al servidor.
 *
 *   npm run user -- list
 *   npm run user -- create <correo> [--admin]
 *   npm run user -- passwd <correo>
 *   npm run user -- remove <correo>
 *   npm run user -- super <correo>     (define al unico super admin; debe ser administrador)
 *   npm run user -- reset-2fa <correo> (desactiva el 2FA de quien perdio el celular y los codigos de recuperacion)
 */
import { createInterface } from 'node:readline'
import { hashPassword } from '../src/auth/password.js'
import { db } from '../src/db.js'

const MIN_LENGTH = 12

/** Pide un texto por consola; si `hidden`, no muestra lo que se escribe. */
function ask(question: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    const out = rl as unknown as { _writeToOutput: (text: string) => void }
    const write = out._writeToOutput.bind(rl)
    let muted = false
    out._writeToOutput = (text) => {
      if (!muted) write(text)
    }
    rl.question(question, (answer) => {
      rl.close()
      if (hidden) process.stdout.write('\n')
      resolve(answer)
    })
    muted = hidden // el prompt ya se imprimio; desde aqui se oculta la escritura
  })
}

function normalize(email: string | undefined): string {
  const value = (email ?? '').trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254) {
    console.error('Correo no valido.')
    process.exit(1)
  }
  return value
}

async function askPassword(): Promise<string> {
  const first = await ask(`Contrasena (minimo ${MIN_LENGTH} caracteres): `, true)
  if (first.length < MIN_LENGTH || first.length > 128) {
    console.error(`La contrasena debe tener entre ${MIN_LENGTH} y 128 caracteres.`)
    process.exit(1)
  }
  const second = await ask('Repetila: ', true)
  if (first !== second) {
    console.error('Las contrasenas no coinciden.')
    process.exit(1)
  }
  return first
}

const [command, rawEmail, ...flags] = process.argv.slice(2)

/** La clave puede venir por NEW_USER_PASSWORD (sin escribirla en pantalla) o se pide por consola. */
async function passwordFromEnvOrPrompt(): Promise<string> {
  const fromEnv = process.env.NEW_USER_PASSWORD
  if (fromEnv === undefined) return askPassword()
  if (fromEnv.length < MIN_LENGTH || fromEnv.length > 128) {
    console.error(`NEW_USER_PASSWORD debe tener entre ${MIN_LENGTH} y 128 caracteres.`)
    process.exit(1)
  }
  return fromEnv
}

switch (command) {
  case 'list': {
    const rows = db.prepare('SELECT id, email, role, is_super, created_at FROM users ORDER BY id').all() as {
      id: number
      email: string
      role: string
      is_super: number
      created_at: string
    }[]
    if (rows.length === 0) console.log('No hay cuentas.')
    for (const r of rows) console.log(`${r.id}\t${r.is_super ? 'super' : r.role}\t${r.email}\t${r.created_at}`)
    break
  }

  case 'super': {
    // Define al UNICO super admin (el anterior deja de serlo). Debe ser un administrador.
    const email = normalize(rawEmail)
    const row = db.prepare('SELECT id, role FROM users WHERE email = ?').get(email) as { id: number; role: string } | undefined
    if (!row) {
      console.error('No existe esa cuenta.')
      process.exit(1)
    }
    if (row.role !== 'admin') {
      console.error('Solo un administrador puede ser super admin.')
      process.exit(1)
    }
    db.transaction(() => {
      db.prepare('UPDATE users SET is_super = 0 WHERE is_super = 1').run()
      db.prepare('UPDATE users SET is_super = 1 WHERE id = ?').run(row.id)
    })()
    console.log(`Super admin: ${email}`)
    break
  }

  case 'create': {
    const email = normalize(rawEmail)
    const role = flags.includes('--admin') ? 'admin' : 'user'
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
      console.error('Ya existe una cuenta con ese correo. Para cambiar la clave usa: passwd')
      process.exit(1)
    }
    const hash = await hashPassword(await passwordFromEnvOrPrompt())
    // Cuenta nueva: la contrasena inicial la conoce quien la creo, asi que en el primer ingreso se obliga a cambiarla.
    db.prepare('INSERT INTO users (email, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)').run(email, hash, role)
    console.log(`Cuenta creada (${role}): ${email}`)
    break
  }

  case 'passwd': {
    const email = normalize(rawEmail)
    if (!db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
      console.error('No existe esa cuenta.')
      process.exit(1)
    }
    const hash = await hashPassword(await passwordFromEnvOrPrompt())
    db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hash, email)
    // Cierra las sesiones abiertas de esa cuenta.
    db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)').run(email)
    console.log(`Contrasena actualizada y sesiones cerradas: ${email}`)
    break
  }

  case 'reset-2fa': {
    // Para quien perdio el celular Y los codigos de recuperacion: desactiva su 2FA (despues puede volver a activarlo).
    const email = normalize(rawEmail)
    const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: number } | undefined
    if (!target) {
      console.error('No existe esa cuenta.')
      process.exit(1)
    }
    db.transaction(() => {
      db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = NULL WHERE id = ?').run(target.id)
      db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(target.id)
    })()
    console.log(`Verificacion en dos pasos desactivada: ${email}`)
    break
  }

  case 'remove': {
    const email = normalize(rawEmail)
    const target = db.prepare('SELECT is_super FROM users WHERE email = ?').get(email) as { is_super: number } | undefined
    if (target?.is_super) {
      console.error('No se puede eliminar al super admin. Primero traspasa el rol con: super <otro correo>')
      process.exit(1)
    }
    const result = db.prepare('DELETE FROM users WHERE email = ?').run(email)
    console.log(result.changes ? `Cuenta eliminada: ${email}` : 'No existe esa cuenta.')
    break
  }

  default:
    console.log('Uso: npm run user -- <list | create | passwd | reset-2fa | remove> [correo] [--admin]')
    process.exit(command ? 1 : 0)
}
