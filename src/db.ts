import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import path from 'node:path'
import { config } from './config.js'

try {
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true })
} catch (error) {
  // Lo mas comun: DB_PATH apunta a una carpeta que no existe o sin permisos de escritura en el hosting.
  console.error(
    `\nNo se pudo crear la carpeta de la base de datos: ${path.dirname(config.dbPath)}\n` +
      `Revisa DB_PATH (ahora: ${config.dbPath}): la carpeta debe existir y tener permisos de escritura.\n`,
  )
  throw error
}

/**
 * Base de datos SQLite con el modulo incluido en Node (node:sqlite), sin modulos nativos.
 * Antes se usaba better-sqlite3, pero su binario precompilado exige una glibc mas nueva que la de Hostinger
 * y el servidor se caia al arrancar (503). Esta capa deja la misma interfaz que usaba el resto del codigo:
 * prepare(), exec(), pragma() y transaction().
 */
export interface Statement {
  get(...params: any[]): any
  all(...params: any[]): any[]
  run(...params: any[]): { changes: number | bigint; lastInsertRowid: number | bigint }
}

class Db {
  private readonly raw: DatabaseSync
  private depth = 0

  constructor(file: string) {
    this.raw = new DatabaseSync(file)
  }

  prepare(sql: string): Statement {
    return this.raw.prepare(sql) as unknown as Statement
  }

  exec(sql: string): void {
    this.raw.exec(sql)
  }

  /** Devuelve las filas del PRAGMA (por ejemplo table_info), igual que better-sqlite3. */
  pragma(source: string): any[] {
    return this.raw.prepare(`PRAGMA ${source}`).all() as any[]
  }

  /** Envuelve la funcion en una transaccion: COMMIT si termina bien, ROLLBACK si lanza un error. Admite anidarse. */
  transaction<A extends any[], R>(fn: (...args: A) => R): (...args: A) => R {
    return (...args: A): R => {
      const nested = this.depth > 0
      const savepoint = `sp_${this.depth}`
      this.raw.exec(nested ? `SAVEPOINT ${savepoint}` : 'BEGIN')
      this.depth++
      try {
        const result = fn(...args)
        this.depth--
        this.raw.exec(nested ? `RELEASE ${savepoint}` : 'COMMIT')
        return result
      } catch (error) {
        this.depth--
        this.raw.exec(nested ? `ROLLBACK TO ${savepoint}; RELEASE ${savepoint}` : 'ROLLBACK')
        throw error
      }
    }
  }
}

export const db = new Db(config.dbPath)
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,          -- siempre en minusculas
    password_hash TEXT NOT NULL,                 -- scrypt$N$r$p$salt$hash
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,                 -- sha256 (hex) del token de la cookie
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,                 -- epoch en milisegundos
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`)

// Migracion: `role` se agrego despues de crear la tabla (las bases existentes no la tienen).
const columns = db.pragma('table_info(users)') as { name: string }[]
if (!columns.some((c) => c.name === 'role')) {
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user'))`)
}

// Preferencias por usuario (idioma y tema del CRM). NULL = el usuario aun no eligio.
for (const [name, definition] of [
  ['lang', `TEXT CHECK (lang IN ('en', 'es'))`],
  ['theme', `TEXT CHECK (theme IN ('light', 'dark'))`],
] as const) {
  if (!columns.some((c) => c.name === name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${definition}`)
}

// Estado de la cuenta: `banned` = baneo permanente; `suspended_until` = suspension temporal (epoch en ms).
// Una cuenta esta activa si no esta baneada y la suspension ya vencio (o no tiene). Solo el super admin las cambia.
for (const [name, definition] of [
  ['banned', 'INTEGER NOT NULL DEFAULT 0 CHECK (banned IN (0, 1))'],
  ['suspended_until', 'INTEGER'],
] as const) {
  if (!columns.some((c) => c.name === name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${definition}`)
}

// Primer ingreso: una cuenta recien creada (por el super admin, por consola o por el arranque inicial) trae una contrasena
// INICIAL que otra persona conoce, asi que la primera vez se obliga a cambiarla. Las cuentas que ya existian quedan en 0.
if (!columns.some((c) => c.name === 'must_change_password')) {
  db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1))`)
}

// Navegador/dispositivo de cada sesion (para listar "Sesiones activas" en Configuracion).
const sessionColumns = db.pragma('table_info(sessions)') as { name: string }[]
if (!sessionColumns.some((c) => c.name === 'user_agent')) db.exec('ALTER TABLE sessions ADD COLUMN user_agent TEXT')

// Datos de perfil: nombre, apellido y foto. La foto se guarda como data URL (JPEG/PNG/WebP, ya reducida por la web)
// y se sirve por /api/auth/avatar; `avatar_at` sirve para que el navegador la vuelva a pedir cuando cambia.
for (const [name, definition] of [
  ['first_name', 'TEXT'],
  ['last_name', 'TEXT'],
  ['avatar', 'TEXT'],
  ['avatar_at', 'INTEGER'],
] as const) {
  if (!columns.some((c) => c.name === name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${definition}`)
}

// Super admin: como maximo UNO. Lo garantiza la base de datos con un indice unico parcial,
// asi ninguna ruta ni script puede crear un segundo aunque tenga un error.
if (!columns.some((c) => c.name === 'is_super')) {
  db.exec(`ALTER TABLE users ADD COLUMN is_super INTEGER NOT NULL DEFAULT 0 CHECK (is_super IN (0, 1))`)
}
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS one_super_admin ON users(is_super) WHERE is_super = 1`)

// Verificacion en dos pasos (2FA) con app autenticadora (TOTP). `totp_secret` se guarda desde que se empieza a activar,
// pero solo vale cuando `totp_enabled` = 1 (despues de confirmar con un codigo). `totp_last_step` evita reusar un codigo.
for (const [name, definition] of [
  ['totp_secret', 'TEXT'],
  ['totp_enabled', 'INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1))'],
  ['totp_last_step', 'INTEGER'],
] as const) {
  if (!columns.some((c) => c.name === name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${definition}`)
}

// Codigos de recuperacion del 2FA: de un solo uso y guardados como hash (nunca en claro).
db.exec(`
  CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);
`)

// Passkeys (huella, rostro o PIN del dispositivo). Solo se guarda la clave publica: la privada nunca sale del equipo.
db.exec(`
  CREATE TABLE IF NOT EXISTS passkeys (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   BLOB NOT NULL,
    counter      INTEGER NOT NULL DEFAULT 0,
    transports   TEXT,
    name         TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
`)

// Clientes del CRM. `created_by` queda en NULL si se borra la cuenta que lo creo.
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT,
    phone      TEXT,
    company    TEXT,
    notes      TEXT,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at);
`)

// Categoria del cliente: se calcula sola a partir del plan de mantenimiento contratado
// (routes/clients.ts). Se guarda en su propia columna para poder filtrar e indexar.
const clientColumns = db.pragma('table_info(clients)') as { name: string }[]
if (!clientColumns.some((c) => c.name === 'category')) {
  db.exec(
    `ALTER TABLE clients ADD COLUMN category TEXT NOT NULL DEFAULT 'bronze' CHECK (category IN ('bronze', 'silver', 'gold', 'diamond'))`,
  )
}

// Plan de mantenimiento contratado (NULL = todavia no tiene ninguno).
if (!clientColumns.some((c) => c.name === 'maintenance_plan')) {
  db.exec(
    `ALTER TABLE clients ADD COLUMN maintenance_plan TEXT CHECK (maintenance_plan IN ('static', 'server', 'crmb', 'crmf'))`,
  )
}

/** Minusculas y sin tildes: "nunez" encuentra "Núñez". */
export const normalizeText = (s: string): string =>
  s
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase()

/** Todo lo "personal" que se puede buscar de un cliente, ya normalizado (telefono tal cual y solo digitos). */
export function clientSearchText(c: {
  name: string
  company?: string | null
  email?: string | null
  phone?: string | null
  notes?: string | null
}): string {
  return normalizeText(
    [c.name, c.company, c.email, c.phone, c.phone?.replace(/\D/g, ''), c.notes].filter(Boolean).join(' '),
  )
}

// Texto de busqueda precalculado: asi la busqueda se hace en el servidor y la web solo pide una pagina.
if (!clientColumns.some((c) => c.name === 'search_text')) {
  db.exec(`ALTER TABLE clients ADD COLUMN search_text TEXT NOT NULL DEFAULT ''`)
  const rows = db.prepare('SELECT id, name, company, email, phone, notes FROM clients').all() as {
    id: number
    name: string
    company: string | null
    email: string | null
    phone: string | null
    notes: string | null
  }[]
  const update = db.prepare('UPDATE clients SET search_text = ? WHERE id = ?')
  db.transaction(() => {
    for (const r of rows) update.run(clientSearchText(r), r.id)
  })()
}

db.exec('CREATE INDEX IF NOT EXISTS idx_clients_category ON clients(category, id)')

// "Posible cliente": alguien que pidio una cotizacion pero todavia no es cliente. Los que ya existian quedan como clientes (0).
if (!clientColumns.some((c) => c.name === 'prospect')) {
  db.exec('ALTER TABLE clients ADD COLUMN prospect INTEGER NOT NULL DEFAULT 0 CHECK (prospect IN (0, 1))')
}

// Costo cotizado del mantenimiento: mensual, en centavos (entero, sin errores de redondeo) y con su moneda.
// NULL = todavia no se cotizo.
if (!clientColumns.some((c) => c.name === 'maintenance_price')) {
  db.exec('ALTER TABLE clients ADD COLUMN maintenance_price INTEGER CHECK (maintenance_price IS NULL OR maintenance_price >= 0)')
}
if (!clientColumns.some((c) => c.name === 'maintenance_currency')) {
  db.exec(`ALTER TABLE clients ADD COLUMN maintenance_currency TEXT NOT NULL DEFAULT 'ARS' CHECK (maintenance_currency IN ('ARS', 'USD'))`)
}

// Pagos / cobros. Importes en centavos. `method` y `provider_ref` dejan lista la integracion con Mercado Pago:
// el webhook buscara el pago por `provider_ref` (id de la preferencia o suscripcion) y lo marcara como pagado.
// RESTRICT: un cliente con pagos no se puede borrar (es historial contable).
db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    concept      TEXT NOT NULL DEFAULT '',
    amount       INTEGER NOT NULL CHECK (amount > 0),
    currency     TEXT NOT NULL DEFAULT 'ARS' CHECK (currency IN ('ARS', 'USD')),
    due_date     TEXT NOT NULL,                  -- AAAA-MM-DD
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid')),
    paid_at      TEXT,
    method       TEXT CHECK (method IN ('manual', 'mercadopago')),
    provider_ref TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, due_date);
  CREATE INDEX IF NOT EXISTS idx_payments_client ON payments(client_id);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_provider ON payments(provider_ref) WHERE provider_ref IS NOT NULL;
`)

// Debito automatico: una suscripcion de Mercado Pago por cliente (la vigente es la ultima no cancelada).
// `mp_id` es el id de la suscripcion (preapproval) en Mercado Pago. Importes en centavos de ARS.
// Al borrar el cliente se borran sus suscripciones; sus pagos quedan como historial (subscription_id pasa a NULL).
db.exec(`
  CREATE TABLE IF NOT EXISTS subscriptions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id         INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    mp_id             TEXT NOT NULL UNIQUE,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'paused', 'cancelled')),
    amount            INTEGER NOT NULL CHECK (amount > 0),
    init_point        TEXT,                          -- link donde el cliente ingresa su tarjeta
    next_payment_date TEXT,                          -- AAAA-MM-DD, segun Mercado Pago
    created_by        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_subscriptions_client ON subscriptions(client_id);
`)

// Cada cobro automatico pertenece a una suscripcion; `rejected` marca el intento que el banco rechazo (sigue pendiente).
const paymentColumns = db.pragma('table_info(payments)') as { name: string }[]
if (!paymentColumns.some((c) => c.name === 'subscription_id')) {
  db.exec('ALTER TABLE payments ADD COLUMN subscription_id INTEGER REFERENCES subscriptions(id) ON DELETE SET NULL')
}
if (!paymentColumns.some((c) => c.name === 'rejected')) {
  db.exec('ALTER TABLE payments ADD COLUMN rejected INTEGER NOT NULL DEFAULT 0 CHECK (rejected IN (0, 1))')
}
// Un solo cobro por suscripcion y vencimiento: asi un aviso repetido o la conciliacion nunca duplican.
db.exec(
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_sub_due ON payments(subscription_id, due_date) WHERE subscription_id IS NOT NULL',
)

// Tablero de tareas (compartido por todos los administradores).
// `position` es un numero real: para soltar una tarjeta entre dos vecinas se usa el punto medio,
// asi mover una tarjeta cambia UNA sola fila y no hay que renumerar la columna.
db.exec(`
  CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'doing', 'done')),
    position    REAL NOT NULL,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, position);
`)

// Cada tarea pertenece a un cliente. La columna admite NULL solo para las tareas que se crearon antes de esta regla
// (la API exige cliente al crear y al editar, asi que se les asigna uno la primera vez que se tocan). RESTRICT: un
// cliente con tareas no se puede borrar, para que ninguna quede huerfana.
const taskColumns = db.pragma('table_info(tasks)') as { name: string }[]
if (!taskColumns.some((c) => c.name === 'client_id')) {
  db.exec('ALTER TABLE tasks ADD COLUMN client_id INTEGER REFERENCES clients(id) ON DELETE RESTRICT')
}
db.exec('CREATE INDEX IF NOT EXISTS idx_tasks_client ON tasks(client_id)')

// Registro de errores (del servidor y de la web). Los iguales se agrupan por `fingerprint` y suben `count`.
// Nunca guarda cuerpos de peticiones: solo el mensaje, el detalle tecnico y donde ocurrio (ya enmascarados).
db.exec(`
  CREATE TABLE IF NOT EXISTS error_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    source      TEXT NOT NULL CHECK (source IN ('server', 'web')),
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    status      INTEGER,
    user_email  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    ref         TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_error_log_seen ON error_log(last_seen DESC);
`)

// Formularios de relevamiento: un enlace por cliente (token aleatorio) que el cliente completa para contar que necesita.
// `answers` y `result` son JSON. Si se borra el cliente se borran tambien sus formularios.
db.exec(`
  CREATE TABLE IF NOT EXISTS forms (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT NOT NULL UNIQUE,
    client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'submitted')),
    answers      TEXT,
    result       TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL,
    submitted_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_forms_client ON forms(client_id);
`)

export type Role = 'admin' | 'user'
export type Lang = 'en' | 'es'
export type Theme = 'light' | 'dark'

export interface UserRow {
  id: number
  email: string
  password_hash: string
  created_at: string
  role: Role
  lang: Lang | null
  theme: Theme | null
  is_super: 0 | 1
  first_name: string | null
  last_name: string | null
  avatar: string | null
  avatar_at: number | null
  banned: 0 | 1
  suspended_until: number | null
  must_change_password: 0 | 1
  totp_secret: string | null
  totp_enabled: 0 | 1
  totp_last_step: number | null
}

// Costos fijos del negocio (hosting, dominios, herramientas, sueldos...). Importes en centavos de ARS.
// El dashboard los resta de lo cobrado para mostrar ganancias y perdidas mes a mes.
//  - monthly: se paga todos los meses entre `start_month` y `end_month` (NULL = sigue vigente).
//  - yearly:  se paga una vez por ano; en el dashboard se reparte en 12 partes (un doceavo por mes) para no dar saltos.
//  - once:    un gasto unico, cuenta solo en `start_month`.
db.exec(`
  CREATE TABLE IF NOT EXISTS expenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    amount      INTEGER NOT NULL CHECK (amount > 0),
    frequency   TEXT NOT NULL DEFAULT 'monthly' CHECK (frequency IN ('monthly', 'yearly', 'once')),
    start_month TEXT NOT NULL,                   -- AAAA-MM
    end_month   TEXT,                            -- AAAA-MM o NULL
    note        TEXT NOT NULL DEFAULT '',
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_expenses_start ON expenses(start_month);
`)

// Precios editables desde el CRM y promociones. Importes en centavos de ARS.
//  - price_overrides: precio de lista que reemplaza al que trae la web por defecto (si no hay fila, se usa el de la web).
//  - promotions: descuento en porcentaje sobre los productos elegidos (`products` = lista JSON), con fechas opcionales.
//    La web muestra el precio de lista tachado y el precio con descuento.
db.exec(`
  CREATE TABLE IF NOT EXISTS price_overrides (
    product    TEXT PRIMARY KEY,
    amount     INTEGER NOT NULL CHECK (amount > 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  CREATE TABLE IF NOT EXISTS promotions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    percent    INTEGER NOT NULL CHECK (percent BETWEEN 1 AND 90),
    products   TEXT NOT NULL,                    -- JSON: ["landing","store",...]
    starts_on  TEXT,                             -- AAAA-MM-DD o NULL (ya empezo)
    ends_on    TEXT,                             -- AAAA-MM-DD o NULL (sin fin)
    active     INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
`)
