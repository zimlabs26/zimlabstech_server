import { db } from './db.js'
import { captureError } from './errorlog.js'
import { MpError, mpDownload, mpEnabled, mpRequest } from './mercadopago.js'

/**
 * Saldo e ingresos reales de la cuenta de Mercado Pago, a partir del "reporte de dinero liberado".
 * Mercado Pago no tiene una API de saldo, asi que se piden reportes (de menos de 90 dias cada uno), se descargan en CSV
 * y se calcula:
 *  - Saldo disponible: el BALANCE_AMOUNT del ultimo movimiento (coincide con la fila "total" del reporte).
 *  - Ingresos de cada mes: lo que entro como "payment" (pagos, transferencias, dinero en cuenta).
 * Todo es de SOLO LECTURA sobre el dinero: solo se piden y descargan reportes. Los importes se guardan en centavos.
 * Un reporte tarda varios minutos en generarse, por eso corre en segundo plano y el resultado queda guardado.
 */

db.exec(`
  CREATE TABLE IF NOT EXISTS mp_summary (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
`)

export interface MpSummary {
  /** Saldo disponible en centavos de ARS. */
  balance: number
  /** Hasta cuando llega la informacion (ISO). */
  asOf: string
  /** Ingresos por mes (AAAA-MM), en centavos: lo que entro como pago o transferencia. */
  income: Record<string, number>
  /** Rendimientos de la cuenta por mes, en centavos (aparte de los ingresos). */
  yields: Record<string, number>
  updatedAt: string
}

const KEY = 'release'
const STALE_MS = 6 * 3600_000
const DAY = 86_400_000

export const getMpSummary = (): MpSummary | null => {
  const row = db.prepare('SELECT value FROM mp_summary WHERE key = ?').get(KEY) as { value: string } | undefined
  return row ? (JSON.parse(row.value) as MpSummary) : null
}

/** Hace mas de 6 horas que no se actualiza (o nunca se hizo). */
export const isStale = (s: MpSummary | null) => !s || Date.now() - Date.parse(s.updatedAt) > STALE_MS

let running: Promise<void> | null = null
export const isSyncing = () => running !== null
let lastFailure = 0
/** Tras un fallo no se reintenta por 15 minutos (no insistir contra la API ni llenar el registro de errores). */
export const canRetry = () => Date.now() - lastFailure > 15 * 60_000

/* ---------- CSV ---------- */

/** Divide una linea CSV respetando comillas. */
function splitCsv(line: string): string[] {
  const out: string[] = []
  let cur = ''
  let quoted = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"'
        i++
      } else if (c === '"') quoted = false
      else cur += c
    } else if (c === '"') quoted = true
    else if (c === ',') {
      out.push(cur)
      cur = ''
    } else cur += c
  }
  out.push(cur)
  return out
}

const cents = (v: string | undefined) => {
  const n = Number.parseFloat(v ?? '')
  return Number.isFinite(n) ? Math.round(n * 100) : 0
}

export interface ParsedReport {
  /** Saldo al final del periodo (centavos), si el reporte lo trae. */
  balance: number | null
  income: Record<string, number>
  yields: Record<string, number>
}

/** Lee un reporte de dinero liberado (CSV con encabezados) y calcula saldo e ingresos por mes. */
export function parseReleaseCsv(csv: string): ParsedReport {
  const lines = csv.replace(/^﻿/, '').split(/\r?\n/).filter((l) => l.trim())
  const header = splitCsv(lines[0] ?? '')
  const ix = (name: string) => header.indexOf(name)
  const iDate = ix('DATE')
  const iType = ix('RECORD_TYPE')
  const iDesc = ix('DESCRIPTION')
  const iCredit = ix('NET_CREDIT_AMOUNT')
  const iBalance = ix('BALANCE_AMOUNT')
  if ([iDate, iType, iDesc, iCredit, iBalance].some((i) => i < 0)) throw new Error('El reporte de Mercado Pago no trae las columnas esperadas')

  const out: ParsedReport = { balance: null, income: {}, yields: {} }
  let totalRow: number | null = null
  for (const line of lines.slice(1)) {
    const r = splitCsv(line)
    const type = r[iType]
    if (type === 'total') {
      totalRow = cents(r[iCredit])
      continue
    }
    if (type === 'initial_available_balance') {
      if (out.balance === null) out.balance = cents(r[iBalance])
      continue
    }
    if (type !== 'release') continue
    out.balance = cents(r[iBalance]) // el saldo corrido despues de cada movimiento: el ultimo es el actual
    const month = (r[iDate] ?? '').slice(0, 7)
    const credit = cents(r[iCredit])
    if (!/^\d{4}-\d{2}$/.test(month) || credit <= 0) continue
    if (r[iDesc] === 'payment') out.income[month] = (out.income[month] ?? 0) + credit
    else if (r[iDesc] === 'asset_management') out.yields[month] = (out.yields[month] ?? 0) + credit
  }
  if (totalRow !== null) out.balance = totalRow // la fila "total" es el saldo neto del periodo
  return out
}

/* ---------- Pedido de reportes ---------- */

const CONFIG = {
  file_name_prefix: 'zimlabs-movimientos',
  include_withdrawal_at_end: true,
  execute_after_withdrawal: false,
  check_available_balance: true,
  compensate_detail: false,
  display_timezone: 'GMT-03',
  separator: ',',
  report_translation: 'en',
  scheduled: false,
  frequency: { hour: 0, type: 'monthly', value: 1 },
  columns: ['DATE', 'SOURCE_ID', 'EXTERNAL_REFERENCE', 'RECORD_TYPE', 'DESCRIPTION', 'NET_CREDIT_AMOUNT', 'NET_DEBIT_AMOUNT', 'GROSS_AMOUNT', 'MP_FEE_AMOUNT', 'TAXES_AMOUNT', 'BALANCE_AMOUNT', 'PAYMENT_METHOD_TYPE', 'CURRENCY'].map((key) => ({ key })),
}

/** La configuracion de reportes se crea una sola vez por cuenta; si ya existe no se toca. */
async function ensureConfig(): Promise<void> {
  try {
    await mpRequest('GET', '/v1/account/release_report/config')
  } catch (error) {
    if (!(error instanceof MpError) || error.status !== 404) throw error
    await mpRequest('POST', '/v1/account/release_report/config', CONFIG)
  }
}

const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z')

/** Tramos seguidos, sin solaparse, de menos de 90 dias, desde el primer dia del mes de hace 5 meses hasta ahora. */
function windows(now: Date): [Date, Date][] {
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 5, 1)
  const out: [Date, Date][] = []
  for (let begin = start; begin < now.getTime(); ) {
    const end = Math.min(begin + 84 * DAY - 1000, now.getTime())
    out.push([new Date(begin), new Date(end)])
    begin = end + 1000
  }
  return out
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** Pide un reporte, espera a que termine (varios minutos) y devuelve su CSV. */
async function fetchReport(begin: Date, end: Date): Promise<string> {
  const task = await mpRequest<{ id: number }>('POST', '/v1/account/release_report', { begin_date: iso(begin), end_date: iso(end) })
  const deadline = Date.now() + 20 * 60_000
  while (Date.now() < deadline) {
    await sleep(10_000)
    const status = await mpRequest<{ status?: string; file_name?: string | null }>('GET', `/v1/account/release_report/task/${task.id}`)
    if (status.file_name) return mpDownload(`/v1/account/release_report/${encodeURIComponent(status.file_name)}`)
    if (['error', 'failed', 'cancelled'].includes(status.status ?? '')) throw new Error(`El reporte de Mercado Pago fallo (${status.status})`)
  }
  throw new Error('El reporte de Mercado Pago tardo demasiado en generarse')
}

async function run(): Promise<void> {
  await ensureConfig()
  const now = new Date()
  const parts = windows(now)
  // Los tramos se piden juntos: cada uno tarda unos minutos y asi se generan en paralelo.
  const reports = await Promise.all(parts.map(([b, e]) => fetchReport(b, e).then(parseReleaseCsv)))
  const income: Record<string, number> = {}
  const yields: Record<string, number> = {}
  for (const r of reports) {
    for (const [m, v] of Object.entries(r.income)) income[m] = (income[m] ?? 0) + v
    for (const [m, v] of Object.entries(r.yields)) yields[m] = (yields[m] ?? 0) + v
  }
  const balance = reports[reports.length - 1]?.balance ?? 0
  const summary: MpSummary = { balance, asOf: iso(now), income, yields, updatedAt: new Date().toISOString() }
  db.prepare(
    "INSERT INTO mp_summary (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
  ).run(KEY, JSON.stringify(summary))
}

/** Actualiza el saldo y los ingresos en segundo plano. Si ya hay una actualizacion en curso, no hace otra. */
export function startSync(): void {
  if (running || !mpEnabled()) return
  running = run()
    .catch((error) => {
      lastFailure = Date.now()
      captureError(error, { kind: 'mercadopago', message: 'No se pudo actualizar el saldo desde los reportes de Mercado Pago', path: '/api/dashboard/balance', method: 'GET', alert: false })
    })
    .finally(() => {
      running = null
    })
}
