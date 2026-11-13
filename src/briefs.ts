/**
 * Formularios de relevamiento: el cliente cuenta que necesita (sin elegir un plan) y el sistema deduce que tipo de
 * servicio le corresponde. Los criterios viven aca, en un solo lugar, para poder ajustarlos facil.
 */

export const plans = ['static', 'server', 'crmb', 'crmf'] as const
export type BriefPlan = (typeof plans)[number]

type Kind = 'static' | 'dynamic' | 'crm' | 'none'
/** `pts` = peso en la complejidad; `kind` = que tipo de servicio exige como minimo ('none' = no define el servicio). */
type Weight = { pts: number; kind: Kind }

/** Que necesita que haga el sistema. */
export const features = {
  showcase: { pts: 0, kind: 'static' },
  contact: { pts: 0, kind: 'static' },
  content: { pts: 1, kind: 'dynamic' },
  notifications: { pts: 1, kind: 'dynamic' },
  booking: { pts: 2, kind: 'dynamic' },
  shop: { pts: 3, kind: 'dynamic' },
  customers: { pts: 3, kind: 'crm' },
  accounts: { pts: 3, kind: 'crm' },
  pipeline: { pts: 3, kind: 'crm' },
  billing: { pts: 3, kind: 'crm' },
  integrations: { pts: 3, kind: 'crm' },
  tasks: { pts: 2, kind: 'crm' },
  reports: { pts: 2, kind: 'crm' },
  roles: { pts: 2, kind: 'crm' },
} as const satisfies Record<string, Weight>

/** Secciones del menu lateral del sistema. Tener un menu con secciones ya es una aplicacion con datos (CRM). */
export const tabs = {
  dashboard: { pts: 1, kind: 'crm' },
  clients: { pts: 2, kind: 'crm' },
  payments: { pts: 2, kind: 'crm' },
  tasks: { pts: 2, kind: 'crm' },
  reports: { pts: 2, kind: 'crm' },
  calendar: { pts: 2, kind: 'crm' },
  products: { pts: 2, kind: 'crm' },
  sales: { pts: 2, kind: 'crm' },
  invoices: { pts: 2, kind: 'crm' },
  documents: { pts: 1, kind: 'crm' },
  messages: { pts: 2, kind: 'crm' },
  support: { pts: 2, kind: 'crm' },
  team: { pts: 2, kind: 'crm' },
  settings: { pts: 0, kind: 'crm' },
} as const satisfies Record<string, Weight>

/** Seguridad y acceso: todo esto presupone usuarios con cuenta. */
export const security = {
  twofa: { pts: 1, kind: 'crm' },
  fingerprint: { pts: 1, kind: 'crm' },
  autosignout: { pts: 0, kind: 'crm' },
  sessions: { pts: 0, kind: 'crm' },
  activity: { pts: 1, kind: 'crm' },
  backups: { pts: 1, kind: 'crm' },
} as const satisfies Record<string, Weight>

/** Idioma y apariencia: no definen por si solos el tipo de servicio (una web tambien puede tenerlos). */
export const prefs = {
  lang_es: { pts: 0, kind: 'none' },
  lang_en: { pts: 0, kind: 'none' },
  theme: { pts: 1, kind: 'none' },
} as const satisfies Record<string, Weight>

/** Datos y herramientas. */
export const tools = {
  export: { pts: 1, kind: 'crm' },
  import: { pts: 1, kind: 'crm' },
  search: { pts: 1, kind: 'crm' },
  attachments: { pts: 1, kind: 'crm' },
  pdf: { pts: 1, kind: 'crm' },
  realtime: { pts: 1, kind: 'crm' },
  mobile: { pts: 1, kind: 'none' },
  branding: { pts: 1, kind: 'none' },
} as const satisfies Record<string, Weight>

export type FeatureId = keyof typeof features
export type TabId = keyof typeof tabs
export type SecurityId = keyof typeof security
export type PrefId = keyof typeof prefs
export type ToolId = keyof typeof tools

const ids = <T extends object>(o: T) => Object.keys(o) as [keyof T & string, ...(keyof T & string)[]]
export const featureIds = ids(features)
export const tabIds = ids(tabs)
export const securityIds = ids(security)
export const prefIds = ids(prefs)
export const toolIds = ids(tools)

/** Cuanta gente usara el sistema / cuantos registros manejara. */
export const userScale = { solo: 0, small: 1, medium: 2, large: 3 } as const
export const recordScale = { few: 0, some: 1, many: 2 } as const
export const timelines = ['flexible', 'months', 'urgent'] as const
export const devices = ['computer', 'phone', 'tablet'] as const
export const haveNeedUnsure = ['have', 'need', 'unsure'] as const
export const maintenanceInterest = ['yes', 'maybe', 'no'] as const

export type UserScale = keyof typeof userScale
export type RecordScale = keyof typeof recordScale

export interface BriefAnswers {
  business: string
  goals: string
  features: FeatureId[]
  /** Secciones del menu que quiere tener. */
  tabs: TabId[]
  security: SecurityId[]
  prefs: PrefId[]
  tools: ToolId[]
  /** "Agregar otro": cosas que el formulario no ofrece, escritas por el cliente. */
  featuresExtra: string[]
  /** Idiomas que el formulario no ofrece (ademas de espanol e ingles). */
  languagesExtra: string[]
  tabsExtra: string[]
  securityExtra: string[]
  prefsExtra: string[]
  toolsExtra: string[]
  users: UserScale
  records: RecordScale
  migrate: boolean
  devices: (typeof devices)[number][]
  branding: (typeof haveNeedUnsure)[number]
  domain: (typeof haveNeedUnsure)[number]
  maintenance: (typeof maintenanceInterest)[number]
  timeline: (typeof timelines)[number]
  budget: string
  notes: string
}

export interface BriefResult {
  plan: BriefPlan
  /** Complejidad total (suma de todo lo que marco + escala). */
  score: number
  /** Lo que mas peso, de mayor a menor. Cada uno es "grupo.id" (por ejemplo "tab.reports"); los formularios viejos traen solo el id de una funcion. */
  reasons: string[]
  /** Por que se eligio ese plan (clave corta que la web traduce). */
  rule: 'info_only' | 'dynamic' | 'crm' | 'crm_full'
}

/** Con este puntaje (o mas) un CRM pasa de basico a completo. */
const BIG_SCORE = 26

/**
 * Criterio:
 *  1. Solo muestra informacion / recibe consultas            -> web estatica
 *  2. Necesita algo dinamico (reservas, tienda, avisos...)    -> web con servidor
 *  3. Necesita gestionar datos o usuarios (clientes, cobros,
 *     menu con secciones, seguridad de acceso...)             -> CRM basico
 *  4. ...y ademas es grande (muchas secciones o funciones,
 *     mucha gente o datos, o se conecta con otros sistemas)   -> CRM completo
 * Lo que el cliente escribe a mano ("agregar otro") no cambia el tipo de servicio, pero suma complejidad.
 */
export function classify(a: BriefAnswers): BriefResult {
  const uniq = <T>(list: readonly T[] | undefined): T[] => [...new Set(list ?? [])]
  const groups = [
    { prefix: 'f', picked: uniq(a.features), table: features as Record<string, Weight> },
    { prefix: 'tab', picked: uniq(a.tabs), table: tabs as Record<string, Weight> },
    { prefix: 'sec', picked: uniq(a.security), table: security as Record<string, Weight> },
    { prefix: 'pref', picked: uniq(a.prefs), table: prefs as Record<string, Weight> },
    { prefix: 'tool', picked: uniq(a.tools), table: tools as Record<string, Weight> },
  ]
  const items = groups.flatMap((g) =>
    g.picked.map((id) => ({ key: `${g.prefix}.${id}`, group: g.prefix, id: String(id), ...g.table[String(id)] })),
  )

  const extras = Math.min(5, [a.featuresExtra, a.languagesExtra, a.tabsExtra, a.securityExtra, a.prefsExtra, a.toolsExtra].reduce((n, l) => n + (l?.length ?? 0), 0))
  const langs = uniq(a.prefs)
  const bothLanguages = langs.includes('lang_es') && langs.includes('lang_en')
  const score =
    items.reduce((sum, i) => sum + i.pts, 0) +
    extras +
    (bothLanguages ? 1 : 0) +
    userScale[a.users] +
    recordScale[a.records] +
    (a.migrate ? 1 : 0)

  const reasons = items
    .filter((i) => i.pts > 0)
    .sort((x, y) => y.pts - x.pts)
    .slice(0, 5)
    .map((i) => i.key)

  const crm = items.filter((i) => i.kind === 'crm')
  const dynamic = items.filter((i) => i.kind === 'dynamic')

  if (crm.length === 0 && dynamic.length === 0) return { plan: 'static', score, reasons, rule: 'info_only' }
  if (crm.length === 0) return { plan: 'server', score, reasons, rule: 'dynamic' }

  const crmFeatures = items.filter((i) => i.group === 'f' && i.kind === 'crm').length
  const tabCount = items.filter((i) => i.group === 'tab').length
  const picked = (id: string) => items.some((i) => i.id === id)
  const big =
    score >= BIG_SCORE ||
    crmFeatures >= 5 ||
    tabCount >= 8 ||
    (a.users === 'large' && tabCount >= 5) ||
    (picked('integrations') && (a.users !== 'solo' || picked('roles')))
  return big ? { plan: 'crmf', score, reasons, rule: 'crm_full' } : { plan: 'crmb', score, reasons, rule: 'crm' }
}
