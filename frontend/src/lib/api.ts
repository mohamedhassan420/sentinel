// Everything the frontend asks the backend for goes through this file.

export type Log = {
  id: number
  time: string // ISO 8601, UTC
  host: string
  user: string
  source: string
  event_id: number | null // firewalls and mail gateways do not number their events
  message: string
  fields: Record<string, string | number> // the same details by name; rules test these
  scenario: string
}

export type LogPage = { total: number; logs: Log[] }

// All values are strings because they come straight from form controls.
// An empty string means "no filter".
export type LogFilters = {
  q: string
  source: string
  event_id: string
  scenario: string
  host: string
  user: string
}

export type FilterOptions = { sources: string[]; event_ids: number[]; scenarios: string[] }

export type RunResult = { added: number; attack: number; background: number; alerts: number }

// Most urgent first: the order the dashboard and the filters list them in.
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const
export type Severity = (typeof SEVERITIES)[number]

// The life of an alert, in order. The backend accepts exactly these four.
export const STATUSES = ['New', 'In progress', 'Closed as true positive', 'Closed as false positive'] as const
export type Status = (typeof STATUSES)[number]
// "Open" means nobody has decided yet.
export const OPEN_STATUSES: Status[] = ['New', 'In progress']

export type Alert = {
  id: number
  time: string // when the last matching log happened
  rule_id: string
  title: string
  severity: Severity
  attack_tactics: string[] // the attacker's goal, e.g. "Credential Access"
  attack_techniques: string[] // the method, e.g. "T1110"
  host: string
  user: string
  log_ids: number[] // the logs that made the rule fire
  status: Status
}

export type AlertPage = { total: number; alerts: Alert[] }

export type Technique = { id: string; name: string }

export type Rule = {
  name: string // the rule's file name without ".yml"; alerts call it rule_id
  title: string
  description: string
  severity: Severity
  tactics: string[]
  techniques: Technique[]
  log_source: string
  false_positives: string[]
}

// Everything on a rule's Explain page.
export type RuleDetail = Rule & {
  yaml_text: string // the rule file exactly as written
  explanation: {
    attack: string
    log_shows: string
    why: string
    security_plus: { topic: string; text: string }
  }
}

export type AlertDetail = { alert: Alert; logs: Log[]; rule: Rule | null }

export type Dashboard = {
  open_by_severity: Record<Severity, number>
  by_status: Record<Status, number>
  tactics: { tactic: string; alerts: number }[] // all 14, in the order an attack moves
  techniques: (Technique & { alerts: number })[] // only the ones seen
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, init)
  } catch (error) {
    if ((error as Error).name === 'AbortError') throw error
    throw new Error('Could not reach the Sentinel server. Check it is running, then try again.')
  }
  if (response.status === 404) throw new Error('The Sentinel server has nothing at this address.')
  if (!response.ok) throw new Error(`The Sentinel server answered with an error (${response.status}).`)
  return response.json()
}

export function getLogs(filters: LogFilters, signal: AbortSignal) {
  const active = Object.entries(filters).filter(([, value]) => value !== '')
  return request<LogPage>(`/api/logs?${new URLSearchParams(active)}`, { signal })
}

export function getFilterOptions() {
  return request<FilterOptions>('/api/logs/filters')
}

export function runScenario(scenario: string) {
  return request<RunResult>(`/api/simulate/${scenario}`, { method: 'POST' })
}

export function getAlerts(
  filters: { statuses?: readonly Status[]; severity?: Severity; limit?: number },
  signal: AbortSignal,
) {
  const params = new URLSearchParams()
  for (const status of filters.statuses ?? []) params.append('status', status)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.limit) params.set('limit', String(filters.limit))
  return request<AlertPage>(`/api/alerts?${params}`, { signal })
}

export function getAlert(id: number, signal: AbortSignal) {
  return request<AlertDetail>(`/api/alerts/${id}`, { signal })
}

export function setAlertStatus(id: number, status: Status) {
  return request<Alert>(`/api/alerts/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
}

export function getDashboard(signal: AbortSignal) {
  return request<Dashboard>('/api/dashboard', { signal })
}

export function getRules(signal: AbortSignal) {
  return request<Rule[]>('/api/rules', { signal })
}

export function getRule(name: string, signal: AbortSignal) {
  return request<RuleDetail>(`/api/rules/${encodeURIComponent(name)}`, { signal })
}
