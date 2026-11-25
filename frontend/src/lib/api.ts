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

export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

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
  status: string
}

export type AlertPage = { total: number; alerts: Alert[] }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, init)
  } catch (error) {
    if ((error as Error).name === 'AbortError') throw error
    throw new Error('Could not reach the Sentinel server. Check it is running, then try again.')
  }
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

export function getAlerts(signal: AbortSignal) {
  return request<AlertPage>('/api/alerts', { signal })
}
