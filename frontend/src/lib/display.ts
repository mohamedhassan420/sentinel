// Small lookups shared by several pages.

import type { Log, Severity } from '@/lib/api'

// Where Sentinel's code lives. The About page and the footer link to it.
export const SOURCE_URL = 'https://github.com/mohamedhassan420/sentinel'

// Each severity has its own colour, used for a dot beside the word and a
// stripe down a table row's left edge. The word is always shown too, so
// nothing depends on telling colours apart.
export const SEVERITY_STYLE: Record<Severity, { dot: string; edge: string }> = {
  Low: { dot: 'bg-severity-low', edge: 'border-l-severity-low' },
  Medium: { dot: 'bg-severity-medium', edge: 'border-l-severity-medium' },
  High: { dot: 'bg-severity-high', edge: 'border-l-severity-high' },
  Critical: { dot: 'bg-severity-critical', edge: 'border-l-severity-critical' },
}

// "T1566.001" -> https://attack.mitre.org/techniques/T1566/001/
export function techniqueUrl(technique: string) {
  return `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`
}

// Plain-English names for the event types, keyed by "source:event ID" because
// each tool numbers its own events (Sysmon's event 1 is not Windows' event 1).
// Firewalls and mail gateways have no event IDs, hence "null".
const EVENT_NAMES: Record<string, string> = {
  'Windows Security:4624': 'Logon succeeded',
  'Windows Security:4625': 'Logon failed',
  'Windows Security:4720': 'Account created',
  'Windows Security:4732': 'Added to a local group',
  'Sysmon:1': 'Process started',
  'Sysmon:3': 'Network connection',
  'PowerShell:4104': 'Script block',
  'Firewall:null': 'Connection closed',
  'Email Gateway:null': 'Message delivered',
}

export function eventName(log: Log) {
  return EVENT_NAMES[`${log.source}:${log.event_id}`]
}

export function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

// The time from one moment to another in words: "9 s", "28 min", "1 h 5 min".
export function timeBetween(startIso: string, endIso: string) {
  const seconds = Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min`
  return minutes % 60 === 0 ? `${minutes / 60} h` : `${Math.floor(minutes / 60)} h ${minutes % 60} min`
}

// "a.khan on WKS-FIN-03": who and where, for an incident's one-line description.
export function whoAndWhere(users: string[], hosts: string[]) {
  if (hosts.length === 0) return users.join(', ')
  return `${users.join(', ')} on ${hosts.join(', ')}`
}

// Do two times from the server fall on the same day, where the reader is?
export function sameDay(iso: string, otherIso: string) {
  return new Date(iso).toDateString() === new Date(otherIso).toDateString()
}
