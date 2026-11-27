import { Circle, CircleCheck, CircleDashed, CircleSlash } from 'lucide-react'

import type { Severity, Status } from '@/lib/api'
import { SEVERITY_STYLE, techniqueUrl } from '@/lib/display'

// A coloured dot and the word. The word is what carries the meaning.
export function SeverityLabel({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-2 font-medium">
      <span aria-hidden className={`size-2 shrink-0 rounded-full ${SEVERITY_STYLE[severity].dot}`} />
      {severity}
    </span>
  )
}

const STATUS_ICON = {
  New: Circle,
  'In progress': CircleDashed,
  'Closed as true positive': CircleCheck,
  'Closed as false positive': CircleSlash,
}

// Open alerts read in the main text colour; closed ones step back.
export function StatusLabel({ status }: { status: Status }) {
  const Icon = STATUS_ICON[status]
  const closed = status.startsWith('Closed')
  return (
    <span className={`inline-flex items-start gap-1.5 ${closed ? 'text-muted-foreground' : ''}`}>
      {/* Sized in "em" so the icon follows the size of the text beside it. */}
      <Icon aria-hidden className={`mt-[0.15em] size-[1.15em] shrink-0 ${status === 'New' ? 'text-primary' : ''}`} />
      {status}
    </span>
  )
}

// An incident is Open while any of its alerts still needs a decision.
export function IncidentStatusLabel({ status }: { status: 'Open' | 'Closed' }) {
  const Icon = status === 'Open' ? Circle : CircleCheck
  return (
    <span className={`inline-flex items-start gap-1.5 ${status === 'Closed' ? 'text-muted-foreground' : ''}`}>
      <Icon aria-hidden className={`mt-[0.15em] size-[1.15em] shrink-0 ${status === 'Open' ? 'text-primary' : ''}`} />
      {status}
    </span>
  )
}

// An ATT&CK technique ID that opens MITRE's page about it in a new tab.
// `roomy` gives it a taller tap area on phones without moving anything: the
// extra padding is cancelled by an equal negative margin.
export function TechniqueLink({ id, name, roomy }: { id: string; name?: string; roomy?: boolean }) {
  return (
    <a
      href={techniqueUrl(id)}
      target="_blank"
      rel="noreferrer"
      title={`Read about ${id} on attack.mitre.org (opens in a new tab)`}
      className={`text-link ${roomy ? 'max-sm:-my-3 max-sm:inline-block max-sm:py-3' : ''}`}
    >
      <span className="tabular-nums">{id}</span>
      {name && ` ${name}`}
    </a>
  )
}
