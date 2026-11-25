import { useState } from 'react'

import type { Log } from '@/lib/api'
import { eventName } from '@/lib/display'

// The event's number and plain-English name, with the tool that wrote it underneath.
export function LogEvent({ log }: { log: Log }) {
  return (
    <>
      {log.event_id !== null && <span className="tabular-nums">{log.event_id} </span>}
      <span className={log.event_id === null ? undefined : 'text-muted-foreground'}>{eventName(log)}</span>
    </>
  )
}

// The raw log text: two lines until clicked, then the whole message.
// It is shown as plain text. React escapes it, so log content can never run
// as HTML or script in the page.
export function LogMessage({ message }: { message: string }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <button
      type="button"
      onClick={() => setExpanded(!expanded)}
      aria-expanded={expanded}
      title={expanded ? 'Show less' : 'Show the full message'}
      className="block w-full cursor-pointer rounded-sm py-0.5 text-left font-mono text-xs leading-5 text-foreground/85 outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <span className={`wrap-anywhere ${expanded ? 'block whitespace-pre-wrap' : 'line-clamp-2'}`}>{message}</span>
    </button>
  )
}
