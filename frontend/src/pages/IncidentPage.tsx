import { useState } from 'react'
import { ArrowLeft, Download, RotateCw } from 'lucide-react'

import { IncidentStatusLabel, SeverityLabel, StatusLabel, TechniqueLink } from '@/components/labels'
import { LogEvent, LogMessage } from '@/components/LogParts'
import { Message } from '@/components/Message'
import { SummaryCard } from '@/components/SummaryCard'
import { Timestamp } from '@/components/Timestamp'
import { Button } from '@/components/ui/button'
import { getIncident, getIncidentSummary, getReport, type Incident, type IncidentDetail } from '@/lib/api'
import { plural, sameDay, SEVERITY_STYLE, timeBetween, whoAndWhere } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// One incident: the alerts of one attack in the order they happened, what
// they add up to, the AI's summary, and the report to hand to a manager.
export default function IncidentPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad((signal) => getIncident(id, signal))

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <a href="#/incidents" className="text-link inline-flex min-h-11 items-center gap-1.5 text-sm sm:min-h-0">
        <ArrowLeft aria-hidden className="size-4" />
        Back to incidents
      </a>
      {error ? (
        <div className="panel mt-4">
          <Message title="This incident could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        </div>
      ) : data === null ? (
        <div className="panel mt-4">
          <Message title="Loading the incident…" />
        </div>
      ) : (
        <Details detail={data} />
      )}
    </div>
  )
}

function Details({ detail }: { detail: IncidentDetail }) {
  const { incident, techniques, indicators } = detail
  return (
    <>
      <div className="mt-3 flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
        <div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            <span className="flex items-center gap-1.5">
              <SeverityLabel severity={incident.severity} />
              <span className="text-muted-foreground">severity incident</span>
            </span>
            <IncidentStatusLabel status={incident.status} />
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Incident #{incident.id}</h1>
          <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
            {plural(incident.alerts, 'alert')} involving {whoAndWhere(incident.users, incident.hosts)}, over{' '}
            {timeBetween(incident.start_time, incident.end_time)}. They share a host or a user and happened close
            together, so they are treated as one attack.
          </p>
        </div>
        <DownloadReport incident={incident} />
      </div>

      <div className="mt-6 grid grid-cols-1 items-start gap-4 lg:grid-cols-3">
        <div className="grid min-w-0 grid-cols-1 gap-4 lg:col-span-2">
          <Timeline detail={detail} />
          <SummaryCard incident={incident} />
        </div>

        <div className="grid min-w-0 grid-cols-1 gap-4">
          <section aria-labelledby="facts-heading" className="panel p-5 text-sm">
            <h2 id="facts-heading" className="text-base font-medium">
              Details
            </h2>
            <dl className="mt-3 grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-2.5">
              <dt className="text-muted-foreground">First alert</dt>
              <dd>
                <Timestamp iso={incident.start_time} inline />
              </dd>
              <dt className="text-muted-foreground">Last alert</dt>
              <dd>
                <Timestamp iso={incident.end_time} inline />
              </dd>
              <dt className="text-muted-foreground">Duration</dt>
              <dd>{timeBetween(incident.start_time, incident.end_time)}</dd>
              <dt className="text-muted-foreground">Hosts</dt>
              <dd className="wrap-anywhere">{incident.hosts.join(', ') || 'None identified'}</dd>
              <dt className="text-muted-foreground">Users</dt>
              <dd className="wrap-anywhere">{incident.users.join(', ')}</dd>
              <dt className="text-muted-foreground">Alerts</dt>
              <dd>
                {incident.alerts}
                <span className="text-muted-foreground">
                  {incident.open_alerts === 0
                    ? ', all decided'
                    : incident.open_alerts === incident.alerts
                      ? ', none decided yet'
                      : `, ${incident.open_alerts} still undecided`}
                </span>
              </dd>
            </dl>
            <p className="mt-4 border-t pt-3 text-muted-foreground">
              {incident.status === 'Open'
                ? 'The incident closes by itself when every one of its alerts has been closed.'
                : 'Every alert has been closed. A new alert on the same host or user would reopen it.'}
            </p>
          </section>

          <section aria-labelledby="indicators-heading" className="panel p-5 text-sm">
            <h2 id="indicators-heading" className="text-base font-medium">
              Indicators of compromise
            </h2>
            {indicators.length === 0 ? (
              <p className="mt-1 text-muted-foreground">
                No outside addresses, files or new accounts appear in the evidence of these alerts.
              </p>
            ) : (
              <>
                <p className="mt-1 text-muted-foreground">
                  Evidence to search other machines for, or to block. Each is shown as plain text so it cannot be
                  opened by accident.
                </p>
                {/* Log text, so plain text only. These are never made into links. */}
                <dl className="mt-3 grid gap-2.5">
                  {indicators.map((indicator) => (
                    <div key={`${indicator.kind} ${indicator.value}`}>
                      <dt className="text-xs text-muted-foreground">{indicator.kind}</dt>
                      <dd className="font-mono text-xs leading-5 wrap-anywhere">{indicator.value}</dd>
                    </div>
                  ))}
                </dl>
              </>
            )}
          </section>

          <section aria-labelledby="techniques-heading" className="panel p-5 text-sm">
            <h2 id="techniques-heading" className="text-base font-medium">
              ATT&amp;CK techniques
            </h2>
            <p className="mt-1 text-muted-foreground">The methods the alerts point to, and how many alerts each.</p>
            <ul className="mt-2 grid">
              {techniques.map((technique) => (
                <li key={technique.id} className="flex min-h-11 items-center justify-between gap-3 sm:min-h-8">
                  <TechniqueLink id={technique.id} name={technique.name} roomy />
                  <span className="text-muted-foreground tabular-nums" title={plural(technique.alerts, 'alert')}>
                    {technique.alerts}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>
    </>
  )
}

// The incident's PDF report. Pressing the button asks for the AI summary
// first (it is usually stored already), so the report never goes out
// without the text the card on this page shows.
function DownloadReport({ incident }: { incident: Incident }) {
  const [building, setBuilding] = useState(false)
  const [error, setError] = useState('')

  async function download() {
    setBuilding(true)
    setError('')
    try {
      // If the AI cannot answer, the report is still made, from the alert data.
      await getIncidentSummary(incident.id).catch(() => null)
      const file = URL.createObjectURL(await getReport(incident.id))
      // The browser saves a file when a link with "download" is clicked.
      const link = document.createElement('a')
      link.href = file
      link.download = `sentinel-incident-${incident.id}.pdf`
      link.click()
      // The file in memory is let go once the browser has had time to save it.
      setTimeout(() => URL.revokeObjectURL(file), 10_000)
    } catch (problem) {
      setError((problem as Error).message)
    } finally {
      setBuilding(false)
    }
  }

  return (
    <div className="max-sm:w-full sm:max-w-xs sm:text-right">
      <Button onClick={download} disabled={building} className="max-sm:w-full">
        <Download aria-hidden />
        {building ? 'Building the report…' : 'Download report'}
      </Button>
      <p aria-live="polite" className={`mt-2 text-xs ${error ? 'text-error' : 'text-muted-foreground'}`}>
        {error ||
          'A PDF for a manager: summary, timeline, affected hosts and users, indicators, techniques and recommended actions.'}
      </p>
    </div>
  )
}

// The timeline: every alert in the order it happened, one step each. Each
// step leads with its ATT&CK tactic, the attacker's goal at that moment.
function Timeline({ detail }: { detail: IncidentDetail }) {
  const { incident, timeline } = detail
  // An alert closed as a false positive does not count as part of the
  // attack, unless every alert was one (the same rule the server uses).
  const allFalse = timeline.every((step) => step.alert.status === 'Closed as false positive')
  const reached = new Set<string>() // the tactics seen so far, going down the timeline

  return (
    <section aria-labelledby="timeline-heading" className="panel p-5">
      <h2 id="timeline-heading" className="font-medium">
        Timeline
      </h2>
      <p className="mt-1 max-w-[70ch] text-sm text-muted-foreground">
        {timeline.length === 1
          ? 'The one alert in this incident, with the log line that set it off.'
          : `The ${timeline.length} alerts in the order they happened, each with the log line that set it off.`}{' '}
        A tactic is the attacker&apos;s goal at that step. It is marked in teal where the attack reaches it for the
        first time.
      </p>

      {/* How far the attack got, at a glance: the tactics in the order it reached them. */}
      <ol aria-label="ATT&CK tactics, in the order the attack reached them" className="mt-4 flex flex-wrap gap-1.5">
        {incident.tactics.map((tactic, index) => (
          <li key={tactic} className="flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs">
            <span className="font-semibold text-primary tabular-nums">{index + 1}</span>
            {tactic}
          </li>
        ))}
      </ol>

      <ol className="mt-6">
        {timeline.map(({ alert, evidence }, index) => {
          const counts = allFalse || alert.status !== 'Closed as false positive'
          const tactics = alert.attack_tactics.map((tactic) => {
            const first = counts && !reached.has(tactic)
            if (first) reached.add(tactic)
            return { tactic, first }
          })
          const previous = index > 0 ? timeline[index - 1].alert : null
          const isLast = index === timeline.length - 1
          const gap =
            previous && (previous.time === alert.time ? 'Same moment' : `${timeBetween(previous.time, alert.time)} later`)
          // The date is shown on the first step, and again only if a step falls on a new day.
          const timeOnly = previous !== null && sameDay(previous.time, alert.time)

          return (
            <li
              key={alert.id}
              className={`grid grid-cols-[1rem_minmax(0,1fr)] gap-x-3 sm:grid-cols-[5.5rem_1rem_minmax(0,1fr)] sm:gap-x-4 ${counts ? '' : 'opacity-60'}`}
            >
              {/* When: the time, and how long after the step before. */}
              <div className="hidden text-right text-sm sm:block">
                <Timestamp iso={alert.time} timeOnly={timeOnly} />
                {gap && <span className="block text-xs text-muted-foreground">{gap}</span>}
              </div>

              {/* The rail: a dot in the severity's colour, on a line that
                  runs from the first step to the last. */}
              <div aria-hidden className="relative flex justify-center">
                {timeline.length > 1 && (
                  <span
                    className={`absolute w-px bg-border ${index === 0 ? 'top-2' : 'top-0'} ${isLast ? 'h-2' : 'bottom-0'}`}
                  />
                )}
                <span
                  className={`relative mt-1 size-2.5 rounded-full ring-4 ring-card ${SEVERITY_STYLE[alert.severity].dot}`}
                />
              </div>

              <div className={`min-w-0 ${isLast ? '' : 'pb-7'}`}>
                <p className="text-xs text-muted-foreground tabular-nums sm:hidden">
                  <Timestamp iso={alert.time} inline timeOnly={timeOnly} />
                  {gap && <span className="ml-2">{gap}</span>}
                </p>
                <p className="flex flex-wrap gap-x-3 text-sm max-sm:mt-1">
                  {tactics.map(({ tactic, first }) => (
                    <span key={tactic} className={first ? 'font-medium text-primary' : 'text-muted-foreground'}>
                      {tactic}
                      {first && <span className="sr-only"> (reached for the first time)</span>}
                    </span>
                  ))}
                </p>
                <h3 className="mt-0.5 font-medium text-balance">
                  <a href={`#/alerts/${alert.id}`} className="text-link text-foreground hover:text-primary">
                    {alert.title}
                  </a>
                </h3>
                <p className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                  <SeverityLabel severity={alert.severity} />
                  <StatusLabel status={alert.status} />
                  <span className="text-muted-foreground">
                    {alert.user} on {alert.host}
                  </span>
                </p>
                {evidence && (
                  <div className="mt-2.5 rounded-md border bg-background/50 px-3 py-2">
                    <p className="text-xs">
                      <span className="text-muted-foreground">{evidence.source} </span>
                      <LogEvent log={evidence} />
                      {alert.log_ids.length > 1 && (
                        <span className="text-muted-foreground">
                          , the last of {alert.log_ids.length} matching log lines
                        </span>
                      )}
                    </p>
                    <LogMessage message={evidence.message} />
                  </div>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
