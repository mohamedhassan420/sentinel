import { useState } from 'react'
import { ArrowLeft, RotateCw } from 'lucide-react'

import { SeverityLabel, TechniqueLink } from '@/components/labels'
import { LogEvent, LogMessage } from '@/components/LogParts'
import { Message } from '@/components/Message'
import { Timestamp } from '@/components/Timestamp'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getAlert, setAlertStatus, STATUSES, type Alert, type AlertDetail, type Status } from '@/lib/api'
import { plural } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// One alert: what fired, why, the logs that prove it, and the analyst's decision.
export default function AlertPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad((signal) => getAlert(id, signal))

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <a href="#/alerts" className="text-link inline-flex min-h-11 items-center gap-1.5 text-sm sm:min-h-0">
        <ArrowLeft aria-hidden className="size-4" />
        Back to alerts
      </a>
      {error ? (
        <div className="panel mt-4">
          <Message title="This alert could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        </div>
      ) : data === null ? (
        <div className="panel mt-4">
          <Message title="Loading the alert…" />
        </div>
      ) : (
        <Details detail={data} />
      )}
    </div>
  )
}

function Details({ detail }: { detail: AlertDetail }) {
  const { logs, rule } = detail
  // The alert as last saved. It starts as what the server sent and is
  // replaced by the server's answer each time the status changes.
  const [alert, setAlert] = useState(detail.alert)

  return (
    <>
      {/* A flex row, so the dot, the word and the rest sit on one line. */}
      <div className="mt-3 flex items-center gap-1.5 text-sm">
        <SeverityLabel severity={alert.severity} /> <span className="text-muted-foreground">severity alert</span>
      </div>
      <h1 className="mt-1 text-2xl font-semibold tracking-tight text-balance">{alert.title}</h1>

      <div className="mt-6 grid grid-cols-1 items-start gap-4 lg:grid-cols-3">
        <div className="grid min-w-0 grid-cols-1 gap-4 lg:col-span-2">
          <section aria-labelledby="why-heading" className="panel p-5">
            <h2 id="why-heading" className="font-medium">
              Why this fired
            </h2>
            {rule ? (
              <>
                <p className="mt-2 max-w-[70ch] text-sm leading-6">{rule.description}</p>
                <a href={`#/rules/${rule.name}`} className="text-link mt-3 inline-flex min-h-11 items-center text-sm sm:min-h-0">
                  Read how this rule works
                </a>
              </>
            ) : (
              <p className="mt-2 text-sm text-muted-foreground">
                The rule that raised this alert ({alert.rule_id}) is no longer installed, so its explanation is not
                available. The evidence below is unchanged.
              </p>
            )}
          </section>

          <section aria-labelledby="evidence-heading" className="panel overflow-clip">
            <div className="p-5 pb-3">
              <h2 id="evidence-heading" className="font-medium">
                Evidence
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {logs.length === 1
                  ? 'The log line that made the rule fire.'
                  : `The ${logs.length} log lines that made the rule fire, oldest first.`}{' '}
                Select a message to read all of it.
              </p>
            </div>
            <div className="border-t">
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-20 pl-5 sm:w-28">Time</TableHead>
                    <TableHead className="hidden w-44 sm:table-cell">Event</TableHead>
                    <TableHead>Message</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((log) => (
                    <TableRow key={log.id} className="[&>td]:align-top">
                      <TableCell className="pl-5 tabular-nums">
                        <Timestamp iso={log.time} />
                      </TableCell>
                      <TableCell className="hidden whitespace-normal sm:table-cell">
                        <LogEvent log={log} />
                        <span className="block text-xs text-muted-foreground">{log.source}</span>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <span className="mb-1 block sm:hidden">
                          <LogEvent log={log} />
                        </span>
                        <LogMessage message={log.message} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </section>
        </div>

        <div className="grid min-w-0 grid-cols-1 gap-4">
          <StatusPicker alert={alert} onSaved={setAlert} />

          <section aria-labelledby="facts-heading" className="panel p-5 text-sm">
            <h2 id="facts-heading" className="text-base font-medium">
              Details
            </h2>
            <dl className="mt-3 grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-2.5">
              <dt className="text-muted-foreground">Time</dt>
              <dd>
                <Timestamp iso={alert.time} inline />
              </dd>
              <dt className="text-muted-foreground">Host</dt>
              <dd className="wrap-anywhere">{alert.host}</dd>
              <dt className="text-muted-foreground">User</dt>
              <dd className="wrap-anywhere">{alert.user}</dd>
              <dt className="text-muted-foreground">Log source</dt>
              <dd>{rule?.log_source ?? logs[0]?.source}</dd>
              <dt className="text-muted-foreground">Evidence</dt>
              <dd>{plural(alert.log_ids.length, 'log line')}</dd>
              <dt className="text-muted-foreground">Tactic</dt>
              <dd>{alert.attack_tactics.join(', ')}</dd>
              <dt className="text-muted-foreground">Technique</dt>
              <dd className="grid gap-1">
                {(rule?.techniques ?? alert.attack_techniques.map((technique) => ({ id: technique, name: '' }))).map(
                  (technique) => (
                    <span key={technique.id}>
                      <TechniqueLink id={technique.id} name={technique.name} roomy />
                    </span>
                  ),
                )}
              </dd>
            </dl>
          </section>

          {rule && rule.false_positives.length > 0 && (
            <section aria-labelledby="rule-out-heading" className="panel p-5 text-sm">
              <h2 id="rule-out-heading" className="text-base font-medium">
                Harmless causes to rule out
              </h2>
              <p className="mt-1 text-muted-foreground">
                If one of these explains the evidence, close the alert as a false positive.
              </p>
              <ul className="mt-3 grid list-disc gap-2 pl-5 marker:text-muted-foreground">
                {rule.false_positives.map((cause) => (
                  <li key={cause}>{cause}</li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>
    </>
  )
}

// The four statuses as one set of radio buttons. Picking one saves it at once.
function StatusPicker({ alert, onSaved }: { alert: Alert; onSaved: (alert: Alert) => void }) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function change(status: Status) {
    setSaving(true)
    setError('')
    try {
      onSaved(await setAlertStatus(alert.id, status))
    } catch (problem) {
      setError(`The status was not saved. ${(problem as Error).message}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="panel p-5">
      <fieldset disabled={saving} className="min-w-0">
        <legend className="font-medium">Status</legend>
        <div className="mt-3 grid gap-1.5">
          {STATUSES.map((status) => (
            <label
              key={status}
              className="flex min-h-11 cursor-pointer items-center gap-3 rounded-md border px-3 text-sm transition-colors hover:bg-muted has-checked:border-primary has-checked:bg-primary/10 has-focus-visible:ring-2 has-focus-visible:ring-ring has-disabled:cursor-wait sm:min-h-10"
            >
              <input
                type="radio"
                name="status"
                checked={alert.status === status}
                onChange={() => change(status)}
                className="size-4 accent-primary outline-none"
              />
              {status}
            </label>
          ))}
        </div>
      </fieldset>
      <p aria-live="polite" className={`mt-3 text-sm ${error ? 'text-error' : 'text-muted-foreground'}`}>
        {error ||
          'A true positive was a real attack. A false positive was harmless activity the rule mistook for one.'}
      </p>
    </section>
  )
}
