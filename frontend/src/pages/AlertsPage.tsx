import { useEffect, useState } from 'react'
import { RotateCw } from 'lucide-react'

import { Message } from '@/components/Message'
import { Timestamp } from '@/components/Timestamp'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getAlerts, type Alert, type AlertPage, type Severity } from '@/lib/api'

// Each severity has its own colour, used for a dot beside the word and a
// stripe down the row's left edge. The word is always shown too, so nothing
// depends on telling colours apart.
const SEVERITY_STYLE: Record<Severity, { dot: string; edge: string }> = {
  Low: { dot: 'bg-severity-low', edge: 'border-l-severity-low' },
  Medium: { dot: 'bg-severity-medium', edge: 'border-l-severity-medium' },
  High: { dot: 'bg-severity-high', edge: 'border-l-severity-high' },
  Critical: { dot: 'bg-severity-critical', edge: 'border-l-severity-critical' },
}

// "T1566.001" -> https://attack.mitre.org/techniques/T1566/001/
function techniqueUrl(technique: string) {
  return `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`
}

export default function AlertsPage() {
  const [page, setPage] = useState<AlertPage | null>(null)
  const [error, setError] = useState('')
  // Adding 1 to this number makes the effect below fetch again.
  const [reload, setReload] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    getAlerts(controller.signal)
      .then((result) => {
        setPage(result)
        setError('')
      })
      .catch((problem: Error) => {
        if (problem.name !== 'AbortError') setError(problem.message)
      })
    return () => controller.abort()
  }, [reload])

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        An alert is a detection rule saying these logs look like an attack and a person should check. Each one names
        the MITRE ATT&amp;CK technique it points to.
      </p>

      <div className="mt-6 overflow-hidden rounded-lg border bg-card">
        {error ? (
          <Message title="The alerts could not be loaded" detail={error}>
            <Button variant="outline" onClick={() => setReload((n) => n + 1)}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        ) : page === null ? (
          <Message title="Loading alerts…" />
        ) : page.total === 0 ? (
          <Message
            title="No alerts yet"
            detail="Alerts appear when the detection rules match new logs. Run a scenario on the Logs page to write some."
          >
            <Button asChild>
              <a href="#/">Go to Logs</a>
            </Button>
          </Message>
        ) : (
          <Table className="table-fixed">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-20 pl-3 sm:w-24">Time</TableHead>
                <TableHead className="hidden w-24 sm:table-cell">Severity</TableHead>
                <TableHead>Alert</TableHead>
                <TableHead className="hidden w-56 lg:table-cell">ATT&amp;CK</TableHead>
                <TableHead className="hidden w-32 md:table-cell">Host</TableHead>
                <TableHead className="hidden w-24 md:table-cell">User</TableHead>
                <TableHead className="hidden w-20 text-right sm:table-cell">Evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.alerts.map((alert) => (
                <AlertRow key={alert.id} alert={alert} />
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {page !== null && page.total > 0 && !error && (
        <p className="mt-3 text-sm text-muted-foreground">
          {page.alerts.length < page.total
            ? `Showing the newest ${page.alerts.length} of ${page.total} alerts.`
            : `${page.total} ${page.total === 1 ? 'alert' : 'alerts'}, newest first`}
        </p>
      )}
    </div>
  )
}

function AlertRow({ alert }: { alert: Alert }) {
  const style = SEVERITY_STYLE[alert.severity]
  const severity = (
    <span className="inline-flex items-center gap-2 font-medium">
      <span aria-hidden className={`size-2 rounded-full ${style.dot}`} />
      {alert.severity}
    </span>
  )
  const techniques = (
    <>
      {alert.attack_techniques.map((technique) => (
        <a
          key={technique}
          href={techniqueUrl(technique)}
          target="_blank"
          rel="noreferrer"
          title={`Read about ${technique} on attack.mitre.org`}
          className="mr-2 rounded-sm tabular-nums text-primary underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
        >
          {technique}
        </a>
      ))}
      <span className="block text-xs text-muted-foreground">{alert.attack_tactics.join(', ')}</span>
    </>
  )
  const evidence = `${alert.log_ids.length} ${alert.log_ids.length === 1 ? 'log' : 'logs'}`

  return (
    <TableRow className="[&>td]:align-top">
      <TableCell className={`border-l-2 pl-2.5 tabular-nums ${style.edge}`}>
        <Timestamp iso={alert.time} />
      </TableCell>
      <TableCell className="hidden sm:table-cell">{severity}</TableCell>
      <TableCell className="whitespace-normal">
        {/* Phones have no room for the other columns, so their content moves in here. */}
        <span className="mb-1 block text-xs sm:hidden">{severity}</span>
        {alert.title}
        <span className="mt-1 block lg:hidden">{techniques}</span>
        <span className="mt-1 block text-xs text-muted-foreground md:hidden">
          {alert.user} on {alert.host}
          <span className="sm:hidden">, {evidence}</span>
        </span>
      </TableCell>
      <TableCell className="hidden whitespace-normal lg:table-cell">{techniques}</TableCell>
      <TableCell className="hidden truncate md:table-cell">{alert.host}</TableCell>
      <TableCell className="hidden truncate md:table-cell">{alert.user}</TableCell>
      <TableCell className="hidden text-right tabular-nums text-muted-foreground sm:table-cell">{evidence}</TableCell>
    </TableRow>
  )
}
