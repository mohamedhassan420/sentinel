import { RotateCw, X } from 'lucide-react'

import { AlertTable } from '@/components/AlertTable'
import { Message } from '@/components/Message'
import { Select } from '@/components/Select'
import { Button } from '@/components/ui/button'
import { getAlerts, OPEN_STATUSES, SEVERITIES, STATUSES, type Status } from '@/lib/api'
import { plural } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// The alert queue. The filters live in the address (#/alerts?severity=High),
// so the dashboard can link straight to a filtered queue and the browser's
// Back button undoes a filter change.
export default function AlertsPage({ params }: { params: URLSearchParams }) {
  // Anything in the address that is not a real status or severity is ignored.
  const status = [...STATUSES, 'all'].find((value) => value === params.get('status')) ?? 'open'
  const severity = SEVERITIES.find((value) => value === params.get('severity')) ?? ''
  const isFiltered = status !== 'open' || severity !== ''

  const statuses = status === 'open' ? OPEN_STATUSES : status === 'all' ? [] : [status as Status]
  const { data, error, loading, reload } = useLoad(
    (signal) => getAlerts({ statuses, severity: severity || undefined }, signal),
    `${status}|${severity}`,
  )

  function setFilter(name: 'status' | 'severity', value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    window.location.hash = `#/alerts${next.size ? `?${next}` : ''}`
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        An alert is a detection rule saying these logs look like an attack and a person should check. Open one to see
        its evidence and decide whether it is real.
      </p>

      <form
        role="search"
        aria-label="Filter alerts"
        onSubmit={(event) => event.preventDefault()}
        className="mt-5 grid grid-cols-[1fr_1fr_auto] items-end gap-2 sm:grid-cols-[14rem_14rem_auto] sm:justify-start"
      >
        <Select label="Status" value={status === 'open' ? '' : status} onChange={(v) => setFilter('status', v)}>
          <option value="">Open alerts</option>
          {STATUSES.map((value) => (
            <option key={value}>{value}</option>
          ))}
          <option value="all">All alerts</option>
        </Select>
        <Select label="Severity" value={severity} onChange={(v) => setFilter('severity', v)}>
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value}>{value}</option>
          ))}
        </Select>
        <Button
          type="button"
          variant="ghost"
          disabled={!isFiltered}
          onClick={() => (window.location.hash = '#/alerts')}
          className="max-sm:w-11"
        >
          <X aria-hidden />
          {/* Phones show only the cross; a screen reader still reads the words. */}
          <span className="max-sm:sr-only">Clear filters</span>
        </Button>
      </form>

      {/* How many alerts are listed, said before the list, not after it. */}
      <p role="status" className="mt-4 min-h-5 text-sm text-muted-foreground">
        {data !== null &&
          data.total > 0 &&
          !error &&
          (data.alerts.length < data.total
            ? `Showing the newest ${data.alerts.length} of ${data.total} alerts. Filter to narrow them down.`
            : `${plural(data.total, 'alert')}, newest first`)}
      </p>

      <div className="panel mt-2 overflow-clip">
        {error ? (
          <Message title="The alerts could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        ) : data === null ? (
          <Message title="Loading alerts…" />
        ) : data.total === 0 && isFiltered ? (
          <Message title="No alerts match these filters" detail="Loosen or clear the filters above to see more." />
        ) : data.total === 0 ? (
          <Message
            title="No open alerts"
            detail="Alerts appear when the detection rules match new logs. Run a scenario on the dashboard to write some, or change the status filter to see closed alerts."
          >
            <Button asChild>
              <a href="#/">Go to the dashboard</a>
            </Button>
          </Message>
        ) : (
          <div aria-busy={loading} className={loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
            <AlertTable alerts={data.alerts} />
          </div>
        )}
      </div>
    </div>
  )
}
