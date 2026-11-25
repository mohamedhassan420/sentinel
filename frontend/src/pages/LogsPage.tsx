import { useEffect, useState } from 'react'
import { RotateCw, Search, X } from 'lucide-react'

import { LogEvent, LogMessage } from '@/components/LogParts'
import { Message } from '@/components/Message'
import { Select } from '@/components/Select'
import { Timestamp } from '@/components/Timestamp'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getFilterOptions, getLogs, type FilterOptions, type Log, type LogFilters, type LogPage } from '@/lib/api'
import { plural } from '@/lib/display'
import { scenarioLabel } from '@/lib/scenarios'

const NO_FILTERS: LogFilters = { q: '', source: '', event_id: '', scenario: '', host: '', user: '' }

export default function LogsPage() {
  const [filters, setFilters] = useState(NO_FILTERS)
  const [options, setOptions] = useState<FilterOptions>({ sources: [], event_ids: [], scenarios: [] })
  const [page, setPage] = useState<LogPage | null>(null)
  const [error, setError] = useState('')
  // Adding 1 to this number makes the effects below fetch again.
  const [reload, setReload] = useState(0)
  // "Loading" means the newest request (these filters, this reload) has not
  // been answered yet.
  const requestKey = JSON.stringify(filters) + reload
  const [answeredKey, setAnsweredKey] = useState('')
  const loading = answeredKey !== requestKey

  // Fetch logs whenever the filters change. If the filters change again
  // before the answer arrives, the old request is cancelled.
  useEffect(() => {
    const controller = new AbortController()
    getLogs(filters, controller.signal)
      .then((result) => {
        setPage(result)
        setError('')
        setAnsweredKey(requestKey)
      })
      .catch((problem: Error) => {
        if (problem.name === 'AbortError') return
        setError(problem.message)
        setAnsweredKey(requestKey)
      })
    return () => controller.abort()
  }, [filters, reload, requestKey])

  // The dropdown choices come from what is actually stored. If this fails,
  // the logs request above fails too and shows the error.
  useEffect(() => {
    getFilterOptions().then(setOptions).catch(() => {})
  }, [reload])

  function setFilter(name: keyof LogFilters, value: string) {
    setFilters((current) => ({ ...current, [name]: value }))
  }

  const isFiltered = Object.values(filters).some((value) => value !== '')

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Logs</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        Every line the simulator has written, newest first. A log only records that something happened. Deciding
        whether it matters is the detection engine's job.
      </p>

      <form
        role="search"
        aria-label="Filter logs"
        onSubmit={(event) => event.preventDefault()}
        className="mt-5 grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-[minmax(0,2fr)_repeat(5,minmax(0,1fr))_auto]"
      >
        <div className="relative col-span-2 md:col-span-3 lg:col-span-1">
          <Search
            aria-hidden
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            type="search"
            aria-label="Search message text"
            placeholder="Search message text"
            maxLength={200}
            value={filters.q}
            onChange={(event) => setFilter('q', event.target.value)}
            className="pl-8"
          />
        </div>
        <Select label="Source" labelHidden value={filters.source} onChange={(v) => setFilter('source', v)}>
          <option value="">All sources</option>
          {options.sources.map((source) => (
            <option key={source}>{source}</option>
          ))}
        </Select>
        <Select label="Event ID" labelHidden value={filters.event_id} onChange={(v) => setFilter('event_id', v)}>
          <option value="">All event IDs</option>
          {options.event_ids.map((id) => (
            <option key={id}>{id}</option>
          ))}
        </Select>
        <Select label="Scenario" labelHidden value={filters.scenario} onChange={(v) => setFilter('scenario', v)}>
          <option value="">All scenarios</option>
          {options.scenarios.map((id) => (
            <option key={id} value={id}>
              {scenarioLabel(id)}
            </option>
          ))}
        </Select>
        <Input
          aria-label="Host contains"
          placeholder="Host"
          maxLength={100}
          value={filters.host}
          onChange={(event) => setFilter('host', event.target.value)}
        />
        <Input
          aria-label="User contains"
          placeholder="User"
          maxLength={100}
          value={filters.user}
          onChange={(event) => setFilter('user', event.target.value)}
        />
        <Button
          type="button"
          variant="ghost"
          disabled={!isFiltered}
          onClick={() => setFilters(NO_FILTERS)}
        >
          <X aria-hidden />
          Clear filters
        </Button>
      </form>

      {/* How many lines are listed, said before the list, not after it. */}
      <p role="status" className="mt-4 min-h-5 text-sm text-muted-foreground">
        {page !== null &&
          page.total > 0 &&
          !error &&
          (page.logs.length < page.total
            ? `Showing the newest ${page.logs.length} of ${page.total} log lines. Filter to narrow them down.`
            : plural(page.total, 'log line'))}
      </p>

      <div className="panel mt-2 overflow-clip">
        {error ? (
          <Message title="The logs could not be loaded" detail={error}>
            <Button variant="outline" onClick={() => setReload((n) => n + 1)}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        ) : page === null ? (
          <Message title="Loading logs…" />
        ) : page.total === 0 && isFiltered ? (
          <Message title="No logs match these filters" detail="Loosen or clear the filters above to see more." />
        ) : page.total === 0 ? (
          <Message
            title="No logs yet"
            detail="Run a scenario on the dashboard to write an attack's log lines, hidden among normal activity. The detection rules check them as they arrive."
          >
            <Button asChild>
              <a href="#/">Go to the dashboard</a>
            </Button>
          </Message>
        ) : (
          <div aria-busy={loading} className={loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-20 sm:w-24">Time</TableHead>
                  <TableHead className="hidden w-44 sm:table-cell">Event</TableHead>
                  <TableHead className="hidden w-32 lg:table-cell">Host</TableHead>
                  <TableHead className="hidden w-24 lg:table-cell">User</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead className="hidden w-36 lg:table-cell">Scenario</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {page.logs.map((log) => (
                  <LogRow key={log.id} log={log} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}

function LogRow({ log }: { log: Log }) {
  const isAttack = log.scenario !== 'background'
  return (
    <TableRow className="[&>td]:align-top">
      <TableCell className="tabular-nums">
        <Timestamp iso={log.time} />
      </TableCell>
      <TableCell className="hidden whitespace-normal sm:table-cell">
        <LogEvent log={log} />
        <span className="block text-xs text-muted-foreground">{log.source}</span>
      </TableCell>
      <TableCell className="hidden truncate lg:table-cell">{log.host}</TableCell>
      <TableCell className="hidden truncate lg:table-cell">{log.user}</TableCell>
      <TableCell className="whitespace-normal">
        {/* Phones have no room for an Event column, so it moves in here. */}
        <span className="mb-1 block sm:hidden">
          <LogEvent log={log} />
        </span>
        <LogMessage message={log.message} />
        {/* Until the screen is wide enough for their own columns. */}
        <span className="mt-1 block text-xs text-muted-foreground lg:hidden">
          {log.user} on {log.host}
          {isAttack && <span className="text-foreground"> ({scenarioLabel(log.scenario)})</span>}
        </span>
      </TableCell>
      <TableCell className="hidden lg:table-cell">
        {isAttack ? (
          <span className="rounded-sm border border-input px-1.5 py-0.5 text-xs">{scenarioLabel(log.scenario)}</span>
        ) : (
          <span className="text-xs text-muted-foreground">Background</span>
        )}
      </TableCell>
    </TableRow>
  )
}
