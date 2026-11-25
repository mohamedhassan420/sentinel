import { useEffect, useState } from 'react'
import { Play, RotateCw, Search, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  getFilterOptions,
  getLogs,
  runScenario,
  type FilterOptions,
  type Log,
  type LogFilters,
  type LogPage,
} from '@/lib/api'

const NO_FILTERS: LogFilters = { q: '', source: '', event_id: '', scenario: '', host: '', user: '' }

// Plain-English names for the event IDs, keyed by "source:event ID" because
// each tool numbers its own events (Sysmon's event 1 is not Windows' event 1).
const EVENT_NAMES: Record<string, string> = {
  'Windows Security:4624': 'Logon succeeded',
  'Windows Security:4625': 'Logon failed',
  'Sysmon:1': 'Process started',
}

const dateFormat = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short' })
const timeFormat = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

// "brute_force" -> "Brute force"
function scenarioLabel(scenario: string) {
  const words = scenario.replaceAll('_', ' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}

export default function LogsPage() {
  const [filters, setFilters] = useState(NO_FILTERS)
  const [options, setOptions] = useState<FilterOptions>({ sources: [], event_ids: [], scenarios: [] })
  const [page, setPage] = useState<LogPage | null>(null)
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)
  const [notice, setNotice] = useState({ text: '', isError: false })
  const [expandedId, setExpandedId] = useState<number | null>(null)
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

  async function runBruteForce() {
    setRunning(true)
    setNotice({ text: '', isError: false })
    try {
      const result = await runScenario('brute_force')
      setNotice({
        text: `Added ${result.added} log lines: ${result.attack} from the attack and ${result.background} of normal background activity.`,
        isError: false,
      })
      setReload((n) => n + 1)
    } catch (problem) {
      setNotice({ text: (problem as Error).message, isError: true })
    } finally {
      setRunning(false)
    }
  }

  function setFilter(name: keyof LogFilters, value: string) {
    setFilters((current) => ({ ...current, [name]: value }))
  }

  const isFiltered = Object.values(filters).some((value) => value !== '')

  const runButton = (
    <Button onClick={runBruteForce} disabled={running}>
      <Play aria-hidden />
      {running ? 'Writing logs…' : 'Run brute force'}
    </Button>
  )

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Logs</h1>
          <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
            Every line the simulator has written, newest first. A log only records that something happened. Deciding
            whether it matters is the detection engine's job.
          </p>
        </div>
        {runButton}
      </div>

      <p
        aria-live="polite"
        className={`mt-3 min-h-5 text-sm ${notice.isError ? 'text-destructive' : 'text-muted-foreground'}`}
      >
        {notice.text}
      </p>

      <form
        role="search"
        aria-label="Filter logs"
        onSubmit={(event) => event.preventDefault()}
        className="mt-3 grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-[minmax(0,2fr)_repeat(5,minmax(0,1fr))_auto]"
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
        <FilterSelect label="Source" allLabel="All sources" value={filters.source} onChange={(v) => setFilter('source', v)}>
          {options.sources.map((source) => (
            <option key={source}>{source}</option>
          ))}
        </FilterSelect>
        <FilterSelect label="Event ID" allLabel="All event IDs" value={filters.event_id} onChange={(v) => setFilter('event_id', v)}>
          {options.event_ids.map((id) => (
            <option key={id}>{id}</option>
          ))}
        </FilterSelect>
        <FilterSelect label="Scenario" allLabel="All scenarios" value={filters.scenario} onChange={(v) => setFilter('scenario', v)}>
          {options.scenarios.map((scenario) => (
            <option key={scenario} value={scenario}>
              {scenarioLabel(scenario)}
            </option>
          ))}
        </FilterSelect>
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
          className="col-span-2 md:col-span-3 lg:col-span-1"
        >
          <X aria-hidden />
          Clear filters
        </Button>
      </form>

      <div className="mt-4 overflow-hidden rounded-lg border bg-card">
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
          <Message title="No logs match these filters" detail="Loosen or clear the filters to see more.">
            <Button variant="outline" onClick={() => setFilters(NO_FILTERS)}>
              Clear filters
            </Button>
          </Message>
        ) : page.total === 0 ? (
          <Message
            title="No logs yet"
            detail="Run the brute force scenario to write 40 failed logons and one success, hidden among normal activity."
          >
            {runButton}
          </Message>
        ) : (
          <div aria-busy={loading} className={loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-20 sm:w-24">Time</TableHead>
                  <TableHead className="hidden w-44 sm:table-cell">Event</TableHead>
                  <TableHead className="hidden w-32 md:table-cell">Host</TableHead>
                  <TableHead className="hidden w-24 md:table-cell">User</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead className="hidden w-28 lg:table-cell">Scenario</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {page.logs.map((log) => (
                  <LogRow
                    key={log.id}
                    log={log}
                    expanded={expandedId === log.id}
                    onToggle={() => setExpandedId(expandedId === log.id ? null : log.id)}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {page !== null && page.total > 0 && !error && (
        <p className="mt-3 text-sm text-muted-foreground">
          {page.logs.length < page.total
            ? `Showing the newest ${page.logs.length} of ${page.total} log lines. Filter to narrow them down.`
            : `${page.total} log ${page.total === 1 ? 'line' : 'lines'}`}
        </p>
      )}
    </div>
  )
}

function LogRow({ log, expanded, onToggle }: { log: Log; expanded: boolean; onToggle: () => void }) {
  const time = new Date(log.time)
  const isAttack = log.scenario !== 'background'
  const event = (
    <>
      <span className="tabular-nums">{log.event_id}</span>{' '}
      <span className="text-muted-foreground">{EVENT_NAMES[`${log.source}:${log.event_id}`]}</span>
    </>
  )
  return (
    <TableRow className="[&>td]:align-top">
      <TableCell className="tabular-nums">
        <time dateTime={log.time} title={time.toLocaleString()}>
          {timeFormat.format(time)}
          <span className="block text-xs text-muted-foreground">{dateFormat.format(time)}</span>
        </time>
      </TableCell>
      <TableCell className="hidden whitespace-normal sm:table-cell">
        {event}
        <span className="block text-xs text-muted-foreground">{log.source}</span>
      </TableCell>
      <TableCell className="hidden truncate md:table-cell">{log.host}</TableCell>
      <TableCell className="hidden truncate md:table-cell">{log.user}</TableCell>
      <TableCell className="whitespace-normal">
        {/* Phones have no room for an Event column, so it moves in here. */}
        <span className="mb-1 block sm:hidden">{event}</span>
        {/* The message is shown as plain text. React escapes it, so log
            content can never run as HTML or script in the page. */}
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          title={expanded ? 'Show less' : 'Show the full message'}
          className="block w-full cursor-pointer rounded-sm text-left font-mono text-xs leading-5 text-foreground/85 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {/* Two lines until clicked, then the whole message. */}
          <span className={`wrap-anywhere ${expanded ? 'block whitespace-pre-wrap' : 'line-clamp-2'}`}>
            {log.message}
          </span>
        </button>
        <span className="mt-1 block text-xs text-muted-foreground md:hidden">
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

function FilterSelect({
  label,
  allLabel,
  value,
  onChange,
  children,
}: {
  label: string
  allLabel: string
  value: string
  onChange: (value: string) => void
  children: React.ReactNode
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className="h-8 w-full min-w-0 rounded-lg border border-input bg-input/30 px-2 text-base outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 md:text-sm"
    >
      <option value="">{allLabel}</option>
      {children}
    </select>
  )
}

// The empty, loading and error states all share this layout.
function Message({ title, detail, children }: { title: string; detail?: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-16 text-center">
      <p className="font-medium">{title}</p>
      {detail && <p className="max-w-[50ch] text-sm text-muted-foreground">{detail}</p>}
      {children}
    </div>
  )
}
