import { RotateCw } from 'lucide-react'

import { AlertTable } from '@/components/AlertTable'
import { SeverityLabel, StatusLabel, TechniqueLink } from '@/components/labels'
import { Message } from '@/components/Message'
import { RunScenario } from '@/components/RunScenario'
import { Button } from '@/components/ui/button'
import { getAlerts, getDashboard, OPEN_STATUSES, SEVERITIES, STATUSES, type Dashboard } from '@/lib/api'
import { plural, SEVERITY_STYLE } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// The home page: what is waiting for an analyst, and how far the attacks got.
export default function DashboardPage() {
  // Two questions for the server, asked together so the page fills in one go.
  const { data, error, loading, reload } = useLoad((signal) =>
    Promise.all([getDashboard(signal), getAlerts({ statuses: OPEN_STATUSES, limit: 5 }, signal)]),
  )

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        The alerts waiting for an analyst, and the stages of an attack they point to.
      </p>

      {data === null ? (
        <div className="panel mt-6">
          {error ? (
            <Message title="The dashboard could not be loaded" detail={error}>
              <Button variant="outline" onClick={reload}>
                <RotateCw aria-hidden />
                Try again
              </Button>
            </Message>
          ) : (
            <Message title="Loading the dashboard…" />
          )}
        </div>
      ) : (
        // One column of panels. On phones the ATT&CK panel moves to the end
        // (see Tactics), so the alerts are not buried under it.
        <div className="mt-6 flex flex-col gap-4">
          {/* A refresh that failed keeps the last numbers on screen and says so. */}
          {error && (
            <p role="alert" className="text-sm text-error">
              These numbers could not be refreshed. {error}
            </p>
          )}
          <div className="grid gap-4 lg:grid-cols-3">
            <div
              aria-busy={loading}
              className={`lg:col-span-2 ${loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}`}
            >
              <OpenAlerts board={data[0]} />
            </div>
            <RunScenario onDone={reload} />
          </div>
          <Tactics board={data[0]} />
          <section aria-labelledby="newest-heading" className="panel overflow-clip">
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 px-5 pt-5 pb-3">
              <h2 id="newest-heading" className="font-medium">
                Newest open alerts
              </h2>
              {data[1].total > 0 && (
                <a href="#/alerts" className="text-link text-sm max-sm:-my-3 max-sm:py-3">
                  See all {plural(data[1].total, 'open alert')}
                </a>
              )}
            </div>
            {data[1].total === 0 ? (
              <p className="px-5 pb-5 text-sm text-muted-foreground">
                Nothing is waiting. New alerts appear here as soon as a rule fires.
              </p>
            ) : (
              <div className="border-t">
                <AlertTable alerts={data[1].alerts} />
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  )
}

// How many alerts still need a decision, split by severity, then the whole
// queue by status.
function OpenAlerts({ board }: { board: Dashboard }) {
  const open = SEVERITIES.reduce((sum, severity) => sum + board.open_by_severity[severity], 0)
  const total = STATUSES.reduce((sum, status) => sum + board.by_status[status], 0)

  return (
    <section aria-labelledby="open-heading" className="panel h-full p-5">
      {/* The heading is for screen readers and the page outline. Everyone
          else reads the big number, which says the same thing. */}
      <h2 id="open-heading" className="sr-only">
        Open alerts
      </h2>
      <div className="grid gap-x-6 gap-y-4 sm:grid-cols-[minmax(0,1fr)_auto]">
        <div>
          <p>
            <span className="text-5xl font-semibold tracking-tight">{open}</span>
            <span className="ml-3 text-lg font-medium">open {open === 1 ? 'alert' : 'alerts'}</span>
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            {total === 0 ? (
              // A first-time visitor lands here with nothing on screen yet.
              <>
                No rule has fired yet. Run a scenario to see the detection rules at work, or{' '}
                <a href="#/about" className="text-link">
                  read what Sentinel is
                </a>
                .
              </>
            ) : open === 0
                ? 'The queue is clear: every alert has been closed.'
                : 'New or in progress: nobody has yet decided whether these are real attacks.'}
          </p>
        </div>
        {/* The same alerts counted as attacks: related alerts are grouped into one incident. */}
        <a
          href="#/incidents"
          title="See the open incidents"
          className="group rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring max-sm:border-t max-sm:pt-3 sm:border-l sm:pl-6"
        >
          <p className="sm:pt-2.5">
            <span className="text-3xl font-semibold tracking-tight group-hover:text-primary">{board.open_incidents}</span>
            <span className="ml-2.5 font-medium group-hover:underline">
              open {board.open_incidents === 1 ? 'incident' : 'incidents'}
            </span>
          </p>
          <p className="mt-1 text-sm text-muted-foreground sm:max-w-44">Related alerts, grouped into one attack each.</p>
        </a>
      </div>

      {/* The mix at a glance: one thin bar, each severity as wide as its share. */}
      <div aria-hidden className="mt-5 flex h-2 gap-0.5 overflow-hidden rounded-full bg-muted">
        {SEVERITIES.map(
          (severity) =>
            board.open_by_severity[severity] > 0 && (
              <span
                key={severity}
                className={SEVERITY_STYLE[severity].dot}
                style={{ flexGrow: board.open_by_severity[severity] }}
              />
            ),
        )}
      </div>
      <ul className="mt-3 grid grid-cols-2 gap-x-4 sm:grid-cols-4">
        {SEVERITIES.map((severity) => (
          <li key={severity}>
            <a
              href={`#/alerts?severity=${severity}`}
              title={`See the open ${severity.toLowerCase()} alerts`}
              className="group -mx-2 block rounded-md px-2 py-2 text-sm outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
            >
              <SeverityLabel severity={severity} />
              <span className="mt-0.5 block text-2xl font-semibold group-hover:text-primary">
                {board.open_by_severity[severity]}
              </span>
            </a>
          </li>
        ))}
      </ul>

      <ul className="mt-4 flex flex-wrap gap-x-6 border-t pt-3 text-sm">
        {STATUSES.map((status) => (
          <li key={status}>
            <a
              href={`#/alerts?status=${encodeURIComponent(status)}`}
              title={`See the alerts with the status "${status}"`}
              className="group inline-flex min-h-11 items-center gap-2 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring sm:min-h-8"
            >
              <span className="group-hover:underline">
                <StatusLabel status={status} />
              </span>
              <span className="font-semibold tabular-nums">{board.by_status[status]}</span>
            </a>
          </li>
        ))}
      </ul>
    </section>
  )
}

// The ATT&CK strip: the 14 tactics in the order an attack moves through
// them, each one lit if alerts point to it, brighter the more there are.
function Tactics({ board }: { board: Dashboard }) {
  const most = Math.max(1, ...board.tactics.map((row) => row.alerts))
  // Three steps of one colour. More alerts, brighter bar.
  const heat = (alerts: number) =>
    alerts === 0 ? 'bg-heat-0' : alerts / most > 2 / 3 ? 'bg-heat-3' : alerts / most > 1 / 3 ? 'bg-heat-2' : 'bg-heat-1'

  return (
    <section aria-labelledby="tactics-heading" className="panel p-5 max-sm:order-1">
      <h2 id="tactics-heading" className="font-medium">
        ATT&amp;CK tactics the alerts point to
      </h2>
      <p className="mt-1 max-w-[75ch] text-sm text-muted-foreground">
        A tactic is what the attacker is trying to achieve at one step. These are MITRE ATT&amp;CK's 14, in the order an
        attack usually moves through them. The later the lit steps, the further an attack has got.
      </p>
      <ol className="mt-5 grid grid-cols-2 gap-x-0.5 gap-y-4 sm:grid-cols-4 md:grid-cols-7 xl:grid-cols-14">
        {board.tactics.map((row, index) => (
          <li key={row.tactic}>
            {/* Lit steps switch on one after another, left to right. */}
            <span
              aria-hidden
              className={`block h-2 transition-colors duration-300 motion-reduce:transition-none ${heat(row.alerts)}`}
              style={{ transitionDelay: `${index * 40}ms` }}
            />
            <span
              className={`mt-2 block pr-2 text-xs leading-4 ${row.alerts ? '' : 'text-muted-foreground'}`}
            >
              {/* A soft hyphen: the one word too long for its column may break here. */}
              {row.tactic.replace('Reconnaissance', 'Reconnais\u00ADsance')}
            </span>
            <span className="block pr-2 text-xs leading-5 text-muted-foreground">
              {row.alerts ? (
                <>
                  <span className="text-sm font-semibold text-foreground tabular-nums">{row.alerts}</span>{' '}
                  {row.alerts === 1 ? 'alert' : 'alerts'}
                </>
              ) : (
                <span className="sr-only">no alerts</span>
              )}
            </span>
          </li>
        ))}
      </ol>

      <h3 className="mt-6 text-sm font-medium">Techniques seen</h3>
      {board.techniques.length === 0 ? (
        <p className="mt-1 text-sm text-muted-foreground">
          None yet. A technique is the method an attacker uses to reach a tactic.
        </p>
      ) : (
        // Two tight columns on phones, one flowing line of links on wider screens.
        <ul className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:flex sm:flex-wrap sm:gap-x-6 sm:text-sm">
          {board.techniques.map((technique) => (
            <li key={technique.id} className="inline-flex min-h-11 items-center gap-2 sm:min-h-7">
              <TechniqueLink id={technique.id} name={technique.name} roomy />
              <span className="text-muted-foreground tabular-nums" title={plural(technique.alerts, 'alert')}>
                {technique.alerts}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
