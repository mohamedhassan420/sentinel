import { RotateCw } from 'lucide-react'

import { IncidentStatusLabel, SeverityLabel } from '@/components/labels'
import { Message } from '@/components/Message'
import { Select } from '@/components/Select'
import { Timestamp } from '@/components/Timestamp'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getIncidents, type Incident } from '@/lib/api'
import { plural, SEVERITY_STYLE, whoAndWhere } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// The incidents: related alerts grouped into one attack each. Like the alert
// queue, the filter lives in the address (#/incidents?status=Closed).
export default function IncidentsPage({ params }: { params: URLSearchParams }) {
  const status = (['Closed', 'all'] as const).find((value) => value === params.get('status')) ?? 'Open'
  const { data, error, loading, reload } = useLoad(
    (signal) => getIncidents({ status: status === 'all' ? undefined : status }, signal),
    status,
  )

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Incidents</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        An incident is a group of alerts that share a host or a user and happened within 30 minutes of each other, so
        they are probably one attack. Open one to follow it step by step.
      </p>

      <form
        role="search"
        aria-label="Filter incidents"
        onSubmit={(event) => event.preventDefault()}
        className="mt-5 sm:w-56"
      >
        <Select
          label="Status"
          value={status === 'Open' ? '' : status}
          onChange={(value) => (window.location.hash = value ? `#/incidents?status=${value}` : '#/incidents')}
        >
          <option value="">Open incidents</option>
          <option value="Closed">Closed incidents</option>
          <option value="all">All incidents</option>
        </Select>
      </form>

      {/* How many incidents are listed, said before the list, not after it. */}
      <p role="status" className="mt-4 min-h-5 text-sm text-muted-foreground">
        {data !== null &&
          data.total > 0 &&
          !error &&
          (data.incidents.length < data.total
            ? `Showing the newest ${data.incidents.length} of ${data.total} incidents.`
            : `${plural(data.total, 'incident')}, newest first`)}
      </p>

      <div className="panel mt-2 overflow-clip">
        {error ? (
          <Message title="The incidents could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        ) : data === null ? (
          <Message title="Loading incidents…" />
        ) : data.total === 0 && status === 'Closed' ? (
          <Message
            title="No closed incidents"
            detail="An incident closes when every one of its alerts has been closed as a true or a false positive."
          />
        ) : data.total === 0 ? (
          <Message
            title={status === 'Open' ? 'No open incidents' : 'No incidents yet'}
            detail="Incidents appear when the detection rules raise alerts. Run a scenario on the dashboard: the full attack chain makes the clearest one."
          >
            <Button asChild>
              <a href="#/">Go to the dashboard</a>
            </Button>
          </Message>
        ) : (
          <div aria-busy={loading} className={loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
            <IncidentTable incidents={data.incidents} />
          </div>
        )}
      </div>
    </div>
  )
}

function IncidentTable({ incidents }: { incidents: Incident[] }) {
  return (
    <Table className="table-fixed">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="w-20 pl-3 sm:w-24">Last alert</TableHead>
          <TableHead className="hidden w-24 sm:table-cell">Severity</TableHead>
          <TableHead>Incident</TableHead>
          <TableHead className="hidden w-28 md:table-cell">Alerts</TableHead>
          <TableHead className="hidden w-24 md:table-cell">Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {incidents.map((incident) => (
          <TableRow key={incident.id} className="relative [&>td]:align-top">
            <TableCell className={`border-l-2 pl-2.5 tabular-nums ${SEVERITY_STYLE[incident.severity].edge}`}>
              <Timestamp iso={incident.end_time} />
            </TableCell>
            <TableCell className="hidden sm:table-cell">
              <SeverityLabel severity={incident.severity} />
            </TableCell>
            <TableCell className="whitespace-normal">
              {/* Small screens have no room for the other columns, so their
                  content moves in here, as it does in the alert queue. */}
              <span className="mb-1 flex justify-between gap-3 text-xs md:hidden">
                <span className="sm:hidden">
                  <SeverityLabel severity={incident.severity} />
                </span>
                <IncidentStatusLabel status={incident.status} />
              </span>
              {/* One link covers the whole row (see .row-link in index.css). */}
              <a href={`#/incidents/${incident.id}`} className="row-link">
                Incident #{incident.id}
              </a>
              <span className="ml-2 text-muted-foreground">{whoAndWhere(incident.users, incident.hosts)}</span>
              <span className="mt-1 block text-xs text-muted-foreground">
                {progression(incident.tactics)}
                <span className="md:hidden">, {alertCount(incident)}</span>
              </span>
            </TableCell>
            <TableCell className="hidden whitespace-normal md:table-cell">
              <span className="tabular-nums">{incident.alerts}</span>
              {incident.open_alerts > 0 && (
                <span className="block text-xs text-muted-foreground tabular-nums">{incident.open_alerts} undecided</span>
              )}
            </TableCell>
            <TableCell className="hidden md:table-cell">
              <IncidentStatusLabel status={incident.status} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

// How far the attack got, in one line: where it started and where it ended.
function progression(tactics: string[]) {
  if (tactics.length <= 2) return tactics.join(', then ')
  return `${tactics.length} ATT&CK tactics, from ${tactics[0]} to ${tactics[tactics.length - 1]}`
}

function alertCount(incident: Incident) {
  const undecided = incident.open_alerts > 0 ? `, ${incident.open_alerts} undecided` : ''
  return `${plural(incident.alerts, 'alert')}${undecided}`
}
