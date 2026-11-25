import { SeverityLabel, StatusLabel, TechniqueLink } from '@/components/labels'
import { Timestamp } from '@/components/Timestamp'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { Alert } from '@/lib/api'
import { SEVERITY_STYLE } from '@/lib/display'

// The alert list, shared by the Alerts page and the dashboard.
export function AlertTable({ alerts }: { alerts: Alert[] }) {
  return (
    <Table className="table-fixed">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="w-20 pl-3 sm:w-24">Time</TableHead>
          <TableHead className="hidden w-24 sm:table-cell">Severity</TableHead>
          <TableHead>Alert</TableHead>
          <TableHead className="hidden w-52 xl:table-cell">ATT&amp;CK</TableHead>
          <TableHead className="hidden w-32 lg:table-cell">Host</TableHead>
          <TableHead className="hidden w-24 lg:table-cell">User</TableHead>
          <TableHead className="hidden w-36 md:table-cell">Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {alerts.map((alert) => (
          <AlertRow key={alert.id} alert={alert} />
        ))}
      </TableBody>
    </Table>
  )
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <TableRow className="relative [&>td]:align-top">
      <TableCell className={`border-l-2 pl-2.5 tabular-nums ${SEVERITY_STYLE[alert.severity].edge}`}>
        <Timestamp iso={alert.time} />
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <SeverityLabel severity={alert.severity} />
      </TableCell>
      <TableCell className="whitespace-normal">
        {/* Small screens have no room for the other columns, so their content
            moves in here: severity and status above the title, the rest below. */}
        <span className="mb-1 flex justify-between gap-3 text-xs md:hidden">
          <span className="sm:hidden">
            <SeverityLabel severity={alert.severity} />
          </span>
          <StatusLabel status={alert.status} />
        </span>
        {/* One link covers the whole row (see .row-link in index.css). */}
        <a href={`#/alerts/${alert.id}`} className="row-link">
          {alert.title}
        </a>
        {/* The whole row is one link here, so the techniques are plain text. */}
        <span className="mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground xl:hidden">
          <span>
            <span className="text-foreground/85 tabular-nums">{alert.attack_techniques.join(', ')}</span>{' '}
            {alert.attack_tactics.join(', ')}
          </span>
          <span className="lg:hidden">
            {alert.user} on {alert.host}
          </span>
        </span>
      </TableCell>
      <TableCell className="hidden whitespace-normal xl:table-cell">
        {/* "relative" lifts these links above the row-wide link, so they can be clicked. */}
        <span className="relative flex flex-wrap gap-x-2">
          {alert.attack_techniques.map((technique) => (
            <TechniqueLink key={technique} id={technique} />
          ))}
        </span>
        <span className="block text-xs text-muted-foreground">{alert.attack_tactics.join(', ')}</span>
      </TableCell>
      <TableCell className="hidden truncate lg:table-cell">{alert.host}</TableCell>
      <TableCell className="hidden truncate lg:table-cell">{alert.user}</TableCell>
      <TableCell className="hidden whitespace-normal md:table-cell">
        <StatusLabel status={alert.status} />
      </TableCell>
    </TableRow>
  )
}
