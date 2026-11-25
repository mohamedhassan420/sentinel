import { RotateCw } from 'lucide-react'

import { SeverityLabel, TechniqueLink } from '@/components/labels'
import { Message } from '@/components/Message'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getRules } from '@/lib/api'
import { SEVERITY_STYLE } from '@/lib/display'
import { useLoad } from '@/lib/hooks'

// Every detection rule. Each row opens the rule's Explain page.
export default function RulesPage() {
  const { data, error, reload } = useLoad(getRules)

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">Detection rules</h1>
      <p className="mt-1 max-w-[65ch] text-sm text-muted-foreground">
        A rule describes what an attack looks like in the logs. Sentinel checks every new log line against all of
        them. Open a rule for a plain-English explanation of the attack and of how the rule catches it.
      </p>

      <div className="panel mt-6 overflow-clip">
        {error ? (
          <Message title="The rules could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        ) : data === null ? (
          <Message title="Loading rules…" />
        ) : (
          <Table className="table-fixed">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-3">Rule</TableHead>
                <TableHead className="hidden w-24 sm:table-cell">Severity</TableHead>
                <TableHead className="hidden w-44 md:table-cell">Reads</TableHead>
                <TableHead className="hidden w-80 lg:table-cell">ATT&amp;CK technique</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((rule) => (
                <TableRow key={rule.name} className="relative [&>td]:align-top">
                  <TableCell className={`whitespace-normal border-l-2 pl-2.5 ${SEVERITY_STYLE[rule.severity].edge}`}>
                    <span className="mb-1 block text-xs sm:hidden">
                      <SeverityLabel severity={rule.severity} />
                    </span>
                    <a href={`#/rules/${rule.name}`} className="row-link">
                      {rule.title}
                    </a>
                    <span className="mt-1 block text-xs text-muted-foreground md:hidden">Reads {rule.log_source}</span>
                    {/* On small screens the whole row is one link, so the techniques are plain text here. */}
                    <span className="mt-1 block text-xs text-muted-foreground lg:hidden">
                      {rule.techniques.map((technique) => `${technique.id} ${technique.name}`).join(', ')}
                    </span>
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <SeverityLabel severity={rule.severity} />
                  </TableCell>
                  <TableCell className="hidden whitespace-normal md:table-cell">{rule.log_source}</TableCell>
                  <TableCell className="hidden whitespace-normal lg:table-cell">
                    {/* "relative" lifts these links above the row-wide link, so they can be clicked. */}
                    <span className="relative grid gap-0.5">
                      {rule.techniques.map((technique) => (
                        <span key={technique.id}>
                          <TechniqueLink id={technique.id} name={technique.name} />
                        </span>
                      ))}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  )
}
