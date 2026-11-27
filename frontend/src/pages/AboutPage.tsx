import { Code, Play } from 'lucide-react'

import { SeverityLabel, TechniqueLink } from '@/components/labels'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { SOURCE_URL } from '@/lib/display'
import { SCENARIOS } from '@/lib/scenarios'

// What each attack teaches: the ATT&CK techniques its two rules point to and
// the Security+ topic it connects to. The scenario's name and description come from lib/scenarios.
const COVERAGE: Record<string, { techniques: string[]; topic: string }> = {
  brute_force: { techniques: ['T1110', 'T1133', 'T1078'], topic: 'Password attacks and account lockout' },
  phishing: { techniques: ['T1566.001', 'T1204.002'], topic: 'Social engineering and email security' },
  powershell: { techniques: ['T1059.001', 'T1027.010', 'T1105'], topic: 'Indicators of malicious code' },
  privilege_escalation: { techniques: ['T1136.001', 'T1098'], topic: 'Least privilege and account management' },
  exfiltration: { techniques: ['T1048', 'T1048.003'], topic: 'Data loss prevention and network monitoring' },
}

// What Sentinel is, for a visitor who arrives from a CV: how an attack
// becomes a report, what is simulated, and who built it.
export default function AboutPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-14">
      <h1 className="max-w-[22ch] text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
        A SOC triage tool for simulated attacks
      </h1>
      <p className="mt-4 max-w-[62ch] text-lg leading-8 text-foreground/90">
        Sentinel writes an attack as log lines, catches it with ten Sigma-style detection rules, and turns the alerts
        into one incident with a timeline and a PDF report.
      </p>
      <p className="mt-2 max-w-[62ch] text-muted-foreground">
        Nothing real is attacked. Every log line is text the simulator wrote.
      </p>
      <div className="mt-7 flex flex-wrap gap-3">
        <Button asChild className="px-4">
          <a href="#/">
            <Play aria-hidden />
            Run a scenario
          </a>
        </Button>
        <Button asChild variant="outline" className="px-4">
          <a href={SOURCE_URL} target="_blank" rel="noreferrer" title="Opens GitHub in a new tab">
            <Code aria-hidden />
            Read the source code
          </a>
        </Button>
      </div>

      <section aria-labelledby="how-heading" className="mt-14 border-t pt-10 sm:mt-16">
        <h2 id="how-heading" className="text-xl font-semibold tracking-tight">
          How an attack becomes a report
        </h2>
        <p className="mt-2 max-w-[65ch] text-muted-foreground">
          The five steps a security operations centre (SOC) works through, shown with the full attack chain: a
          phishing email that ends with 2 GB leaving the network.
        </p>
        {/* A row of five on wide screens, where "subgrid" (on each step) lines
            the five up part by part. Below that each step is its own row: the
            words on the left, the piece of the app on the right. */}
        <ol className="mt-8 grid xl:grid-cols-5 xl:gap-x-6">
          <Step number={1} title="The simulator writes logs" link={['#/logs', 'See the logs']}>
            <StepText>
              One click writes the attack as 9 log lines, hidden among 60 lines of normal office activity.
            </StepText>
            <Piece>
              <p className="text-muted-foreground">Sysmon 1, process started</p>
              <dl className="mt-1.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3">
                <dt className="text-muted-foreground">ParentImage</dt>
                <dd>WINWORD.EXE</dd>
                <dt className="text-muted-foreground">Image</dt>
                <dd>cmd.exe</dd>
                <dt className="text-muted-foreground">User</dt>
                <dd>CORP\a.khan</dd>
              </dl>
            </Piece>
          </Step>
          <Step number={2} title="Rules turn matches into alerts" link={['#/rules', 'See the detection rules']}>
            <StepText>
              Ten rules check every new line. A match raises an alert tagged with its MITRE ATT&amp;CK technique.
            </StepText>
            <Piece sans>
              <SeverityLabel severity="High" />
              <p className="mt-1.5 font-medium">Office Application Starts A Command Shell</p>
              <p className="mt-1 text-xs text-muted-foreground">
                <span className="text-foreground/85 tabular-nums">T1204.002</span> Execution
              </p>
            </Piece>
          </Step>
          <Step number={3} title="Related alerts become one incident" link={['#/incidents', 'See the incidents']}>
            <StepText>
              Alerts that share a host or a user within 30 minutes are grouped, so the attack reads as one story.
            </StepText>
            <Piece sans>
              <p>
                <span className="text-2xl font-semibold tracking-tight">9</span> alerts,{' '}
                <span className="text-2xl font-semibold tracking-tight">1</span> incident
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                a.khan on WKS-FIN-03, from Initial Access to Exfiltration in 28 minutes
              </p>
            </Piece>
          </Step>
          <Step number={4} title="AI suggests, the analyst decides" link={['#/alerts', 'See the alerts']}>
            <StepText>
              Each alert and each incident gets a written summary, a suggested severity and next steps. Nothing
              changes until a person accepts.
            </StepText>
            {/* The dashed outline is the app's own sign for a suggestion nobody has reviewed. */}
            <Piece sans dashed>
              <p className="text-xs text-primary">AI suggestion</p>
              <p className="mt-1.5 flex flex-wrap items-center gap-x-2.5">
                Suggested severity
                <SeverityLabel severity="Critical" />
              </p>
              <p className="mt-1 text-xs text-muted-foreground">Not reviewed</p>
            </Piece>
          </Step>
          <Step number={5} title="One click makes the report">
            <StepText>
              The incident page builds a PDF with six sections, from the executive summary to the recovery steps.
            </StepText>
            <Piece>
              <p className="text-muted-foreground">Indicators of compromise</p>
              <p className="mt-1.5">198[.]51[.]100[.]23</p>
              <p>accounts@c0rp[.]example</p>
              <p>svc_update</p>
            </Piece>
          </Step>
        </ol>
      </section>

      <section aria-labelledby="real-heading" className="mt-14 border-t pt-10 sm:mt-16">
        <h2 id="real-heading" className="text-xl font-semibold tracking-tight">
          What is simulated and what is real
        </h2>
        <div className="mt-6 grid gap-x-12 gap-y-8 md:grid-cols-2">
          <Facts title="Simulated">
            <li>Every log line. The simulator writes text into a database and sends nothing over a network.</li>
            <li>The company. Hosts such as WKS-FIN-03 and users such as a.khan do not exist.</li>
            <li>The attackers' addresses, which come from ranges reserved for examples in documentation.</li>
            <li>
              The AI answers in demo mode, which is what the public site runs. They are stored examples written by
              hand, so the site needs no API key.
            </li>
          </Facts>
          <Facts title="Real">
            <li>
              The ten detection rules: YAML files in the open Sigma format, each tested against logs that must fire it
              and logs that must not.
            </li>
            <li>The rule engine and the correlation that groups alerts, written in plain Python.</li>
            <li>The MITRE ATT&amp;CK mapping. Every alert carries its tactic and its technique ID.</li>
            <li>
              The AI in live mode: Claude, through the Anthropic API. Log text reaches it as evidence, never as
              instructions.
            </li>
          </Facts>
        </div>
      </section>

      <section aria-labelledby="attacks-heading" className="mt-14 border-t pt-10 sm:mt-16">
        <h2 id="attacks-heading" className="text-xl font-semibold tracking-tight">
          Five attacks and what each one teaches
        </h2>
        <p className="mt-2 max-w-[65ch] text-muted-foreground">
          Two rules watch each attack, so an attacker who slips past one can still trip the other. The full attack
          chain plays four of the five in order on one machine.
        </p>
        <div className="panel mt-6 overflow-clip">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-4 sm:w-48">Attack</TableHead>
                <TableHead className="hidden sm:table-cell">What the logs show</TableHead>
                <TableHead className="hidden w-56 lg:table-cell">ATT&amp;CK techniques</TableHead>
                <TableHead className="hidden w-64 xl:table-cell">Security+ topic</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {SCENARIOS.filter((scenario) => scenario.id in COVERAGE).map((scenario) => (
                <TableRow key={scenario.id} className="hover:bg-transparent [&>td]:align-top [&>td]:whitespace-normal">
                  <TableCell className="pl-4 font-medium">
                    {scenario.label}
                    {/* Narrow screens have no room for the other columns, so their content moves in here. */}
                    <span className="mt-1 block text-sm font-normal text-muted-foreground sm:hidden">
                      {scenario.description}
                    </span>
                    <span className="mt-1 block text-xs font-normal text-muted-foreground lg:hidden">
                      <span className="text-foreground/85 tabular-nums">
                        {COVERAGE[scenario.id].techniques.join(', ')}
                      </span>{' '}
                      <span className="xl:hidden">{COVERAGE[scenario.id].topic}</span>
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground sm:table-cell">
                    {scenario.description}
                    <span className="mt-1 hidden text-xs lg:block xl:hidden">{COVERAGE[scenario.id].topic}</span>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell">
                    <span className="flex flex-wrap gap-x-3">
                      {COVERAGE[scenario.id].techniques.map((technique) => (
                        <TechniqueLink key={technique} id={technique} />
                      ))}
                    </span>
                  </TableCell>
                  <TableCell className="hidden xl:table-cell">{COVERAGE[scenario.id].topic}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <section aria-labelledby="built-heading" className="mt-14 border-t pt-10 sm:mt-16">
        <h2 id="built-heading" className="text-xl font-semibold tracking-tight">
          Who built Sentinel
        </h2>
        <div className="mt-4 grid gap-x-12 gap-y-8 md:grid-cols-2">
          <div className="grid max-w-[62ch] content-start gap-3 leading-7 text-foreground/90">
            <p>
              Sentinel is a portfolio project by Mohamed Hassan, a final-year student studying for CompTIA Security+
              and working towards a SOC analyst role.
            </p>
            <p>
              Claude, an AI model made by Anthropic, wrote the code in six phases to Mohamed's plan. Mohamed decided
              what to build, tested each phase and learned to explain every part of it.
            </p>
            <p>
              <a href={SOURCE_URL} target="_blank" rel="noreferrer" className="text-link">
                Read the source code on GitHub
              </a>
            </p>
          </div>
          <dl className="grid content-start gap-4 text-sm">
            <Fact term="Backend">Python 3.12, FastAPI and SQLite</Fact>
            <Fact term="Frontend">React, TypeScript and Tailwind CSS</Fact>
            <Fact term="Tests">Every rule is tested both ways, and the tests run on every change</Fact>
            <Fact term="The public site">
              One Docker container on a free host. It sleeps after 15 quiet minutes, so the first page can take a
              minute to load. Everyone shares one store of logs, which empties itself when it fills up.
            </Fact>
          </dl>
        </div>
      </section>
    </div>
  )
}

// One step of the pipeline: its number, what happens, and a piece of the app
// that shows it. `link` is [address, words] for where the step lives in the app.
function Step({
  number,
  title,
  link,
  children,
}: {
  number: number
  title: string
  link?: [string, string]
  children: React.ReactNode
}) {
  return (
    <li className="grid content-start gap-x-8 gap-y-3 border-t py-6 first:border-t-0 first:pt-0 sm:grid-cols-2 xl:row-span-4 xl:grid-cols-1 xl:grid-rows-subgrid xl:border-t-0 xl:py-0">
      <div className="sm:col-start-1">
        {/* The number, then a line running on to the next step. */}
        <p aria-hidden className="flex items-center gap-3 text-sm font-semibold text-primary tabular-nums">
          {number}
          <span className="hidden h-px flex-1 bg-border xl:block" />
        </p>
        <h3 className="mt-2 font-medium text-balance">{title}</h3>
      </div>
      {children}
      {link && (
        <p className="sm:col-start-1">
          <a href={link[0]} className="text-link text-sm max-sm:-my-3 max-sm:inline-block max-sm:py-3">
            {link[1]}
          </a>
        </p>
      )}
    </li>
  )
}

function StepText({ children }: { children: React.ReactNode }) {
  return <p className="text-sm leading-6 text-muted-foreground sm:col-start-1">{children}</p>
}

// A small piece of the app, as it looks there. Log text is set in the
// monospace face; `sans` is for pieces that the app shows in its usual face.
function Piece({ sans, dashed, children }: { sans?: boolean; dashed?: boolean; children: React.ReactNode }) {
  return (
    <div
      className={`self-start rounded-lg border bg-card p-3.5 sm:col-start-2 sm:row-span-3 sm:row-start-1 xl:col-start-1 xl:row-span-1 xl:row-start-auto ${
        sans ? 'text-sm' : 'font-mono text-xs leading-5'
      } ${dashed ? 'border-dashed border-primary/60' : ''}`}
    >
      {children}
    </div>
  )
}

function Facts({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="font-medium">{title}</h3>
      <ul className="mt-3 grid max-w-[62ch] list-disc gap-2.5 pl-5 leading-7 text-foreground/90 marker:text-muted-foreground">
        {children}
      </ul>
    </div>
  )
}

function Fact({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-x-6 gap-y-0.5 sm:grid-cols-[8rem_minmax(0,1fr)]">
      <dt className="text-muted-foreground">{term}</dt>
      <dd className="leading-6">{children}</dd>
    </div>
  )
}
