import { useState } from 'react'
import { Play } from 'lucide-react'

import { Select } from '@/components/Select'
import { Button } from '@/components/ui/button'
import { runScenario, type RunResult } from '@/lib/api'
import { plural } from '@/lib/display'
import { SCENARIOS } from '@/lib/scenarios'

// Pick an attack and have the simulator write its log lines. `onDone` runs
// after the logs are stored, so the page around it can fetch the new numbers.
export function RunScenario({ onDone }: { onDone: () => void }) {
  const [scenario, setScenario] = useState(SCENARIOS[0])
  const [running, setRunning] = useState(false)
  // What the last run did, or why it failed. Both are cleared by picking another scenario.
  const [result, setResult] = useState<RunResult | null>(null)
  const [error, setError] = useState('')

  function choose(id: string) {
    setScenario(SCENARIOS.find((candidate) => candidate.id === id) ?? SCENARIOS[0])
    setResult(null)
    setError('')
  }

  async function run() {
    setRunning(true)
    setResult(null)
    setError('')
    try {
      setResult(await runScenario(scenario.id))
      onDone()
    } catch (problem) {
      setError((problem as Error).message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <section aria-labelledby="run-heading" className="panel flex flex-col p-5">
      <h2 id="run-heading" className="font-medium">
        Run a scenario
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        The simulator writes an attack as log lines, hidden among normal office activity. Nothing real is attacked.
      </p>
      <div className="mt-4">
        <Select label="Scenario" value={scenario.id} onChange={choose}>
          {SCENARIOS.map((candidate) => (
            <option key={candidate.id} value={candidate.id}>
              {candidate.label}
            </option>
          ))}
        </Select>
      </div>
      {/* One line that changes: what the scenario will write, or what the last run did. */}
      <p aria-live="polite" className={`mt-3 mb-4 text-sm ${error ? 'text-error' : 'text-muted-foreground'}`}>
        {error ? (
          error
        ) : result ? (
          <>
            Added {plural(result.added, 'log line')}: {result.attack} from the attack and {result.background} of normal
            activity. The rules raised{' '}
            <a href="#/alerts" className="text-link">
              {plural(result.alerts, 'alert')}
            </a>
            {result.alerts > 0 && (
              <>
                , grouped into{' '}
                <a href="#/incidents" className="text-link">
                  {plural(result.incidents, 'incident')}
                </a>
              </>
            )}
            .
          </>
        ) : (
          scenario.description
        )}
      </p>
      <Button onClick={run} disabled={running} className="mt-auto w-full">
        <Play aria-hidden />
        {running ? 'Writing logs…' : 'Run scenario'}
      </Button>
    </section>
  )
}
