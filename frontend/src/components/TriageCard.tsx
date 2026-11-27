import { useState } from 'react'
import { CircleCheck, Pencil, RotateCw, TriangleAlert } from 'lucide-react'

import { SeverityLabel } from '@/components/labels'
import { Select } from '@/components/Select'
import { Button } from '@/components/ui/button'
import { getTriage, reviewTriage, SEVERITIES, type Alert, type Review, type Severity, type Triage } from '@/lib/api'
import { useLoad } from '@/lib/hooks'

// The AI's triage of one alert: what happened, how bad, what to do next.
// It is a suggestion. Nothing about the alert changes because of it, and the
// card says so until the analyst has accepted it or put their own in its place.
export function TriageCard({ alert }: { alert: Alert }) {
  const { data, error, loading, reload } = useLoad((signal) => getTriage(alert.id, signal))

  // Still waiting for the first answer. The box is about as tall as the
  // answer will be, so the evidence below does not jump when it arrives.
  if (data === null && !error) {
    return (
      <section aria-labelledby="triage-heading" aria-busy className={`${PENDING} min-h-80 p-5`}>
        <Heading />
        <p className="mt-2 text-sm text-muted-foreground">Asking the AI to read the evidence…</p>
        <div aria-hidden className="mt-5 grid gap-2.5 motion-safe:animate-pulse">
          {['w-11/12', 'w-full', 'w-4/5', 'w-2/5'].map((width) => (
            <div key={width} className={`h-3 rounded-sm bg-muted ${width}`} />
          ))}
        </div>
      </section>
    )
  }

  // No suggestion: the server could not be reached, or the AI could not
  // answer. The rest of the page is unaffected, and the analyst can retry.
  const problem = error || data?.problem
  if (problem || !data?.triage) {
    return (
      <section aria-labelledby="triage-heading" className="panel p-5">
        <Heading />
        <p className="mt-2 max-w-[70ch] text-sm leading-6">
          There is no AI suggestion for this alert. The rule&apos;s explanation above and the evidence below are
          everything needed to triage it by hand.
        </p>
        <p className="mt-2 max-w-[70ch] text-sm text-muted-foreground wrap-anywhere">{problem}</p>
        <Button variant="outline" className="mt-4" onClick={reload} disabled={loading}>
          <RotateCw aria-hidden className={loading ? 'motion-safe:animate-spin' : ''} />
          {loading ? 'Asking again…' : 'Ask the AI again'}
        </Button>
      </section>
    )
  }

  return <Suggestion suggested={data.triage} ruleSeverity={alert.severity} />
}

// A dashed teal outline means "a suggestion nobody has decided on yet".
// Once the analyst reviews it, the card becomes an ordinary solid panel.
const PENDING = 'rounded-lg border border-dashed border-primary/60 bg-card'

function Heading() {
  return (
    <h2 id="triage-heading" className="font-medium">
      AI triage
    </h2>
  )
}

function Suggestion({ suggested, ruleSeverity }: { suggested: Triage; ruleSeverity: Severity }) {
  // The triage as last saved: replaced by the server's answer after each review.
  const [triage, setTriage] = useState(suggested)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const reviewed = triage.review !== 'Not reviewed'
  // What the card shows: the analyst's version once there is one, else the AI's.
  const current: Review = {
    severity: triage.final_severity ?? triage.severity,
    summary: triage.final_summary ?? triage.summary,
    next_steps: triage.final_next_steps ?? triage.next_steps,
  }

  async function save(review: Review) {
    setSaving(true)
    setError('')
    try {
      setTriage(await reviewTriage(triage.alert_id, review))
      setEditing(false)
    } catch (problem) {
      setError(`Your decision was not saved. ${(problem as Error).message}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <section aria-labelledby="triage-heading" className={`${reviewed ? 'panel' : PENDING} p-5`}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <Heading />
        <p className="text-xs text-muted-foreground">
          {triage.source === 'demo' ? 'Stored demo answer, not a live AI call' : `Answered by ${triage.model}`}
        </p>
      </div>
      <ReviewState triage={triage} />

      {editing ? (
        <EditForm start={current} saving={saving} onSave={save} onCancel={() => setEditing(false)} />
      ) : (
        <>
          <p className="mt-4 max-w-[70ch] text-sm leading-6 whitespace-pre-line">{current.summary}</p>

          <dl className="mt-5 grid grid-cols-1 gap-x-8 gap-y-4 text-sm sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <div>
              <dt className="text-muted-foreground">{reviewed ? 'Severity' : 'Suggested severity'}</dt>
              <dd className="mt-1">
                <SeverityLabel severity={current.severity} />
                <SeverityNote triage={triage} current={current.severity} ruleSeverity={ruleSeverity} />
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">AI confidence</dt>
              <dd className="mt-1 font-medium">{triage.confidence}</dd>
            </div>
          </dl>

          {current.next_steps.length > 0 && (
            <>
              <h3 className="mt-5 text-sm text-muted-foreground">Next steps, most urgent first</h3>
              <ol className="mt-2 grid max-w-[70ch] list-decimal gap-2 pl-5 text-sm leading-6 marker:text-muted-foreground marker:tabular-nums">
                {current.next_steps.map((step, index) => (
                  <li key={index} className="pl-1">
                    {step}
                  </li>
                ))}
              </ol>
            </>
          )}

          <div className="mt-5 flex flex-wrap gap-2">
            {!reviewed && (
              <Button onClick={() => save(current)} disabled={saving}>
                <CircleCheck aria-hidden />
                {saving ? 'Saving…' : 'Accept suggestion'}
              </Button>
            )}
            <Button variant="outline" onClick={() => setEditing(true)} disabled={saving}>
              <Pencil aria-hidden />
              {reviewed ? 'Edit triage' : 'Edit before accepting'}
            </Button>
          </div>
        </>
      )}
      {error && (
        <p role="alert" className="mt-3 text-sm text-error">
          {error}
        </p>
      )}
    </section>
  )
}

// One line under the heading saying whose words these are.
function ReviewState({ triage }: { triage: Triage }) {
  if (triage.review === 'Not reviewed') {
    return (
      <p aria-live="polite" className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
        <span className="rounded-sm border border-primary/50 px-1.5 py-0.5 text-xs font-medium text-primary">
          AI suggestion
        </span>
        Not reviewed. Nothing changes until you accept it or edit it.
      </p>
    )
  }
  return (
    <p aria-live="polite" className="mt-2 flex items-start gap-1.5 text-sm text-muted-foreground">
      <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-primary" />
      {triage.review === 'Accepted'
        ? 'You accepted the AI suggestion as written.'
        : 'You edited the AI suggestion. This is your version.'}
    </p>
  )
}

// How the severity shown compares with the rule's and with the AI's, and why.
function SeverityNote({ triage, current, ruleSeverity }: { triage: Triage; current: Severity; ruleSeverity: Severity }) {
  // SEVERITIES runs from most to least urgent, so a later place is a lower severity.
  const lowerThanRule = SEVERITIES.indexOf(current) > SEVERITIES.indexOf(ruleSeverity)
  return (
    <>
      {current !== triage.severity ? (
        <p className="mt-1.5 text-muted-foreground">
          The AI suggested {triage.severity}. The rule says {ruleSeverity}.
        </p>
      ) : (
        // The AI's reason only fits the severity the AI chose.
        <p className="mt-1.5 max-w-[60ch] leading-6">{triage.severity_reason}</p>
      )}
      {current === triage.severity && current !== ruleSeverity && !lowerThanRule && (
        <p className="mt-1.5 text-muted-foreground">Higher than the rule, which says {ruleSeverity}.</p>
      )}
      {/* An attacker's best outcome is an alert talked down. If the suggestion
          sits below the rule's own severity, the card makes that hard to miss. */}
      {lowerThanRule && triage.review === 'Not reviewed' && (
        <p className="mt-2 flex max-w-[60ch] items-start gap-1.5 text-severity-medium">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
          Lower than the rule, which says {ruleSeverity}. Check the evidence supports that before accepting.
        </p>
      )}
    </>
  )
}

const FIELD =
  'w-full rounded-lg border border-input bg-input/30 px-2.5 py-2 text-base leading-6 text-foreground outline-none transition-colors field-sizing-content hover:border-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 sm:text-sm'

// The limits the server enforces, checked here first so the message is helpful.
const MAX_STEPS = 8
const MAX_STEP_LENGTH = 500

function EditForm({
  start,
  saving,
  onSave,
  onCancel,
}: {
  start: Review
  saving: boolean
  onSave: (review: Review) => void
  onCancel: () => void
}) {
  const [severity, setSeverity] = useState(start.severity)
  const [summary, setSummary] = useState(start.summary)
  const [steps, setSteps] = useState(start.next_steps.join('\n'))

  // One step per line; blank lines are dropped.
  const stepList = steps
    .split('\n')
    .map((step) => step.trim())
    .filter(Boolean)
  const stepsProblem =
    stepList.length > MAX_STEPS
      ? `Keep to ${MAX_STEPS} steps at most. There are ${stepList.length}.`
      : stepList.some((step) => step.length > MAX_STEP_LENGTH)
        ? `Keep each step under ${MAX_STEP_LENGTH} characters.`
        : ''

  return (
    <form
      className="mt-4 grid max-w-[70ch] gap-4"
      onSubmit={(event) => {
        event.preventDefault()
        onSave({ severity, summary: summary.trim(), next_steps: stepList })
      }}
    >
      <div className="sm:w-48">
        <Select label="Severity" value={severity} onChange={(value) => setSeverity(value as Severity)}>
          {SEVERITIES.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </Select>
      </div>
      <label className="grid gap-1 text-sm">
        <span className="text-muted-foreground">Summary</span>
        <textarea
          value={summary}
          onChange={(event) => setSummary(event.target.value)}
          required
          maxLength={2000}
          rows={4}
          className={FIELD}
        />
      </label>
      <label className="grid gap-1 text-sm">
        <span className="text-muted-foreground">Next steps, one per line</span>
        <textarea
          value={steps}
          onChange={(event) => setSteps(event.target.value)}
          rows={5}
          aria-invalid={stepsProblem ? true : undefined}
          aria-describedby="steps-problem"
          className={FIELD}
        />
        <span id="steps-problem" aria-live="polite" className="text-error empty:hidden">
          {stepsProblem}
        </span>
      </label>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={saving || summary.trim() === '' || stepsProblem !== ''}>
          {saving ? 'Saving…' : 'Save triage'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
