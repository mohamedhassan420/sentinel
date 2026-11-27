import { useId, useState } from 'react'
import { CircleCheck, Pencil, RotateCw, TriangleAlert } from 'lucide-react'

import { SeverityLabel } from '@/components/labels'
import { Select } from '@/components/Select'
import { Button } from '@/components/ui/button'
import { SEVERITIES, type Severity } from '@/lib/api'
import { useLoad } from '@/lib/hooks'

// The card that shows an AI suggestion and lets the analyst accept or edit
// it. It is used twice: for an alert's triage (TriageCard) and for an
// incident's summary (SummaryCard). Those two say what to load and how to
// save; everything on screen is here.
//
// A suggestion changes nothing by itself, and the card says so until the
// analyst has accepted it or put their own version in its place.

// What the analyst decides: a severity, a summary and one or more lists of steps.
export type Decision = { severity: Severity; summary: string; lists: string[][] }

// A suggestion as the card needs it, whichever kind it is.
export type Suggested = {
  source: 'live' | 'demo' // Claude answered just now, or a stored demo answer
  model: string | null
  review: 'Not reviewed' | 'Accepted' | 'Edited'
  // The AI's own severity, its reason, and how sure it is. These never change.
  severity: Severity
  severity_reason: string
  confidence: 'Low' | 'Medium' | 'High'
  // What the card shows: the analyst's version once there is one, else the AI's.
  current: Decision
}

type Wording = {
  title: string // the card's heading
  waiting: string // shown while the AI is answering
  missing: string // shown when there is no suggestion: what to do without one
  // One entry for each list of steps: its heading on the card, its name in
  // the edit form, and the most steps the server accepts.
  lists: { heading: string; field: string; max: number }[]
  maxSummary: number // the longest summary the server accepts
  // What the AI's severity is compared with: the rule's own for an alert,
  // the highest alert's for an incident. E.g. { name: 'the rule', verb: 'says' }.
  baseline: { severity: Severity; name: string; verb: string }
}

type Props = Wording & {
  load: (signal: AbortSignal) => Promise<{ suggested: Suggested | null; problem: string }>
  save: (decision: Decision) => Promise<Suggested>
}

export function ReviewCard({ load, save, ...wording }: Props) {
  const headingId = useId()
  const { data, error, loading, reload } = useLoad(load)
  const heading = (
    <h2 id={headingId} className="font-medium">
      {wording.title}
    </h2>
  )

  // Still waiting for the first answer. The box is about as tall as the
  // answer will be, so whatever is below does not jump when it arrives.
  if (data === null && !error) {
    return (
      <section aria-labelledby={headingId} aria-busy className={`${PENDING} min-h-80 p-5`}>
        {heading}
        <p className="mt-2 text-sm text-muted-foreground">{wording.waiting}</p>
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
  if (problem || !data?.suggested) {
    return (
      <section aria-labelledby={headingId} className="panel p-5">
        {heading}
        <p className="mt-2 max-w-[70ch] text-sm leading-6">{wording.missing}</p>
        <p className="mt-2 max-w-[70ch] text-sm text-muted-foreground wrap-anywhere">{problem}</p>
        <Button variant="outline" className="mt-4" onClick={reload} disabled={loading}>
          <RotateCw aria-hidden className={loading ? 'motion-safe:animate-spin' : ''} />
          {loading ? 'Asking again…' : 'Ask the AI again'}
        </Button>
      </section>
    )
  }

  return <Suggestion first={data.suggested} save={save} wording={wording} heading={heading} headingId={headingId} />
}

// A dashed teal outline means "a suggestion nobody has decided on yet".
// Once the analyst reviews it, the card becomes an ordinary solid panel.
const PENDING = 'rounded-lg border border-dashed border-primary/60 bg-card'

function Suggestion({
  first,
  save,
  wording,
  heading,
  headingId,
}: {
  first: Suggested
  save: Props['save']
  wording: Wording
  heading: React.ReactNode
  headingId: string
}) {
  // The suggestion as last saved: replaced by the server's answer after each review.
  const [suggested, setSuggested] = useState(first)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const reviewed = suggested.review !== 'Not reviewed'
  const { current } = suggested

  async function decide(decision: Decision) {
    setSaving(true)
    setError('')
    try {
      setSuggested(await save(decision))
      setEditing(false)
    } catch (problem) {
      setError(`Your decision was not saved. ${(problem as Error).message}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <section aria-labelledby={headingId} className={`${reviewed ? 'panel' : PENDING} p-5`}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">
          {suggested.source === 'demo' ? 'Stored demo answer, not a live AI call' : `Answered by ${suggested.model}`}
        </p>
      </div>
      <ReviewState review={suggested.review} />

      {editing ? (
        <EditForm start={current} wording={wording} saving={saving} onSave={decide} onCancel={() => setEditing(false)} />
      ) : (
        <>
          <p className="mt-4 max-w-[70ch] text-sm leading-6 whitespace-pre-line">{current.summary}</p>

          <dl className="mt-5 grid grid-cols-1 gap-x-8 gap-y-4 text-sm sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <div>
              <dt className="text-muted-foreground">{reviewed ? 'Severity' : 'Suggested severity'}</dt>
              <dd className="mt-1">
                <SeverityLabel severity={current.severity} />
                <SeverityNote suggested={suggested} baseline={wording.baseline} />
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">AI confidence</dt>
              <dd className="mt-1 font-medium">{suggested.confidence}</dd>
            </div>
          </dl>

          {wording.lists.map(
            (list, number) =>
              current.lists[number].length > 0 && (
                <div key={list.heading}>
                  <h3 className="mt-5 text-sm text-muted-foreground">{list.heading}</h3>
                  <ol className="mt-2 grid max-w-[70ch] list-decimal gap-2 pl-5 text-sm leading-6 marker:text-muted-foreground marker:tabular-nums">
                    {current.lists[number].map((step, index) => (
                      <li key={index} className="pl-1">
                        {step}
                      </li>
                    ))}
                  </ol>
                </div>
              ),
          )}

          <div className="mt-5 flex flex-wrap gap-2">
            {!reviewed && (
              <Button onClick={() => decide(current)} disabled={saving}>
                <CircleCheck aria-hidden />
                {saving ? 'Saving…' : 'Accept suggestion'}
              </Button>
            )}
            <Button variant="outline" onClick={() => setEditing(true)} disabled={saving}>
              <Pencil aria-hidden />
              {reviewed ? 'Edit' : 'Edit before accepting'}
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
function ReviewState({ review }: { review: Suggested['review'] }) {
  if (review === 'Not reviewed') {
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
      {review === 'Accepted'
        ? 'You accepted the AI suggestion as written.'
        : 'You edited the AI suggestion. This is your version.'}
    </p>
  )
}

// How the severity shown compares with the baseline and with the AI's, and why.
function SeverityNote({ suggested, baseline }: { suggested: Suggested; baseline: Wording['baseline'] }) {
  const current = suggested.current.severity
  // SEVERITIES runs from most to least urgent, so a later place is a lower severity.
  const lower = SEVERITIES.indexOf(current) > SEVERITIES.indexOf(baseline.severity)
  const comparedWith = `${baseline.name}, which ${baseline.verb} ${baseline.severity}`
  return (
    <>
      {current !== suggested.severity ? (
        <p className="mt-1.5 text-muted-foreground">
          The AI suggested {suggested.severity}, and {baseline.name} {baseline.verb} {baseline.severity}.
        </p>
      ) : (
        // The AI's reason only fits the severity the AI chose.
        <p className="mt-1.5 max-w-[60ch] leading-6">{suggested.severity_reason}</p>
      )}
      {current === suggested.severity && current !== baseline.severity && !lower && (
        <p className="mt-1.5 text-muted-foreground">Higher than {comparedWith}.</p>
      )}
      {/* An attacker's best outcome is an alert talked down. If the suggestion
          sits below the baseline, the card makes that hard to miss. */}
      {lower && suggested.review === 'Not reviewed' && (
        <p className="mt-2 flex max-w-[60ch] items-start gap-1.5 text-severity-medium">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
          Lower than {comparedWith}. Check the evidence supports that before accepting.
        </p>
      )}
    </>
  )
}

const FIELD =
  'w-full rounded-lg border border-input bg-input/30 px-2.5 py-2 text-base leading-6 text-foreground outline-none transition-colors field-sizing-content hover:border-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 sm:text-sm'

// The longest one step may be. The server enforces it; it is checked here
// first so the message is helpful.
const MAX_STEP_LENGTH = 500

function EditForm({
  start,
  wording,
  saving,
  onSave,
  onCancel,
}: {
  start: Decision
  wording: Wording
  saving: boolean
  onSave: (decision: Decision) => void
  onCancel: () => void
}) {
  const problemId = useId()
  const [severity, setSeverity] = useState(start.severity)
  const [summary, setSummary] = useState(start.summary)
  // Each list of steps is edited as text, one step per line.
  const [texts, setTexts] = useState(start.lists.map((steps) => steps.join('\n')))

  // Blank lines are dropped.
  const lists = texts.map((text) =>
    text
      .split('\n')
      .map((step) => step.trim())
      .filter(Boolean),
  )
  const problems = lists.map((steps, number) =>
    steps.length > wording.lists[number].max
      ? `Keep to ${wording.lists[number].max} steps at most. There are ${steps.length}.`
      : steps.some((step) => step.length > MAX_STEP_LENGTH)
        ? `Keep each step under ${MAX_STEP_LENGTH} characters.`
        : '',
  )

  return (
    <form
      className="mt-4 grid max-w-[70ch] gap-4"
      onSubmit={(event) => {
        event.preventDefault()
        onSave({ severity, summary: summary.trim(), lists })
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
          maxLength={wording.maxSummary}
          rows={4}
          className={FIELD}
        />
      </label>
      {wording.lists.map((list, number) => (
        <label key={list.field} className="grid gap-1 text-sm">
          <span className="text-muted-foreground">{list.field}, one per line</span>
          <textarea
            value={texts[number]}
            onChange={(event) => setTexts(texts.map((text, index) => (index === number ? event.target.value : text)))}
            rows={5}
            aria-invalid={problems[number] ? true : undefined}
            aria-describedby={`${problemId}-${number}`}
            className={FIELD}
          />
          <span id={`${problemId}-${number}`} aria-live="polite" className="text-error empty:hidden">
            {problems[number]}
          </span>
        </label>
      ))}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={saving || summary.trim() === '' || problems.some(Boolean)}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
