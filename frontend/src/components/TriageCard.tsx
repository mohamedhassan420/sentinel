import { ReviewCard, type Decision, type Suggested } from '@/components/ReviewCard'
import { getTriage, reviewTriage, type Alert, type Triage } from '@/lib/api'

// The AI's triage of one alert: what happened, how bad, what to do next.
// ReviewCard draws it; this file says where it comes from and where the
// analyst's decision goes.
export function TriageCard({ alert }: { alert: Alert }) {
  return (
    <ReviewCard
      title="AI triage"
      waiting="Asking the AI to read the evidence…"
      missing="There is no AI suggestion for this alert. The rule's explanation above and the evidence below are everything needed to triage it by hand."
      lists={[{ heading: 'Next steps, most urgent first', field: 'Next steps', max: 8 }]}
      maxSummary={2000}
      baseline={{ severity: alert.severity, name: 'the rule', verb: 'says' }}
      load={async (signal) => {
        const result = await getTriage(alert.id, signal)
        return { suggested: result.triage && forCard(result.triage), problem: result.problem }
      }}
      save={async (decision: Decision) =>
        forCard(
          await reviewTriage(alert.id, {
            severity: decision.severity,
            summary: decision.summary,
            next_steps: decision.lists[0],
          }),
        )
      }
    />
  )
}

// A triage in the shape the card shows: the analyst's version of each part
// once there is one, else the AI's.
function forCard(triage: Triage): Suggested {
  return {
    ...triage,
    current: {
      severity: triage.final_severity ?? triage.severity,
      summary: triage.final_summary ?? triage.summary,
      lists: [triage.final_next_steps ?? triage.next_steps],
    },
  }
}
