import { ReviewCard, type Decision, type Suggested } from '@/components/ReviewCard'
import { getIncidentSummary, reviewIncidentSummary, type Incident, type IncidentSummary } from '@/lib/api'

// The AI's summary of one incident: the story of the attack, how bad it is
// as a whole, and what to do about it. This is the text the PDF report
// prints, in the analyst's version once they have reviewed it.
export function SummaryCard({ incident }: { incident: Incident }) {
  return (
    <ReviewCard
      title="AI incident summary"
      waiting="Asking the AI to read the alerts and their evidence…"
      missing="There is no AI summary for this incident. The timeline above has everything needed to write one by hand, and the report is built from the alert data instead."
      lists={[
        { heading: 'Containment: stop the attack spreading, most urgent first', field: 'Containment steps', max: 6 },
        {
          heading: 'Recovery: remove what the attacker left and return to normal',
          field: 'Recovery steps',
          max: 6,
        },
      ]}
      maxSummary={3000}
      baseline={{ severity: incident.severity, name: 'the highest alert', verb: 'is' }}
      load={async (signal) => {
        const result = await getIncidentSummary(incident.id, signal)
        return { suggested: result.summary && forCard(result.summary), problem: result.problem }
      }}
      save={async (decision: Decision) =>
        forCard(
          await reviewIncidentSummary(incident.id, {
            severity: decision.severity,
            summary: decision.summary,
            containment: decision.lists[0],
            recovery: decision.lists[1],
          }),
        )
      }
    />
  )
}

// A summary in the shape the card shows: the analyst's version of each part
// once there is one, else the AI's.
function forCard(summary: IncidentSummary): Suggested {
  return {
    ...summary,
    current: {
      severity: summary.final_severity ?? summary.severity,
      summary: summary.final_summary ?? summary.summary,
      lists: [summary.final_containment ?? summary.containment, summary.final_recovery ?? summary.recovery],
    },
  }
}
