import { ArrowLeft, GraduationCap, RotateCw } from 'lucide-react'

import { SeverityLabel, TechniqueLink } from '@/components/labels'
import { Message } from '@/components/Message'
import { Button } from '@/components/ui/button'
import { getRule, type RuleDetail } from '@/lib/api'
import { useLoad } from '@/lib/hooks'

// Explain mode: one rule, written for someone who is learning.
export default function RulePage({ name }: { name: string }) {
  const { data, error, reload } = useLoad((signal) => getRule(name, signal))

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
      <a href="#/rules" className="text-link inline-flex min-h-11 items-center gap-1.5 text-sm sm:min-h-0">
        <ArrowLeft aria-hidden className="size-4" />
        Back to rules
      </a>
      {error ? (
        <div className="panel mt-4">
          <Message title="This rule could not be loaded" detail={error}>
            <Button variant="outline" onClick={reload}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          </Message>
        </div>
      ) : data === null ? (
        <div className="panel mt-4">
          <Message title="Loading the rule…" />
        </div>
      ) : (
        <Explanation rule={data} />
      )}
    </div>
  )
}

function Explanation({ rule }: { rule: RuleDetail }) {
  const { explanation } = rule
  return (
    <>
      <h1 className="mt-3 max-w-[30ch] text-3xl font-semibold tracking-tight text-balance">{rule.title}</h1>
      <dl className="mt-4 flex flex-wrap gap-x-10 gap-y-3 text-sm">
        <div>
          <dt className="text-muted-foreground">Severity</dt>
          <dd className="mt-0.5">
            <SeverityLabel severity={rule.severity} />
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Reads</dt>
          <dd className="mt-0.5">{rule.log_source}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">ATT&amp;CK tactic</dt>
          <dd className="mt-0.5">{rule.tactics.join(', ')}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">ATT&amp;CK technique</dt>
          <dd className="mt-0.5 grid gap-0.5">
            {rule.techniques.map((technique) => (
              <span key={technique.id}>
                <TechniqueLink id={technique.id} name={technique.name} roomy />
              </span>
            ))}
          </dd>
        </div>
      </dl>

      <div className="mt-8 grid grid-cols-1 items-start gap-x-12 gap-y-8 border-t pt-8 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="grid min-w-0 grid-cols-1 gap-8">
          <Part title="What the attack is" text={explanation.attack} />
          <Part title="What the log shows" text={explanation.log_shows} />
          <Part title="Why the rule catches it" text={explanation.why} />

          <section aria-labelledby="file-heading">
            <h2 id="file-heading" className="text-lg font-semibold">
              The rule file
            </h2>
            <p className="mt-2 max-w-[68ch] leading-7 text-foreground/90">
              This is the whole rule, exactly as the engine reads it. It is written in Sigma, the open format SOC teams
              use to share detection rules. The lines that start with # are notes for people.
            </p>
            {/* Shown as plain text, one line at a time, with the notes dimmed. */}
            <pre className="mt-4 overflow-x-auto rounded-lg border bg-card p-4 font-mono text-xs leading-5">
              {rule.yaml_text
                .trimEnd()
                .split('\n')
                .map((line, index) => (
                  <span key={index} className={line.trimStart().startsWith('#') ? 'block text-muted-foreground' : 'block'}>
                    {line + '\n'}
                  </span>
                ))}
            </pre>
          </section>

          {rule.false_positives.length > 0 && (
            <section aria-labelledby="false-heading">
              <h2 id="false-heading" className="text-lg font-semibold">
                What else can set it off
              </h2>
              <p className="mt-2 max-w-[68ch] leading-7 text-foreground/90">
                No rule is perfect. These harmless things look the same in the logs, so an analyst rules them out
                before treating the alert as an attack.
              </p>
              <ul className="mt-3 grid max-w-[68ch] list-disc gap-2 pl-5 leading-7 marker:text-muted-foreground">
                {rule.false_positives.map((cause) => (
                  <li key={cause}>{cause}</li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <aside
          aria-labelledby="exam-heading"
          className="rounded-lg border border-primary/40 bg-primary/5 p-5 lg:sticky lg:top-6"
        >
          <p className="flex items-center gap-2 text-sm text-primary">
            <GraduationCap aria-hidden className="size-4" />
            Security+ connection
          </p>
          <h2 id="exam-heading" className="mt-2 text-lg font-semibold">
            {explanation.security_plus.topic}
          </h2>
          <Paragraphs text={explanation.security_plus.text} className="mt-2 text-sm leading-6" />
        </aside>
      </div>
    </>
  )
}

function Part({ title, text }: { title: string; text: string }) {
  return (
    <section>
      <h2 className="text-lg font-semibold">{title}</h2>
      <Paragraphs text={text} className="mt-2 max-w-[68ch] leading-7 text-foreground/90" />
    </section>
  )
}

// The explanation files separate paragraphs with a blank line.
function Paragraphs({ text, className }: { text: string; className: string }) {
  return (
    <div className={`grid gap-3 ${className}`}>
      {text
        .trim()
        .split(/\n\s*\n/)
        .map((paragraph) => (
          <p key={paragraph}>{paragraph}</p>
        ))}
    </div>
  )
}
