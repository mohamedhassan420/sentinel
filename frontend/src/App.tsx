import { useEffect } from 'react'

import { Message } from '@/components/Message'
import { Button } from '@/components/ui/button'
import { SOURCE_URL } from '@/lib/display'
import { useRoute } from '@/lib/hooks'
import AboutPage from '@/pages/AboutPage'
import AlertPage from '@/pages/AlertPage'
import AlertsPage from '@/pages/AlertsPage'
import DashboardPage from '@/pages/DashboardPage'
import IncidentPage from '@/pages/IncidentPage'
import IncidentsPage from '@/pages/IncidentsPage'
import LogsPage from '@/pages/LogsPage'
import RulePage from '@/pages/RulePage'
import RulesPage from '@/pages/RulesPage'

// The top bar's links. `section` is the first word of the address after "#/".
const NAV = [
  { section: '', label: 'Dashboard' },
  { section: 'incidents', label: 'Incidents' },
  { section: 'alerts', label: 'Alerts' },
  { section: 'logs', label: 'Logs' },
  { section: 'rules', label: 'Detections' },
  { section: 'about', label: 'About' },
]

// The two links a phone's top bar has no room for (see the header below).
// About also sits apart, at the right-hand end: it is about the tool, not part of it.
const NARROW: Record<string, string> = { '': 'max-sm:hidden', about: 'ml-auto max-sm:hidden' }

// Which page an address shows, or nothing if the address makes no sense.
function pageFor(parts: string[], params: URLSearchParams) {
  const [section = '', id, ...rest] = parts
  if (rest.length > 0) return null
  if (id === undefined) {
    if (section === '') return <DashboardPage />
    if (section === 'incidents') return <IncidentsPage params={params} />
    if (section === 'alerts') return <AlertsPage params={params} />
    if (section === 'logs') return <LogsPage />
    if (section === 'rules') return <RulesPage />
    if (section === 'about') return <AboutPage />
  }
  // `key` gives each alert, incident and rule a fresh page, so one never
  // briefly shows another's details. An alert's or incident's id must be a
  // whole number, and a rule's name plain letters, digits and underscores:
  // anything else is not sent to the server at all.
  else if (section === 'alerts' && /^[1-9]\d{0,14}$/.test(id)) return <AlertPage key={id} id={Number(id)} />
  else if (section === 'incidents' && /^[1-9]\d{0,14}$/.test(id)) return <IncidentPage key={id} id={Number(id)} />
  else if (section === 'rules' && /^\w{1,100}$/.test(id)) return <RulePage key={id} name={id} />
  return null
}

// The app shell: a top bar shared by every page, with the page below it.
export default function App() {
  const { parts, params } = useRoute()
  const path = parts.join('/')

  // A new page starts at its top. (Changing a filter keeps the same path,
  // so it does not jump.) The braces matter: React treats anything an effect
  // returns as its clean-up function, and scrollTo returns a value in newer
  // browsers.
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [path])

  // The browser tab, the history list and screen readers all name a page by
  // its title: "Alerts | Sentinel", or plain "Sentinel" for a mistyped address.
  const section = NAV.find((item) => item.section === (parts[0] ?? ''))
  useEffect(() => {
    document.title = section ? `${section.label} | Sentinel` : 'Sentinel'
  }, [section])

  return (
    // A column as tall as the window at least, so the footer sits at the
    // bottom of the window even under a short page.
    <div className="flex min-h-svh flex-col">
      {/* Invisible until a keyboard user presses Tab: jumps past the top bar.
          It moves the focus itself, because the address after "#" is taken
          by the page names. */}
      <a
        href="#main"
        onClick={(event) => {
          event.preventDefault()
          document.getElementById('main')?.focus()
        }}
        className="sr-only focus-visible:not-sr-only focus-visible:absolute focus-visible:top-2 focus-visible:left-2 focus-visible:z-10 focus-visible:rounded-md focus-visible:bg-primary focus-visible:px-3 focus-visible:py-2 focus-visible:text-sm focus-visible:font-medium focus-visible:text-primary-foreground"
      >
        Skip to the page content
      </a>
      <header className="border-b bg-card">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-1 px-3 sm:gap-8 sm:px-6">
          {/* Six links do not fit across a phone. There the logo, which
              leads to the dashboard anyway, stands in for the Dashboard link
              and carries its underline, and About is reached from the footer. */}
          <a
            href="#/"
            aria-label="Sentinel, to the dashboard"
            aria-current={parts.length === 0 ? 'page' : undefined}
            className="flex h-full min-w-11 shrink-0 items-center gap-2.5 rounded-sm border-b-2 border-transparent pt-0.5 font-semibold tracking-tight outline-none focus-visible:ring-2 focus-visible:ring-ring max-sm:justify-center max-sm:aria-[current=page]:border-primary"
          >
            <img src="/favicon.svg" alt="" className="size-6" />
            <span className="max-sm:sr-only">Sentinel</span>
          </a>
          <nav aria-label="Main" className="flex h-full flex-1 text-sm sm:gap-3">
            {NAV.map((item) => (
              <a
                key={item.section}
                href={`#/${item.section}`}
                aria-current={item.section === (parts[0] ?? '') ? 'page' : undefined}
                className={`flex ${NARROW[item.section] ?? ''} items-center rounded-sm border-b-2 border-transparent px-2 pt-0.5 text-muted-foreground outline-none transition-colors hover:text-foreground focus-visible:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset aria-[current=page]:border-primary aria-[current=page]:font-medium aria-[current=page]:text-foreground`}
              >
                {item.label}
              </a>
            ))}
          </nav>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="flex-1 outline-none">
        {pageFor(parts, params) ?? (
          <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
            <div className="panel">
              <Message title="There is no page at this address" detail="The link may be old or mistyped.">
                <Button asChild>
                  <a href="#/">Go to the dashboard</a>
                </Button>
              </Message>
            </div>
          </div>
        )}
      </main>
      <footer className="border-t">
        <div className="mx-auto flex max-w-7xl flex-wrap items-baseline justify-between gap-x-8 gap-y-2 px-4 py-5 text-sm text-muted-foreground sm:px-6">
          <p>Sentinel is a training tool. Every log line is simulated, and nothing real is attacked.</p>
          <p className="flex gap-6">
            <a href="#/about" className="text-link max-sm:-my-3 max-sm:py-3">
              About Sentinel
            </a>
            <a
              href={SOURCE_URL}
              target="_blank"
              rel="noreferrer"
              title="Opens GitHub in a new tab"
              className="text-link max-sm:-my-3 max-sm:py-3"
            >
              Source code
            </a>
          </p>
        </div>
      </footer>
    </div>
  )
}
