import { useSyncExternalStore } from 'react'

import AlertsPage from '@/pages/AlertsPage'
import LogsPage from '@/pages/LogsPage'

const PAGES = [
  { hash: '#/', label: 'Logs', Page: LogsPage },
  { hash: '#/alerts', label: 'Alerts', Page: AlertsPage },
]

// ponytail: with two pages, the part of the address after "#" picks the page.
// Move to a router library when Phase 3 adds a page per alert and per rule.
function subscribeToHash(onChange: () => void) {
  window.addEventListener('hashchange', onChange)
  return () => window.removeEventListener('hashchange', onChange)
}

// The app shell: a top bar shared by every page, with the page below it.
export default function App() {
  const hash = useSyncExternalStore(subscribeToHash, () => window.location.hash)
  const current = PAGES.find((page) => page.hash === hash) ?? PAGES[0]

  return (
    <div className="min-h-svh">
      <header className="border-b bg-card">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-8 px-4 sm:px-6">
          <a href="#/" className="flex items-center gap-2.5 font-semibold tracking-tight">
            <img src="/favicon.svg" alt="" className="size-6" />
            Sentinel
          </a>
          <nav aria-label="Main" className="flex h-full gap-5 text-sm">
            {PAGES.map((page) => (
              <a
                key={page.hash}
                href={page.hash}
                aria-current={page === current ? 'page' : undefined}
                className="flex items-center border-b-2 border-transparent px-1 pt-0.5 text-muted-foreground outline-none hover:text-foreground focus-visible:text-foreground focus-visible:underline aria-[current=page]:border-primary aria-[current=page]:font-medium aria-[current=page]:text-foreground"
              >
                {page.label}
              </a>
            ))}
          </nav>
        </div>
      </header>
      <main>
        <current.Page />
      </main>
    </div>
  )
}
