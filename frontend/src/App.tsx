import LogsPage from '@/pages/LogsPage'

// The app shell: a top bar shared by every page, with the page below it.
// Phase 1 has one page. Later phases add more links to the nav.
export default function App() {
  return (
    <div className="min-h-svh">
      <header className="border-b bg-card">
        <div className="mx-auto flex h-14 max-w-7xl items-center gap-8 px-4 sm:px-6">
          <a href="/" className="flex items-center gap-2.5 font-semibold tracking-tight">
            <img src="/favicon.svg" alt="" className="size-6" />
            Sentinel
          </a>
          <nav aria-label="Main" className="flex h-full text-sm">
            <a
              href="/"
              aria-current="page"
              className="flex items-center border-b-2 border-primary px-1 pt-0.5 font-medium"
            >
              Logs
            </a>
          </nav>
        </div>
      </header>
      <main>
        <LogsPage />
      </main>
    </div>
  )
}
