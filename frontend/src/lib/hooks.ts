import { useEffect, useState, useSyncExternalStore } from 'react'

// ---------------------------------------------------------------- Loading data

// Fetch something when a page appears, and again whenever `key` changes or
// reload() is called. While a newer answer is on its way the old data stays
// on screen (the page dims it), so nothing jumps about.
export function useLoad<T>(load: (signal: AbortSignal) => Promise<T>, key = '') {
  const [reloads, setReloads] = useState(0)
  const requestKey = `${key}#${reloads}`
  const [answer, setAnswer] = useState<{ key: string; data: T | null; error: string }>({
    key: '',
    data: null,
    error: '',
  })

  useEffect(() => {
    // If the key changes before the answer arrives, the old request is cancelled.
    const controller = new AbortController()
    load(controller.signal)
      .then((data) => setAnswer({ key: requestKey, data, error: '' }))
      .catch((problem: Error) => {
        if (problem.name === 'AbortError') return
        setAnswer((old) => ({ key: requestKey, data: old.data, error: problem.message }))
      })
    return () => controller.abort()
    // `load` is left out on purpose: `key` says when its answer would change.
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey])

  return {
    data: answer.data,
    error: answer.error,
    loading: answer.key !== requestKey,
    reload: () => setReloads((n) => n + 1),
  }
}

// ------------------------------------------------------------------- The route

// The part of the address after "#" says which page to show:
//   #/alerts/12            -> parts ["alerts", "12"]
//   #/alerts?severity=High -> parts ["alerts"], params severity=High
// ponytail: fine for a handful of pages. Move to a router library if pages
// start to nest or need to load data before they show.
function subscribeToHash(onChange: () => void) {
  window.addEventListener('hashchange', onChange)
  return () => window.removeEventListener('hashchange', onChange)
}

export function useRoute() {
  const hash = useSyncExternalStore(subscribeToHash, () => window.location.hash)
  const [path, query = ''] = hash.replace(/^#\/?/, '').split('?')
  return { parts: path.split('/').filter(Boolean), params: new URLSearchParams(query) }
}
