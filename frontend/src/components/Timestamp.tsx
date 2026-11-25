const dateFormat = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short' })
const timeFormat = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

// A UTC time from the server, shown in the reader's own time zone:
// the time on top, the date underneath.
export function Timestamp({ iso }: { iso: string }) {
  const time = new Date(iso)
  return (
    <time dateTime={iso} title={time.toLocaleString()}>
      {timeFormat.format(time)}
      <span className="block text-xs text-muted-foreground">{dateFormat.format(time)}</span>
    </time>
  )
}
