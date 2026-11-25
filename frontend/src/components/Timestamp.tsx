const dateFormat = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short' })
const timeFormat = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})

// A UTC time from the server, shown in the reader's own time zone:
// the time on top and the date underneath, or side by side with `inline`.
export function Timestamp({ iso, inline }: { iso: string; inline?: boolean }) {
  const time = new Date(iso)
  return (
    <time dateTime={iso} title={time.toLocaleString()} className="tabular-nums">
      {timeFormat.format(time)}
      <span className={inline ? 'ml-2 text-muted-foreground' : 'block text-xs text-muted-foreground'}>
        {dateFormat.format(time)}
      </span>
    </time>
  )
}
