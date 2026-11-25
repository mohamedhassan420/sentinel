// The app's one dropdown: the browser's own <select>, styled to match the
// inputs, with its name written above it. Taller on phones so it is easy to tap.
export function Select({
  label,
  labelHidden,
  value,
  onChange,
  children,
}: {
  label: string
  // Hides the name from sight (screen readers still read it). Only for a row
  // of filters where each first option already says what the dropdown is.
  labelHidden?: boolean
  value: string
  onChange: (value: string) => void
  children: React.ReactNode
}) {
  return (
    <label className="grid min-w-0 gap-1 text-sm">
      <span className={labelHidden ? 'sr-only' : 'text-muted-foreground'}>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-11 w-full min-w-0 rounded-lg border border-input bg-input/30 px-2 text-base text-foreground outline-none transition-colors hover:border-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 sm:h-8 sm:text-sm"
      >
        {children}
      </select>
    </label>
  )
}
