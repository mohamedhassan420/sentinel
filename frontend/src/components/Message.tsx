// The empty, loading and error states of every table share this layout.
export function Message({ title, detail, children }: { title: string; detail?: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-16 text-center">
      <p className="font-medium">{title}</p>
      {detail && <p className="max-w-[50ch] text-sm text-muted-foreground">{detail}</p>}
      {children}
    </div>
  )
}
