import { ExternalLink } from 'lucide-react'

interface Props {
  /** Standalone route to open (must be a top-level Route outside AppShell). */
  path: string
  /** window.open name — used as the target so re-clicks reuse the same window. */
  windowName: string
  /** Tooltip text. */
  title?: string
  /** Visible label; defaults to "Pop out". */
  label?: string
  className?: string
}

/**
 * Opens a tab/page in an independent OS window — same pattern the chat popout
 * uses. The opened window mounts a route that lives *outside* AppShell so
 * neither the sidebar nor the top bar render, giving the operator a focused
 * full-screen workspace they can drag to a second monitor.
 */
export default function PopoutButton({
  path, windowName, title = 'Open in independent browser window',
  label = 'Pop out', className,
}: Props) {
  const onClick = () => {
    const w = Math.min(1400, window.screen.availWidth - 80)
    const h = Math.min(900, window.screen.availHeight - 80)
    const left = Math.max(0, Math.floor((window.screen.availWidth - w) / 2))
    const top = 40
    const features = [
      `width=${w}`, `height=${h}`, `left=${left}`, `top=${top}`,
      'resizable=yes', 'scrollbars=yes', 'location=no',
      'menubar=no', 'toolbar=no', 'status=no',
    ].join(',')
    const popup = window.open(path, windowName, features)
    if (popup) popup.focus()
    else alert('Popup blocked — please allow popups for this site.')
  }
  return (
    <button
      onClick={onClick}
      title={title}
      className={
        className
          ?? 'px-2 py-1 text-xs rounded border border-border hover:bg-muted flex items-center gap-1 text-muted-foreground hover:text-foreground'
      }
    >
      <ExternalLink className="h-3 w-3" /> {label}
    </button>
  )
}
