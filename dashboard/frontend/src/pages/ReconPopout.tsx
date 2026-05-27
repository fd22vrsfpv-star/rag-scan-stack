import ReconExplorer from './ReconExplorer'

/**
 * Standalone full-window mount of the Recon Explorer. Routed at /recon-popout
 * outside AppShell so the sidebar/top-bar don't render, giving operators a
 * focused workspace they can drag to a second monitor.
 */
export default function ReconPopout() {
  return (
    <div className="min-h-screen bg-background text-foreground p-4">
      <ReconExplorer />
    </div>
  )
}
