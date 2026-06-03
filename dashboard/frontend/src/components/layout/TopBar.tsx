import { useLocation } from 'react-router-dom'
import { useHealth } from '@/api/reports'
import { useScanCount } from '@/api/scans'
import { useEngagements } from '@/api/engagements'
import { useUIStore } from '@/stores/ui'
import { useAutoSelectEngagementScope } from '@/hooks/useAutoSelectEngagementScope'
import { BUILD_VERSION } from '@/lib/constants'
import { MessageCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

const ROUTE_TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/scans/launch': 'Launch Scan',
  '/scans': 'Scan Monitor',
  '/assets': 'Assets',
  '/findings': 'Findings Explorer',
  '/recommendations': 'Recommendations',
  '/settings/kb-overrides': 'KB Overrides',
  '/recon': 'Recon & Scope Intelligence',
  '/exploits': 'Exploit Manager',
  '/reports': 'Reports',
  '/feedback': 'Feedback',
  '/settings': 'Settings',
  '/engagements': 'Engagements',
  '/opsec': 'OpSec Dashboard',
}

export function TopBar() {
  const location = useLocation()
  const { data: health } = useHealth()
  const { data: activeScans = 0 } = useScanCount()
  const { data: engData } = useEngagements()
  const { chatOpen, setChatOpen, selectedEngagementId, setSelectedEngagement } = useUIStore()
  // When engagement changes, auto-select the largest scope (one-time per change).
  useAutoSelectEngagementScope()

  const title = ROUTE_TITLES[location.pathname] || 'Pentest Dashboard'
  // activeScans comes from useScanCount() — already filtered and polled slowly

  const healthyCount = health
    ? Object.values(health.services).filter(s => s.status === 'healthy').length
    : 0
  const totalServices = health ? Object.keys(health.services).length : 0

  const engagements = engData?.engagements?.filter(e => e.status !== 'archived') ?? []

  return (
    <header className="h-12 border-b border-border bg-card flex items-center justify-between px-4">
      <div className="flex items-center gap-3">
        <h1 className="text-sm font-semibold">{title}</h1>
        <span className="text-[9px] text-muted-foreground font-mono">v{BUILD_VERSION}</span>
      </div>

      <div className="flex items-center gap-4">
        {/* Engagement selector */}
        <select
          value={selectedEngagementId ?? ''}
          onChange={e => {
            const eid = e.target.value || null
            const eng = engagements.find(en => en.id === eid)
            setSelectedEngagement(eid, eng?.scope_name ?? null)
          }}
          className="h-7 text-xs rounded border border-border bg-background px-2 text-foreground max-w-[180px]"
        >
          <option value="">All Engagements</option>
          {engagements.map(e => (
            <option key={e.id} value={e.id}>{e.name}</option>
          ))}
        </select>

        {activeScans > 0 && (
          <div className="flex items-center gap-1.5 text-xs">
            <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-muted-foreground">{activeScans} active scan{activeScans !== 1 ? 's' : ''}</span>
          </div>
        )}

        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <div className={cn(
            'h-2 w-2 rounded-full',
            healthyCount === totalServices ? 'bg-green-500' : healthyCount > 0 ? 'bg-yellow-500' : 'bg-red-500',
          )} />
          <span>{healthyCount}/{totalServices}</span>
        </div>

        <button
          onClick={() => {
            // Always open chat in a new window so it doesn't get hidden behind
            // the main app. If the popup already exists, just focus it.
            const w = Math.min(800, window.screen.availWidth - 100)
            const h = Math.min(900, window.screen.availHeight - 100)
            const left = Math.max(0, window.screen.availWidth - w - 60)
            const top = 60
            const features = `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes,location=no,menubar=no,toolbar=no,status=no`
            const popup = window.open('/chat-popout', 'rag-chat-popout', features)
            if (popup) {
              setChatOpen(false)  // close any in-page panel
              popup.focus()
            } else {
              // Popup blocked — fall back to in-page panel
              setChatOpen(!chatOpen)
            }
          }}
          className={cn(
            'flex items-center gap-1.5 px-2 py-1 rounded-md text-xs transition-colors',
            chatOpen ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent',
          )}
        >
          <MessageCircle className="h-3.5 w-3.5" />
          <span>Chat</span>
          <kbd className="hidden sm:inline text-[10px] px-1 py-0.5 rounded bg-muted text-muted-foreground">Ctrl+.</kbd>
        </button>
      </div>
    </header>
  )
}
