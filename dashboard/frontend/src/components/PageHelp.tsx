import { useState, useEffect } from 'react'
import { HelpCircle, ChevronDown, ChevronRight, X } from 'lucide-react'
import { cn } from '@/lib/utils'

const STORAGE_KEY = 'pagehelp-collapsed'

function getCollapsed(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') } catch { return {} }
}

function setCollapsed(id: string, val: boolean) {
  const state = getCollapsed()
  state[id] = val
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

export default function PageHelp({ id, title, children }: {
  id: string
  title: string
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(true)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    const state = getCollapsed()
    if (state[id] === true) setOpen(false)
    if (state[`${id}-dismissed`]) setDismissed(true)
  }, [id])

  const toggle = () => {
    const next = !open
    setOpen(next)
    setCollapsed(id, !next)
  }

  const dismiss = () => {
    setDismissed(true)
    setCollapsed(`${id}-dismissed`, true)
  }

  if (dismissed) return null

  return (
    <div className={cn(
      'mb-4 rounded-lg border transition-all',
      'bg-primary/[0.03] border-primary/20',
    )}>
      <button
        onClick={toggle}
        className="w-full flex items-center gap-2 px-3 py-2 text-left"
      >
        <HelpCircle className="h-3.5 w-3.5 text-primary shrink-0" />
        <span className="text-xs font-medium text-primary flex-1">{title}</span>
        {open
          ? <ChevronDown className="h-3 w-3 text-primary/60" />
          : <ChevronRight className="h-3 w-3 text-primary/60" />}
        <span
          role="button"
          onClick={e => { e.stopPropagation(); dismiss() }}
          className="p-0.5 rounded hover:bg-primary/10 text-primary/40 hover:text-primary/70"
          title="Dismiss permanently"
        >
          <X className="h-3 w-3" />
        </span>
      </button>
      {open && (
        <div className="px-3 pb-2.5 text-xs text-muted-foreground leading-relaxed space-y-1">
          {children}
        </div>
      )}
    </div>
  )
}
