import { useState, type ReactNode } from 'react'
import { HelpCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * Small inline pop-up help. Renders a "?" icon; on hover/focus/click it shows a
 * short explanation. Self-contained (no external tooltip lib). Use next to a
 * label or control to explain what it does.
 *
 *   <InfoTip text="Generates recs for every detected open port." />
 */
export default function InfoTip({
  text,
  side = 'top',
  className,
}: {
  text: ReactNode
  side?: 'top' | 'bottom' | 'left' | 'right'
  className?: string
}) {
  const [open, setOpen] = useState(false)

  const pos = {
    top: 'bottom-full left-1/2 -translate-x-1/2 mb-1.5',
    bottom: 'top-full left-1/2 -translate-x-1/2 mt-1.5',
    left: 'right-full top-1/2 -translate-y-1/2 mr-1.5',
    right: 'left-full top-1/2 -translate-y-1/2 ml-1.5',
  }[side]

  return (
    <span className={cn('relative inline-flex items-center align-middle', className)}>
      <button
        type="button"
        aria-label="Help"
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen((o) => !o) }}
        className="text-muted-foreground/70 hover:text-primary transition-colors cursor-help"
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </button>
      {open && (
        <span
          role="tooltip"
          className={cn(
            'absolute z-50 w-64 rounded-md border border-border bg-popover px-3 py-2',
            'text-xs font-normal leading-relaxed text-foreground shadow-lg',
            'whitespace-normal text-left normal-case',
            pos,
          )}
        >
          {text}
        </span>
      )}
    </span>
  )
}
