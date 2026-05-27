import { SEVERITY_BG, type Severity } from '@/lib/constants'
import { cn } from '@/lib/utils'

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const label = severity ?? 'unknown'
  const s = label.toLowerCase() as Severity
  return (
    <span className={cn('inline-block px-2 py-0.5 rounded text-xs font-medium', SEVERITY_BG[s] || 'bg-gray-500 text-white')}>
      {label.toUpperCase()}
    </span>
  )
}
