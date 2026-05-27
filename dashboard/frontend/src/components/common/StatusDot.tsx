import { cn } from '@/lib/utils'

const STATUS_COLORS: Record<string, string> = {
  healthy: 'bg-green-500',
  running: 'bg-blue-500 animate-pulse',
  active: 'bg-blue-500 animate-pulse',
  queued: 'bg-blue-400 animate-pulse',
  stalled: 'bg-yellow-500 animate-pulse',
  completed: 'bg-green-500',
  failed: 'bg-red-500',
  stopped: 'bg-yellow-500',
  lost: 'bg-red-500',
  unreachable: 'bg-red-500',
  degraded: 'bg-yellow-500',
  partial: 'bg-yellow-500',
  timeout: 'bg-red-500',
  cancelled: 'bg-yellow-500',
  error: 'bg-red-500',
}

export function StatusDot({ status }: { status: string }) {
  return (
    <span className={cn('inline-block h-2 w-2 rounded-full', STATUS_COLORS[status] || 'bg-gray-400')} />
  )
}
