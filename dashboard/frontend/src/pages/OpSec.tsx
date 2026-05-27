import { useState } from 'react'
import { useOpsecTimeline, useOpsecAlerts, useScheduledScans, useCancelScheduledScan, type RecentScan } from '@/api/opsec'
import { ShieldAlert, AlertTriangle, Clock, Trash2, Wifi, Activity } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

const STATUS_COLORS: Record<string, string> = {
  completed: 'text-green-400',
  finished: 'text-green-400',
  running: 'text-blue-400',
  queued: 'text-zinc-400',
  failed: 'text-red-400',
  stopped: 'text-amber-400',
  unknown: 'text-muted-foreground',
}

export default function OpSec() {
  const [hours, setHours] = useState(24)
  const [threshold, setThreshold] = useState(20)
  const { data: timeline, isLoading: tlLoading } = useOpsecTimeline(hours)
  const { data: alertData } = useOpsecAlerts(threshold)
  const { data: schedData } = useScheduledScans()
  const cancelScan = useCancelScheduledScan()

  const alerts = alertData?.alerts ?? []
  const buckets = timeline?.buckets ?? []
  const sourceIps = timeline?.source_ips ?? []
  const recentScans = timeline?.recent_scans ?? []
  const scheduledScans = schedData?.scheduled_scans ?? []
  const maxCount = Math.max(...buckets.map(b => b.count), 1)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <ShieldAlert className="h-5 w-5" /> OpSec Dashboard
        </h2>
        <div className="flex items-center gap-2">
          <select value={hours} onChange={e => setHours(Number(e.target.value))}
            className="h-7 px-2 text-xs rounded border border-border bg-background">
            <option value={6}>Last 6h</option>
            <option value={24}>Last 24h</option>
            <option value={168}>Last 7d</option>
          </select>
          <label className="text-xs text-muted-foreground flex items-center gap-1">
            Alert threshold:
            <input type="number" value={threshold} onChange={e => setThreshold(Number(e.target.value))}
              className="w-12 h-7 px-1 text-xs rounded border border-border bg-background text-center" />
          </label>
        </div>
      </div>

      {/* Alerts banner */}
      {alerts.length > 0 && (
        <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/5 space-y-1">
          {alerts.map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              <span className="text-red-300">{a.message}</span>
            </div>
          ))}
        </div>
      )}

      {/* Scan rate chart */}
      <div className="p-4 rounded-lg border border-border bg-card">
        <h3 className="text-xs font-medium text-muted-foreground mb-3">Scan Rate (per hour)</h3>
        {tlLoading ? (
          <div className="text-xs text-muted-foreground">Loading...</div>
        ) : buckets.length === 0 ? (
          <div className="text-xs text-muted-foreground">No scan activity in this period.</div>
        ) : (
          <div className="flex items-end gap-1 h-32">
            {buckets.map((b, i) => (
              <div key={i} className="flex-1 flex flex-col items-center group relative">
                <div
                  className={cn(
                    'w-full rounded-t',
                    b.count > threshold ? 'bg-red-500' : 'bg-primary/60',
                  )}
                  style={{ height: `${(b.count / maxCount) * 100}%`, minHeight: b.count > 0 ? '4px' : '0px' }}
                />
                <div className="absolute -top-6 hidden group-hover:block text-[10px] bg-popover px-1 rounded shadow whitespace-nowrap">
                  {b.hour}: {b.count}
                </div>
              </div>
            ))}
          </div>
        )}
        {buckets.length > 0 && (
          <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
            <span>{buckets[0]?.hour}</span>
            <span>{buckets[buckets.length - 1]?.hour}</span>
          </div>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Source IPs */}
        <div className="p-4 rounded-lg border border-border bg-card">
          <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
            <Wifi className="h-3 w-3" /> Source IP / Node Usage
          </h3>
          {sourceIps.length === 0 ? (
            <div className="text-xs text-muted-foreground">No data</div>
          ) : (
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {sourceIps.map(s => (
                <div key={s.source} className="flex items-center justify-between text-xs">
                  <span className="font-mono">{s.source}</span>
                  <span className="text-muted-foreground">{s.count} scans</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Scheduled Scans */}
        <div className="p-4 rounded-lg border border-border bg-card">
          <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
            <Clock className="h-3 w-3" /> Scheduled Scans
          </h3>
          {scheduledScans.length === 0 ? (
            <div className="text-xs text-muted-foreground">No scheduled scans</div>
          ) : (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {scheduledScans.map(s => (
                <div key={s.id} className="flex items-center justify-between text-xs p-2 rounded border border-border">
                  <div>
                    <div className="font-medium">{s.scan_type}</div>
                    <div className="text-muted-foreground">
                      {new Date(s.scheduled_at).toLocaleString()}
                      {s.jitter_seconds > 0 && ` (+${s.jitter_seconds}s jitter)`}
                    </div>
                    <div className={cn(
                      'text-[10px] capitalize',
                      s.status === 'scheduled' ? 'text-blue-400' : s.status === 'running' ? 'text-green-400' : 'text-muted-foreground',
                    )}>{s.status}</div>
                  </div>
                  {s.status === 'scheduled' && (
                    <button
                      onClick={() => cancelScan.mutate(s.id)}
                      className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent Scan Activity Log */}
      <div className="p-4 rounded-lg border border-border bg-card">
        <h3 className="text-xs font-medium text-muted-foreground mb-3 flex items-center gap-1">
          <Activity className="h-3 w-3" /> Scan Activity Log ({recentScans.length} scans)
        </h3>
        {recentScans.length === 0 ? (
          <div className="text-xs text-muted-foreground">No scan activity in this period.</div>
        ) : (
          <div className="max-h-[500px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="bg-accent/30 sticky top-0">
                <tr>
                  <th className="text-left px-2 py-1.5 font-medium w-20">Status</th>
                  <th className="text-left px-2 py-1.5 font-medium w-24">Type</th>
                  <th className="text-left px-2 py-1.5 font-medium w-28">Source IP</th>
                  <th className="text-left px-2 py-1.5 font-medium">Target</th>
                  <th className="text-left px-2 py-1.5 font-medium w-32">Started</th>
                  <th className="text-left px-2 py-1.5 font-medium w-32">Ended</th>
                  <th className="text-right px-2 py-1.5 font-medium w-16">Duration</th>
                  <th className="text-left px-2 py-1.5 font-medium w-16">Mode</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {recentScans.map((scan, i) => (
                  <ScanRow key={`${scan.job_id}-${i}`} scan={scan} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function ScanRow({ scan }: { scan: RecentScan }) {
  const statusColor = STATUS_COLORS[scan.status] || 'text-muted-foreground'
  const target = scan.target_url
    || (scan.targets?.length ? scan.targets.join(', ') : '')
    || ''

  return (
    <tr className={cn('hover:bg-accent/20', scan.error && 'bg-red-500/5')}>
      <td className="px-2 py-1.5">
        <span className={cn('font-medium capitalize', statusColor)}>{scan.status}</span>
      </td>
      <td className="px-2 py-1.5">
        <span className="px-1.5 py-0.5 bg-accent rounded font-mono">{scan.scan_type}</span>
      </td>
      <td className="px-2 py-1.5 font-mono">
        {scan.source_ip}
        {scan.hostname && scan.hostname !== scan.source_ip && (
          <span className="text-muted-foreground/50 ml-1 text-[10px]">({scan.hostname.slice(0, 8)})</span>
        )}
      </td>
      <td className="px-2 py-1.5 font-mono truncate max-w-[220px]" title={target}>
        {target || '-'}
        {scan.error && (
          <span className="text-red-400 ml-1 text-[10px]" title={scan.error}>({scan.error.slice(0, 40)})</span>
        )}
      </td>
      <td className="px-2 py-1.5 text-muted-foreground whitespace-nowrap">
        {scan.started_at ? formatDate(scan.started_at) : '-'}
      </td>
      <td className="px-2 py-1.5 text-muted-foreground whitespace-nowrap">
        {scan.ended_at ? formatDate(scan.ended_at) : scan.status === 'running' ? <span className="text-blue-400">in progress</span> : '-'}
      </td>
      <td className="px-2 py-1.5 text-right text-muted-foreground">
        {scan.duration_s != null ? `${scan.duration_s}s` : ''}
      </td>
      <td className="px-2 py-1.5">
        <span className={cn('text-[10px]',
          scan.execution_mode === 'remote' ? 'text-amber-400' : 'text-muted-foreground',
        )}>
          {scan.execution_mode}
          {scan.node_id && <span className="ml-0.5">({scan.node_id.slice(0, 6)})</span>}
        </span>
      </td>
    </tr>
  )
}
