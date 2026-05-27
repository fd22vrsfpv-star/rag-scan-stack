import { useState } from 'react'
import { useFindings } from '@/api/findings'
import { useAssets } from '@/api/assets'
import { useScans } from '@/api/scans'
import { useHealth } from '@/api/reports'
import { useCloudPosture } from '@/api/cloudSuggestor'
import { useUIStore } from '@/stores/ui'
import { SeverityBadge } from '@/components/common/SeverityBadge'
import { StatusDot } from '@/components/common/StatusDot'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie,
} from 'recharts'
import { SEVERITY_COLORS, SEVERITY_LEVELS, type Severity } from '@/lib/constants'
import { cn, formatDate } from '@/lib/utils'

function getResultCount(result: unknown): string {
  if (result && typeof result === 'object' && !Array.isArray(result)) {
    const r = result as Record<string, unknown>
    for (const key of ['count', 'total', 'length']) {
      if (typeof r[key] === 'number') return String(r[key])
    }
    for (const val of Object.values(r)) {
      if (Array.isArray(val)) return String(val.length)
    }
  }
  if (Array.isArray(result)) return String(result.length)
  return '—'
}

export default function Dashboard() {
  const [recentTab, setRecentTab] = useState<'findings' | 'scans'>('findings')
  const selectedEngagementId = useUIStore(s => s.selectedEngagementId)
  const { data: findingsData } = useFindings({
    limit: 10,
    engagement_id: selectedEngagementId || undefined,
  })
  const { data: assetsData } = useAssets()
  const { data: scansData } = useScans()
  const { data: health } = useHealth()
  const { data: cloudPosture } = useCloudPosture()

  const agg = findingsData?.aggregations?.by_severity || {}
  const chartData = SEVERITY_LEVELS
    .filter(s => agg[s] != null)
    .map(s => ({ name: s, value: agg[s] }))
  const totalFindings = findingsData?.total ?? 0
  const totalAssets = assetsData?.count ?? 0
  const activeScans = scansData?.jobs?.filter(j => j.status === 'running' || j.status === 'queued').length ?? 0
  const healthyServices = health
    ? Object.values(health.services).filter(s => s.status === 'healthy').length
    : 0

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
        <StatCard title="Total Findings" value={totalFindings} subtitle={`${agg.critical ?? 0} critical`} color="text-red-500" />
        <StatCard title="Assets Discovered" value={totalAssets} />
        <StatCard title="Active Scans" value={activeScans} color="text-green-500" />
        <StatCard title="Services Online" value={`${healthyServices}/${health ? Object.keys(health.services).length : 0}`} />
        {cloudPosture && (cloudPosture.total_cloud_findings > 0 || cloudPosture.active_cloud_creds > 0) && (
          <Link to="/scans/launch" className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors">
            <p className="text-xs text-muted-foreground">Cloud Advisor</p>
            <p className="text-2xl font-bold mt-1 text-cyan-500">{cloudPosture.total_open_recommendations}</p>
            <div className="flex gap-1.5 mt-1 flex-wrap">
              {(cloudPosture.open_recommendations.critical ?? 0) > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] bg-red-600 text-white rounded">{cloudPosture.open_recommendations.critical} critical</span>
              )}
              {(cloudPosture.open_recommendations.high ?? 0) > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] bg-orange-600 text-white rounded">{cloudPosture.open_recommendations.high} high</span>
              )}
              {(cloudPosture.open_recommendations.medium ?? 0) > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] bg-yellow-400 text-black rounded">{cloudPosture.open_recommendations.medium} med</span>
              )}
            </div>
          </Link>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Chart */}
        <div className="bg-card border border-border rounded-lg p-4">
          <h2 className="text-sm font-semibold mb-3">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData}>
              <XAxis dataKey="name" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {chartData.map(entry => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as Severity] || '#6b7280'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Active Scans */}
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Active Scans</h2>
            <Link to="/scans" className="text-xs text-primary hover:underline">View all</Link>
          </div>
          <div className="space-y-2">
            {scansData?.jobs?.filter(j => j.status !== 'completed' && j.status !== 'failed').slice(0, 5).map(job => (
              <div key={job.job_id} className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0">
                <div className="flex items-center gap-2">
                  <StatusDot status={job.status} />
                  <span className="text-xs font-mono">{job.type}</span>
                </div>
                <span className="text-xs text-muted-foreground">{job.status}</span>
              </div>
            )) ?? (
              <p className="text-xs text-muted-foreground">No active scans</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent Findings / Recent Scans */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setRecentTab('findings')}
              className={cn(
                'px-2 py-0.5 rounded text-xs border',
                recentTab === 'findings' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground',
              )}
            >Recent Findings</button>
            <button
              onClick={() => setRecentTab('scans')}
              className={cn(
                'px-2 py-0.5 rounded text-xs border',
                recentTab === 'scans' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground',
              )}
            >Recent Scans</button>
          </div>
          <Link to={recentTab === 'findings' ? '/findings' : '/scans'} className="text-xs text-primary hover:underline">View all</Link>
        </div>

        {recentTab === 'findings' ? (
          <div className="space-y-2">
            {findingsData?.findings?.slice(0, 8).map((f, i) => (
              <div key={i} className="flex items-center gap-3 py-1.5 border-b border-border/50 last:border-0">
                <SeverityBadge severity={f.severity} />
                <span className="text-xs flex-1 truncate">{f.title}</span>
                <span className="text-xs text-muted-foreground font-mono">{f.ip}</span>
                <span className="text-xs text-muted-foreground">{f.source}</span>
              </div>
            )) ?? (
              <p className="text-xs text-muted-foreground">No findings yet</p>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {scansData?.jobs
              ?.filter(j => j.status === 'completed' || j.status === 'failed')
              .sort((a, b) => (b.completed_at ?? '').localeCompare(a.completed_at ?? ''))
              .slice(0, 8)
              .map(job => (
                <Link key={job.job_id} to={`/scans/${job.job_id}`} className="flex items-center gap-3 py-1.5 border-b border-border/50 last:border-0 hover:bg-muted/50 -mx-1 px-1 rounded">
                  <StatusDot status={job.status} />
                  <span className="text-xs font-mono flex-1">{job.type}</span>
                  <span className="text-xs text-muted-foreground">{job.completed_at ? formatDate(job.completed_at) : '—'}</span>
                  <span className="text-xs text-muted-foreground font-mono">{getResultCount(job.result)}</span>
                </Link>
              )) ?? (
              <p className="text-xs text-muted-foreground">No completed scans</p>
            )}
            {scansData?.jobs?.filter(j => j.status === 'completed' || j.status === 'failed').length === 0 && (
              <p className="text-xs text-muted-foreground">No completed scans</p>
            )}
          </div>
        )}
      </div>

      {/* Quick Launch */}
      <div className="flex gap-3">
        <Link
          to="/scans/launch"
          className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
        >
          Launch Scan
        </Link>
        <Link
          to="/reports"
          className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm hover:bg-secondary/80"
        >
          Generate Report
        </Link>
      </div>
    </div>
  )
}

function StatCard({ title, value, subtitle, color }: {
  title: string
  value: number | string
  subtitle?: string
  color?: string
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <p className="text-xs text-muted-foreground">{title}</p>
      <p className={`text-2xl font-bold mt-1 ${color || ''}`}>{value}</p>
      {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
    </div>
  )
}
