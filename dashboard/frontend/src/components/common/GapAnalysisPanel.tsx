import { useState } from 'react'
import {
  useGapReport, useTriggerGapAnalysis, useAutoFillGaps,
  useGapSchedule, useSetGapSchedule,
  type GapReport, type GapTargetDetail,
} from '@/api/agents'
import { cn } from '@/lib/utils'
import { Play, Loader2, Zap, RefreshCw, CheckCircle2, XCircle, Clock, Timer } from 'lucide-react'

const CATEGORY_ORDER = [
  'subdomain_enumeration', 'dns_resolution', 'tls_certificates',
  'http_probing', 'asn_mapping', 'whois', 'waf_detection', 'port_enumeration',
]

const CATEGORY_SHORT: Record<string, string> = {
  subdomain_enumeration: 'Subs',
  dns_resolution: 'DNS',
  tls_certificates: 'TLS',
  http_probing: 'HTTP',
  asn_mapping: 'ASN',
  whois: 'WHOIS',
  waf_detection: 'WAF',
  port_enumeration: 'Ports',
}


export function GapAnalysisAgentPanel({ engagementId }: { engagementId: string }) {
  const { data, isLoading } = useGapReport(engagementId)
  const triggerGap = useTriggerGapAnalysis()
  const autoFill = useAutoFillGaps()
  const { data: schedData } = useGapSchedule(engagementId)
  const setSchedule = useSetGapSchedule()
  const schedule = schedData?.schedule
  const report = data?.report as GapReport | null

  const summary = report?.report?.summary
  const targets = report?.report?.targets || {}
  const recs = report?.recommendations || []
  const passiveRecs = recs.filter(r => r.passive)
  const activeRecs = recs.filter(r => !r.passive)

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Zap className="h-4 w-4" /> Recon Gap Analysis
          {report?.status && (
            <span className={cn('px-1.5 py-0.5 text-[10px] rounded', {
              'bg-green-500/10 text-green-400': report.status === 'completed',
              'bg-blue-500/10 text-blue-400': report.status === 'running',
              'bg-red-500/10 text-red-400': report.status === 'failed',
              'bg-yellow-500/10 text-yellow-400': report.status === 'pending',
            })}>
              {report.status}
            </span>
          )}
        </h3>
        <div className="flex items-center gap-2">
          {report?.completed_at && (
            <span className="text-[10px] text-muted-foreground flex items-center gap-1">
              <Clock className="h-2.5 w-2.5" />
              {new Date(report.completed_at).toLocaleString()}
            </span>
          )}
          <button
            onClick={() => triggerGap.mutate(engagementId)}
            disabled={triggerGap.isPending || report?.status === 'running'}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
          >
            {triggerGap.isPending || report?.status === 'running'
              ? <Loader2 className="h-2.5 w-2.5 animate-spin" />
              : <Play className="h-2.5 w-2.5" />}
            {report ? 'Re-run' : 'Run Analysis'}
          </button>
          {passiveRecs.length > 0 && (
            <button
              onClick={() => autoFill.mutate({ engagementId, reportId: report?.id })}
              disabled={autoFill.isPending}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-green-600 hover:bg-green-500 text-white disabled:opacity-50"
            >
              {autoFill.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Zap className="h-2.5 w-2.5" />}
              Auto-Fill ({passiveRecs.length})
            </button>
          )}
        </div>
      </div>

      {/* Auto-Schedule Toggle */}
      <div className="flex items-center gap-3 text-xs bg-muted/30 rounded p-2">
        <Timer className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-muted-foreground">Auto-run when idle:</span>
        <button
          onClick={() => setSchedule.mutate({
            engagementId,
            enabled: !schedule?.enabled,
            interval_minutes: schedule?.interval_minutes ?? 30,
            auto_fill: schedule?.auto_fill ?? true,
          })}
          disabled={setSchedule.isPending}
          className={cn('px-2 py-0.5 rounded text-[10px] font-medium border',
            schedule?.enabled
              ? 'bg-green-500/20 text-green-400 border-green-500/30'
              : 'bg-muted text-muted-foreground border-border'
          )}
        >
          {schedule?.enabled ? 'Enabled' : 'Disabled'}
        </button>
        {schedule?.enabled && (
          <>
            <select
              value={schedule.interval_minutes}
              onChange={e => setSchedule.mutate({
                engagementId,
                enabled: true,
                interval_minutes: Number(e.target.value),
                auto_fill: schedule.auto_fill,
              })}
              className="text-[10px] px-1.5 py-0.5 rounded bg-background border border-border"
            >
              <option value={15}>Every 15 min</option>
              <option value={30}>Every 30 min</option>
              <option value={60}>Every 1 hour</option>
              <option value={120}>Every 2 hours</option>
            </select>
            <label className="flex items-center gap-1 text-[10px]">
              <input
                type="checkbox"
                checked={schedule.auto_fill}
                onChange={e => setSchedule.mutate({
                  engagementId,
                  enabled: true,
                  interval_minutes: schedule.interval_minutes,
                  auto_fill: e.target.checked,
                })}
                className="h-3 w-3"
              />
              Auto-fill passive
            </label>
          </>
        )}
      </div>

      {isLoading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}

      {!report && !isLoading && (
        <p className="text-xs text-muted-foreground">
          Run gap analysis to identify missing recon data for this engagement's scope targets.
        </p>
      )}

      {/* Summary */}
      {summary && (
        <div className="flex gap-4 text-xs">
          <span>Targets: <span className="font-medium">{summary.total_targets}</span></span>
          <span>Coverage: <span className={cn('font-medium',
            summary.avg_coverage_pct >= 70 ? 'text-green-400' :
            summary.avg_coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400'
          )}>{summary.avg_coverage_pct}%</span></span>
          <span>Gaps: <span className={cn('font-medium',
            summary.total_gaps > 0 ? 'text-amber-400' : 'text-green-400'
          )}>{summary.total_gaps}</span></span>
          {report!.scans_dispatched > 0 && (
            <span>Scans dispatched: <span className="font-medium">{report!.scans_dispatched}</span></span>
          )}
        </div>
      )}

      {/* Coverage Table */}
      {Object.keys(targets).length > 0 && (
        <div className="overflow-x-auto max-h-64 overflow-y-auto">
          <table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border">
                <th className="text-left py-1 px-2 font-medium text-muted-foreground">Target</th>
                {CATEGORY_ORDER.map(cat => (
                  <th key={cat} className="text-center py-1 px-1 font-medium text-muted-foreground">{CATEGORY_SHORT[cat]}</th>
                ))}
                <th className="text-right py-1 px-2 font-medium text-muted-foreground">%</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(targets).slice(0, 50).map(([target, info]) => {
                const tInfo = info as GapTargetDetail
                return (
                  <tr key={target} className="border-b border-border/30 hover:bg-muted/20">
                    <td className="py-0.5 px-2 font-mono truncate max-w-[180px]" title={target}>{target}</td>
                    {CATEGORY_ORDER.map(cat => {
                      const c = tInfo.categories?.[cat]
                      if (!c) return <td key={cat} className="text-center py-0.5 text-muted-foreground">-</td>
                      return (
                        <td key={cat} className="text-center py-0.5">
                          {c.has_data
                            ? <CheckCircle2 className="h-3 w-3 text-green-500 inline" />
                            : <XCircle className="h-3 w-3 text-red-400 inline" />}
                        </td>
                      )
                    })}
                    <td className="text-right py-0.5 px-2">
                      <span className={cn('font-medium',
                        tInfo.coverage_pct >= 70 ? 'text-green-400' :
                        tInfo.coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400'
                      )}>{tInfo.coverage_pct}%</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {Object.keys(targets).length > 50 && (
            <p className="text-[10px] text-muted-foreground mt-1 px-2">
              Showing 50 of {Object.keys(targets).length} targets
            </p>
          )}
        </div>
      )}

      {/* Recommendations */}
      {recs.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground font-medium">
            Recommendations ({passiveRecs.length} passive, {activeRecs.length} active)
          </summary>
          <div className="mt-1 grid grid-cols-1 md:grid-cols-2 gap-0.5 max-h-40 overflow-y-auto">
            {recs.slice(0, 30).map((rec, i) => (
              <div key={i} className={cn(
                'flex items-center justify-between text-[10px] px-2 py-0.5 rounded',
                rec.passive ? 'bg-green-500/5' : 'bg-amber-500/5',
              )}>
                <span className="flex items-center gap-1">
                  <span className={rec.passive ? 'text-green-400' : 'text-amber-400'}>
                    {rec.passive ? 'P' : 'A'}
                  </span>
                  <span className="font-mono">{rec.scan_type}</span>
                  <span className="text-muted-foreground truncate max-w-[120px]">{rec.target}</span>
                </span>
                <span className="text-muted-foreground">{rec.category_label}</span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}
