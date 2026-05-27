import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import {
  useAgentsStatus, useGapReport, useTriggerGapAnalysis, useAutoFillGaps,
  type AgentInfo, type GapReport, type GapTargetDetail,
} from '@/api/agents'
import { useUIStore } from '@/stores/ui'
import { cn } from '@/lib/utils'
import {
  Bot, Cpu, Search, Shield, Loader2, Play, ExternalLink,
  CheckCircle2, XCircle, RefreshCw, Zap, Settings, Clock, Cloud,
} from 'lucide-react'

const AGENT_ICONS: Record<string, typeof Bot> = {
  'pentest-agent': Shield,
  'osint-agent': Search,
  'scan-recommender': Cpu,
  'recon-agent': RefreshCw,
  'gap-agent': Zap,
  'cloud-triage-agent': Cloud,
}

const STATUS_COLORS: Record<string, string> = {
  running: 'bg-green-500',
  idle: 'bg-blue-500',
  error: 'bg-red-500',
  unreachable: 'bg-gray-500',
}

const STATUS_TEXT: Record<string, string> = {
  running: 'text-green-400',
  idle: 'text-blue-400',
  error: 'text-red-400',
  unreachable: 'text-gray-400',
}

// Where clicking each card navigates to
const AGENT_LINKS: Record<string, string> = {
  'pentest-agent': '/agent-sessions',
  'osint-agent': '/follow-ups',
  'scan-recommender': '/exploits',
  'recon-agent': '/engagements',
  'gap-agent': '/engagements',
  'cloud-triage-agent': '/cloud-posture',
}

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

// ── Run-now hooks ─────────────────────────────────────────────────────

function useRunOsintScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ ok: boolean }>('/agent/scan', { method: 'POST', body: JSON.stringify({}) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents-status'] }),
  })
}

function useRunReconAgentNow(engagementId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<{ ok: boolean }>(`/recon-agent/${engagementId}/run-now`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents-status'] }),
  })
}


export default function AIAgents() {
  const { data: agentsData, isLoading } = useAgentsStatus()
  const selectedEngagement = useUIStore(s => s.selectedEngagementId)
  const agents = agentsData?.agents ?? []

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold flex items-center gap-2">
          <Bot className="h-5 w-5" /> AI Agents
        </h2>
        {!selectedEngagement && (
          <span className="text-xs text-muted-foreground">Select an engagement in the top bar for per-engagement agents</span>
        )}
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading agents...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {agents.map(agent => (
            <AgentCard key={agent.id} agent={agent} engagementId={selectedEngagement} />
          ))}
        </div>
      )}

      {selectedEngagement && (
        <GapAnalysisPanel engagementId={selectedEngagement} />
      )}
    </div>
  )
}


function AgentCard({ agent, engagementId }: { agent: AgentInfo; engagementId: string | null }) {
  const Icon = AGENT_ICONS[agent.id] || Bot
  const navigate = useNavigate()
  const triggerGap = useTriggerGapAnalysis()
  const autoFill = useAutoFillGaps()
  const runOsint = useRunOsintScan()
  const runRecon = useRunReconAgentNow(engagementId)
  const link = AGENT_LINKS[agent.id]

  const handleCardClick = () => {
    if (link) navigate(link)
  }

  return (
    <div
      className="bg-card border border-border rounded-lg p-3 space-y-2 cursor-pointer hover:border-primary/50 transition-colors"
      onClick={handleCardClick}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span className="font-semibold text-sm">{agent.name}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={cn('h-2 w-2 rounded-full', STATUS_COLORS[agent.status] || 'bg-gray-400')} />
          <span className={cn('text-[10px] font-medium', STATUS_TEXT[agent.status] || 'text-gray-400')}>
            {agent.status}
          </span>
        </div>
      </div>

      <p className="text-[11px] text-muted-foreground">{agent.description}</p>

      {/* Agent-specific stats */}
      <div className="flex flex-wrap gap-2 text-[10px]">
        {agent.active_sessions != null && (
          <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
            {agent.active_sessions} active session{agent.active_sessions !== 1 ? 's' : ''}
          </span>
        )}
        {agent.findings_created != null && (
          <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
            {agent.findings_created} follow-ups created
          </span>
        )}
        {agent.enabled_engagements != null && (
          <span className={cn('px-1.5 py-0.5 rounded border',
            agent.enabled_engagements > 0 ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-muted text-muted-foreground border-border'
          )}>
            {agent.enabled_engagements} engagement{agent.enabled_engagements !== 1 ? 's' : ''} enabled
          </span>
        )}
        {agent.coverage_total != null && (
          <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
            {agent.coverage_completed}/{agent.coverage_total} coverage
            {(agent.coverage_running ?? 0) > 0 && <span className="text-green-400 ml-1">({agent.coverage_running} running)</span>}
            {(agent.coverage_pending ?? 0) > 0 && ` (${agent.coverage_pending} pending)`}
          </span>
        )}
        {agent.gaps_found != null && (
          <span className={cn('px-1.5 py-0.5 rounded border',
            agent.gaps_found > 0 ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-green-500/10 text-green-400 border-green-500/20'
          )}>
            {agent.gaps_found} gap{agent.gaps_found !== 1 ? 's' : ''} found
          </span>
        )}
        {agent.last_run && (
          <span className="text-muted-foreground flex items-center gap-0.5">
            <Clock className="h-2.5 w-2.5" />
            {new Date(agent.last_run).toLocaleDateString()} {new Date(agent.last_run).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        )}
      </div>

      {/* Actions — stop propagation so clicks don't navigate */}
      <div className="flex gap-1.5 pt-1" onClick={e => e.stopPropagation()}>
        {/* Run Now buttons */}
        {agent.id === 'osint-agent' && (
          <button
            onClick={() => runOsint.mutate()}
            disabled={runOsint.isPending}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-blue-600 hover:bg-blue-500 text-white"
          >
            {runOsint.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Play className="h-2.5 w-2.5" />}
            Run Now
          </button>
        )}
        {agent.id === 'recon-agent' && engagementId && (
          <button
            onClick={() => runRecon.mutate()}
            disabled={runRecon.isPending}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-blue-600 hover:bg-blue-500 text-white"
          >
            {runRecon.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Play className="h-2.5 w-2.5" />}
            Run Now
          </button>
        )}
        {agent.id === 'gap-agent' && engagementId && (
          <>
            <button
              onClick={() => triggerGap.mutate(engagementId)}
              disabled={triggerGap.isPending}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-blue-600 hover:bg-blue-500 text-white"
            >
              {triggerGap.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Play className="h-2.5 w-2.5" />}
              Run Now
            </button>
            <button
              onClick={() => autoFill.mutate({ engagementId })}
              disabled={autoFill.isPending}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-green-600 hover:bg-green-500 text-white"
            >
              {autoFill.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Zap className="h-2.5 w-2.5" />}
              Auto-Fill
            </button>
          </>
        )}

        {/* Configure / View links */}
        {agent.id === 'pentest-agent' && (
          <a href="/agent-sessions" className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-muted hover:bg-muted/80 border border-border">
            <ExternalLink className="h-2.5 w-2.5" /> Sessions
          </a>
        )}
        {agent.id === 'osint-agent' && (
          <a href="/follow-ups" className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-muted hover:bg-muted/80 border border-border">
            <ExternalLink className="h-2.5 w-2.5" /> Follow-Ups
          </a>
        )}
        {(agent.id === 'recon-agent' || agent.id === 'gap-agent') && (
          <a href="/engagements" className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-muted hover:bg-muted/80 border border-border">
            <Settings className="h-2.5 w-2.5" /> Configure
          </a>
        )}
      </div>
    </div>
  )
}


function GapAnalysisPanel({ engagementId }: { engagementId: string }) {
  const { data, isLoading } = useGapReport(engagementId)
  const triggerGap = useTriggerGapAnalysis()
  const autoFill = useAutoFillGaps()
  const report = data?.report as GapReport | null

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-lg p-4">
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (!report) {
    return (
      <div className="bg-card border border-border rounded-lg p-4 space-y-2">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Zap className="h-4 w-4" /> Recon Gap Analysis
        </h3>
        <p className="text-xs text-muted-foreground">No gap analysis has been run for this engagement yet.</p>
        <button
          onClick={() => triggerGap.mutate(engagementId)}
          disabled={triggerGap.isPending}
          className="flex items-center gap-1 px-3 py-1.5 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white"
        >
          {triggerGap.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
          Run Gap Analysis
        </button>
      </div>
    )
  }

  const summary = report.report?.summary
  const targets = report.report?.targets || {}

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Zap className="h-4 w-4" /> Gap Analysis Report
          <span className={cn('px-1.5 py-0.5 text-[10px] rounded', {
            'bg-green-500/10 text-green-400': report.status === 'completed',
            'bg-blue-500/10 text-blue-400': report.status === 'running',
            'bg-red-500/10 text-red-400': report.status === 'failed',
            'bg-yellow-500/10 text-yellow-400': report.status === 'pending',
          })}>
            {report.status}
          </span>
        </h3>
        <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
          {report.completed_at && (
            <span>{new Date(report.completed_at).toLocaleString()}</span>
          )}
          <button
            onClick={() => triggerGap.mutate(engagementId)}
            disabled={triggerGap.isPending}
            className="flex items-center gap-1 px-2 py-0.5 rounded bg-muted hover:bg-muted/80 border border-border text-foreground"
          >
            <RefreshCw className="h-2.5 w-2.5" /> Re-run
          </button>
        </div>
      </div>

      {summary && (
        <div className="flex gap-4 text-xs">
          <div>
            <span className="text-muted-foreground">Targets:</span>{' '}
            <span className="font-medium">{summary.total_targets}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Avg Coverage:</span>{' '}
            <span className={cn('font-medium', summary.avg_coverage_pct >= 70 ? 'text-green-400' : summary.avg_coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400')}>
              {summary.avg_coverage_pct}%
            </span>
          </div>
          <div>
            <span className="text-muted-foreground">Gaps:</span>{' '}
            <span className={cn('font-medium', summary.total_gaps > 0 ? 'text-amber-400' : 'text-green-400')}>
              {summary.total_gaps}
            </span>
          </div>
          {report.scans_dispatched > 0 && (
            <div>
              <span className="text-muted-foreground">Scans dispatched:</span>{' '}
              <span className="font-medium">{report.scans_dispatched}</span>
            </div>
          )}
        </div>
      )}

      {Object.keys(targets).length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[10px]">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-1 px-2 font-medium text-muted-foreground">Target</th>
                {CATEGORY_ORDER.map(cat => (
                  <th key={cat} className="text-center py-1 px-1.5 font-medium text-muted-foreground">
                    {CATEGORY_SHORT[cat]}
                  </th>
                ))}
                <th className="text-right py-1 px-2 font-medium text-muted-foreground">Coverage</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(targets).map(([target, info]) => (
                <TargetRow key={target} target={target} info={info as GapTargetDetail} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {report.recommendations && report.recommendations.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-muted-foreground">Recommendations</h4>
            {report.recommendations.some(r => r.passive) && (
              <button
                onClick={() => autoFill.mutate({ engagementId, reportId: report.id })}
                disabled={autoFill.isPending}
                className="flex items-center gap-1 px-2 py-0.5 text-[10px] rounded bg-green-600 hover:bg-green-500 text-white"
              >
                {autoFill.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Zap className="h-2.5 w-2.5" />}
                Auto-Fill Passive ({report.recommendations.filter(r => r.passive).length})
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
            {report.recommendations.map((rec, i) => (
              <div key={i} className={cn(
                'flex items-center justify-between text-[10px] px-2 py-1 rounded',
                rec.passive ? 'bg-green-500/5 border border-green-500/20' : 'bg-amber-500/5 border border-amber-500/20',
              )}>
                <div className="flex items-center gap-1.5">
                  <span className={rec.passive ? 'text-green-400' : 'text-amber-400'}>
                    {rec.passive ? 'PASSIVE' : 'ACTIVE'}
                  </span>
                  <span className="font-mono">{rec.scan_type}</span>
                  <span className="text-muted-foreground truncate max-w-[200px]">{rec.target}</span>
                </div>
                <span className="text-muted-foreground">{rec.category_label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


function TargetRow({ target, info }: { target: string; info: GapTargetDetail }) {
  return (
    <tr className="border-b border-border/50 hover:bg-muted/30">
      <td className="py-1 px-2 font-mono truncate max-w-[200px]" title={target}>{target}</td>
      {CATEGORY_ORDER.map(cat => {
        const catData = info.categories?.[cat]
        if (!catData) {
          return <td key={cat} className="text-center py-1 px-1.5 text-muted-foreground">-</td>
        }
        return (
          <td key={cat} className="text-center py-1 px-1.5">
            {catData.has_data ? (
              <CheckCircle2 className="h-3 w-3 text-green-500 inline" />
            ) : (
              <XCircle className="h-3 w-3 text-red-400 inline" />
            )}
            {catData.finding_count > 0 && (
              <span className="ml-0.5 text-muted-foreground">{catData.finding_count}</span>
            )}
          </td>
        )
      })}
      <td className="text-right py-1 px-2">
        <span className={cn('font-medium',
          info.coverage_pct >= 70 ? 'text-green-400' :
          info.coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400'
        )}>
          {info.coverage_pct}%
        </span>
      </td>
    </tr>
  )
}
