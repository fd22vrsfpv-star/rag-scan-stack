import { useState } from 'react'
import {
  useTargetedReconLookup,
  useTargetedReconExecute,
  type ReconCommand,
  type ExecuteResult,
} from '@/api/targeted-recon'
import { useUIStore } from '@/stores/ui'

const RISK_BADGE: Record<string, string> = {
  safe: 'bg-green-700 text-white',
  active: 'bg-yellow-600 text-black',
  exploit: 'bg-red-600 text-white',
}

export default function TargetedRecon() {
  const [target, setTarget] = useState('')
  const [port, setPort] = useState<number | undefined>()
  const [service, setService] = useState('')
  const [submitted, setSubmitted] = useState<{ t: string; p?: number; s?: string } | null>(null)
  const [selectedNode, setSelectedNode] = useState('')
  const [results, setResults] = useState<Record<string, ExecuteResult>>({})
  const [runningTools, setRunningTools] = useState<Set<string>>(new Set())
  const engagementId = useUIStore((s: { selectedEngagementId: string | null }) => s.selectedEngagementId)

  const { data, isLoading } = useTargetedReconLookup(
    submitted?.t || '',
    submitted?.p,
    submitted?.s
  )
  const execMutation = useTargetedReconExecute()

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    setSubmitted({ t: target.trim(), p: port, s: service || undefined })
    setResults({})
  }

  const handleExecute = async (cmd: ReconCommand) => {
    if (!selectedNode || !submitted) return
    const key = `${cmd.tool}:${cmd.command}`
    setRunningTools((prev) => new Set(prev).add(key))
    try {
      const res = await execMutation.mutateAsync({
        node_id: selectedNode,
        command: cmd.command,
        tool_name: cmd.tool,
        target: submitted.t,
        port: submitted.p,
        service: submitted.s,
        auto_ingest: true,
        engagement_id: engagementId || undefined,
      })
      setResults((prev) => ({ ...prev, [key]: res }))
    } catch {
      // mutation error handled by react-query
    } finally {
      setRunningTools((prev) => {
        const next = new Set(prev)
        next.delete(key)
        return next
      })
    }
  }

  const handleRunAllSafe = async () => {
    if (!data || !selectedNode) return
    const safeCmds = data.commands.filter((c) => c.risk === 'safe' && c.command)
    for (const cmd of safeCmds) {
      await handleExecute(cmd)
    }
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold">Targeted Recon</h1>
      <p className="text-muted-foreground text-sm">
        Select a target and port to get recommended commands from the knowledge base.
        Execute them on a remote proxy node with automatic result ingestion.
      </p>

      {/* Lookup Form */}
      <form onSubmit={handleLookup} className="flex gap-3 items-end flex-wrap">
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Target (IP/hostname)</label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="10.0.0.5"
            className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border w-56"
            required
          />
        </div>
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Port</label>
          <input
            type="number"
            value={port ?? ''}
            onChange={(e) => setPort(e.target.value ? Number(e.target.value) : undefined)}
            placeholder="22"
            className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border w-24"
          />
        </div>
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Service (optional)</label>
          <input
            value={service}
            onChange={(e) => setService(e.target.value)}
            placeholder="ssh"
            className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border w-32"
          />
        </div>
        <button
          type="submit"
          className="bg-primary text-primary-foreground px-4 py-1.5 rounded-md text-sm font-medium"
        >
          Lookup
        </button>
      </form>

      {isLoading && <p className="text-muted-foreground text-sm">Loading recommendations...</p>}

      {data && (
        <>
          {/* Service Info */}
          <div className="bg-card border border-border rounded-lg p-4 space-y-2">
            <div className="flex items-center gap-3">
              <span className="font-semibold text-lg">
                {data.service || 'Unknown Service'}
              </span>
              {data.port && (
                <span className="text-xs bg-muted px-2 py-0.5 rounded">port {data.port}</span>
              )}
              <span className="text-sm text-muted-foreground">{data.service_description}</span>
            </div>
            {data.common_vulns.length > 0 && (
              <div className="text-xs text-muted-foreground">
                <span className="font-medium">Known vulns:</span>{' '}
                {data.common_vulns.slice(0, 5).join(' · ')}
              </div>
            )}
          </div>

          {/* Node Selector + Run All */}
          <div className="flex items-center gap-3">
            <label className="text-sm text-muted-foreground">Execute on:</label>
            <select
              value={selectedNode}
              onChange={(e) => setSelectedNode(e.target.value)}
              className="bg-muted rounded-md px-3 py-1.5 text-sm border border-border"
            >
              <option value="">Select a node...</option>
              {data.nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name} ({n.type})
                </option>
              ))}
            </select>
            {selectedNode && (
              <button
                onClick={handleRunAllSafe}
                disabled={execMutation.isPending}
                className="bg-green-700 text-white px-3 py-1.5 rounded-md text-sm font-medium disabled:opacity-50"
              >
                Run All Safe
              </button>
            )}
            <span className="text-xs text-muted-foreground ml-auto">
              {data.commands.length} commands available
            </span>
          </div>

          {/* Command List */}
          <div className="space-y-2">
            {data.commands.map((cmd) => {
              const key = `${cmd.tool}:${cmd.command}`
              const isRunning = runningTools.has(key)
              const res = results[key]

              return (
                <CommandCard
                  key={key}
                  cmd={cmd}
                  nodeSelected={!!selectedNode}
                  isRunning={isRunning}
                  result={res}
                  onExecute={() => handleExecute(cmd)}
                />
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

function CommandCard({
  cmd,
  nodeSelected,
  isRunning,
  result,
  onExecute,
}: {
  cmd: ReconCommand
  nodeSelected: boolean
  isRunning: boolean
  result?: ExecuteResult
  onExecute: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-card border border-border rounded-lg p-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className={`text-xs px-2 py-0.5 rounded font-medium ${RISK_BADGE[cmd.risk]}`}>
          {cmd.risk}
        </span>
        <span className="font-mono text-sm font-semibold">{cmd.tool}</span>
        <span className="text-xs text-muted-foreground">{cmd.purpose}</span>
        {cmd.has_parser && (
          <span className="text-xs bg-blue-800 text-blue-100 px-1.5 py-0.5 rounded">
            auto-ingest
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {result && (
            <span
              className={`text-xs px-2 py-0.5 rounded ${
                result.ok ? 'bg-green-800 text-green-100' : 'bg-red-800 text-red-100'
              }`}
            >
              {result.ok
                ? `exit ${result.exit_code} · ${result.duration_ms}ms`
                : 'failed'}
              {result.structured_result?.stats?.findings_inserted
                ? ` · ${result.structured_result.stats.findings_inserted} findings`
                : ''}
              {result.ingest_result
                ? ' · ingested'
                : ''}
            </span>
          )}
          <button
            onClick={onExecute}
            disabled={!nodeSelected || isRunning || !cmd.command}
            className="bg-primary text-primary-foreground px-3 py-1 rounded text-xs font-medium disabled:opacity-40"
          >
            {isRunning ? 'Running...' : 'Run'}
          </button>
        </div>
      </div>

      {cmd.command && (
        <pre className="text-xs font-mono bg-muted/50 p-2 rounded overflow-x-auto whitespace-pre-wrap">
          {cmd.command}
        </pre>
      )}

      {result && (
        <div className="space-y-1">
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-primary underline"
          >
            {expanded ? 'Hide output' : 'Show output'}
          </button>
          {expanded && (
            <div className="space-y-2">
              {result.stdout && (
                <div>
                  <div className="text-xs font-medium text-muted-foreground">stdout</div>
                  <pre className="text-xs font-mono bg-black/50 text-green-300 p-2 rounded max-h-60 overflow-auto whitespace-pre-wrap">
                    {result.stdout}
                  </pre>
                </div>
              )}
              {result.stderr && (
                <div>
                  <div className="text-xs font-medium text-muted-foreground">stderr</div>
                  <pre className="text-xs font-mono bg-black/50 text-red-300 p-2 rounded max-h-40 overflow-auto whitespace-pre-wrap">
                    {result.stderr}
                  </pre>
                </div>
              )}
              {result.structured_result?.stats && (
                <div className="text-xs bg-muted/50 p-2 rounded">
                  <span className="font-medium">Parse method:</span>{' '}
                  {result.structured_result.stats.parse_method}
                  {' · '}
                  <span className="font-medium">Findings:</span>{' '}
                  {result.structured_result.stats.findings_inserted}
                  {result.structured_result.stats.vulns_inserted > 0 &&
                    ` (${result.structured_result.stats.vulns_inserted} vulns)`}
                  {result.structured_result.stats.web_findings_inserted > 0 &&
                    ` (${result.structured_result.stats.web_findings_inserted} web)`}
                  {result.structured_result.stats.recon_findings_inserted > 0 &&
                    ` (${result.structured_result.stats.recon_findings_inserted} recon)`}
                  {result.structured_result.stats.errors.length > 0 && (
                    <span className="text-red-400">
                      {' · '}Errors: {result.structured_result.stats.errors.join(', ')}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
