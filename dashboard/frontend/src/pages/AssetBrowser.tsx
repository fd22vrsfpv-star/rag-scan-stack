import { useState, useMemo, useEffect, Fragment } from 'react'
import { useQueryClient, useQuery } from '@tanstack/react-query'
import PageHelp from '@/components/PageHelp'
import { useAssets, useAssetPorts, useAssetVulns, usePortRecommendations, useSubdomains, useDeleteAssets, useDeleteSubdomains, useAssetCredentials, useAllCredentials, useUpdateCredentialStatus, useCreateCredential, useDeleteCredential, usePurgeDomain, usePurgePattern, useDetectedSoftware, useBulkDismissSoftware, useCveTuning, useUpdateCveTuning, useSearchsploit, getDdgSearchUrls, useResearchCache, useVulnxFindings, type DdgSearchResponse } from '@/api/assets'
import { apiFetch } from '@/api/client'
import { useTargetedReconLookup, useTargetedReconExecute } from '@/api/targeted-recon'
import { cn } from '@/lib/utils'
import type { PurgeResult, PurgePatternResult } from '@/api/assets'
import type { Subdomain, CredentialFinding, CreateCredentialParams, DetectedSoftware } from '@/api/assets'
import { DataTable } from '@/components/common/DataTable'
import { StatusDot } from '@/components/common/StatusDot'
import type { ColumnDef, RowSelectionState } from '@tanstack/react-table'
import type { Asset, Port, Vuln, ScanRecommendation } from '@/lib/types'
import { X, Trash2, Key, Plus, ShieldCheck, ShieldX, ShieldQuestion, ShieldOff, AlertTriangle, Globe, Camera, Cpu, Settings2, Search, ExternalLink, Cloud, Server } from 'lucide-react'
import { ScopeAssignModal } from '@/components/common/ScopeAssignModal'
import { ScopeFilter } from '@/components/common/ScopeFilter'
import { useScopeFilter } from '@/hooks/useScopeFilter'
import { useUIStore } from '@/stores/ui'
import { useScreenshots, useReconDomainOverview } from '@/api/recon'
import { apiUrl } from '@/api/client'
import { ScreenshotThumbnail } from '@/components/common/ScreenshotThumbnail'
import * as Dialog from '@radix-ui/react-dialog'

// Decode a cloud-import asset's hostname (engagement_short/<filename>) into
// a human-friendly description. Returns null for non-cloud-import assets.
function describeCloudImportHostname(row: Asset): { label: string; sub: string | null } | null {
  const tags = row.tags || []
  if (!tags.includes('cloud_import')) return null
  const hn = row.hostname || ''
  const slash = hn.indexOf('/')
  const filename = slash >= 0 ? hn.slice(slash + 1) : hn
  // <GroupName>_Users.CSV → group membership
  const groupMatch = /^(.+)_Users\.CSV$/i.exec(filename)
  if (groupMatch) {
    return { label: filename, sub: `Group: ${groupMatch[1]}` }
  }
  if (/^Users\.CSV$/i.test(filename)) return { label: filename, sub: 'Master users list' }
  if (/^Groups\.CSV$/i.test(filename)) return { label: filename, sub: 'Master groups list' }
  if (/AzureADRoleMembers/i.test(filename)) return { label: filename, sub: 'Role assignments' }
  if (/AzureADApplications/i.test(filename)) return { label: filename, sub: 'App registrations' }
  if (/Get-?AzPasswords|KeyVault|StorageAccountKeys|AppServiceCreds|AutomationAccounts/i.test(filename)) {
    return { label: filename, sub: 'Secrets / credentials' }
  }
  return { label: filename, sub: null }
}

const assetColumns: ColumnDef<Asset, unknown>[] = [
  { accessorKey: 'ip', header: 'IP Address', size: 140, cell: ({ getValue }) => <span className="font-mono text-sm">{String(getValue())}</span> },
  { accessorKey: 'hostname', header: 'Hostname / File', cell: ({ row }) => {
    const desc = describeCloudImportHostname(row.original)
    if (desc) {
      return (
        <div className="flex flex-col leading-tight">
          <span className="font-mono text-xs font-medium break-all">{desc.label}</span>
          {desc.sub && <span className="text-[10px] text-muted-foreground">{desc.sub}</span>}
        </div>
      )
    }
    return <span className="font-mono text-sm font-medium">{String(row.original.hostname ?? '-')}</span>
  }},
  { accessorKey: 'os', header: 'OS / Type / Provider', size: 160, cell: ({ row }) => {
    const tags = row.original.tags || []
    if (tags.includes('cloud_import')) {
      const provider = tags.find(t => ['microburst','azurehound','prowler','scoutsuite','pacu','cloudfox'].includes(t))
      return <span className="text-xs px-1.5 py-0.5 rounded border bg-cyan-500/15 text-cyan-400 border-cyan-500/30">{provider || 'cloud_import'}</span>
    }
    const os = row.original.os
    if (os) {
      return <span className="text-sm text-muted-foreground">{String(os)}</span>
    }
    // OS unknown — fall back to cloud-hosting provider tag(s) so the column
    // is informative for vanity domains where we don't have an OS fingerprint.
    const providers = row.original.provider ?? []
    if (providers.length > 0) {
      return (
        <div className="flex flex-wrap gap-0.5">
          {providers.map(p => (
            <span key={p} className="text-[10px] px-1.5 py-0.5 rounded border bg-blue-500/15 text-blue-400 border-blue-500/30 uppercase font-medium">{p}</span>
          ))}
        </div>
      )
    }
    return <span className="text-sm text-muted-foreground">—</span>
  }},
  { accessorKey: 'open_ports_count', header: 'Ports', size: 70, cell: ({ getValue }) => {
    const v = Number(getValue() ?? 0)
    return <span className={`text-sm font-medium ${v > 0 ? 'text-primary' : 'text-muted-foreground'}`}>{v}</span>
  }},
  { accessorKey: 'recon_findings_count', header: 'Findings', size: 80, cell: ({ getValue }) => {
    const v = Number(getValue() ?? 0)
    return <span className={`text-sm font-medium ${v > 0 ? 'text-primary' : 'text-muted-foreground'}`}>{v.toLocaleString()}</span>
  }},
  { accessorKey: 'discovered_by', header: 'Discovered By', size: 200, cell: ({ getValue }) => {
    const sources = (getValue() as string[] | undefined) ?? []
    if (!sources.length) return <span className="text-xs text-muted-foreground">—</span>
    return (
      <div className="flex gap-0.5 flex-wrap">
        {sources.map(s => (
          <span key={s} className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono border bg-zinc-500/15 text-zinc-300 border-zinc-500/30">{s}</span>
        ))}
      </div>
    )
  }},
  { accessorKey: 'first_seen', header: 'First Seen', size: 100, cell: ({ getValue }) => {
    const v = getValue() as string | undefined
    return <span className="text-xs text-muted-foreground">{v ? new Date(v).toLocaleDateString() : '—'}</span>
  }},
]

const severityColor: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30',
}

const portColumns: ColumnDef<Port, unknown>[] = [
  { accessorKey: 'port', header: 'Port', size: 60, minSize: 40 },
  { accessorKey: 'proto', header: 'Proto', size: 55, minSize: 40 },
  { accessorKey: 'service', header: 'Service', size: 100, minSize: 60 },
  { accessorKey: 'product', header: 'Product', size: 140, minSize: 80 },
  { accessorKey: 'version', header: 'Version', size: 160, minSize: 80 },
  { accessorKey: 'finding_count', header: 'Findings', size: 75, minSize: 55, cell: ({ getValue }) => {
    const count = getValue() as number | undefined
    return count ? <span className="text-xs font-medium">{count}</span> : <span className="text-xs text-muted-foreground">—</span>
  }},
  { accessorKey: 'max_severity', header: 'Severity', size: 85, minSize: 60, cell: ({ getValue }) => {
    const sev = getValue() as string | null
    if (!sev) return <span className="text-xs text-muted-foreground">—</span>
    return <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${severityColor[sev] ?? ''}`}>{sev.toUpperCase()}</span>
  }},
  { accessorKey: 'banner', header: 'Banner', size: 300, minSize: 100, cell: ({ getValue }) => <span className="text-xs whitespace-pre-wrap break-all">{String(getValue() ?? '')}</span> },
]

const subdomainColumns: ColumnDef<Subdomain, unknown>[] = [
  { accessorKey: 'subdomain', header: 'Subdomain', cell: ({ getValue }) => <span className="font-mono text-sm font-medium">{String(getValue())}</span> },
  { accessorKey: 'parent_domain', header: 'Parent Domain', cell: ({ getValue }) => <span className="text-sm text-muted-foreground">{String(getValue())}</span> },
  { accessorKey: 'resolved_ip', header: 'Resolved IP', size: 140, cell: ({ getValue }) => <span className="font-mono text-sm">{String(getValue() || '—')}</span> },
  { accessorKey: 'discovery_source', header: 'Source', size: 110, cell: ({ getValue }) =>
    <span className="inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-medium border bg-zinc-500/15 text-zinc-300 border-zinc-500/30">{String(getValue() ?? '')}</span>
  },
  { accessorKey: 'created_at', header: 'Discovered', size: 160, cell: ({ getValue }) => {
    const v = getValue() as string
    if (!v) return '—'
    try { return new Date(v).toLocaleString() } catch { return v }
  }},
]

const CRED_STATUS_STYLES: Record<string, { bg: string; icon: typeof ShieldCheck }> = {
  valid: { bg: 'bg-green-500/20 text-green-400 border-green-500/30', icon: ShieldCheck },
  invalid: { bg: 'bg-red-500/20 text-red-400 border-red-500/30', icon: ShieldX },
  unknown: { bg: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30', icon: ShieldQuestion },
  remediated: { bg: 'bg-blue-500/20 text-blue-400 border-blue-500/30', icon: ShieldOff },
}

function CredStatusBadge({ status }: { status: string }) {
  const s = CRED_STATUS_STYLES[status] || CRED_STATUS_STYLES.unknown
  const Icon = s.icon
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border ${s.bg}`}>
      <Icon className="h-3 w-3" />
      {status}
    </span>
  )
}

const SECRET_TYPES = ['password', 'aws_key', 'azure_key', 'ssh_key', 'api_token', 'ntlm_hash', 'kerberos_ticket', 'certificate', 'other'] as const
const PROTOCOLS = ['ssh', 'ftp', 'rdp', 'smb', 'http', 'https', 'telnet', 'vnc', 'mysql', 'mssql', 'postgres', 'oracle', 'ldap', 'snmp', 'winrm', 'other'] as const

function AddCredentialModal({ onClose }: { onClose: () => void }) {
  const createCred = useCreateCredential()
  const [form, setForm] = useState<CreateCredentialParams>({
    ip: '', port: 0, protocol: 'ssh', username: '', secret_value: '', secret_type: 'password',
    status: 'unknown', source: 'manual', banner: '',
  })
  const set = (k: keyof CreateCredentialParams, v: string | number) => setForm(prev => ({ ...prev, [k]: v }))

  const BANNER_PLACEHOLDERS: Record<string, string> = {
    ssh: 'SSH-2.0-OpenSSH_8.9',
    http: 'Apache/2.4.54 (Ubuntu)',
    https: 'nginx/1.24.0',
    ftp: '220 vsFTPd 3.0.5',
    smb: 'Windows Server 2019',
    mysql: '5.7.42-MySQL Community',
    postgres: 'PostgreSQL 15.4',
    mssql: 'Microsoft SQL Server 2019',
    rdp: 'Microsoft Terminal Services',
    telnet: '',
    vnc: 'RFB 003.008',
  }
  const DEFAULT_PORTS: Record<string, number> = {
    ssh: 22, ftp: 21, http: 80, https: 443, rdp: 3389, smb: 445,
    telnet: 23, vnc: 5900, mysql: 3306, mssql: 1433, postgres: 5432,
    oracle: 1521, ldap: 389, snmp: 161, winrm: 5985,
  }

  const handleSubmit = () => {
    createCred.mutate(form, { onSuccess: () => onClose() })
  }

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-[60]" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[90vw] max-w-[500px] bg-card border border-border rounded-lg shadow-2xl z-[70] p-5">
          <div className="flex items-center justify-between mb-4">
            <Dialog.Title className="text-sm font-semibold">Add Credential</Dialog.Title>
            <Dialog.Close className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></Dialog.Close>
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <label className="space-y-1">
              <span className="text-muted-foreground">IP Address</span>
              <input value={form.ip} onChange={e => set('ip', e.target.value)} placeholder="10.0.0.1"
                className="w-full bg-muted rounded px-2 py-1.5 border border-border font-mono text-xs" />
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Port</span>
              <input type="number" value={form.port} onChange={e => set('port', parseInt(e.target.value) || 0)}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border font-mono text-xs" />
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Protocol</span>
              <select value={form.protocol} onChange={e => {
                const proto = e.target.value
                set('protocol', proto)
                // Auto-set default port if port is 0 or matches another protocol's default
                const curPort = form.port || 0
                const isDefaultPort = curPort === 0 || Object.values(DEFAULT_PORTS).includes(curPort)
                if (isDefaultPort && DEFAULT_PORTS[proto]) {
                  set('port', DEFAULT_PORTS[proto])
                }
              }}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border text-xs">
                {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Secret Type</span>
              <select value={form.secret_type} onChange={e => set('secret_type', e.target.value)}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border text-xs">
                {SECRET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Username</span>
              <input value={form.username} onChange={e => set('username', e.target.value)} placeholder="admin"
                className="w-full bg-muted rounded px-2 py-1.5 border border-border font-mono text-xs" />
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Password / Secret</span>
              <input value={form.secret_value} onChange={e => set('secret_value', e.target.value)}
                placeholder={form.secret_type === 'password' ? 'P@ssw0rd' : form.secret_type === 'ssh_key' ? '/path/to/id_rsa' : 'secret value'}
                type={form.secret_type === 'password' ? 'text' : 'text'}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border font-mono text-xs" />
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Status</span>
              <select value={form.status} onChange={e => set('status', e.target.value)}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border text-xs">
                <option value="unknown">unknown</option>
                <option value="valid">valid</option>
                <option value="invalid">invalid</option>
                <option value="remediated">remediated</option>
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Source</span>
              <input value={form.source} onChange={e => set('source', e.target.value)} placeholder="manual"
                className="w-full bg-muted rounded px-2 py-1.5 border border-border text-xs" />
            </label>
            <label className="space-y-1">
              <span className="text-muted-foreground">Banner</span>
              <input value={form.banner} onChange={e => set('banner', e.target.value)}
                placeholder={BANNER_PLACEHOLDERS[form.protocol || ''] || 'Service banner'}
                className="w-full bg-muted rounded px-2 py-1.5 border border-border font-mono text-xs" />
            </label>
          </div>
          {createCred.error && (
            <p className="text-xs text-red-500 mt-2">{String(createCred.error)}</p>
          )}
          <div className="flex justify-end gap-2 mt-4">
            <button onClick={onClose} className="px-3 py-1.5 text-xs rounded border border-border hover:bg-accent">Cancel</button>
            <button onClick={handleSubmit} disabled={createCred.isPending || !form.username}
              className="px-3 py-1.5 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
              {createCred.isPending ? 'Adding...' : 'Add Credential'}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

function CredentialSection({ ip }: { ip: string }) {
  const { data: credData } = useAssetCredentials(ip)
  const updateStatus = useUpdateCredentialStatus()
  const credentials = credData?.credentials ?? []

  if (credentials.length === 0) {
    return (
      <div>
        <h4 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
          <Key className="h-3.5 w-3.5" /> Credentials (0)
        </h4>
        <p className="text-xs text-muted-foreground">No credentials discovered for this asset</p>
      </div>
    )
  }

  return (
    <div>
      <h4 className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
        <Key className="h-3.5 w-3.5" /> Credentials ({credentials.length})
      </h4>
      <div className="space-y-2">
        {credentials.map((c) => (
          <div key={c.id} className="border border-border rounded-md p-3 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-mono font-medium">{c.username}</span>
                <span className="text-muted-foreground">@</span>
                <span className="font-mono">{c.protocol}://{c.ip}:{c.port}</span>
              </div>
              <CredStatusBadge status={c.status || 'unknown'} />
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground">
              <div>Type: <span className="text-foreground">{c.auth_type || c.secret_type}</span></div>
              <div>Source: <span className="text-foreground">{c.source}</span></div>
              <div>Discovered: <span className="text-foreground">
                {c.discovered_at ? new Date(c.discovered_at).toLocaleString() : c.created_at ? new Date(c.created_at).toLocaleString() : '—'}
              </span></div>
              <div>Last Verified: <span className="text-foreground">
                {c.last_verified_at ? new Date(c.last_verified_at).toLocaleString() : '—'}
              </span></div>
              {c.banner && <div className="col-span-2">Banner: <span className="text-foreground font-mono">{c.banner}</span></div>}
            </div>
            <div className="flex items-center gap-1.5 pt-1">
              <span className="text-muted-foreground mr-1">Set status:</span>
              {(['valid', 'invalid', 'unknown', 'remediated'] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => updateStatus.mutate({ id: c.id, status: s })}
                  disabled={c.status === s || updateStatus.isPending}
                  className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                    c.status === s
                      ? 'opacity-50 cursor-not-allowed border-border'
                      : 'hover:bg-accent border-border hover:border-primary cursor-pointer'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function PortDetailDialog({
  port,
  ip,
  vulns,
  onClose,
}: {
  port: Port
  ip: string
  vulns: Vuln[]
  onClose: () => void
}) {
  const portVulns = vulns
    .filter(v => v.port === port.port && v.proto === port.proto)
    .filter((v, i, arr) => arr.findIndex(u => u.script === v.script && u.output === v.output) === i)

  // Smart recon lookup for this port
  const { data: reconData, isLoading: reconLoading } = useTargetedReconLookup(ip, port.port, port.service || undefined)
  const reconExecute = useTargetedReconExecute()
  const [selectedNode, setSelectedNode] = useState('')
  const [execResults, setExecResults] = useState<Record<string, { ok: boolean; stdout: string; stderr: string }>>({})

  const commands = reconData?.commands ?? []
  const nodes = reconData?.nodes ?? []
  const riskColors: Record<string, string> = {
    safe: 'text-green-400 bg-green-500/10 border-green-500/30',
    active: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    exploit: 'text-red-400 bg-red-500/10 border-red-500/30',
  }

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-[60]" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[90vw] max-w-[800px] max-h-[85vh] overflow-y-auto bg-card border border-border rounded-lg shadow-2xl z-[70] p-5">
          <div className="flex items-center justify-between mb-4">
            <Dialog.Title className="text-sm font-semibold">
              {ip} — Port {port.port}/{port.proto}
              {reconData?.service && <span className="ml-2 text-muted-foreground font-normal">({reconData.service})</span>}
            </Dialog.Title>
            <Dialog.Close className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>

          {/* Port details */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mb-4">
            <div><span className="text-muted-foreground">Service:</span> {port.service || '—'}</div>
            <div><span className="text-muted-foreground">Product:</span> {port.product || '—'}</div>
            <div><span className="text-muted-foreground">Version:</span> {port.version || '—'}</div>
            <div className="col-span-2">
              <span className="text-muted-foreground">Banner:</span>{' '}
              <span className="font-mono break-all">{port.banner || '—'}</span>
            </div>
          </div>

          {/* Service description + known vulns from KB */}
          {reconData?.service_description && (
            <div className="bg-muted/30 border border-border rounded p-2.5 mb-4 text-xs">
              <p className="text-muted-foreground">{reconData.service_description}</p>
              {reconData.common_vulns.length > 0 && (
                <div className="mt-1.5 space-y-0.5">
                  {reconData.common_vulns.map((v, i) => (
                    <div key={i} className="text-[10px] text-red-400">{v}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Vulnerabilities found */}
          {portVulns.length > 0 && (
            <div className="mb-4">
              <h4 className="text-xs font-medium text-muted-foreground mb-2">
                Findings ({portVulns.length})
              </h4>
              {portVulns.map((v, i) => (
                <div key={i} className="border border-border rounded-md p-2 mb-2">
                  <p className="text-xs font-medium">{v.script}</p>
                  <pre className="text-[10px] mt-1 bg-muted rounded p-1 overflow-x-auto max-h-24">{v.output?.slice(0, 500)}</pre>
                </div>
              ))}
            </div>
          )}

          {/* Smart Recon commands */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-medium text-muted-foreground">
                Recommended Scans ({commands.length})
              </h4>
              {nodes.length > 0 && (
                <select value={selectedNode} onChange={e => setSelectedNode(e.target.value)}
                  className="bg-muted rounded px-2 py-0.5 text-[10px] border border-border w-36">
                  <option value="">Run on node...</option>
                  {nodes.map(n => <option key={n.id} value={n.id}>{n.name}</option>)}
                </select>
              )}
            </div>
            {reconLoading ? (
              <p className="text-xs text-muted-foreground">Loading recommendations...</p>
            ) : commands.length > 0 ? (
              <div className="space-y-1.5">
                {commands.map((cmd, i) => {
                  const result = execResults[cmd.command]
                  return (
                    <div key={i} className="border border-border rounded p-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-medium border', riskColors[cmd.risk] || '')}>
                          {cmd.risk}
                        </span>
                        <span className="text-[10px] font-medium">{cmd.tool}</span>
                        <span className="text-[9px] text-muted-foreground flex-1">{cmd.purpose}</span>
                        {cmd.has_parser && <span className="text-[8px] px-1 rounded bg-primary/10 text-primary border border-primary/30">auto-ingest</span>}
                        <button
                          onClick={() => {
                            if (!selectedNode) return
                            reconExecute.mutate({
                              node_id: selectedNode, command: cmd.command, tool_name: cmd.tool,
                              target: ip, port: port.port,
                            }, {
                              onSuccess: (r) => setExecResults(prev => ({ ...prev, [cmd.command]: { ok: r.ok, stdout: r.stdout, stderr: r.stderr } })),
                              onError: (e) => setExecResults(prev => ({ ...prev, [cmd.command]: { ok: false, stdout: '', stderr: String(e) } })),
                            })
                          }}
                          disabled={!selectedNode || reconExecute.isPending}
                          className="px-1.5 py-0.5 text-[9px] font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                        >Run</button>
                      </div>
                      <pre className="text-[9px] font-mono bg-muted rounded px-1.5 py-0.5 overflow-x-auto select-all text-muted-foreground">{cmd.command}</pre>
                      {result && (
                        <pre className={cn('text-[9px] rounded p-1 max-h-24 overflow-y-auto whitespace-pre-wrap',
                          result.ok ? 'bg-green-500/5 border border-green-500/20' : 'bg-red-500/5 border border-red-500/20'
                        )}>{result.stdout?.slice(0, 1000) || result.stderr?.slice(0, 500) || 'No output'}</pre>
                      )}
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No recommendations for this service</p>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export default function AssetBrowser() {
  // Support deep-linking: /assets?tab=software&search=IIS&ip=192.168.1.150
  const [urlParams] = useState(() => new URLSearchParams(window.location.search))
  const initialTab = (['assets', 'subdomains', 'credentials', 'software'].includes(urlParams.get('tab') || '')
    ? urlParams.get('tab') as 'assets' | 'subdomains' | 'credentials' | 'software'
    : 'assets')
  const initialSearch = urlParams.get('search') || ''
  const initialIp = urlParams.get('ip') || ''

  const [tab, setTab] = useState(initialTab)
  const [softwareSourceFilter, setSoftwareSourceFilter] = useState<string>('')
  const [softwareProductFilter, setSoftwareProductFilter] = useState<string>(initialSearch)
  const [softwareProductInput, setSoftwareProductInput] = useState<string>(initialSearch)
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set())
  const [showCveOnly, setShowCveOnly] = useState(false)
  const [hideBlankProductVersion, setHideBlankProductVersion] = useState(true)
  const [softwareSort, setSoftwareSort] = useState<'hostname' | 'product' | 'version' | 'cve-count'>('hostname')
  const [showBulkDismiss, setShowBulkDismiss] = useState(false)
  const [exploitLookup, setExploitLookup] = useState<{ product: string; version: string; cveFlags?: any[] } | null>(null)
  const [selectedProducts, setSelectedProducts] = useState<Set<string>>(new Set())
  const [showCveTuning, setShowCveTuning] = useState(false)
  const { data: cveTuningData } = useCveTuning()
  const updateCveTuning = useUpdateCveTuning()
  const [tuningDraft, setTuningDraft] = useState<Record<string, string>>({})
  const [dismissReason, setDismissReason] = useState('Banner-detected version likely patched — CVE predates current patch level')
  const [dismissYearBefore, setDismissYearBefore] = useState(2023)
  const [dismissProduct, setDismissProduct] = useState('')
  const [dismissResult, setDismissResult] = useState<string | null>(null)
  const bulkDismiss = useBulkDismissSoftware()
  const [selectedIp, setSelectedIp] = useState<string | null>(null)
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null)
  const [selectedPort, setSelectedPort] = useState<Port | null>(null)
  const [detailTab, setDetailTab] = useState<'ports' | 'credentials' | 'screenshots' | 'recon'>('ports')
  const [search, setSearch] = useState('')
  const [credStatusFilter, setCredStatusFilter] = useState<string>('')
  const globalScope = useUIStore(s => s.selectedScopeName)
  const [scopeFilter, setScopeFilter] = useState(globalScope || '')
  const { matchesScope, isFiltering: isScopeFiltering } = useScopeFilter(scopeFilter)
  const [portsFilter, setPortsFilter] = useState<'all' | 'with-ports' | 'no-ports'>('all')
  // 'all' (default) | 'hosts-only' (hide cloud-import placeholders) | 'cloud-only'
  // Cloud-import assets use synthetic IPs (127.0.1.1, 127.0.0.1) or cloud import tags,
  // which the operator may not recognize. This chip surfaces them under a friendly
  // label and lets you isolate / hide them with one click.
  const [assetKindFilter, setAssetKindFilter] = useState<'all' | 'hosts-only' | 'cloud-only'>('all')
  // Provider filter — 'any' means no filter; 'untagged' shows assets with no
  // provider tags (often legacy IP-only hosts); other values match assets
  // whose provider[] array contains the selected tag.
  const [providerFilter, setProviderFilter] = useState<'any' | 'untagged' | string>('any')

  // Sync with global engagement scope changes
  useEffect(() => {
    setScopeFilter(globalScope || '')
  }, [globalScope])

  // Clear selections when scope changes
  useEffect(() => {
    setAssetSelection({})
    setSubdomainSelection({})
  }, [scopeFilter])
  const [showAddCred, setShowAddCred] = useState(false)
  const [assetSelection, setAssetSelection] = useState<RowSelectionState>({})
  const [subdomainSelection, setSubdomainSelection] = useState<RowSelectionState>({})

  // Use server-side filtering for asset kinds to improve performance and consistency
  const serverAssetKind = assetKindFilter === 'all' ? undefined : assetKindFilter
  const { data: assetsData, isLoading } = useAssets(5000, serverAssetKind)
  const { data: portsData } = useAssetPorts(selectedIp || '')
  const { data: vulnsData } = useAssetVulns(selectedIp || '')
  const { data: subdomainsData, isLoading: subdomainsLoading } = useSubdomains()
  const { data: allCredsData, isLoading: credsLoading } = useAllCredentials(credStatusFilter || undefined)
  // Unified search — sent to API search param (ORs across product, version, hostname, IP)
  const _apiSearch = softwareProductFilter.length >= 2 ? softwareProductFilter : undefined
  const { data: softwareData, isLoading: softwareLoading } = useDetectedSoftware(_apiSearch, undefined, softwareSourceFilter || undefined)
  const updateCredStatus = useUpdateCredentialStatus()
  const deleteCred = useDeleteCredential()
  const deleteAssets = useDeleteAssets()
  const deleteSubdomains = useDeleteSubdomains()
  const purgeDomain = usePurgeDomain()
  const [showPurge, setShowPurge] = useState(false)
  const [showScopeModal, setShowScopeModal] = useState<'assets' | 'subdomains' | null>(null)
  const [showPatternPurge, setShowPatternPurge] = useState(false)
  const [purgePatternInput, setPurgePatternInput] = useState('')
  const [purgePreviewData, setPurgePreviewData] = useState<PurgePatternResult | null>(null)
  const purgePattern = usePurgePattern()
  const [purgeDomainInput, setPurgeDomainInput] = useState('')
  const [purgePreview, setPurgePreview] = useState<PurgeResult | null>(null)

  const allAssets = assetsData?.assets ?? []
  const allSubdomainsList = subdomainsData?.subdomains ?? []
  const allCredentials = allCredsData?.credentials ?? []

  // When searching, bypass scope filter to find items across all scopes
  const assets = useMemo(() => {
    let filtered = allAssets

    // Apply scope filtering (but not for cloud imports when network scope is selected)
    if (!search && isScopeFiltering) {
      filtered = filtered.filter(a => {
        // Cloud import assets should be hidden when filtering by network scopes
        const isCloudAsset = (a.tags || []).includes('cloud_import') ||
          a.ip === '127.0.1.1' || a.ip === '127.0.0.1' ||
          (a.tags || []).some(tag => ['microburst', 'azurehound', 'prowler', 'scoutsuite', 'pacu', 'cloudfox'].includes(tag))

        if (isCloudAsset) {
          // Hide cloud assets when filtering by network scopes (they don't belong to network scopes)
          return false
        }

        return matchesScope(a.hostname || a.ip || '')
      })
    }

    // Apply ports filtering
    if (portsFilter === 'with-ports') {
      filtered = filtered.filter(a => (a.open_ports_count ?? 0) > 0)
    } else if (portsFilter === 'no-ports') {
      filtered = filtered.filter(a => (a.open_ports_count ?? 0) === 0)
    }

    // Apply provider filtering
    if (providerFilter === 'untagged') {
      filtered = filtered.filter(a => !(a.provider && a.provider.length > 0))
    } else if (providerFilter !== 'any') {
      filtered = filtered.filter(a => (a.provider || []).includes(providerFilter))
    }

    return filtered
    // scopeFilter is included for parity with the `subdomains` memo below and
    // to guarantee invalidation when the local scope dropdown changes, even
    // though matchesScope identity would normally cover it.
  }, [allAssets, isScopeFiltering, matchesScope, search, portsFilter, providerFilter, assetKindFilter, scopeFilter])

  // Available provider chips derived from the current asset set, sorted by
  // count desc — operators see what tags exist without us hardcoding the list.
  const providerCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    let untagged = 0
    for (const a of allAssets) {
      const ps = a.provider ?? []
      if (ps.length === 0) { untagged += 1; continue }
      for (const p of ps) counts[p] = (counts[p] || 0) + 1
    }
    return { counts, untagged }
  }, [allAssets])

  const subdomains = useMemo(() => {
    let filtered = allSubdomainsList
    // Apply scope filter (client-side matching against scope targets)
    if (!search && isScopeFiltering) {
      filtered = filtered.filter(s => matchesScope(s.subdomain || ''))
    }
    // Apply text search on top of scope filter
    if (search) {
      const q = search.toLowerCase()
      filtered = filtered.filter(s =>
        (s.subdomain || '').toLowerCase().includes(q) ||
        (s.resolved_ip || '').includes(q)
      )
    }
    return filtered
  }, [allSubdomainsList, isScopeFiltering, matchesScope, search, scopeFilter])

  const selectedAssetCount = Object.values(assetSelection).filter(Boolean).length
  const selectedSubdomainCount = Object.values(subdomainSelection).filter(Boolean).length

  const handleDeleteAssets = () => {
    const ips = Object.keys(assetSelection).filter(k => assetSelection[k])
    if (!ips.length) return
    if (!window.confirm(`Delete ${ips.length} asset(s) and all related ports, vulns, and findings? This cannot be undone.`)) return
    deleteAssets.mutate(ips, { onSuccess: () => setAssetSelection({}) })
  }

  const handleDeleteSubdomains = () => {
    const subs = Object.keys(subdomainSelection).filter(k => subdomainSelection[k])
    if (!subs.length) return
    if (!window.confirm(`Delete ${subs.length} subdomain(s)? This cannot be undone.`)) return
    deleteSubdomains.mutate(subs, { onSuccess: () => setSubdomainSelection({}) })
  }

  const handleCloseSlideOver = () => {
    setSelectedPort(null)
    setSelectedIp(null)
  }

  return (
    <div className="space-y-4">
      <PageHelp id="assets" title="How to use Assets">
        <p>Discovered hosts, ports, subdomains, software versions, and credentials from all scans. Click a host IP to drill down into open ports, vulnerabilities, and screenshots. The <strong>Software</strong> tab flags known CVEs. The <strong>Credentials</strong> tab tracks discovered creds with status tracking (valid/invalid/remediated).</p>
      </PageHelp>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setTab('assets')}
            className={`px-3 py-1 text-sm rounded-md border ${tab === 'assets' ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
          >Assets</button>
          <button
            onClick={() => setTab('subdomains')}
            className={`px-3 py-1 text-sm rounded-md border ${tab === 'subdomains' ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
          >Subdomains</button>
          <button
            onClick={() => setTab('credentials')}
            className={`px-3 py-1 text-sm rounded-md border ${tab === 'credentials' ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
          >Credentials</button>
          <button
            onClick={() => setTab('software')}
            className={`px-3 py-1 text-sm rounded-md border ${tab === 'software' ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
          >Software</button>
        </div>
        <div className="flex items-center gap-3">
          <ScopeFilter value={scopeFilter} onChange={setScopeFilter} />
          <span className="text-xs text-muted-foreground">
            {tab === 'assets' ? `${assets.length} assets` : tab === 'subdomains' ? `${subdomains.length} subdomains` : tab === 'credentials' ? `${allCredentials.length} credentials` : `${softwareData?.count ?? 0} detections`}
            {isScopeFiltering ? ` in ${scopeFilter}` : ''}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        {tab !== 'software' && (
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={tab === 'assets' ? 'Search assets...' : tab === 'subdomains' ? 'Search subdomains...' : 'Search credentials...'}
            className="w-full max-w-sm bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
          />
        )}
        {tab === 'assets' && (
          <>
            <div className="flex items-center gap-1">
              {(['all', 'with-ports', 'no-ports'] as const).map(f => (
                <button key={f} onClick={() => setPortsFilter(f)}
                  className={`px-2 py-1 text-xs rounded border ${portsFilter === f ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}
                >{f === 'all' ? 'All' : f === 'with-ports' ? 'With Ports' : 'No Ports'}</button>
              ))}
            </div>
            <div className="flex items-center gap-1" title="Cloud imports use synthetic IPs (127.0.x.x) as placeholders — not real hosts. Use these chips to isolate or hide them.">
              {([
                { id: 'all',         label: 'Hosts + Cloud', icon: null },
                { id: 'hosts-only',  label: 'Hosts only',    icon: Server },
                { id: 'cloud-only',  label: 'Cloud Imports', icon: Cloud },
              ] as const).map(({ id, label, icon: Ic }) => (
                <button key={id} onClick={() => setAssetKindFilter(id)}
                  className={`px-2 py-1 text-xs rounded border flex items-center gap-1 ${assetKindFilter === id ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300' : 'border-border text-muted-foreground hover:text-foreground'}`}
                >
                  {Ic && <Ic className="h-3 w-3" />}{label}
                </button>
              ))}
            </div>
            {/* Cloud-hosting provider — driven by assets.provider[] which the
                ETL parsers populate from CNAME / TLS cert / HTTP header
                signals. "Any" disables the filter, "Untagged" shows assets
                we couldn't classify yet. */}
            <div className="flex items-center gap-1" title="Filter by cloud-hosting provider (assets.provider). Tags come from CNAME / cert / header signals — covers vanity domains.">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground mr-0.5">Provider:</span>
              <button
                onClick={() => setProviderFilter('any')}
                className={`px-2 py-1 text-xs rounded border ${providerFilter === 'any' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}
              >Any</button>
              {Object.entries(providerCounts.counts)
                .sort(([, a], [, b]) => b - a)
                .map(([p, count]) => (
                <button
                  key={p}
                  onClick={() => setProviderFilter(p)}
                  className={`px-2 py-1 text-xs rounded border uppercase font-medium ${providerFilter === p ? 'border-blue-500/50 bg-blue-500/15 text-blue-300' : 'border-border text-muted-foreground hover:text-foreground'}`}
                >
                  {p} <span className="ml-1 text-[10px] opacity-70 normal-case">{count}</span>
                </button>
              ))}
              {providerCounts.untagged > 0 && (
                <button
                  onClick={() => setProviderFilter('untagged')}
                  className={`px-2 py-1 text-xs rounded border ${providerFilter === 'untagged' ? 'border-zinc-500/50 bg-zinc-500/15 text-zinc-300' : 'border-border text-muted-foreground hover:text-foreground'}`}
                >Untagged <span className="ml-1 text-[10px] opacity-70">{providerCounts.untagged}</span></button>
              )}
            </div>
          </>
        )}
        <button
          onClick={() => { setShowPurge(true); setPurgePreview(null); setPurgeDomainInput('') }}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/30 rounded-md hover:bg-red-500/20"
        >
          <Trash2 className="w-3.5 h-3.5" /> Purge Domain
        </button>
        <button
          onClick={() => { setShowPatternPurge(true); setPurgePreviewData(null); setPurgePatternInput('') }}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/30 rounded-md hover:bg-red-500/20"
        >
          <Trash2 className="w-3.5 h-3.5" /> Purge by Pattern
        </button>
      </div>

      {/* Purge Domain Dialog */}
      <Dialog.Root open={showPurge} onOpenChange={setShowPurge}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60 z-50" />
          <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-card border border-border rounded-xl shadow-2xl w-full max-w-md p-6 space-y-4">
            <Dialog.Title className="text-lg font-semibold flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-500" /> Purge Domain
            </Dialog.Title>
            <p className="text-sm text-muted-foreground">
              Delete <strong>all</strong> data for a domain — assets, ports, vulns, findings, recon, scope, screenshots, and more. This cannot be undone.
            </p>
            <input
              value={purgeDomainInput}
              onChange={e => { setPurgeDomainInput(e.target.value); setPurgePreview(null) }}
              placeholder="example.com"
              className="w-full bg-muted rounded-md px-3 py-2 text-sm border border-border outline-none focus:border-primary font-mono"
            />

            {/* Preview results */}
            {purgePreview && purgePreview.dry_run && (
              <div className="bg-muted/60 border border-border rounded-md p-3 space-y-2 max-h-48 overflow-y-auto">
                <p className="text-sm font-medium">
                  {purgePreview.total_rows === 0
                    ? 'No data found for this domain.'
                    : `Found ${purgePreview.total_rows?.toLocaleString()} rows across ${Object.keys(purgePreview.tables).length} tables:`}
                </p>
                {purgePreview.total_rows! > 0 && (
                  <div className="space-y-1">
                    {Object.entries(purgePreview.tables).map(([table, count]) => (
                      <div key={table} className="flex justify-between text-xs">
                        <span className="font-mono text-muted-foreground">{table}</span>
                        <span className="font-medium">{count.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Post-delete result */}
            {purgePreview && !purgePreview.dry_run && purgePreview.ok && (
              <div className="bg-green-500/10 border border-green-500/30 rounded-md p-3">
                <p className="text-sm font-medium text-green-400">
                  Deleted {purgePreview.total_deleted?.toLocaleString()} rows for {purgePreview.domain}
                </p>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowPurge(false)}
                className={`px-3 py-1.5 text-sm rounded-md border ${purgePreview && !purgePreview.dry_run && purgePreview.ok ? 'border-green-500 bg-green-500/20 text-green-400 hover:bg-green-500/30 font-medium' : 'border-border bg-muted hover:bg-muted/80'}`}
              >{purgePreview && !purgePreview.dry_run && purgePreview.ok ? 'Done' : 'Cancel'}</button>

              {/* Preview button */}
              {(!purgePreview || purgePreview.dry_run) && (
                <button
                  onClick={() => purgeDomain.mutate({ domain: purgeDomainInput, dryRun: true }, { onSuccess: (data) => setPurgePreview(data) })}
                  disabled={!purgeDomainInput.trim() || purgeDomain.isPending}
                  className="px-3 py-1.5 text-sm rounded-md border border-primary bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
                >
                  {purgeDomain.isPending ? 'Scanning...' : 'Preview'}
                </button>
              )}

              {/* Confirm delete button — only after preview with results */}
              {purgePreview?.dry_run && purgePreview.total_rows! > 0 && (
                <button
                  onClick={() => purgeDomain.mutate({ domain: purgeDomainInput, dryRun: false }, { onSuccess: (data) => setPurgePreview(data) })}
                  disabled={purgeDomain.isPending}
                  className="px-3 py-1.5 text-sm rounded-md border border-red-500 bg-red-500/20 text-red-400 hover:bg-red-500/30 disabled:opacity-50 font-medium"
                >
                  {purgeDomain.isPending ? 'Deleting...' : `Delete ${purgePreview.total_rows?.toLocaleString()} rows`}
                </button>
              )}
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Purge by Pattern Dialog */}
      {showPatternPurge && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center" onClick={() => setShowPatternPurge(false)}>
          <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md p-6 space-y-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-500" /> Purge by Pattern
            </h3>
            <p className="text-sm text-muted-foreground">
              Delete all data matching an IP range, hostname pattern, or URL pattern across all tables. Use * or % as wildcards.
            </p>
            <input
              value={purgePatternInput}
              onChange={e => { setPurgePatternInput(e.target.value); setPurgePreviewData(null) }}
              placeholder="192.168.1.* or *.example.com"
              className="w-full bg-muted rounded-md px-3 py-2 text-sm border border-border outline-none focus:border-primary font-mono"
              autoFocus
            />

            {purgePreviewData && purgePreviewData.dry_run && (
              <div className="bg-muted/60 border border-border rounded-md p-3 space-y-2 max-h-48 overflow-y-auto">
                <p className="text-sm font-medium">
                  {purgePreviewData.total === 0
                    ? 'No data found matching this pattern.'
                    : `Found ${purgePreviewData.total.toLocaleString()} rows across tables:`}
                </p>
                {purgePreviewData.total > 0 && (
                  <div className="space-y-1">
                    {Object.entries(purgePreviewData.details).map(([table, count]) => (
                      <div key={table} className="flex justify-between text-xs">
                        <span className="font-mono text-muted-foreground">{table}</span>
                        <span className="font-medium">{typeof count === 'number' ? count.toLocaleString() : String(count)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {purgePreviewData && !purgePreviewData.dry_run && purgePreviewData.ok && (
              <div className="bg-green-500/10 border border-green-500/30 rounded-md p-3">
                <p className="text-sm font-medium text-green-400">
                  Deleted {purgePreviewData.total.toLocaleString()} rows matching "{purgePreviewData.pattern}"
                </p>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button onClick={() => setShowPatternPurge(false)}
                className={`px-3 py-1.5 text-sm rounded-md border ${purgePreviewData && !purgePreviewData.dry_run && purgePreviewData.ok ? 'border-green-500 bg-green-500/20 text-green-400 hover:bg-green-500/30 font-medium' : 'border-border bg-muted hover:bg-muted/80'}`}>{purgePreviewData && !purgePreviewData.dry_run && purgePreviewData.ok ? 'Done' : 'Cancel'}</button>

              {(!purgePreviewData || purgePreviewData.dry_run) && (
                <button
                  onClick={() => purgePattern.mutate({ pattern: purgePatternInput, dry_run: true }, { onSuccess: (data) => setPurgePreviewData(data) })}
                  disabled={!purgePatternInput.trim() || purgePattern.isPending}
                  className="px-3 py-1.5 text-sm rounded-md border border-primary bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
                >
                  {purgePattern.isPending ? 'Scanning...' : 'Preview'}
                </button>
              )}

              {purgePreviewData?.dry_run && purgePreviewData.total > 0 && (
                <button
                  onClick={() => purgePattern.mutate({ pattern: purgePatternInput, dry_run: false }, { onSuccess: (data) => setPurgePreviewData(data) })}
                  disabled={purgePattern.isPending}
                  className="px-3 py-1.5 text-sm rounded-md border border-red-500 bg-red-500/20 text-red-400 hover:bg-red-500/30 disabled:opacity-50 font-medium"
                >
                  {purgePattern.isPending ? 'Deleting...' : `Delete ${purgePreviewData.total.toLocaleString()} rows`}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Selection toolbar */}
      {tab === 'assets' && selectedAssetCount > 0 && (
        <div className="flex items-center gap-3 bg-muted/60 border border-border rounded-md px-3 py-2">
          <span className="text-xs font-medium">{selectedAssetCount} selected</span>
          <button
            onClick={() => setShowScopeModal('assets')}
            className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 rounded hover:bg-cyan-500/20"
          >
            <Globe className="h-3 w-3" /> Assign to Scope
          </button>
          <button
            onClick={handleDeleteAssets}
            disabled={deleteAssets.isPending}
            className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/30 rounded hover:bg-red-500/20 disabled:opacity-50"
          >
            <Trash2 className="h-3 w-3" />
            {deleteAssets.isPending ? 'Deleting...' : 'Delete'}
          </button>
          <button
            onClick={() => setAssetSelection({})}
            className="text-xs text-muted-foreground hover:text-foreground underline"
          >Clear</button>
        </div>
      )}
      {tab === 'subdomains' && selectedSubdomainCount > 0 && (
        <div className="flex items-center gap-3 bg-muted/60 border border-border rounded-md px-3 py-2">
          <span className="text-xs font-medium">{selectedSubdomainCount} selected</span>
          <button
            onClick={() => setShowScopeModal('subdomains')}
            className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 rounded hover:bg-cyan-500/20"
          >
            <Globe className="h-3 w-3" /> Assign to Scope
          </button>
          <button
            onClick={handleDeleteSubdomains}
            disabled={deleteSubdomains.isPending}
            className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/30 rounded hover:bg-red-500/20 disabled:opacity-50"
          >
            <Trash2 className="h-3 w-3" />
            {deleteSubdomains.isPending ? 'Deleting...' : 'Delete'}
          </button>
          <button
            onClick={() => setSubdomainSelection({})}
            className="text-xs text-muted-foreground hover:text-foreground underline"
          >Clear</button>
        </div>
      )}

      {tab === 'assets' && (isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : (
        <DataTable
          data={assets}
          columns={assetColumns}
          onRowClick={(row) => {
            setSelectedPort(null)
            // For cloud_import assets the IP is a synthetic marker (127.0.x.x)
            // and the meaningful identity is the asset id (one row per CSV).
            // Open the recon tab directly so the operator sees the linked
            // findings instead of empty ports/screenshots.
            const isCloudImport = (row.tags || []).includes('cloud_import') ||
              row.ip === '127.0.1.1' || row.ip === '127.0.0.1' ||
              (row.tags || []).some(tag => ['microburst', 'azurehound', 'prowler', 'scoutsuite', 'pacu', 'cloudfox'].includes(tag))
            setDetailTab(isCloudImport ? 'recon' : 'ports')
            setSelectedAssetId(row.id || null)
            setSelectedIp(row.ip)
          }}
          globalFilter={search}
          onGlobalFilterChange={setSearch}
          selectable
          rowSelection={assetSelection}
          onRowSelectionChange={setAssetSelection}
          getRowId={(row) => row.ip}
        />
      ))}

      {tab === 'subdomains' && (subdomainsLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : (
        <DataTable
          data={subdomains}
          columns={subdomainColumns}
          globalFilter={search}
          onGlobalFilterChange={setSearch}
          selectable
          rowSelection={subdomainSelection}
          onRowSelectionChange={setSubdomainSelection}
          getRowId={(row) => row.subdomain}
        />
      ))}

      {tab === 'credentials' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground">Status:</span>
            {['', 'valid', 'invalid', 'unknown', 'remediated'].map((s) => (
              <button
                key={s}
                onClick={() => setCredStatusFilter(s)}
                className={`px-2 py-0.5 text-xs rounded border ${credStatusFilter === s ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
              >{s || 'All'}</button>
            ))}
            <div className="ml-auto">
              <button
                onClick={() => setShowAddCred(true)}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded border border-primary text-primary hover:bg-primary hover:text-primary-foreground transition-colors"
              ><Plus className="h-3 w-3" /> Add Credential</button>
            </div>
          </div>
          {credsLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : allCredentials.length === 0 ? (
            <p className="text-sm text-muted-foreground">No credentials found</p>
          ) : (
            <div className="space-y-2">
              {allCredentials
                .filter((c) => {
                  if (!search) return true
                  const s = search.toLowerCase()
                  return (c.username?.toLowerCase().includes(s) || c.ip?.toLowerCase().includes(s) || c.protocol?.toLowerCase().includes(s) || c.source?.toLowerCase().includes(s))
                })
                .map((c) => (
                <div key={c.id} className="border border-border rounded-md p-3 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Key className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="font-mono font-medium">{c.username || '(none)'}</span>
                      <span className="text-muted-foreground">@</span>
                      <span className="font-mono">{c.protocol}://{c.ip || '?'}:{c.port}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CredStatusBadge status={c.status || 'unknown'} />
                      <button
                        onClick={() => { if (window.confirm('Delete this credential?')) deleteCred.mutate(c.id) }}
                        disabled={deleteCred.isPending}
                        className="text-red-400 hover:text-red-300 disabled:opacity-50"
                        title="Delete credential"
                      ><Trash2 className="h-3.5 w-3.5" /></button>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-x-4 gap-y-1 text-muted-foreground">
                    <div>Type: <span className="text-foreground">{c.auth_type || c.secret_type}</span></div>
                    <div>Source: <span className="text-foreground">{c.source}</span></div>
                    <div>Protocol: <span className="text-foreground">{c.protocol}</span></div>
                    <div>Discovered: <span className="text-foreground">
                      {c.discovered_at ? new Date(c.discovered_at).toLocaleString() : c.created_at ? new Date(c.created_at).toLocaleString() : '—'}
                    </span></div>
                    <div>Last Verified: <span className="text-foreground">
                      {c.last_verified_at ? new Date(c.last_verified_at).toLocaleString() : '—'}
                    </span></div>
                    {c.banner && <div>Banner: <span className="text-foreground font-mono">{c.banner}</span></div>}
                  </div>
                  <div className="flex items-center gap-1.5 pt-1">
                    <span className="text-muted-foreground mr-1">Set status:</span>
                    {(['valid', 'invalid', 'unknown', 'remediated'] as const).map((s) => (
                      <button
                        key={s}
                        onClick={() => updateCredStatus.mutate({ id: c.id, status: s })}
                        disabled={c.status === s || updateCredStatus.isPending}
                        className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                          c.status === s
                            ? 'opacity-50 cursor-not-allowed border-border'
                            : 'hover:bg-accent border-border hover:border-primary cursor-pointer'
                        }`}
                      >{s}</button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'software' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <input
              className="px-3 py-1.5 bg-card border border-border rounded text-sm w-64"
              placeholder="Search product, version, host..."
              value={softwareProductInput}
              onChange={e => { setSoftwareProductInput(e.target.value); setSoftwareProductFilter(e.target.value) }}
            />
            <span className="text-xs text-muted-foreground">Source:</span>
            {['', 'nmap', 'httpx', 'whatweb', 'katana', 'wafw00f', 'zap', 'nuclei', 'playwright', 'gowitness'].map((s) => (
              <button
                key={s}
                onClick={() => setSoftwareSourceFilter(s)}
                className={`px-2 py-0.5 text-xs rounded border ${softwareSourceFilter === s ? 'bg-primary text-primary-foreground border-primary' : 'bg-muted border-border text-muted-foreground hover:text-foreground'}`}
              >{s || 'All'}</button>
            ))}
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setHideBlankProductVersion(!hideBlankProductVersion)}
                className={`px-2.5 py-0.5 text-xs font-medium rounded border ${hideBlankProductVersion ? 'bg-primary/20 text-primary border-primary/50' : 'border-border text-muted-foreground hover:text-foreground'}`}
              >Hide Blank</button>
              <button
                onClick={() => setShowCveOnly(!showCveOnly)}
                className={`flex items-center gap-1 px-2.5 py-0.5 text-xs font-medium rounded border ${showCveOnly ? 'bg-red-500/20 text-red-400 border-red-500/50' : 'border-border text-muted-foreground hover:text-foreground'}`}
              ><AlertTriangle className="h-3 w-3" /> CVE/Exploits Only</button>
              <button
                onClick={() => setShowBulkDismiss(true)}
                className="flex items-center gap-1 px-2.5 py-0.5 text-xs font-medium rounded border border-orange-500/50 text-orange-400 hover:bg-orange-500/10"
              ><ShieldOff className="h-3 w-3" /> Bulk Dismiss</button>
              <button
                onClick={() => { setShowCveTuning(true); setTuningDraft({}) }}
                className="flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-medium rounded border border-primary/50 text-primary hover:bg-primary/10"
                title="CVE rule tuning"
              ><Settings2 className="h-3.5 w-3.5" /> Tune Rules</button>
            </div>
          </div>
          {softwareData?.summary && (
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: 'Assets', value: softwareData.summary.asset_count },
                { label: 'Products', value: softwareData.summary.product_count },
                { label: 'Detections', value: softwareData.summary.total_detections },
                { label: 'Sources', value: softwareData.summary.source_count },
              ].map(s => (
                <div key={s.label} className="border border-border rounded-md p-2.5 text-center">
                  <div className="text-lg font-semibold">{s.value}</div>
                  <div className="text-[10px] text-muted-foreground">{s.label}</div>
                </div>
              ))}
            </div>
          )}
          {softwareLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : !softwareData?.items?.length ? (
            <p className="text-sm text-muted-foreground">No software detected yet. Run Nmap, httpx, or WhatWeb scans to populate.</p>
          ) : (() => {
            // Deduplicate: one row per hostname+product+version
            const deduped = Object.values(
              softwareData.items.reduce<Record<string, DetectedSoftware & { sources: string[] }>>((acc, sw) => {
                const key = `${sw.hostname || sw.ip}|${sw.product}|${sw.version || ''}`
                if (!acc[key]) {
                  acc[key] = { ...sw, sources: [sw.source] }
                } else {
                  if (!acc[key].sources.includes(sw.source)) acc[key].sources.push(sw.source)
                  if ((sw.cve_flags?.length ?? 0) > 0) acc[key].cve_flags = sw.cve_flags
                }
                return acc
              }, {})
            )

            // Filter
            let filtered = deduped.filter(sw => {
              if (showCveOnly && (sw.cve_flags?.length ?? 0) === 0) return false
              if (hideBlankProductVersion && (!sw.product || sw.product.trim() === '' || !sw.version || sw.version.trim() === '')) return false
              if (softwareProductFilter) {
                const q = softwareProductFilter.toLowerCase()
                const matchesProduct = sw.product?.toLowerCase().includes(q)
                const matchesVersion = sw.version?.toLowerCase().includes(q)
                const matchesHost = sw.hostname?.toLowerCase().includes(q) || sw.ip?.toLowerCase().includes(q)
                if (!matchesProduct && !matchesVersion && !matchesHost) return false
              }
              return true
            })

            // Sort
            const sortKey = softwareSort
            filtered.sort((a, b) => {
              if (sortKey === 'cve-count') {
                const diff = (b.cve_flags?.length ?? 0) - (a.cve_flags?.length ?? 0)
                if (diff !== 0) return diff
              }
              if (sortKey === 'product') return (a.product || '').localeCompare(b.product || '')
              if (sortKey === 'version') return (a.version || '').localeCompare(b.version || '')
              return (a.hostname || a.ip || '').localeCompare(b.hostname || b.ip || '')
            })

            const totalCves = filtered.reduce((s, i) => s + (i.cve_flags?.length ?? 0), 0)
            const uniqueProducts = new Set(filtered.filter(f => f.version).map(f => `${f.product}|${f.version}`))

            return (
              <div className="space-y-2">
                {/* Stats row */}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-foreground/60">{filtered.length} rows, {uniqueProducts.size} unique products</span>
                  {totalCves > 0 && <span className="text-[10px] text-red-400">{totalCves} CVE flags</span>}
                  <div className="ml-auto flex items-center gap-2">
                    {selectedProducts.size > 0 && (
                      <span className="text-[10px] text-purple-400">{selectedProducts.size} selected</span>
                    )}
                    <BulkCheckButton uniqueCount={uniqueProducts.size} selectedProducts={selectedProducts} />
                  </div>
                </div>

                {/* Sort buttons */}
                <div className="flex items-center gap-1">
                  <span className="text-[10px] text-muted-foreground">Sort:</span>
                  {(['hostname', 'product', 'version', 'cve-count'] as const).map(s => (
                    <button key={s} onClick={() => setSoftwareSort(s)}
                      className={`px-2 py-0.5 text-[10px] rounded border ${softwareSort === s ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}
                    >{s === 'cve-count' ? 'CVE Count' : s.charAt(0).toUpperCase() + s.slice(1)}</button>
                  ))}
                </div>

                {/* Table */}
                <div className="border border-border rounded-md overflow-x-auto overflow-y-auto max-h-[60vh] max-w-full">
                  <table className="w-full text-xs table-fixed min-w-[900px]">
                    <thead className="sticky top-0 bg-card z-10">
                      <tr className="bg-muted/30 border-b border-border">
                        <th className="px-2 py-2 w-8 flex-shrink-0">
                          <input type="checkbox"
                            checked={selectedProducts.size === filtered.length && filtered.length > 0}
                            onChange={e => {
                              if (e.target.checked) setSelectedProducts(new Set(filtered.map(sw => `${sw.product}|${sw.version || ''}`)))
                              else setSelectedProducts(new Set())
                            }}
                            className="rounded" />
                        </th>
                        <th className="text-left px-3 py-2 font-medium cursor-pointer hover:text-primary w-32" onClick={() => setSoftwareSort('hostname')}>
                          Hostname {softwareSort === 'hostname' && '▾'}
                        </th>
                        <th className="text-left px-3 py-2 font-medium cursor-pointer hover:text-primary w-36" onClick={() => setSoftwareSort('product')}>
                          Product {softwareSort === 'product' && '▾'}
                        </th>
                        <th className="text-left px-3 py-2 font-medium w-40 cursor-pointer hover:text-primary" onClick={() => setSoftwareSort('version')}>
                          Version {softwareSort === 'version' && '▾'}
                        </th>
                        <th className="text-left px-3 py-2 font-medium w-16">Port</th>
                        <th className="text-left px-3 py-2 font-medium w-24">Sources</th>
                        <th className="text-left px-3 py-2 font-medium w-16 cursor-pointer hover:text-primary" onClick={() => setSoftwareSort('cve-count')}>
                          CVEs {softwareSort === 'cve-count' && '▾'}
                        </th>
                        <th className="text-left px-3 py-2 font-medium w-32">Research</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((sw, i) => {
                        const hasCve = (sw.cve_flags?.length ?? 0) > 0
                        const rowKey = `${sw.product}|${sw.version || ''}|${sw.hostname || sw.ip}`
                        const isExpanded = expandedHosts.has(rowKey)
                        return (
                          <Fragment key={i}>
                          <tr className={`border-t border-border/30 hover:bg-muted/20 cursor-pointer ${hasCve ? 'bg-red-500/5' : ''}`}
                              onClick={() => {
                                const next = new Set(expandedHosts)
                                isExpanded ? next.delete(rowKey) : next.add(rowKey)
                                setExpandedHosts(next)
                              }}>
                            <td className="px-2 py-1.5" onClick={e => e.stopPropagation()}>
                              <input type="checkbox"
                                checked={selectedProducts.has(`${sw.product}|${sw.version || ''}`)}
                                onChange={e => {
                                  const key = `${sw.product}|${sw.version || ''}`
                                  const next = new Set(selectedProducts)
                                  e.target.checked ? next.add(key) : next.delete(key)
                                  setSelectedProducts(next)
                                }}
                                className="rounded" />
                            </td>
                            <td className="px-3 py-1.5 font-mono truncate max-w-0" title={sw.hostname || sw.ip || '—'}>
                              {sw.hostname || sw.ip || '—'}
                            </td>
                            <td className="px-3 py-1.5 font-medium truncate max-w-0" title={sw.product}>
                              <span className="truncate">{sw.product}</span>
                              {hasCve && <AlertTriangle className="inline h-3 w-3 text-red-400 ml-1 flex-shrink-0" />}
                            </td>
                            <td className={`px-3 py-1.5 font-mono truncate max-w-0 ${hasCve ? 'text-red-400' : 'text-primary'}`} title={sw.version || '—'}>
                              {sw.version || '—'}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-muted-foreground">{sw.port ?? '—'}</td>
                            <td className="px-3 py-1.5">
                              <div className="flex gap-0.5 flex-wrap overflow-hidden">
                                {(sw as any).sources?.slice(0, 3).map((s: string) => (
                                  <span key={s} className="inline-block px-1 py-0.5 rounded text-[9px] font-mono border bg-zinc-500/15 text-zinc-300 border-zinc-500/30 whitespace-nowrap">{s}</span>
                                ))}
                                {((sw as any).sources?.length || 0) > 3 && (
                                  <span className="text-[9px] text-muted-foreground">+{(sw as any).sources.length - 3}</span>
                                )}
                              </div>
                            </td>
                            <td className="px-3 py-1.5">
                              {hasCve ? (
                                <span className="text-red-400 font-medium cursor-help"
                                  title={sw.cve_flags!.map((f: any) => f.title?.slice(0, 50)).join('\n')}>
                                  {sw.cve_flags!.length}
                                </span>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </td>
                            <td className="px-3 py-1.5" onClick={e => e.stopPropagation()}>
                              <div className="flex items-center gap-1">
                                {(sw as any).ai_checked && (
                                  <span className="h-2 w-2 rounded-full bg-green-500 shrink-0" title="AI checked" />
                                )}
                                <button
                                  onClick={() => setExploitLookup({ product: sw.product, version: sw.version || '', cveFlags: sw.cve_flags })}
                                  className="px-1.5 py-0.5 rounded text-[10px] border border-purple-500/40 text-purple-400 hover:bg-purple-500/10"
                                  title="AI-powered exploit & CVE research"
                                ><Search className="inline h-2.5 w-2.5 mr-0.5" />{(sw as any).ai_checked ? 'View' : 'AI Check'}</button>
                              </div>
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="bg-muted/10">
                              <td colSpan={8} className="px-4 py-2">
                                <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
                                  <div><span className="text-muted-foreground">Product:</span> <span className="font-medium">{sw.product}</span></div>
                                  <div><span className="text-muted-foreground">Version:</span> <span className="font-mono text-primary">{sw.version || '—'}</span></div>
                                  <div><span className="text-muted-foreground">Host:</span> <span className="font-mono">{sw.hostname || sw.ip || '—'}</span></div>
                                  <div><span className="text-muted-foreground">Port:</span> <span className="font-mono">{sw.port ?? '—'}{sw.protocol ? `/${sw.protocol}` : ''}</span></div>
                                  <div><span className="text-muted-foreground">Detection:</span> {sw.detection_type?.replace(/_/g, ' ')}</div>
                                  <div><span className="text-muted-foreground">Sources:</span> {(sw as any).sources?.join(', ') || sw.source}</div>
                                  <div><span className="text-muted-foreground">First Seen:</span> {sw.first_seen ? new Date(sw.first_seen).toLocaleString() : '—'}</div>
                                  <div><span className="text-muted-foreground">Last Seen:</span> {sw.last_seen ? new Date(sw.last_seen).toLocaleString() : '—'}</div>
                                  {sw.occurrence_count && <div><span className="text-muted-foreground">Occurrences:</span> {sw.occurrence_count}</div>}
                                  {hasCve && (
                                    <div className="col-span-2 mt-1 pt-1 border-t border-border/30 space-y-1 max-w-full overflow-hidden">
                                      <span className="text-red-400 font-medium text-[11px]">CVE/Exploit Flags:</span>
                                      <div className="flex flex-wrap gap-1 max-w-full overflow-hidden">
                                        {sw.cve_flags!.slice(0, 10).map((f: any, fi: number) => {
                                          // Extract CVE IDs from the title
                                          const cveMatch = (f.title || '').match(/CVE-\d{4}-\d+/g) || []
                                          const edbMatch = (f.title || '').match(/EDB-\d+/g) || []
                                          return (
                                            <div key={fi} className="text-[10px] max-w-full">
                                              {cveMatch.slice(0, 2).map((cid: string) => (
                                                <a key={cid} href={`https://nvd.nist.gov/vuln/detail/${cid}`} target="_blank" rel="noopener noreferrer"
                                                  className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10 mr-1 whitespace-nowrap">
                                                  {cid} <ExternalLink className="h-2 w-2" />
                                                </a>
                                              ))}
                                              {edbMatch.slice(0, 1).map((eid: string) => (
                                                <a key={eid} href={`https://www.exploit-db.com/exploits/${eid.replace('EDB-','')}`} target="_blank" rel="noopener noreferrer"
                                                  className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border border-orange-500/40 text-orange-400 hover:bg-orange-500/10 mr-1">
                                                  {eid} <ExternalLink className="h-2 w-2" />
                                                </a>
                                              ))}
                                              {!cveMatch.length && !edbMatch.length && (
                                                <span className="text-red-300 truncate max-w-xs" title={f.title}>
                                                  {f.title?.slice(0, 40)}
                                                  {(f.title?.length || 0) > 40 && '...'}
                                                </span>
                                              )}
                                            </div>
                                          )
                                        })}
                                        {(sw.cve_flags?.length || 0) > 10 && (
                                          <span className="text-[10px] text-muted-foreground px-1.5 py-0.5">
                                            +{(sw.cve_flags?.length || 0) - 10} more
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                          </Fragment>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )
          })()}
        </div>
      )}

      {/* Bulk Dismiss CVE Dialog */}
      {showBulkDismiss && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-card border border-border rounded-lg p-5 w-full max-w-md space-y-4">
            <h3 className="text-sm font-semibold">Bulk Dismiss CVE Follow-Ups</h3>
            <p className="text-xs text-muted-foreground">
              Dismiss CVE flags as false positives and train the agent to reduce future confidence for similar matches.
            </p>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">CVEs published before year</label>
                <input type="number" value={dismissYearBefore} onChange={e => setDismissYearBefore(Number(e.target.value))}
                  className="w-full bg-muted rounded px-3 py-1.5 text-sm border border-border" />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Product filter (optional)</label>
                <input value={dismissProduct} onChange={e => setDismissProduct(e.target.value)} placeholder="e.g. IIS, Apache"
                  className="w-full bg-muted rounded px-3 py-1.5 text-sm border border-border" />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Reason (required)</label>
                <textarea value={dismissReason} onChange={e => setDismissReason(e.target.value)} rows={3}
                  className="w-full bg-muted rounded px-3 py-1.5 text-sm border border-border" />
              </div>
            </div>
            {dismissResult && (
              <p className={`text-xs ${dismissResult.includes('Error') ? 'text-red-400' : 'text-green-400'}`}>{dismissResult}</p>
            )}
            <div className="flex justify-end gap-2">
              <button onClick={() => { setShowBulkDismiss(false); setDismissResult(null) }}
                className="px-3 py-1.5 text-xs rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
              <button
                disabled={!dismissReason || bulkDismiss.isPending}
                onClick={() => {
                  bulkDismiss.mutate({
                    reason: dismissReason,
                    cve_year_before: dismissYearBefore || undefined,
                    product: dismissProduct || undefined,
                  }, {
                    onSuccess: (data) => {
                      setDismissResult(`Dismissed ${data.dismissed} follow-ups, created ${data.feedback_created} feedback entries`)
                    },
                    onError: (err) => setDismissResult(`Error: ${err}`),
                  })
                }}
                className="px-3 py-1.5 text-xs font-medium rounded border border-orange-500 text-orange-400 hover:bg-orange-500/10 disabled:opacity-50"
              >{bulkDismiss.isPending ? 'Dismissing...' : 'Dismiss & Train'}</button>
            </div>
          </div>
        </div>
      )}

      {/* Exploit Lookup Modal */}
      {exploitLookup && <ExploitLookupModal product={exploitLookup.product} version={exploitLookup.version} cveFlags={exploitLookup.cveFlags} onClose={() => setExploitLookup(null)} />}

      {/* CVE Rule Tuning Dialog */}
      {showCveTuning && cveTuningData?.tuning && (() => {
        const t = cveTuningData.tuning
        const tAny = t as unknown as Record<string, unknown>
        const get = (k: string) => tuningDraft[k] ?? String(tAny[k] ?? '')
        const set = (k: string, v: string) => setTuningDraft(prev => ({ ...prev, [k]: v }))
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-card border border-border rounded-lg p-5 w-full max-w-lg space-y-4">
              <h3 className="text-sm font-semibold flex items-center gap-1.5"><Settings2 className="h-4 w-4" /> CVE Rule Tuning</h3>
              <p className="text-xs text-muted-foreground">
                Adjust how the agent scores software version CVE matches. Lower age penalty multipliers reduce confidence for older CVEs.
              </p>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { key: 'age_penalty_2yr', label: '2-3yr penalty', help: 'Multiplier for CVEs 2-3 years old' },
                  { key: 'age_penalty_3yr', label: '3-5yr penalty', help: 'Multiplier for CVEs 3-5 years old' },
                  { key: 'age_penalty_5yr', label: '5yr+ penalty', help: 'Multiplier for CVEs 5+ years old' },
                ].map(f => (
                  <div key={f.key}>
                    <label className="text-[10px] text-muted-foreground block mb-1" title={f.help}>{f.label}</label>
                    <input type="number" step="0.05" min="0" max="1" value={get(f.key)}
                      onChange={e => set(f.key, e.target.value)}
                      className="w-full bg-muted rounded px-2 py-1 text-sm border border-border font-mono" />
                  </div>
                ))}
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground block mb-1">Min confidence threshold (below this = skip)</label>
                <input type="number" step="0.05" min="0" max="1" value={get('min_confidence_threshold')}
                  onChange={e => set('min_confidence_threshold', e.target.value)}
                  className="w-full bg-muted rounded px-2 py-1 text-sm border border-border font-mono" />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground block mb-1">Skip products (comma-separated, case-insensitive)</label>
                <input value={get('skip_products')} onChange={e => set('skip_products', e.target.value)}
                  placeholder="e.g. child-theme, ajax_handler"
                  className="w-full bg-muted rounded px-2 py-1 text-sm border border-border" />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground block mb-1">Extra product aliases (product:alias1,alias2; ...)</label>
                <input value={get('extra_aliases')} onChange={e => set('extra_aliases', e.target.value)}
                  placeholder="e.g. tomcat:apache tomcat;iis:internet information services"
                  className="w-full bg-muted rounded px-2 py-1 text-sm border border-border" />
              </div>
              <div className="flex justify-end gap-2">
                <button onClick={() => setShowCveTuning(false)}
                  className="px-3 py-1.5 text-xs rounded border border-border text-muted-foreground hover:text-foreground">Cancel</button>
                <button
                  disabled={Object.keys(tuningDraft).length === 0 || updateCveTuning.isPending}
                  onClick={() => {
                    const params: Record<string, unknown> = {}
                    for (const [k, v] of Object.entries(tuningDraft)) {
                      params[k] = ['skip_products', 'extra_aliases'].includes(k) ? v : parseFloat(v)
                    }
                    updateCveTuning.mutate(params, { onSuccess: () => setShowCveTuning(false) })
                  }}
                  className="px-3 py-1.5 text-xs font-medium rounded border border-primary text-primary hover:bg-primary/10 disabled:opacity-50"
                >{updateCveTuning.isPending ? 'Saving...' : 'Save'}</button>
              </div>
            </div>
          </div>
        )
      })()}

      {/* Drill-down slide-over */}
      {selectedIp && (
        <div className="fixed inset-y-0 right-0 w-[80vw] max-w-[1100px] bg-card border-l border-border shadow-xl z-50 overflow-y-auto">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <div>
              <h3 className="text-sm font-semibold font-mono">{selectedIp}</h3>
              {assets.find(a => a.ip === selectedIp)?.hostname && (
                <p className="text-xs text-muted-foreground font-mono">{assets.find(a => a.ip === selectedIp)?.hostname}</p>
              )}
            </div>
            <button onClick={handleCloseSlideOver} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="flex items-center gap-2 px-4 pt-3 border-b border-border">
            <button
              onClick={() => setDetailTab('ports')}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-md border border-b-0 ${detailTab === 'ports' ? 'bg-card text-foreground border-border' : 'bg-muted/50 text-muted-foreground border-transparent hover:text-foreground'}`}
            >Ports ({portsData?.count ?? 0})</button>
            <button
              onClick={() => setDetailTab('recon')}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-md border border-b-0 ${detailTab === 'recon' ? 'bg-card text-foreground border-border' : 'bg-muted/50 text-muted-foreground border-transparent hover:text-foreground'}`}
            >Recon Intel</button>
            <button
              onClick={() => setDetailTab('credentials')}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-md border border-b-0 ${detailTab === 'credentials' ? 'bg-card text-foreground border-border' : 'bg-muted/50 text-muted-foreground border-transparent hover:text-foreground'}`}
            >Credentials</button>
            <button
              onClick={() => setDetailTab('screenshots')}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-md border border-b-0 ${detailTab === 'screenshots' ? 'bg-card text-foreground border-border' : 'bg-muted/50 text-muted-foreground border-transparent hover:text-foreground'}`}
            ><Camera className="h-3 w-3 inline mr-1" />Screenshots</button>
          </div>

          <div className="p-4 space-y-6">
            {detailTab === 'ports' && (
              <div>
                {portsData?.items?.length ? (
                  <DataTable
                    data={portsData.items}
                    columns={portColumns}
                    onRowClick={(row) => setSelectedPort(row)}
                    resizable
                  />
                ) : (
                  <p className="text-xs text-muted-foreground">No ports data</p>
                )}
              </div>
            )}

            {detailTab === 'credentials' && (
              <CredentialSection ip={selectedIp} />
            )}

            {detailTab === 'screenshots' && (
              <AssetScreenshots ip={selectedIp} hostname={assets.find(a => a.ip === selectedIp)?.hostname} />
            )}

            {detailTab === 'recon' && (() => {
              const asset = assets.find(a => a.id === selectedAssetId) ?? assets.find(a => a.ip === selectedIp)
              const isCloudImport = (asset?.tags || []).includes('cloud_import')
              if (isCloudImport && asset?.id) {
                return <CloudImportFindings assetId={asset.id} hostname={asset.hostname} />
              }
              return <AssetReconIntel hostname={asset?.hostname} ip={selectedIp} asset={asset} />
            })()}
          </div>
        </div>
      )}

      {/* Port detail dialog */}
      {selectedPort && selectedIp && (
        <PortDetailDialog
          port={selectedPort}
          ip={selectedIp}
          vulns={vulnsData?.vulns ?? []}
          onClose={() => setSelectedPort(null)}
        />
      )}

      {showAddCred && <AddCredentialModal onClose={() => setShowAddCred(false)} />}

      {showScopeModal === 'assets' && (
        <ScopeAssignModal
          fromScope={scopeFilter || undefined}
          targets={Object.keys(assetSelection).filter(k => assetSelection[k]).map(ip => {
            const asset = assets.find(a => a.ip === ip)
            return { target: asset?.hostname || ip, target_type: asset?.hostname ? 'domain' : 'ip' }
          })}
          onClose={() => setShowScopeModal(null)}
          onSuccess={() => setAssetSelection({})}
        />
      )}
      {showScopeModal === 'subdomains' && (
        <ScopeAssignModal
          fromScope={scopeFilter || undefined}
          targets={Object.keys(subdomainSelection).filter(k => subdomainSelection[k]).map(id => {
            const sub = subdomains.find(s => s.subdomain === id)
            return { target: sub?.subdomain || id, target_type: 'domain' }
          })}
          onClose={() => setShowScopeModal(null)}
          onSuccess={() => setSubdomainSelection({})}
        />
      )}
    </div>
  )
}


function AssetScreenshots({ ip, hostname }: { ip: string; hostname?: string | null }) {
  const search = hostname || ip
  const { data, isLoading } = useScreenshots(search)
  const screenshots = data?.screenshots ?? []

  if (isLoading) return <p className="text-xs text-muted-foreground">Loading screenshots...</p>
  if (!screenshots.length) return <p className="text-xs text-muted-foreground">No screenshots found for {search}. Run GoWitness to capture.</p>

  return (
    <div>
      <p className="text-xs text-muted-foreground mb-2">{screenshots.length} screenshots for {search}</p>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        {screenshots.map((s, i) => (
          <ScreenshotThumbnail key={i} path={s.path} filename={s.filename} />
        ))}
      </div>
    </div>
  )
}


// Drill-down for cloud-import assets (MicroBurst / AzureHound / etc.).
// Each asset is one CSV/JSON file; each finding is one row from that file.
// We just paginate the linked recon_findings — no host-style enrichment.
function CloudImportFindings({ assetId, hostname }: { assetId: string; hostname?: string | null }) {
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 100
  const { data, isLoading } = useQuery({
    queryKey: ['cloud-import-findings', assetId, page],
    queryFn: () => apiFetch<{
      findings: Array<{
        id: string; source: string; finding_type: string; target: string;
        severity: string; data: any; created_at: string
      }>;
      total: number;
    }>(`/recon?asset_id=${encodeURIComponent(assetId)}&limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}`),
  })
  const findings = data?.findings ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // Group counts by finding_type + severity for the header summary
  const byType: Record<string, number> = {}
  for (const f of findings) byType[f.finding_type] = (byType[f.finding_type] || 0) + 1

  if (isLoading) return <p className="text-xs text-muted-foreground">Loading findings…</p>

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between">
        <div>
          <h5 className="text-xs font-semibold">Findings from {hostname?.split('/').pop() || 'this file'}</h5>
          <p className="text-[10px] text-muted-foreground">{total.toLocaleString()} total</p>
        </div>
        {Object.keys(byType).length > 0 && (
          <div className="flex flex-wrap gap-1 text-[10px]">
            {Object.entries(byType).map(([k, v]) => (
              <span key={k} className="px-1.5 py-0.5 rounded border bg-muted/40 border-border font-mono">
                {k}: <span className="font-semibold">{v}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {findings.length === 0 ? (
        <p className="text-xs text-muted-foreground">No findings linked to this asset.</p>
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-muted/40 text-[10px] uppercase text-muted-foreground">
              <tr>
                <th className="px-2 py-1 text-left">Sev</th>
                <th className="px-2 py-1 text-left">Type</th>
                <th className="px-2 py-1 text-left">Target</th>
                <th className="px-2 py-1 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => {
                // Pull a few high-signal fields from data.row for the inline preview
                const row = f.data?.row || {}
                const detailParts: string[] = []
                for (const k of ['UserPrincipalName', 'Mail', 'PrincipalDisplayName', 'RoleDisplayName',
                                 'AppId', 'PrincipalType', 'AccountEnabled', 'UserType',
                                 'AuthenticationType', 'State', 'VaultName', 'Name']) {
                  const v = row[k]
                  if (v != null && v !== '') {
                    detailParts.push(`${k}=${v}`)
                    if (detailParts.length >= 3) break
                  }
                }
                return (
                  <tr key={f.id} className="border-t border-border hover:bg-muted/30">
                    <td className="px-2 py-1">
                      <span className={cn(
                        'px-1.5 py-0.5 text-[9px] rounded border font-medium',
                        f.severity === 'critical' ? 'bg-red-500/15 text-red-400 border-red-500/30' :
                        f.severity === 'high'     ? 'bg-orange-500/15 text-orange-400 border-orange-500/30' :
                        f.severity === 'medium'   ? 'bg-amber-500/15 text-amber-400 border-amber-500/30' :
                        'bg-zinc-500/15 text-zinc-400 border-zinc-500/30'
                      )}>{f.severity}</span>
                    </td>
                    <td className="px-2 py-1 font-mono">{f.finding_type}</td>
                    <td className="px-2 py-1 font-mono break-all max-w-xs">{f.target}</td>
                    <td className="px-2 py-1 text-muted-foreground font-mono text-[10px] break-all">
                      {detailParts.join(', ') || '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-2 text-[11px]">
          <button
            disabled={page === 0}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            className="px-2 py-0.5 rounded border border-border hover:bg-muted disabled:opacity-30"
          >‹ Prev</button>
          <span className="text-muted-foreground">Page {page + 1} of {totalPages.toLocaleString()}</span>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            className="px-2 py-0.5 rounded border border-border hover:bg-muted disabled:opacity-30"
          >Next ›</button>
        </div>
      )}
    </div>
  )
}

function AssetReconIntel({ hostname, ip, asset }: { hostname?: string | null; ip: string; asset?: Asset }) {
  // Query domain overview for the hostname (falls back to IP)
  const lookupDomain = hostname || ip
  const { data: overview, isLoading } = useReconDomainOverview(lookupDomain)

  // Provider info comes from the asset row even when domain overview is empty,
  // so render it before the early-return guards.
  const providers = asset?.provider ?? []
  const evidence = asset?.provider_evidence ?? {}
  const providerBadge = providers.length > 0 && (
    <div className="rounded-md border border-border bg-muted/30 p-3">
      <div className="flex items-center gap-2 mb-1.5">
        <h5 className="text-xs font-medium text-muted-foreground">Cloud Hosting</h5>
        <div className="flex gap-1">
          {providers.map(p => (
            <span key={p} className="px-2 py-0.5 rounded text-[10px] font-medium uppercase border border-blue-500/30 bg-blue-500/10 text-blue-400">{p}</span>
          ))}
        </div>
      </div>
      <div className="space-y-0.5">
        {providers.map(p => {
          const reasons = evidence[p] ?? []
          if (reasons.length === 0) return null
          return (
            <div key={p} className="text-[10px] text-muted-foreground font-mono">
              <span className="opacity-70">{p}:</span> {reasons.join(', ')}
            </div>
          )
        })}
      </div>
    </div>
  )

  if (isLoading) return (
    <div className="space-y-4">
      {providerBadge}
      <p className="text-xs text-muted-foreground">Loading recon data for {lookupDomain}...</p>
    </div>
  )
  if (!overview) return (
    <div className="space-y-4">
      {providerBadge}
      <p className="text-xs text-muted-foreground">No recon data found for {lookupDomain}. Run a passive recon or content recon scan.</p>
    </div>
  )

  const stats = overview.stats
  const httpSvc = overview.http_services ?? []
  const dns = overview.dns_records ?? {}
  const tls = overview.tls_certs ?? []
  const waf = overview.waf_detections ?? []
  const webFindings = overview.web_findings ?? []
  const params = overview.discovered_params ?? []

  return (
    <div className="space-y-4">
      {providerBadge}
      {/* Stats summary */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        {[
          { label: 'Subdomains', value: overview.subdomains?.length ?? 0 },
          { label: 'HTTP Services', value: httpSvc.length },
          { label: 'DNS Records', value: Object.values(dns).reduce((a: number, b) => a + (b as unknown[]).length, 0) },
          { label: 'TLS Certs', value: tls.length },
          { label: 'Web Findings', value: stats.web_findings_count ?? webFindings.length },
          { label: 'Parameters', value: params.length },
        ].map(s => (
          <div key={s.label} className="bg-muted rounded p-2 text-center">
            <div className="text-lg font-bold">{s.value}</div>
            <div className="text-[10px] text-muted-foreground">{s.label}</div>
          </div>
        ))}
      </div>

      {/* HTTP Services */}
      {httpSvc.length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">HTTP Services ({httpSvc.length})</h5>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {httpSvc.map((s, i) => (
              <div key={i} className="flex items-center gap-2 text-xs bg-muted/50 rounded px-2 py-1">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                  Number(s.status_code) >= 200 && Number(s.status_code) < 300 ? 'bg-green-400/10 text-green-400' :
                  Number(s.status_code) >= 300 && Number(s.status_code) < 400 ? 'bg-yellow-400/10 text-yellow-400' :
                  Number(s.status_code) >= 400 ? 'bg-red-400/10 text-red-400' : 'bg-muted text-muted-foreground'
                }`}>{s.status_code || '?'}</span>
                <span className="font-mono truncate flex-1">{s.url}</span>
                <span className="text-muted-foreground">{s.webserver || ''}</span>
                {s.title ? <span className="text-muted-foreground truncate max-w-[150px]">{s.title}</span> : null}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* DNS Records */}
      {Object.keys(dns).length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">DNS Records</h5>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {Object.entries(dns).map(([rtype, entries]) => (
              <div key={rtype}>
                <span className="text-[10px] font-medium text-primary">{rtype.replace('dns_', '').toUpperCase()}</span>
                {(entries as Array<{target: string; values: unknown}>).map((e, i) => (
                  <div key={i} className="text-xs font-mono text-muted-foreground ml-3">
                    {e.target}: {Array.isArray(e.values) ? (e.values as string[]).join(', ') : JSON.stringify(e.values)}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TLS Certs */}
      {tls.length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">TLS Certificates ({tls.length})</h5>
          {tls.map((c, i) => {
            const expired = c.not_after ? new Date(c.not_after) < new Date() : false
            return (
              <div key={i} className="text-xs bg-muted/50 rounded px-2 py-1 mb-1 space-y-0.5">
                <div className="font-mono">{c.subject_cn || c.host}</div>
                <div className="text-muted-foreground">Issuer: {c.issuer || '?'} | Expires: <span className={expired ? 'text-red-400 font-medium' : ''}>{c.not_after || '?'}{expired ? ' (EXPIRED)' : ''}</span></div>
              </div>
            )
          })}
        </div>
      )}

      {/* WAF */}
      {waf.length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">WAF Detection</h5>
          {waf.map((w, i) => (
            <div key={i} className="text-xs bg-muted/50 rounded px-2 py-1 mb-1">
              {w.detected ? <span className="text-yellow-400">{w.firewall || 'WAF Detected'}</span> : <span className="text-green-400">No WAF</span>}
              <span className="text-muted-foreground ml-2">{w.url}</span>
            </div>
          ))}
        </div>
      )}

      {/* Parameters */}
      {params.length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">Discovered Parameters ({params.length})</h5>
          <div className="flex flex-wrap gap-1.5">
            {params.map((p, i) => (
              <span key={i} className="px-2 py-0.5 bg-muted rounded text-xs font-mono border border-border">
                {p.name} <span className="text-muted-foreground">({p.count}x)</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Source distribution */}
      {stats.by_source && Object.keys(stats.by_source).length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-muted-foreground mb-2">Sources</h5>
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.by_source).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([src, cnt]) => (
              <span key={src} className="text-[10px] text-muted-foreground">
                {src}: {String(cnt)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


function ExploitLookupModal({ product, version, cveFlags, onClose }: { product: string; version: string; cveFlags?: any[]; onClose: () => void }) {
  // Load previous research from cache
  const queryClient = useQueryClient()
  const { data: cacheData } = useResearchCache(product, version || undefined)

  // Load VulnX findings for this product/version
  const { data: vulnxData, isLoading: vulnxLoading } = useVulnxFindings(product, version)
  const cachedDdg = cacheData?.entries?.find(e => e.source === 'ddg_search')
  const cachedEdb = cacheData?.entries?.find(e => e.source === 'searchsploit')

  // EDB: start with exact version, offer to widen + AI analyze (sticky per product)
  const _edbWideKey = `edbWide:${product}`
  const [edbWide, _setEdbWide] = useState(() => localStorage.getItem(_edbWideKey) === 'true')
  const setEdbWide = (v: boolean) => { _setEdbWide(v); if (v) localStorage.setItem(_edbWideKey, 'true'); else localStorage.removeItem(_edbWideKey) }
  const edbVersion = edbWide ? '' : (version || '')
  const edbAnalyze = edbWide && !!version
  const { data: edbData, isLoading: edbLoading } = useSearchsploit(product, edbVersion || undefined, edbAnalyze, edbWide ? version : undefined)
  const edbNoVersionResults = !edbWide && !edbLoading && (edbData?.count ?? 0) === 0

  const ddgLinks = getDdgSearchUrls(product, version || undefined)
  const [ddgData, setDdgData] = useState<DdgSearchResponse | null>(null)
  const [ddgLoading, setDdgLoading] = useState(false)
  const [ddgStage, setDdgStage] = useState('')
  const [ddgError, setDdgError] = useState('')
  const [showLog, setShowLog] = useState(false)
  const [llmDebug, setLlmDebug] = useState<any>(null)
  const [manualUrls, setManualUrls] = useState('')
  const [manualUrlResults, setManualUrlResults] = useState<any[]>([])
  const [manualUrlLoading, setManualUrlLoading] = useState(false)
  const [modalTab, setModalTab] = useState<'exploits' | 'research' | 'vulnx' | 'github' | 'log'>('exploits')
  // GitHub PoC tab data (from ddgData or standalone fetch)
  const [githubPocs, setGithubPocs] = useState<any[]>([])
  const [githubLoading, setGithubLoading] = useState(false)

  // Sync GitHub PoCs from ddgData when it arrives
  useEffect(() => {
    if (ddgData?.github_pocs?.length) {
      setGithubPocs(ddgData.github_pocs)
    }
  }, [ddgData])

  // Standalone GitHub search (for the GitHub tab)
  const fetchGithubPocs = async () => {
    setGithubLoading(true)
    try {
      const cveParam = (ddgData?.confirmed_cves || []).map((c: any) => c.cve_id).join(',')
      const r = await apiFetch<{ repos: any[] }>(`/software/github-search?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version || '')}&cve=${encodeURIComponent(cveParam)}&force=true`)
      setGithubPocs(r.repos || [])
    } catch { /* ignore */ }
    setGithubLoading(false)
  }

  // Auto-load from cache only — do NOT auto-trigger web searches
  useEffect(() => {
    if (ddgData) return // already have data
    if (cachedDdg?.results) {
      const cached = cachedDdg.results as DdgSearchResponse
      if (cached.analysis || cached.nvd_cves || cached.raw_results) {
        setDdgData(cached) // load from cache
      }
    }
  }, [cachedDdg])

  const runWebSearch = async (forceRefresh = true) => {
    setDdgLoading(true)
    setDdgError('')
    try {
      const forceParam = forceRefresh ? '&force=true' : ''
      const initial = await apiFetch<any>(
        `/software/ddg-search?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version || '')}${forceParam}`
      )
      // If cached result returned directly
      if (initial.raw_results || initial.from_cache || initial.nvd_cves) {
        setDdgData(initial as DdgSearchResponse)
        setDdgLoading(false)
        queryClient.invalidateQueries({ queryKey: ['research-cache', product, version || undefined] })
        return
      }
      // Background job — poll for completion
      const jobId = initial.job_id
      if (!jobId) { setDdgError('No job started'); setDdgLoading(false); return }
      const poll = setInterval(async () => {
        try {
          const status = await apiFetch<any>(`/software/ddg-search/${jobId}`)
          if (status.status === 'completed' || status.raw_results || status.nvd_cves) {
            clearInterval(poll)
            setDdgData(status as DdgSearchResponse)
            setDdgLoading(false)
            setDdgStage('')
            queryClient.invalidateQueries({ queryKey: ['research-cache', product, version || undefined] })
          } else if (status.status === 'failed') {
            clearInterval(poll)
            setDdgError(status.result?.error || 'Search failed')
            setDdgLoading(false)
            setDdgStage('')
          } else if (status.stage) {
            setDdgStage(status.stage)
          }
        } catch {}
      }, 3000)
      // Timeout after 2 min
      setTimeout(() => { clearInterval(poll); if (ddgLoading) { setDdgLoading(false); setDdgError('Search timed out') } }, 120000)
    } catch (e: any) {
      setDdgError(e.message || 'Search failed')
      setDdgLoading(false)
    }
  }

  const sevColor = (s?: string) => {
    if (!s) return 'text-muted-foreground'
    if (s === 'critical') return 'text-red-400'
    if (s === 'high') return 'text-orange-400'
    if (s === 'medium') return 'text-yellow-400'
    return 'text-muted-foreground'
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg p-5 w-full max-w-3xl max-h-[85vh] overflow-auto space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">
            AI Exploit Research: {product} {version || ''}
          </h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 border-b border-border">
          {([
            ['exploits', 'Exploits & Nuclei'],
            ['research', 'AI Research'],
            ['vulnx', 'VulnX CVEs'],
            ['github', 'GitHub PoCs'],
            ['log', 'Debug Log'],
          ] as [typeof modalTab, string][]).map(([t, label]) => (
            <button key={t} onClick={() => setModalTab(t)}
              className={cn('px-3 py-1.5 text-xs border-b-2 transition-colors',
                modalTab === t ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              {label}
              {t === 'github' && githubPocs.length > 0 && (
                <span className="ml-1 px-1 py-0 rounded-full bg-primary/10 text-[9px]">{githubPocs.length}</span>
              )}
              {t === 'vulnx' && vulnxData && vulnxData.unique_cves > 0 && (
                <span className="ml-1 px-1 py-0 rounded-full bg-red-500/10 text-red-400 text-[9px]">{vulnxData.unique_cves}</span>
              )}
            </button>
          ))}
        </div>

        {/* ── Manual URL submission (top of modal) ── */}
        <div className="border border-purple-500/30 rounded-md p-3 bg-purple-500/5 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-purple-400 shrink-0">Add Advisory URL:</span>
            <input className="flex-1 px-2 py-1.5 bg-card border border-border rounded text-sm"
              placeholder="Paste vendor advisory URL (e.g. jira.atlassian.com/browse/...)"
              value={manualUrls}
              onChange={e => setManualUrls(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && manualUrls.trim()) {
                  setManualUrlLoading(true)
                  fetch('/api/software/scan-urls', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ product, version, urls: manualUrls.split(/[\s,]+/).filter(u => u.startsWith('http')) }),
                  }).then(r => r.json()).then(d => {
                    setManualUrlResults(prev => [...prev, d])
                    setManualUrls('')
                    setManualUrlLoading(false)
                    if (d.analysis?.length && ddgData) {
                      setDdgData(prev => prev ? { ...prev, analysis: [...(prev.analysis || []), ...d.analysis] } : prev)
                    }
                    queryClient.invalidateQueries({ queryKey: ['research-cache', product, version || undefined] })
                  }).catch(() => setManualUrlLoading(false))
                }
              }} />
            <button onClick={() => {
              if (!manualUrls.trim()) return
              setManualUrlLoading(true)
              fetch('/api/software/scan-urls', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ product, version, urls: manualUrls.split(/[\s,]+/).filter(u => u.startsWith('http')) }),
              }).then(r => r.json()).then(d => {
                setManualUrlResults(prev => [...prev, d])
                setManualUrls('')
                setManualUrlLoading(false)
                if (d.analysis?.length && ddgData) {
                  setDdgData(prev => prev ? { ...prev, analysis: [...(prev.analysis || []), ...d.analysis] } : prev)
                }
                queryClient.invalidateQueries({ queryKey: ['research-cache', product, version || undefined] })
              }).catch(() => setManualUrlLoading(false))
            }} disabled={manualUrlLoading || !manualUrls.trim()}
              className="px-3 py-1.5 rounded text-sm font-medium border border-purple-500/50 text-purple-400 hover:bg-purple-500/10 disabled:opacity-50 shrink-0">
              {manualUrlLoading ? 'Scanning...' : 'Scan URL'}
            </button>
          </div>
          {manualUrlResults.length > 0 && (
            <div className="space-y-1.5">
              {manualUrlResults.map((r, i) => (
                <div key={i} className="p-2 rounded border border-purple-500/20 bg-card/50">
                  <div className="text-sm text-foreground/80 flex items-center gap-2 flex-wrap">
                    <span>Scanned {r.pages?.length || 0} page(s): <strong>{r.cve_count || 0} CVEs</strong></span>
                    {r.analysis?.length > 0 && <span className="text-green-400">{r.analysis.filter((a: any) => a.applies === true).length} confirmed</span>}
                    {r.cves_found?.length > 0 && (
                      <button onClick={async () => {
                        for (const cid of r.cves_found) {
                          await fetch('/api/software/cve-decision', {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ product, version, cve_id: cid, action: 'accept' }),
                          })
                        }
                        useUIStore.getState().addNotification(`${r.cves_found.length} CVEs flagged as applicable`, 'success')
                        queryClient.invalidateQueries({ queryKey: ['research-cache', product, version || undefined] })
                      }} className="ml-auto px-2 py-0.5 rounded text-xs font-bold border border-red-500/40 text-red-400 hover:bg-red-500/10">
                        Force-Flag All ({r.cves_found.length})
                      </button>
                    )}
                  </div>
                  {r.pages?.length > 0 && (
                    <div className="mt-1 text-xs text-foreground/60">
                      {r.pages.map((p: any, j: number) => (
                        <a key={j} href={p.url} target="_blank" rel="noopener noreferrer" className="mr-2 text-blue-400 hover:underline">{p.title?.slice(0, 40) || 'page'}</a>
                      ))}
                    </div>
                  )}
                  {r.cves_found?.length > 0 && (
                    <div className="mt-1 text-xs">
                      <span className="text-foreground/50">CVEs: </span>
                      {r.cves_found.map((c: string) => {
                        const anal = r.analysis?.find((a: any) => a.cve_id === c)
                        return (
                          <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer"
                            className={`mr-1.5 font-mono text-xs hover:underline ${anal?.applies === true ? 'text-red-400 font-bold' : anal?.applies === 'likely' ? 'text-yellow-400' : 'text-foreground/60'}`}>
                            {c}{anal?.probability != null ? ` (${anal.probability}%)` : ''}
                          </a>
                        )
                      })}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Confirmed/Likely CVEs (top of modal) ── */}
        {(() => {
          // Only show CVEs that are confirmed or likely applicable to this version
          const knownCves: Array<{id: string; summary?: string; cvss?: number | null; source: string; severity?: string; probability?: number}> = []
          const seen = new Set<string>()

          // From existing follow_up_items (already flagged in the system)
          for (const f of cveFlags || []) {
            for (const cid of ((f.title || '').match(/CVE-\d{4}-\d+/g) || [])) {
              if (!seen.has(cid)) {
                seen.add(cid)
                knownCves.push({id: cid, source: 'flagged', severity: f.severity})
              }
            }
          }

          // From LLM-analyzed EDB results: only items marked applies=true
          for (const e of edbData?.exploits || []) {
            if (e.applies === true && e.codes) {
              for (const code of e.codes.split(';')) {
                const cid = code.trim()
                if (cid.startsWith('CVE-') && !seen.has(cid)) {
                  seen.add(cid)
                  knownCves.push({id: cid, source: 'searchsploit', severity: e.ai_severity})
                }
              }
            }
          }
          // From DDG LLM analysis: only items with applies=true and probability >= 70
          for (const a of ddgData?.analysis || []) {
            if (a.cve_id && !seen.has(a.cve_id) && a.applies === true && (a.probability ?? 100) >= 70) {
              seen.add(a.cve_id)
              knownCves.push({id: a.cve_id, source: 'web_search', severity: a.severity, probability: a.probability})
            }
          }
          // From cached research: AI-confirmed EDB exploits
          for (const entry of cacheData?.entries || []) {
            const r = entry.results as any
            if (entry.source === 'searchsploit' && r?.analyzed) {
              for (const exp of r?.exploits || []) {
                if (exp.applies === true && exp.codes) {
                  for (const code of (exp.codes || '').split(';')) {
                    const cid = code.trim()
                    if (cid.startsWith('CVE-') && !seen.has(cid)) {
                      seen.add(cid)
                      knownCves.push({id: cid, source: 'cached_analysis', severity: exp.ai_severity})
                    }
                  }
                }
              }
            }
            // From DDG cache: only LLM-confirmed (applies=true) results
            if (entry.source === 'ddg_search') {
              for (const a of r?.analysis || []) {
                if (a.cve_id && !seen.has(a.cve_id) && a.applies === true) {
                  seen.add(a.cve_id)
                  knownCves.push({id: a.cve_id, source: 'cached_web_search', severity: a.severity})
                }
              }
            }
          }
          // From live DDG data: only LLM-confirmed (applies=true)
          for (const a of ddgData?.analysis || []) {
            if (a.cve_id && !seen.has(a.cve_id) && a.applies === true) {
              seen.add(a.cve_id)
              knownCves.push({id: a.cve_id, source: 'web_search', severity: a.severity})
            }
          }
          if (knownCves.length === 0) return null
          // Sort: highest CVSS first, then by ID descending (newest first)
          knownCves.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0) || b.id.localeCompare(a.id))
          return (
            <div className="border border-red-500/30 rounded-md p-3 bg-red-500/5">
              <h4 className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-1">
                <AlertTriangle className="h-3.5 w-3.5" /> AI-Confirmed Vulnerabilities for {product} {version} ({knownCves.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {knownCves.map(c => (
                  <a key={c.id} href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 text-xs">
                    <span className="font-mono font-medium text-red-400">{c.id}</span>
                    {c.cvss && <span className={`font-bold ${c.cvss >= 9 ? 'text-red-300' : c.cvss >= 7 ? 'text-orange-400' : 'text-yellow-400'}`}>{c.cvss}</span>}
                    {c.probability != null && <span className={`text-[9px] font-bold px-1 rounded ${c.probability >= 90 ? 'bg-red-500/20 text-red-400' : c.probability >= 70 ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{c.probability}%</span>}
                    <ExternalLink className="h-2.5 w-2.5 text-muted-foreground" />
                  </a>
                ))}
              </div>
              {knownCves.some(c => c.summary) && (
                <details className="mt-2 text-[10px]">
                  <summary className="text-muted-foreground cursor-pointer hover:text-foreground">Details</summary>
                  <div className="mt-1 space-y-0.5">
                    {knownCves.filter(c => c.summary).map(c => (
                      <div key={c.id} className="text-muted-foreground">
                        <span className="font-mono text-red-400">{c.id}</span>: {c.summary?.slice(0, 120)}
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          )
        })()}

        {/* Quick open in browser */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-foreground/50">Open in browser:</span>
          {ddgLinks.map(l => (
            <a key={l.label} href={l.url} target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1 px-2 py-0.5 text-xs rounded border border-border text-foreground/70 hover:text-foreground hover:bg-muted/30">
              <ExternalLink className="h-2.5 w-2.5" />{l.label}
            </a>
          ))}
          {(() => {
            try {
              const vdi = ddgData?.version_date_info || (cachedDdg?.results as any)?.version_date_info
              if (vdi?.release_url) return (
                <a href={vdi.release_url} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 px-2 py-0.5 text-xs rounded border border-green-500/40 text-green-400 hover:bg-green-500/10 font-medium">
                  <ExternalLink className="h-2.5 w-2.5" />Vendor Release Notes
                </a>
              )
              return null
            } catch { return null }
          })()}
          <button onClick={() => {
            setShowLog(!showLog)
            if (!llmDebug) {
              fetch(`/api/software/llm-debug?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version || '')}`)
                .then(r => r.json()).then(setLlmDebug).catch(() => {})
            }
          }} className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded border ${showLog ? 'border-purple-500/50 bg-purple-500/10 text-purple-400' : 'border-border text-foreground/50 hover:text-foreground/80 hover:bg-muted/30'}`}>
            Log
          </button>
        </div>

        {/* ── Log: URLs scraped + LLM prompt/response ── */}
        {showLog && (
          <div className="border border-purple-500/20 rounded-md p-3 bg-purple-500/5 space-y-3 text-xs">
            <h4 className="text-sm font-semibold text-purple-400">Search Log</h4>

            {/* URLs scraped */}
            <div>
              <h5 className="text-xs font-medium text-foreground/70 mb-1">Vendor Pages Scraped</h5>
              <div className="space-y-0.5 max-h-32 overflow-auto">
                {(() => {
                  try {
                    const vs = ddgData?.vendor_sources || (cachedDdg?.results as any)?.vendor_sources
                    return (vs?.urls || []).map((u: string, i: number) => (
                      <a key={i} href={u} target="_blank" rel="noopener noreferrer"
                        className="block text-blue-400 hover:underline truncate">{u}</a>
                    ))
                  } catch { return <span className="text-foreground/40">No data</span> }
                })()}
                {(!ddgData?.vendor_sources?.urls?.length && !(cachedDdg?.results as any)?.vendor_sources?.urls?.length) && (
                  <span className="text-foreground/40">No vendor pages scraped yet</span>
                )}
              </div>
            </div>

            {/* Web search results */}
            <div>
              <h5 className="text-xs font-medium text-foreground/70 mb-1">DDG Web Search Results ({ddgData?.raw_results?.length || (cachedDdg?.results as any)?.raw_results?.length || 0})</h5>
              <div className="space-y-0.5 max-h-32 overflow-auto">
                {(ddgData?.raw_results || (cachedDdg?.results as any)?.raw_results || []).map((r: any, i: number) => (
                  <a key={i} href={r.url} target="_blank" rel="noopener noreferrer"
                    className="block text-blue-400 hover:underline truncate">{r.title || r.url}</a>
                ))}
              </div>
            </div>

            {/* LLM prompt + response */}
            <div>
              <h5 className="text-xs font-medium text-foreground/70 mb-1">LLM Analysis Log</h5>
              {llmDebug?.checks?.length > 0 ? (
                <div className="space-y-2">
                  {llmDebug.checks.map((c: any, i: number) => (
                    <details key={i} className="border border-border/30 rounded p-2">
                      <summary className="text-xs cursor-pointer text-foreground/60 hover:text-foreground">
                        {new Date(c.created_at).toLocaleString()} — {c.model} — {c.tokens} tokens — {c.latency_ms}ms
                        {c.is_error && <span className="text-red-400 ml-1">ERROR</span>}
                      </summary>
                      <div className="mt-2 space-y-2">
                        <div>
                          <span className="text-[10px] text-foreground/40 block mb-0.5">Prompt:</span>
                          <pre className="bg-black/30 rounded p-2 text-[10px] text-foreground/70 whitespace-pre-wrap max-h-48 overflow-auto">{c.prompt}</pre>
                        </div>
                        <div>
                          <span className="text-[10px] text-foreground/40 block mb-0.5">Response:</span>
                          <pre className="bg-black/30 rounded p-2 text-[10px] text-green-400/80 whitespace-pre-wrap max-h-48 overflow-auto">{c.response}</pre>
                        </div>
                        {c.error && <p className="text-red-400 text-[10px]">Error: {c.error}</p>}
                      </div>
                    </details>
                  ))}
                </div>
              ) : llmDebug ? (
                <span className="text-foreground/40">No LLM analysis runs found for this product</span>
              ) : (
                <span className="text-foreground/40 animate-pulse">Loading...</span>
              )}
            </div>
          </div>
        )}

        {/* ── TAB: Exploits & Nuclei ── */}
        {modalTab === 'exploits' && (<>
        {/* ── Section 1: ExploitDB / SearchSploit ── */}
        <div className="border border-border rounded-md p-3 space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold">
              SearchSploit / ExploitDB
              {edbData && <span className="ml-2 text-foreground/60 font-normal text-xs">
                ({edbData.count} results{edbWide ? ' — all versions' : version ? ` for ${version}` : ''})
                {edbData.analyzed && <span className="text-purple-400 ml-1">AI analyzed</span>}
                {edbData.used_cache && <span className="text-green-400 ml-1">from cache</span>}
                {(edbData.cached_cves?.length ?? 0) > 0 && <span className="text-blue-400 ml-1">{edbData.cached_cves.length} cached CVEs</span>}
                {(edbData.inventory_flagged ?? 0) > 0 && <span className="text-orange-400 ml-1">{edbData.inventory_flagged} hosts flagged</span>}
              </span>}
            </h4>
            <div className="flex items-center gap-2">
              {edbWide && edbData?.used_cache && (
                <button onClick={() => { /* force re-query without cache by changing key */ setEdbWide(false); setTimeout(() => setEdbWide(true), 50) }}
                  className="text-[10px] text-purple-400 hover:underline">Force AI Re-analyze</button>
              )}
              {edbWide && (
                <button onClick={() => setEdbWide(false)}
                  className="text-[10px] text-primary hover:underline">Back to exact version</button>
              )}
            </div>
          </div>

          {edbLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-2">
              <div className="h-3.5 w-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              {edbAnalyze ? 'Searching ExploitDB + AI version analysis...' : 'Searching ExploitDB...'}
            </div>
          ) : edbNoVersionResults && version ? (
            <div className="flex items-center gap-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/30">
              <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
              <span className="text-xs text-yellow-300">No ExploitDB results for {product} {version}</span>
              <button onClick={() => setEdbWide(true)}
                className="ml-auto px-2.5 py-1 text-xs rounded border border-purple-500/50 text-purple-400 hover:bg-purple-500/10 font-medium whitespace-nowrap">
                Widen + AI Analyze all {product} versions
              </button>
            </div>
          ) : edbData?.exploits?.length ? (
            <div className="space-y-1.5 max-h-72 overflow-auto">
              {/* Sort: applies=true first, then applies=null, then applies=false */}
              {[...edbData.exploits].sort((a, b) => {
                if (a.applies === b.applies) return 0
                if (a.applies === true) return -1
                if (b.applies === true) return 1
                if (a.applies === false) return 1
                if (b.applies === false) return -1
                return 0
              }).map(e => {
                const appliesColor = e.applies === true ? 'border-red-500/40 bg-red-500/5'
                  : e.applies === false ? 'border-border/30 opacity-60'
                  : 'border-border/40'
                return (
                  <div key={e.id} className={`flex items-start gap-3 p-2.5 rounded border hover:bg-muted/20 text-sm ${appliesColor}`}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {e.applies === true && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">APPLIES</span>}
                        {e.applies === false && <span className="px-1.5 py-0.5 rounded text-xs bg-zinc-500/20 text-zinc-400 border border-zinc-500/30">N/A</span>}
                        {e.ai_severity && <span className={`text-xs font-semibold ${
                          e.ai_severity === 'critical' ? 'text-red-400' : e.ai_severity === 'high' ? 'text-orange-400' : e.ai_severity === 'medium' ? 'text-yellow-400' : 'text-foreground/60'
                        }`}>{e.ai_severity}</span>}
                        <a href={e.edb_url} target="_blank" rel="noopener noreferrer" className="font-semibold text-foreground hover:underline">
                          EDB-{e.id}: {e.title}
                        </a>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-foreground/60">
                        <span>{e.type}</span>
                        <span>{e.platform}</span>
                        {e.date && <span>{e.date}</span>}
                        {e.applies === false ? (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-green-500/20 text-green-400 border border-green-500/40">Non-applicable</span>
                        ) : e.applies === true ? (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">VULNERABLE</span>
                        ) : e.verified ? (
                          <span className="text-foreground/50 font-medium">EDB Verified</span>
                        ) : null}
                      </div>
                      {e.ai_reason && <p className="mt-1 text-xs text-foreground/60 italic">{e.ai_reason}</p>}
                    </div>
                    <a href={e.edb_url} target="_blank" rel="noopener noreferrer"
                      className="shrink-0 px-2.5 py-1 rounded text-xs font-medium border border-orange-500/40 text-orange-400 hover:bg-orange-500/10">View</a>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No exploits found in local ExploitDB.</p>
          )}

          {/* Show cached CVEs if any */}
          {edbData?.cached_cves && edbData.cached_cves.length > 0 && (
            <div className="mt-2 border-t border-border/30 pt-2">
              <h5 className="text-xs font-semibold text-green-400 mb-1">Cached CVE Matches ({edbData.cached_cves.length})</h5>
              <div className="space-y-1 max-h-40 overflow-auto">
                {edbData.cached_cves.map(c => (
                  <div key={c.cve_id} className="text-sm flex items-center gap-2">
                    <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noopener noreferrer"
                      className="font-mono font-semibold text-primary hover:underline">{c.cve_id}</a>
                    {c.cvss && <span className={`font-bold ${c.cvss >= 9 ? 'text-red-400' : c.cvss >= 7 ? 'text-orange-400' : 'text-yellow-400'}`}>CVSS:{c.cvss}</span>}
                    <span className="text-foreground/60 truncate">{c.summary?.slice(0, 80)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Probable Vendor Matches (accept/decline) ── */}
        <VendorProbableMatches product={product} version={version} ddgData={ddgData} cachedDdg={cachedDdg} />

        <ReleaseDateEditor product={product} version={version} ddgData={ddgData} cachedDdg={cachedDdg} />

        </>)}

        {/* ── TAB: AI Research ── */}
        {modalTab === 'research' && (<>
        {/* ── Section 2: Web Search (DDG + AI) ── */}
        <div className="border border-border rounded-md p-3 space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-medium">
              Web Search + AI Analysis
              {ddgData && <span className="ml-1 text-muted-foreground">({ddgData.analysis?.length || 0} relevant, {ddgData.count} total)</span>}
              {ddgData && cachedDdg && !ddgLoading && (
                <span className="ml-1 text-[10px] text-green-400">
                  cached {new Date(cachedDdg.updated_at).toLocaleDateString()}
                </span>
              )}
            </h4>
            <div className="flex items-center gap-2">
              {ddgData && (
                <button onClick={() => runWebSearch()}
                  className="px-2 py-0.5 text-[10px] rounded border border-purple-500/40 text-purple-400 hover:bg-purple-500/10">
                  <Search className="inline h-2.5 w-2.5 mr-0.5" />Fresh Search
                </button>
              )}
              {!ddgData && !ddgLoading && (
                <button onClick={() => runWebSearch()}
                  className="px-2.5 py-1 text-xs rounded border border-purple-500/50 text-purple-400 hover:bg-purple-500/10 font-medium">
                  <Search className="inline h-3 w-3 mr-1" />Search DuckDuckGo
                </button>
              )}
            </div>
          </div>

          {ddgLoading ? (
            <div className="flex items-center gap-2 text-sm text-foreground/70 py-3">
              <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              <span>Searching...</span>
              {ddgStage && <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-medium">{ddgStage}</span>}
              <span className="text-xs text-foreground/40">Runs in background — safe to close this window</span>
            </div>
          ) : ddgError ? (
            <div className="text-xs text-red-400">{ddgError}
              <button onClick={() => runWebSearch()} className="ml-2 text-primary hover:underline">Retry</button>
            </div>
          ) : ddgData ? (
            <>
              {ddgData.analysis?.length > 0 && (
                <div className="space-y-1.5">
                  {[...ddgData.analysis].sort((a, b) => (b.probability ?? 0) - (a.probability ?? 0)).map((r, i) => {
                    const prob = r.probability ?? null
                    const probColor = prob != null ? (prob >= 80 ? 'bg-red-500/20 text-red-400 border-red-500/30' : prob >= 50 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' : prob >= 20 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' : 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30') : ''
                    const appliesBadge = r.applies === true ? 'bg-red-500/20 text-red-400 border-red-500/30' : r.applies === 'likely' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' : r.applies === false ? 'bg-zinc-500/15 text-zinc-500 border-zinc-500/20' : ''
                    const rowBorder = r.applies === true && prob != null && prob >= 70 ? 'border-red-500/40 bg-red-500/5' : r.applies === false ? 'border-border/30 opacity-60' : 'border-border/50'
                    return (
                    <div key={i} className={`flex items-start gap-3 p-3 rounded border hover:bg-muted/20 text-sm ${rowBorder}`}>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          {prob != null && <span className={`px-2 py-0.5 rounded text-xs font-bold border ${probColor}`}>{prob}%</span>}
                          {r.applies != null && <span className={`px-1.5 py-0.5 rounded text-xs font-semibold border ${appliesBadge}`}>{r.applies === true ? 'CONFIRMED' : r.applies === 'likely' ? 'LIKELY' : 'N/A'}</span>}
                          {r.cve_id && <a href={`https://nvd.nist.gov/vuln/detail/${r.cve_id}`} target="_blank" rel="noopener noreferrer" className="text-red-400 font-mono font-semibold hover:underline text-sm">{r.cve_id}</a>}
                          {r.severity && <span className={`font-semibold text-sm ${sevColor(r.severity)}`}>{r.severity}</span>}
                        </div>
                        <div className="mt-1 text-foreground/80">{r.title || r.reason}</div>
                        {r.reason && r.title && <p className="mt-1 text-xs text-foreground/60 italic">{r.reason}</p>}
                        {(r as any).age_note && <p className="mt-0.5 text-xs text-yellow-400 italic">{(r as any).age_note}</p>}
                      </div>
                      {r.url && <a href={r.url} target="_blank" rel="noopener noreferrer"
                        className="shrink-0 px-2 py-0.5 rounded text-[10px] border border-blue-500/40 text-blue-400 hover:bg-blue-500/10">Open</a>}
                    </div>
                    )
                  })}
                </div>
              )}
              {ddgData.raw_results?.length > 0 && (
                <details className="text-xs">
                  <summary className="text-muted-foreground cursor-pointer hover:text-foreground">
                    All search results ({ddgData.raw_results.length})
                  </summary>
                  <div className="space-y-1 mt-2">
                    {ddgData.raw_results.map((r, i) => (
                      <div key={i} className="p-1.5 rounded hover:bg-muted/20">
                        <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{r.title}</a>
                        {r.snippet && <p className="text-muted-foreground mt-0.5 line-clamp-2">{r.snippet}</p>}
                      </div>
                    ))}
                  </div>
                </details>
              )}
              {!ddgData.analysis?.length && !ddgData.raw_results?.length && (
                <p className="text-xs text-muted-foreground">No web results found.</p>
              )}
            </>
          ) : (
            <p className="text-xs text-muted-foreground">
              {cacheData?.has_cache ? 'No cached web search for this product+version. ' : ''}
              Click "Search DuckDuckGo" to find CVEs and exploits via web search with AI filtering.
            </p>
          )}
        </div>

        </>)}

        {/* ── TAB: Exploits (continued — Nuclei in same tab) ── */}
        {modalTab === 'exploits' && ddgData && (<>
        {/* ── Section 3: Nuclei Templates ── */}
        {ddgData?.nuclei_templates && ddgData.nuclei_templates.length > 0 && (
          <div className="border border-cyan-500/30 rounded-md p-3 bg-cyan-500/5 space-y-2">
            <h4 className="text-sm font-semibold text-cyan-400 flex items-center gap-1">
              Nuclei Templates ({ddgData.nuclei_templates.length})
              {(ddgData.nuclei_recs_created ?? 0) > 0 && <span className="text-xs font-normal text-green-400 ml-2">{ddgData.nuclei_recs_created} scan recommendation(s) queued</span>}
            </h4>
            <p className="text-xs text-foreground/60">Matching templates found in nuclei. Run these against the target for active vulnerability verification.</p>
            <div className="space-y-1 max-h-48 overflow-auto">
              {ddgData.nuclei_templates.map((t: any, i: number) => (
                <div key={i} className="flex items-center gap-2 p-2 rounded border border-cyan-500/20 text-sm">
                  <span className={`px-1.5 py-0.5 rounded text-xs font-bold border ${
                    t.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                    t.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                    t.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                    'bg-zinc-500/20 text-zinc-400 border-zinc-500/30'
                  }`}>{t.severity}</span>
                  <span className="font-medium text-foreground">{t.id}</span>
                  {t.tags && <span className="text-xs text-foreground/50">[{t.tags}]</span>}
                  <span className="text-xs text-foreground/60 truncate flex-1">{t.description?.slice(0, 80)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        </>)}

        {/* ── TAB: VulnX CVEs ── */}
        {modalTab === 'vulnx' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold">VulnX Vulnerability Findings</h4>
              {vulnxData && (
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{vulnxData.total_findings} findings</span>
                  <span>{vulnxData.unique_cves} unique CVEs</span>
                </div>
              )}
            </div>

            {vulnxLoading ? (
              <div className="flex items-center gap-2 py-8 text-muted-foreground">
                <div className="h-4 w-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <span className="text-sm">Loading VulnX findings...</span>
              </div>
            ) : !vulnxData || vulnxData.total_findings === 0 ? (
              <div className="py-8 text-center text-muted-foreground">
                <p className="text-sm">No VulnX vulnerabilities found for {product} {version || 'any version'}</p>
                <p className="text-xs mt-1">VulnX scans may not have been run for this product</p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* CVE Summary */}
                <div className="border border-border rounded-md p-3">
                  <h5 className="text-xs font-medium mb-2 text-red-400">CVE Summary</h5>
                  <div className="grid gap-2">
                    {vulnxData.cve_summary.map(cve => (
                      <div key={cve.cve_id} className="flex items-center justify-between p-2 bg-muted/30 rounded text-xs">
                        <div className="flex items-center gap-2">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-red-400 hover:underline"
                          >
                            {cve.cve_id}
                          </a>
                          <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                            cve.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                            cve.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            cve.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {cve.severity}
                          </span>
                          {cve.cvss_score && (
                            <span className="text-muted-foreground">CVSS: {cve.cvss_score}</span>
                          )}
                        </div>
                        <span className="text-muted-foreground">
                          {cve.affected_assets.length} asset{cve.affected_assets.length !== 1 ? 's' : ''}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Detailed Findings */}
                <div className="border border-border rounded-md">
                  <div className="p-3 border-b border-border bg-muted/20">
                    <h5 className="text-xs font-medium">Detailed Findings ({vulnxData.total_findings})</h5>
                  </div>
                  <div className="max-h-64 overflow-auto">
                    {vulnxData.findings.map((finding, i) => (
                      <div key={finding.id} className={`p-3 border-b border-border/30 text-xs ${i % 2 === 1 ? 'bg-muted/10' : ''}`}>
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-foreground mb-1">{finding.title}</div>
                            <div className="text-muted-foreground mb-2 text-[10px] space-x-3">
                              <span>Asset: {finding.hostname || finding.ip}</span>
                              <span>Port: {finding.port}</span>
                              <span>Product: {finding.product} {finding.version}</span>
                            </div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {finding.cve.map(cveId => (
                                <a
                                  key={cveId}
                                  href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="font-mono text-[9px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded hover:underline"
                                >
                                  {cveId}
                                </a>
                              ))}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                              finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                              finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                              finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {finding.severity}
                            </span>
                            <span className="text-[10px] text-muted-foreground">
                              {new Date(finding.created_at).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── TAB: GitHub PoCs ── */}
        {modalTab === 'github' && (
          <GithubPocTab
            product={product}
            version={version || ''}
            cves={(ddgData?.confirmed_cves || []).map((c: any) => c.cve_id)}
            initialPocs={githubPocs}
            onResults={setGithubPocs}
            loading={githubLoading}
            setLoading={setGithubLoading}
          />
        )}

        {/* ── TAB: Debug Log ── */}
        {modalTab === 'log' && showLog && llmDebug && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold">LLM Debug Log</h4>
            <pre className="text-[10px] bg-zinc-900/80 p-3 rounded overflow-auto max-h-64">
              {JSON.stringify(llmDebug, null, 2)}
            </pre>
          </div>
        )}
        {modalTab === 'log' && !showLog && (
          <div className="text-xs text-muted-foreground">
            <p>Run an AI Research first — the debug log appears after the LLM analysis completes.</p>
            <button onClick={() => { setShowLog(true); setModalTab('research') }}
              className="mt-2 px-3 py-1.5 text-xs rounded border border-border hover:bg-muted">
              Go to AI Research tab
            </button>
          </div>
        )}

      </div>
    </div>
  )
}


function BulkCheckButton({ uniqueCount, selectedProducts }: { uniqueCount: number; selectedProducts: Set<string> }) {
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<any>(null)
  const [showOptions, setShowOptions] = useState(false)
  const [useProxy, setUseProxy] = useState(true)
  const [proxyUrl, setProxyUrl] = useState('socks5://node-manager:10125')
  const [rateLimit, setRateLimit] = useState(3)
  const [skipCached, setSkipCached] = useState(true)
  const [deepSearch, setDeepSearch] = useState(false)

  const checkCount = selectedProducts.size || uniqueCount

  const startBulkCheck = async () => {
    setRunning(true)
    setShowOptions(false)
    setProgress(null)
    const selected = selectedProducts.size > 0
      ? [...selectedProducts].map(k => { const [p, v] = k.split('|'); return { product: p, version: v } })
      : []
    try {
      const resp = await fetch('/api/software/bulk-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          skip_cached: skipCached,
          proxy: useProxy ? proxyUrl : '',
          rate_limit: rateLimit,
          selected,
          deep_search: deepSearch,
        }),
      })
      const result = await resp.json()
      if (!result.ok) {
        setProgress({ error: result.error || 'Failed to start' })
        setRunning(false)
        return
      }
      setProgress({ total: result.total, completed: 0, skipped: result.skipped || 0, flagged: 0, current: 'Starting...' })
    } catch (e: any) {
      setProgress({ error: e.message || 'Failed to start' })
      setRunning(false)
      return
    }
    // Start polling
    const poll = setInterval(async () => {
      try {
        const resp = await fetch('/api/software/bulk-check/status')
        const data = await resp.json()
        setProgress(data.progress || data)
        if (!data.running) {
          clearInterval(poll)
          setRunning(false)
          const p = data.progress || {}
          const msg = `AI Check complete: ${p.completed || 0}/${p.total || 0} products checked${p.flagged ? `, ${p.flagged} flagged` : ''}`
          useUIStore.getState().addNotification(msg, p.flagged > 0 ? 'error' : 'success')
        }
      } catch {}
    }, 2000)
  }

  if (running || (progress && !progress.error)) {
    return (
      <div className="flex items-center gap-2 text-xs">
        {running ? (
          <div className="h-3 w-3 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
        ) : (
          <Search className="h-3 w-3 text-green-400" />
        )}
        <span className="text-purple-400 font-medium">
          {progress?.completed ?? 0}/{progress?.total ?? '?'}
        </span>
        {running && progress?.current && <span className="text-foreground/60 truncate max-w-48">{progress.current}</span>}
        {running && progress?.stage && <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[9px] border border-blue-500/30">{progress.stage}</span>}
        {running && progress?.deep_search && <span className="px-1 py-0.5 rounded bg-cyan-500/10 text-cyan-400 text-[9px] border border-cyan-500/30">Deep</span>}
        {!running && <span className="text-green-400">Done</span>}
        {(progress?.flagged ?? 0) > 0 && <span className="text-red-400">{progress.flagged} flagged</span>}
        {running && (
          <button onClick={async () => { await fetch('/api/software/bulk-check/cancel', { method: 'POST' }); setRunning(false) }}
            className="px-1.5 py-0.5 rounded text-[9px] border border-red-500/40 text-red-400 hover:bg-red-500/10">Stop</button>
        )}
      </div>
    )
  }

  if (progress?.error) {
    return <span className="text-xs text-red-400">{progress.error}</span>
  }

  return (
    <div className="relative">
      <button onClick={() => setShowOptions(!showOptions)}
        className="flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-purple-500/40 text-purple-400 hover:bg-purple-500/10"
      ><Search className="h-3 w-3" /> AI Check {selectedProducts.size > 0 ? `Selected (${selectedProducts.size})` : `All (${uniqueCount})`}</button>
      {showOptions && (
        <div className="absolute right-0 top-full mt-1 bg-card border border-border rounded-md p-3 shadow-lg z-20 w-72 space-y-2">
          <h4 className="text-xs font-medium">Bulk AI Check Settings</h4>
          {selectedProducts.size > 0 && (
            <p className="text-[10px] text-purple-400">{selectedProducts.size} products selected (use checkboxes to change)</p>
          )}
          <label className="flex items-center gap-2 text-[10px]">
            <input type="checkbox" checked={skipCached} onChange={e => setSkipCached(e.target.checked)} className="rounded" />
            Skip already-checked products
          </label>
          <label className="flex items-center gap-2 text-[10px]">
            <input type="checkbox" checked={useProxy} onChange={e => setUseProxy(e.target.checked)} className="rounded" />
            Route DDG through proxy
          </label>
          {useProxy && (
            <input value={proxyUrl} onChange={e => setProxyUrl(e.target.value)}
              className="w-full bg-muted rounded px-2 py-1 text-[10px] border border-border font-mono"
              placeholder="socks5://node-manager:10125" />
          )}
          <label className="flex items-center gap-2 text-[10px]">
            Rate limit (seconds):
            <input type="number" min={1} max={30} value={rateLimit} onChange={e => setRateLimit(Number(e.target.value))}
              className="w-14 bg-muted rounded px-1.5 py-0.5 text-xs border border-border" />
          </label>
          <label className="flex items-center gap-2 text-[10px]">
            <input type="checkbox" checked={deepSearch} onChange={e => setDeepSearch(e.target.checked)} className="rounded" />
            <span className="text-cyan-400 font-medium">Deep search</span> — verify each CVE against vendor advisories (slower, more thorough)
          </label>
          <div className="flex justify-end gap-1 pt-1">
            <button onClick={() => setShowOptions(false)}
              className="px-2 py-0.5 text-[10px] rounded border border-border text-muted-foreground">Cancel</button>
            <button onClick={startBulkCheck}
              className="px-2 py-0.5 text-[10px] rounded border border-purple-500 text-purple-400 hover:bg-purple-500/10 font-medium">
              Start ({checkCount})
            </button>
          </div>
        </div>
      )}
    </div>
  )
}


function ReleaseDateEditor({ product, version, ddgData, cachedDdg }: {
  product: string; version: string; ddgData: any; cachedDdg: any
}) {
  const vdi = ddgData?.version_date_info || (cachedDdg?.results as any)?.version_date_info
  const [editing, setEditing] = useState(false)
  const [dateInput, setDateInput] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [isManual, setIsManual] = useState(false)
  const [loaded, setLoaded] = useState(false)

  // Load saved release date from API on mount (independent of DDG search)
  useEffect(() => {
    fetch(`/api/software/release-date?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}`)
      .then(r => r.json())
      .then(d => {
        if (d.release_date) {
          setDateInput(d.release_date)
          setUrlInput(d.release_url || '')
          setIsManual(d.manual || false)
        }
        setLoaded(true)
      }).catch(() => setLoaded(true))
  }, [product, version])

  // Also update from DDG data if available and no manual override
  useEffect(() => {
    if (vdi?.release_date && !isManual) {
      setDateInput(prev => prev || vdi.release_date)
      setUrlInput(prev => prev || vdi.release_url || '')
    }
    if (vdi?.manual_override) setIsManual(true)
  }, [vdi?.release_date, vdi?.release_url])

  const handleSave = async () => {
    setSaving(true)
    try {
      await fetch('/api/software/release-date', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product, version, release_date: dateInput, release_url: urlInput }),
      })
      setSaved(true)
      setEditing(false)
      setTimeout(() => setSaved(false), 3000)
    } catch {}
    setSaving(false)
  }

  const handleClear = async () => {
    setSaving(true)
    try {
      await fetch('/api/software/release-date', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product, version, release_date: '' }),
      })
      setDateInput('')
      setUrlInput('')
      setEditing(false)
    } catch {}
    setSaving(false)
  }

  const hasDate = !!(vdi?.release_date || dateInput)

  return (
    <div className={`flex items-center gap-3 px-3 py-2 rounded border text-xs ${hasDate ? 'border-blue-500/30 bg-blue-500/5' : 'border-border/50 bg-muted/10'}`}>
      <span className="font-semibold text-blue-400 shrink-0">Release Date:</span>
      {editing ? (
        <div className="flex items-center gap-2 flex-1 flex-wrap">
          <input className="px-2 py-1 bg-card border border-border rounded text-sm w-48"
            placeholder="e.g. August 30, 2023" value={dateInput}
            onChange={e => setDateInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleSave() }} />
          <input className="px-2 py-1 bg-card border border-border rounded text-xs w-64"
            placeholder="Source URL (optional)" value={urlInput}
            onChange={e => setUrlInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleSave() }} />
          <button onClick={handleSave} disabled={saving || !dateInput}
            className="px-2 py-1 rounded text-xs font-medium border border-green-500/50 text-green-400 hover:bg-green-500/10 disabled:opacity-50">
            {saving ? 'Saving...' : 'Save'}
          </button>
          <button onClick={() => setEditing(false)}
            className="px-2 py-1 rounded text-xs border border-border text-muted-foreground hover:bg-muted/30">Cancel</button>
          {isManual && (
            <button onClick={handleClear}
              className="px-2 py-1 rounded text-xs border border-red-500/40 text-red-400 hover:bg-red-500/10">Clear Override</button>
          )}
        </div>
      ) : (
        <div className="flex items-center gap-2 flex-1">
          {hasDate ? (
            <>
              <span className="font-semibold text-foreground">{vdi?.release_date || dateInput}</span>
              {isManual && <span className="px-1 py-0.5 rounded text-[9px] font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">MANUAL</span>}
              {vdi?.release_url && <a href={vdi.release_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-xs">(source)</a>}
            </>
          ) : (
            <span className="text-muted-foreground italic">Not set — click Edit to enter the release date</span>
          )}
          <button onClick={() => setEditing(true)}
            className="ml-auto px-2 py-0.5 rounded text-xs border border-border text-muted-foreground hover:bg-muted/30 hover:text-foreground shrink-0">
            Edit
          </button>
          {saved && <span className="text-green-400 text-xs">Saved!</span>}
        </div>
      )}
    </div>
  )
}


function VendorProbableMatches({ product, version, ddgData, cachedDdg }: {
  product: string; version: string; ddgData: any; cachedDdg: any
}) {
  const [decisions, setDecisions] = useState<Record<string, 'accepted' | 'declined'>>({})
  const [loadedDecisions, setLoadedDecisions] = useState(false)
  const [deepResults, setDeepResults] = useState<Record<string, any>>({})
  const [deepSearching, setDeepSearching] = useState<Set<string>>(new Set())
  const [bulkDeepRunning, setBulkDeepRunning] = useState(false)
  const [cveSort, setCveSort] = useState<'date' | 'probability' | 'cve' | 'score'>('date')

  useEffect(() => {
    if (loadedDecisions) return
    fetch(`/api/software/cve-decisions?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}`)
      .then(r => r.json())
      .then(d => {
        const map: Record<string, 'declined'> = {}
        for (const cid of d.declined || []) map[cid] = 'declined'
        setDecisions(prev => ({ ...map, ...prev }))
        setLoadedDecisions(true)
      }).catch(() => setLoadedDecisions(true))
  }, [product, version])

  // Load persisted deep search results
  useEffect(() => {
    fetch(`/api/software/deep-search-cache?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}`)
      .then(r => r.json())
      .then(d => {
        if (d.results && Object.keys(d.results).length > 0) {
          setDeepResults(prev => ({ ...d.results, ...prev }))
        }
      }).catch(() => {})
  }, [product, version])

  const vendorCves: Array<{ cve_id: string; summary: string; source: string; probability?: number }> = []
  const seen = new Set<string>()
  const probMap: Record<string, number> = {}
  for (const a of [...(ddgData?.analysis || []), ...((cachedDdg?.results as any)?.analysis || [])]) {
    if (a.cve_id && a.probability != null) probMap[a.cve_id] = a.probability
  }
  for (const c of [...(ddgData?.nvd_cves || []), ...((cachedDdg?.results as any)?.nvd_cves || [])]) {
    if (c.cve_id && !seen.has(c.cve_id) && (c.source === 'vendor_advisory' || c.source === 'vendor_bulletin' || c.source === 'tenable')) {
      seen.add(c.cve_id)
      vendorCves.push({ ...c, probability: deepResults[c.cve_id]?.probability ?? probMap[c.cve_id] })
    }
  }

  const pending = vendorCves.filter(c => !decisions[c.cve_id])
  const accepted = vendorCves.filter(c => decisions[c.cve_id] === 'accepted')
  const declined = vendorCves.filter(c => decisions[c.cve_id] === 'declined')

  // Get release year for splitting CVEs
  const vdi = ddgData?.version_date_info || (cachedDdg?.results as any)?.version_date_info
  const releaseYear = vdi?.release_year || vdi?.estimated_release_year || 0

  // Helper: extract year from CVE ID
  const cveYear = (cve_id: string): number => {
    const m = cve_id.match(/CVE-(\d{4})/)
    return m ? parseInt(m[1]) : 0
  }

  // Sort function for CVE list
  // Parse CVE-YYYY-NNNNN into [year, seq] for numeric sorting
  const cveParts = (id: string): [number, number] => {
    const m = id.match(/CVE-(\d{4})-(\d+)/)
    return m ? [parseInt(m[1]), parseInt(m[2])] : [0, 0]
  }

  const sortCves = (list: typeof vendorCves) => {
    return [...list].sort((a, b) => {
      if (cveSort === 'probability') return ((deepResults[b.cve_id]?.probability ?? b.probability ?? 0) - (deepResults[a.cve_id]?.probability ?? a.probability ?? 0))
      if (cveSort === 'cve') {
        const [ay, an] = cveParts(a.cve_id)
        const [by, bn] = cveParts(b.cve_id)
        return by !== ay ? by - ay : bn - an // year desc, then seq desc
      }
      // default: date (CVE year descending, then seq descending)
      const [ay, an] = cveParts(a.cve_id)
      const [by, bn] = cveParts(b.cve_id)
      return by !== ay ? by - ay : bn - an
    })
  }

  // Split pending into after-release and before-release
  const pendingAfter = releaseYear ? pending.filter(c => cveYear(c.cve_id) >= releaseYear) : pending
  const pendingBefore = releaseYear ? pending.filter(c => cveYear(c.cve_id) < releaseYear) : []

  if (vendorCves.length === 0) return null

  const handleDecision = async (cve_id: string, action: 'accept' | 'decline') => {
    setDecisions(prev => ({ ...prev, [cve_id]: action === 'accept' ? 'accepted' : 'declined' }))
    try {
      await fetch('/api/software/cve-decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product, version, cve_id, action }),
      })
      if (action === 'accept') {
        useUIStore.getState().addNotification(`${cve_id} accepted and flagged`, 'success')
      }
    } catch {}
  }

  const runDeepSearch = async (cveIds: string[]) => {
    setDeepSearching(prev => new Set([...prev, ...cveIds]))
    try {
      const resp = await fetch('/api/software/cve-deep-search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product, version, cve_ids: cveIds }),
      })
      const data = await resp.json()
      const newResults: Record<string, any> = {}
      for (const r of data.results || []) {
        newResults[r.cve_id] = r
        // Auto-accept if high probability
        if (r.applies === true && (r.probability ?? 0) >= 80) {
          handleDecision(r.cve_id, 'accept')
        }
      }
      setDeepResults(prev => ({ ...prev, ...newResults }))
    } catch {}
    setDeepSearching(prev => {
      const next = new Set(prev)
      cveIds.forEach(id => next.delete(id))
      return next
    })
  }

  const runBulkDeep = async () => {
    setBulkDeepRunning(true)
    // Only deep search CVEs after the release date by default
    const candidates = (releaseYear ? pendingAfter : pending).filter(c => !deepResults[c.cve_id])
    const ids = candidates.map(c => c.cve_id)
    for (let i = 0; i < ids.length; i += 5) {
      await runDeepSearch(ids.slice(i, i + 5))
    }
    setBulkDeepRunning(false)
  }

  return (
    <div className="border border-yellow-500/30 rounded-md p-3 bg-yellow-500/5 space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold text-yellow-400 flex items-center gap-1">
          <AlertTriangle className="h-3.5 w-3.5" />
          Vendor Bulletin — Probable Matches ({pending.length} pending{accepted.length ? `, ${accepted.length} accepted` : ''}{declined.length ? `, ${declined.length} declined` : ''})
        </h4>
        {pending.length > 0 && (
          <button onClick={runBulkDeep} disabled={bulkDeepRunning}
            className="px-2 py-0.5 rounded text-[10px] font-medium border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10 disabled:opacity-50">
            {bulkDeepRunning ? 'Deep Searching...' : `Deep Search All (${(releaseYear ? pendingAfter : pending).filter(c => !deepResults[c.cve_id]).length}${releaseYear ? ' post-release' : ''})`}
          </button>
        )}
      </div>
      <div className="flex items-center gap-1 text-[10px]">
        <span className="text-foreground/40">Sort:</span>
        {(['date', 'probability', 'cve'] as const).map(s => (
          <button key={s} onClick={() => setCveSort(s)}
            className={`px-1.5 py-0.5 rounded border text-[10px] ${cveSort === s ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400' : 'border-border text-foreground/40 hover:text-foreground/70'}`}>
            {s === 'date' ? 'Date' : s === 'probability' ? 'Prob %' : 'CVE #'}
          </button>
        ))}
      </div>
      <p className="text-[10px] text-muted-foreground">
        Found on vendor security pages. Use Deep Search to verify each CVE against vendor advisories.
        {(() => {
          try {
            const vs = ddgData?.vendor_sources || (cachedDdg?.results as any)?.vendor_sources
            if (!vs?.urls?.length) return null
            return (
              <span className="ml-1">
                Sources: {vs.urls.slice(0, 3).map((u: string, i: number) => {
                  let host = u
                  try { host = new URL(u).hostname } catch {}
                  return <a key={i} href={u} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">{host}{i < Math.min(vs.urls.length, 3) - 1 ? ', ' : ''}</a>
                })}
              </span>
            )
          } catch { return null }
        })()}
      </p>
      {(() => {
        const renderCveRow = (c: any) => {
          const dr = deepResults[c.cve_id]
          const isSearching = deepSearching.has(c.cve_id)
          const prob = dr?.probability ?? c.probability
          const yr = cveYear(c.cve_id)
          return (
            <div key={c.cve_id} className={`p-2 rounded border text-sm ${dr?.applies === true ? 'border-red-500/40 bg-red-500/5' : dr?.applies === false ? 'border-zinc-500/30 opacity-70' : 'border-yellow-500/20 bg-yellow-500/5'}`}>
              <div className="flex items-center gap-2">
                {((c as any).published || yr > 0) && <span className="text-[10px] text-foreground/40 font-mono shrink-0" title={(c as any).published || ''}>{(c as any).published || yr}</span>}
                {prob != null && <span className={`px-1.5 py-0.5 rounded text-xs font-bold border shrink-0 ${prob >= 70 ? 'bg-red-500/20 text-red-400 border-red-500/30' : prob >= 40 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' : 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30'}`}>{prob}%</span>}
                {dr?.applies != null && <span className={`px-1 py-0.5 rounded text-xs font-semibold border ${dr.applies === true ? 'bg-red-500/20 text-red-400 border-red-500/30' : dr.applies === 'likely' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' : 'bg-green-500/20 text-green-400 border-green-500/30'}`}>{dr.applies === true ? 'CONFIRMED' : dr.applies === 'likely' ? 'LIKELY' : 'NOT AFFECTED'}</span>}
                <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-yellow-400 hover:underline shrink-0 font-semibold">{c.cve_id}</a>
                <span className="text-foreground/60 truncate flex-1">{c.summary?.slice(0, 60) || 'Vendor bulletin'}</span>
                {!dr && !isSearching && (
                  <button onClick={() => runDeepSearch([c.cve_id])}
                    className="px-2 py-0.5 rounded text-[9px] font-medium border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 shrink-0">Deep Search</button>
                )}
                {isSearching && <span className="text-[9px] text-cyan-400 animate-pulse shrink-0">Searching...</span>}
                <button onClick={() => handleDecision(c.cve_id, 'accept')}
                  className="px-2 py-0.5 rounded text-[9px] font-bold border border-red-500/40 text-red-400 hover:bg-red-500/10 shrink-0">Accept</button>
                <button onClick={() => handleDecision(c.cve_id, 'decline')}
                  className="px-2 py-0.5 rounded text-[9px] border border-zinc-500/40 text-zinc-400 hover:bg-zinc-500/10 shrink-0">Decline</button>
              </div>
              {dr?.reason && <p className="mt-1 text-xs text-foreground/60 italic">{dr.reason}</p>}
              {dr?.pages?.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {dr.pages.filter((p: any) => p.has_cve).map((p: any, i: number) => (
                    <a key={i} href={p.url} target="_blank" rel="noopener noreferrer"
                      className="text-[9px] text-blue-400 hover:underline">{p.title?.slice(0, 40) || 'Advisory'}</a>
                  ))}
                </div>
              )}
            </div>
          )
        }
        return (
          <>
            {/* CVEs published AFTER the release date — more likely to apply */}
            {pendingAfter.length > 0 && (
              <div className="border border-red-500/20 rounded-md p-2 space-y-1.5">
                <h5 className="text-xs font-semibold text-red-400">
                  CVEs After Release Date {releaseYear ? `(${releaseYear}+)` : ''} — {pendingAfter.length} probable
                </h5>
                <div className="space-y-1.5 max-h-48 overflow-auto">
                  {sortCves(pendingAfter).map(renderCveRow)}
                </div>
              </div>
            )}
            {/* CVEs published BEFORE the release date — unlikely */}
            {pendingBefore.length > 0 && (
              <details className="border border-zinc-500/20 rounded-md p-2">
                <summary className="text-xs font-semibold text-zinc-400 cursor-pointer">
                  CVEs Before Release Date {releaseYear ? `(pre-${releaseYear})` : ''} — {pendingBefore.length} unlikely
                  <span className="ml-1 text-[10px] font-normal text-zinc-500">likely already patched in this version</span>
                </summary>
                <div className="space-y-1.5 mt-2 max-h-48 overflow-auto opacity-70">
                  {sortCves(pendingBefore).map(renderCveRow)}
                </div>
              </details>
            )}
          </>
        )
      })()}
      {accepted.length > 0 && (
        <details className="text-[10px]">
          <summary className="text-green-400 cursor-pointer">{accepted.length} accepted</summary>
          <div className="mt-1 flex flex-wrap gap-1">
            {accepted.map(c => (
              <span key={c.cve_id} className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/30 font-mono">{c.cve_id}</span>
            ))}
          </div>
        </details>
      )}
      {declined.length > 0 && (
        <details className="text-[10px]">
          <summary className="text-zinc-500 cursor-pointer">{declined.length} declined</summary>
          <div className="mt-1 flex flex-wrap gap-1">
            {declined.map(c => (
              <span key={c.cve_id} className="px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-500 border border-zinc-500/20 font-mono line-through">{c.cve_id}</span>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}


// ── GitHub PoC search with custom terms + DDG option ──────────────
function GithubPocTab({ product, version, cves, initialPocs, onResults, loading, setLoading }: {
  product: string; version: string; cves: string[]
  initialPocs: any[]; onResults: (r: any[]) => void
  loading: boolean; setLoading: (l: boolean) => void
}) {
  const [extraTerms, setExtraTerms] = useState('')
  const [searchMode, setSearchMode] = useState<'github' | 'ddg'>('github')
  const [ddgResults, setDdgResults] = useState<any[]>([])

  const buildQuery = () => {
    const parts = [product]
    if (version) parts.push(version)
    if (extraTerms.trim()) parts.push(extraTerms.trim())
    // Add first 3 CVEs
    cves.slice(0, 3).forEach(c => parts.push(c))
    return parts.join(' ')
  }

  const searchGithub = async () => {
    setLoading(true)
    try {
      const cveParam = cves.join(',')
      const extra = extraTerms.trim() ? `&extra=${encodeURIComponent(extraTerms.trim())}` : ''
      const r = await apiFetch<{ repos: any[] }>(
        `/software/github-search?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}&cve=${encodeURIComponent(cveParam)}&force=true${extra}`
      )
      onResults(r.repos || [])
    } catch { /* ignore */ }
    setLoading(false)
  }

  const searchDdg = async () => {
    setLoading(true)
    setDdgResults([])
    try {
      const query = `site:github.com ${buildQuery()} exploit OR poc OR vulnerability`
      const r = await apiFetch<{ results: any[] }>(
        `/software/ddg-search-raw?query=${encodeURIComponent(query)}&max_results=20`
      )
      const results = (r.results || []).filter((d: any) =>
        (d.url || d.href || '').includes('github.com')
      )
      setDdgResults(results)
    } catch { /* ignore */ }
    setLoading(false)
  }

  const handleSearch = () => {
    if (searchMode === 'ddg') searchDdg()
    else searchGithub()
  }

  const pocs = initialPocs

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <h4 className="text-sm font-semibold">GitHub PoC / Exploit Repos</h4>
        <select
          value={searchMode}
          onChange={e => setSearchMode(e.target.value as 'github' | 'ddg')}
          className="h-7 px-2 text-xs rounded border border-border bg-background"
        >
          <option value="github">GitHub API</option>
          <option value="ddg">DuckDuckGo</option>
        </select>
        <button onClick={handleSearch} disabled={loading}
          className="px-2 py-1 text-xs rounded border border-border hover:bg-muted disabled:opacity-50">
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {/* Custom search terms */}
      <div className="flex items-center gap-2">
        <input
          value={extraTerms}
          onChange={e => setExtraTerms(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          placeholder="Add search terms (e.g., RCE, bypass, auth)"
          className="flex-1 h-7 px-2 text-xs rounded border border-border bg-background font-mono"
        />
        <span className="text-[10px] text-muted-foreground shrink-0">
          Base: "{product} {version}" + {cves.length} CVE{cves.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* GitHub API results */}
      {pocs.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[10px] text-muted-foreground font-medium">GitHub API ({pocs.length} repos)</div>
          {pocs.map((r: any, i: number) => (
            <a key={i} href={r.url} target="_blank" rel="noopener noreferrer"
              className="block p-2.5 rounded border border-border hover:border-primary/50 transition-colors">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-primary font-medium">{r.repo}</span>
                <span className="flex items-center gap-0.5 text-xs text-yellow-400">
                  <span>&#9733;</span> {r.stars}
                </span>
                {r.language && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-muted border border-border">{r.language}</span>
                )}
                <span className="text-[10px] text-muted-foreground ml-auto">
                  {r.updated ? new Date(r.updated).toLocaleDateString() : ''}
                </span>
              </div>
              {r.description && (
                <p className="text-xs text-muted-foreground mt-1 truncate">{r.description}</p>
              )}
              {r.topics?.length > 0 && (
                <div className="flex gap-1 mt-1">
                  {r.topics.slice(0, 5).map((t: string) => (
                    <span key={t} className="px-1 py-0 rounded text-[9px] bg-primary/10 text-primary">{t}</span>
                  ))}
                </div>
              )}
            </a>
          ))}
        </div>
      )}

      {/* DDG results */}
      {ddgResults.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[10px] text-muted-foreground font-medium">DuckDuckGo ({ddgResults.length} results)</div>
          {ddgResults.map((r: any, i: number) => (
            <a key={i} href={r.url || r.href} target="_blank" rel="noopener noreferrer"
              className="block p-2.5 rounded border border-border hover:border-orange-500/50 transition-colors">
              <div className="text-sm text-orange-400 font-medium truncate">{r.title}</div>
              <div className="text-[10px] text-muted-foreground font-mono truncate">{r.url || r.href}</div>
              {r.snippet && <p className="text-xs text-muted-foreground mt-1">{r.snippet}</p>}
            </a>
          ))}
        </div>
      )}

      {pocs.length === 0 && ddgResults.length === 0 && !loading && (
        <p className="text-xs text-muted-foreground">
          No results yet. Add custom terms and click Search. Use DDG mode to search broader web results filtered to github.com.
        </p>
      )}
    </div>
  )
}
