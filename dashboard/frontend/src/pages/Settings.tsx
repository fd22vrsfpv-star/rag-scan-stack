import { useState, useRef, useMemo, useEffect } from 'react'
import PageHelp from '@/components/PageHelp'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useScopeNames, useScope, useAddToScope, useRemoveFromScope } from '@/api/scope'
import { useBurpStatus } from '@/api/burp'
import { useZapAddons, useInstallAddon, useUninstallAddon } from '@/api/zapAddons'
import type { ZapAddon } from '@/api/zapAddons'
import { useApiKeys, useUpsertApiKey, useDeleteApiKey } from '@/api/apiKeys'
import { useMcpServers, useAddMcpServer, useToggleMcpServer, useDeleteMcpServer, useUpdateMcpoConfig } from '@/api/mcpServers'
import type { McpServer } from '@/api/mcpServers'
import { useExploitWatcherSettings, useUpdateExploitWatcherSettings, type ExploitWatcherSettings } from '@/api/exploitWatcher'
import { useNodeAnalysis, useNodeCleanup, type CleanupOptions, type NodeAnalysis } from '@/api/maintenance'
import { useScanDefaultsStore, type ScanProfile } from '@/stores/scanDefaults'
import { useUIStore, ALPHA_FEATURES } from '@/stores/ui'
import { apiFetch } from '@/api/client'
import { cn } from '@/lib/utils'
import { BUILD_VERSION, SCAN_CATEGORIES, SCAN_FIELDS, TARGET_FIELD_KEYS, TOOL_CLI_OPTIONS } from '@/lib/constants'
import { Trash2, Download, X, Search, RefreshCw, Eye, EyeOff, Plus, Upload, Loader2, CheckCircle2, XCircle, Database, Wifi, Server, ArrowRightLeft, BarChart3, RotateCcw, ChevronDown, ChevronRight, Zap, Power, PowerOff, Shield } from 'lucide-react'

type SettingsTab = 'general' | 'scope' | 'zap-addons' | 'api-keys' | 'database' | 'tool-options' | 'mcp-servers' | 'vendor-pages' | 'scan-timeouts' | 'llm-tuning' | 'exploit-watcher'

export default function Settings() {
  const [tab, setTab] = useState<SettingsTab>('general')
  const [searchQuery, setSearchQuery] = useState('')

  return (
    <div className="space-y-4">
      <PageHelp id="settings" title="How to use Settings">
        <p><strong>General</strong>: proxy config (Burp/ZAP), Docker host IP. <strong>Scope</strong>: define in-scope targets. <strong>Tool Options</strong>: override scan defaults, configure wordlist paths, check files on nodes. <strong>API Keys</strong>: manage keys for cloud providers and external services. <strong>MCP Servers</strong>: add third-party MCP tools.</p>
      </PageHelp>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Settings</h2>

        {/* Search Box */}
        <div className="relative">
          <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search settings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-sm rounded border border-border bg-background focus:outline-none focus:ring-1 focus:ring-primary w-64"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>

      <div className="flex gap-1 border-b border-border">
        {([
          ['general', 'General'],
          ['scope', 'Scope'],
          ['zap-addons', 'ZAP Add-ons'],
          ['api-keys', 'API Keys'],
          ['database', 'Database'],
          ['tool-options', 'Tool Options'],
          ['mcp-servers', 'MCP Servers'],
          ['vendor-pages', 'Vendor Pages'],
          ['scan-timeouts', 'Scan Timeouts'],
          ['llm-tuning', 'LLM Tuning'],
          ['exploit-watcher', 'Exploit Watcher'],
        ] as [SettingsTab, string][]).map(([t, label]) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              'px-3 py-1.5 text-sm border-b-2 transition-colors',
              tab === t ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Show search results if searching, otherwise show selected tab */}
      {searchQuery ? (
        <SearchResults query={searchQuery} onNavigate={(targetTab) => {
          setTab(targetTab)
          setSearchQuery('')
        }} />
      ) : (
        <>
          {tab === 'general' && <GeneralTab />}
          {tab === 'scope' && <ScopeTab />}
          {tab === 'zap-addons' && <ZapAddonsTab />}
          {tab === 'api-keys' && <ApiKeysTab />}
          {tab === 'database' && <DatabaseTab />}
          {tab === 'tool-options' && <ToolOptionsTab />}
          {tab === 'mcp-servers' && <McpServersTab />}
          {tab === 'vendor-pages' && <VendorPagesTab />}
          {tab === 'scan-timeouts' && <ScanTimeoutsTab />}
          {tab === 'llm-tuning' && <LLMTuningTab />}
          {tab === 'exploit-watcher' && <ExploitWatcherTab />}
        </>
      )}
    </div>
  )
}


function VendorPagesTab() {
  const [pages, setPages] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [keyword, setKeyword] = useState('')
  const [url, setUrl] = useState('')
  const [template, setTemplate] = useState('')
  const [note, setNote] = useState('')

  const load = () => {
    setLoading(true)
    fetch('/api/software/vendor-pages').then(r => r.json())
      .then(d => { setPages(d.pages || []); setLoading(false) })
      .catch(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const save = async () => {
    if (!keyword.trim() || !url.trim()) return
    await fetch('/api/software/vendor-pages', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product_keyword: keyword, url, search_template: template, note }),
    })
    setKeyword(''); setUrl(''); setTemplate(''); setNote('')
    load()
  }

  const remove = async (kw: string) => {
    await fetch(`/api/software/vendor-pages/${encodeURIComponent(kw)}`, { method: 'DELETE' })
    load()
  }

  return (
    <div className="space-y-4">
      <div className="p-3 bg-muted/20 rounded border border-border">
        <h3 className="text-sm font-semibold mb-2">Vendor Security / Vulnerability Pages</h3>
        <p className="text-xs text-foreground/60 mb-3">
          Configure vendor-specific search pages that get included in AI Exploit Check searches.
          The <strong>keyword</strong> matches against the product name (e.g. "atlassian" matches "Atlassian Confluence").
          The <strong>template</strong> supports <code>{'{product}'}</code>, <code>{'{version}'}</code>, and <code>{'{url}'}</code> placeholders for building dynamic search URLs.
        </p>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="text-xs text-foreground/60 block mb-1">Product Keyword</label>
            <input value={keyword} onChange={e => setKeyword(e.target.value)} placeholder="e.g. atlassian"
              className="w-full px-2 py-1.5 bg-card border border-border rounded text-sm" />
          </div>
          <div>
            <label className="text-xs text-foreground/60 block mb-1">URL (base or direct)</label>
            <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://vendor.com/security/advisories"
              className="w-full px-2 py-1.5 bg-card border border-border rounded text-sm" />
          </div>
          <div className="col-span-2">
            <label className="text-xs text-foreground/60 block mb-1">Search Template (optional)</label>
            <input value={template} onChange={e => setTemplate(e.target.value)} placeholder="{url}?q={product}+{version} or leave blank to use URL as-is"
              className="w-full px-2 py-1.5 bg-card border border-border rounded text-sm font-mono" />
          </div>
          <div className="col-span-2">
            <label className="text-xs text-foreground/60 block mb-1">Note (optional)</label>
            <input value={note} onChange={e => setNote(e.target.value)} placeholder="What this page covers"
              className="w-full px-2 py-1.5 bg-card border border-border rounded text-sm" />
          </div>
        </div>
        <div className="mt-2 flex justify-end">
          <button onClick={save} disabled={!keyword.trim() || !url.trim()}
            className="px-3 py-1 rounded text-sm font-medium border border-purple-500/50 text-purple-400 hover:bg-purple-500/10 disabled:opacity-50">
            Save Vendor Page
          </button>
        </div>
      </div>

      <div className="space-y-1">
        <h4 className="text-xs font-semibold text-foreground/60">Configured Pages ({pages.length})</h4>
        {loading && <p className="text-xs text-foreground/40">Loading...</p>}
        {!loading && pages.length === 0 && <p className="text-xs text-foreground/40 italic">No vendor pages configured. Add one above.</p>}
        {pages.map(p => (
          <div key={p.product_keyword} className="flex items-start gap-2 p-2 rounded border border-border/50 text-sm">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono font-medium text-purple-400">{p.product_keyword}</span>
                <a href={p.url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-xs truncate">{p.url}</a>
              </div>
              {p.search_template && <div className="text-xs font-mono text-foreground/60 mt-1">Template: {p.search_template}</div>}
              {p.note && <div className="text-xs text-foreground/50 mt-0.5">{p.note}</div>}
            </div>
            <button onClick={() => remove(p.product_keyword)}
              className="px-2 py-0.5 rounded text-xs border border-red-500/40 text-red-400 hover:bg-red-500/10">Delete</button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Wordlist options for Gobuster ───────────────────
const GOBUSTER_WORDLISTS = [
  { key: 'small',       label: 'DirBuster Small',    file: 'DirBuster-2.3-small.txt',           desc: 'Fast — ~87k entries',             category: 'Dir Discovery' },
  { key: 'medium',      label: 'DirBuster Medium',   file: 'DirBuster-2.3-medium.txt',          desc: 'Default — ~220k entries',          category: 'Dir Discovery' },
  { key: 'big',         label: 'DirBuster Big',      file: 'DirBuster-2.3-big.txt',             desc: 'Thorough — ~1.3M entries',         category: 'Dir Discovery' },
  { key: 'common',      label: 'Common Files',       file: 'common.txt',                        desc: 'Common web files/dirs',            category: 'General' },
  { key: 'quickhits',   label: 'Quick Hits',         file: 'quickhits.txt',                     desc: 'High-value targets (backups, configs)', category: 'General' },
  { key: 'raft-small',  label: 'RAFT Small',         file: 'raft-small-directories.txt',        desc: 'RAFT small dir list',              category: 'RAFT' },
  { key: 'raft-medium', label: 'RAFT Medium',        file: 'raft-medium-directories.txt',       desc: 'RAFT medium dir list',             category: 'RAFT' },
  { key: 'raft-large',  label: 'RAFT Large',         file: 'raft-large-directories.txt',        desc: 'RAFT large dir list',              category: 'RAFT' },
  { key: 'api',         label: 'API Endpoints',      file: 'common-api-endpoints.txt',          desc: 'REST/API endpoint discovery',      category: 'API' },
] as const

const ZAP_STRENGTH_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'INSANE'] as const

// ─── General Tab ─────────────────────────────────────
function GeneralTab() {
  const store = useScanDefaultsStore()
  const scopeNames = useScopeNames()

  const [targets, setTargets] = useState(store.defaultTargets)
  const [ports, setPorts] = useState(store.defaultPorts)
  const [rate, setRate] = useState(store.defaultRate)
  const [scope, setScope] = useState(store.defaultScope)
  const [gobusterWordlist, setGobusterWordlist] = useState(store.gobusterWordlist)
  const [gobusterExtensions, setGobusterExtensions] = useState(store.gobusterExtensions)
  const [zapAttackStrength, setZapAttackStrength] = useState(store.zapAttackStrength)
  const [zapSpiderEnabled, setZapSpiderEnabled] = useState(store.zapSpiderEnabled)
  const [exploitProxy, setExploitProxy] = useState(store.exploitProxy)
  const [exploitProxyEnabled, setExploitProxyEnabled] = useState(store.exploitProxyEnabled)
  const [chatSystemPrompt, setChatSystemPrompt] = useState(store.chatSystemPrompt)
  const [llmBackend, setLlmBackend] = useState(store.llmBackend)
  const [saved, setSaved] = useState(false)
  const [proxyTest, setProxyTest] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle')
  const [proxyTestMsg, setProxyTestMsg] = useState('')

  const handleSave = () => {
    store.setDefaults({
      defaultTargets: targets,
      defaultPorts: ports,
      defaultRate: rate,
      defaultScope: scope,
      gobusterWordlist,
      gobusterExtensions,
      zapAttackStrength,
      zapSpiderEnabled,
      exploitProxy,
      exploitProxyEnabled,
      chatSystemPrompt,
      llmBackend,
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  // Group wordlists by category
  const categories = Array.from(new Set(GOBUSTER_WORDLISTS.map(w => w.category)))

  // Sync local state when profile changes
  const handleProfileChange = (name: string) => {
    store.setActiveProfile(name)
    // Update local state from new profile
    const p = store.profiles[name]
    if (p) {
      setPorts(p.defaults.defaultPorts)
      setRate(p.defaults.defaultRate)
      setGobusterWordlist(p.defaults.gobusterWordlist)
      setGobusterExtensions(p.defaults.gobusterExtensions)
      setZapAttackStrength(p.defaults.zapAttackStrength)
      setZapSpiderEnabled(p.defaults.zapSpiderEnabled)
    }
  }

  return (
    <div className="space-y-6">
      {/* Scan Profile Selector */}
      <ProfileSelector onProfileChange={handleProfileChange} />

      {/* Scan Defaults */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Scan Defaults</h3>
        <div className="space-y-3 max-w-xl">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Default Scope</label>
            <select
              value={scope}
              onChange={e => setScope(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            >
              <option value="">None (manual targets)</option>
              {(scopeNames.data?.names ?? []).map(s => (
                <option key={s.name} value={s.name}>{s.name} ({s.target_count} targets)</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Default Targets / Scope URLs</label>
            <textarea
              placeholder={"192.168.1.0/24\nhttps://api.example.com\nhttps://app.example.com/v2"}
              value={targets}
              onChange={e => setTargets(e.target.value)}
              rows={5}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-y font-mono"
            />
            <p className="text-[10px] text-muted-foreground mt-0.5">
              One target per line — IPs, CIDRs, hostnames, or full URLs (for API testing)
            </p>
            {scope && <p className="text-[10px] text-muted-foreground mt-0.5">Overrides scope targets when set</p>}
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Default Ports</label>
            <input
              type="text"
              placeholder="1-1000"
              value={ports}
              onChange={e => setPorts(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Default Rate (pps)</label>
            <input
              type="number"
              placeholder="1000"
              value={rate}
              onChange={e => setRate(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
          </div>
        </div>
      </div>

      {/* Scan Concurrency */}
      <ScanConcurrencySetting />

      {/* Gobuster Configuration */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Gobuster Configuration</h3>
        <div className="space-y-3 max-w-md">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Wordlist</label>
            <select
              value={gobusterWordlist}
              onChange={e => setGobusterWordlist(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            >
              {categories.map(cat => (
                <optgroup key={cat} label={cat}>
                  {GOBUSTER_WORDLISTS.filter(w => w.category === cat).map(w => (
                    <option key={w.key} value={w.key}>
                      {w.label} — {w.desc}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <p className="text-[10px] text-muted-foreground mt-1">
              {GOBUSTER_WORDLISTS.find(w => w.key === gobusterWordlist)?.file ?? ''}
            </p>
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">File Extensions</label>
            <input
              type="text"
              placeholder="php,html,txt"
              value={gobusterExtensions}
              onChange={e => setGobusterExtensions(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
            <p className="text-[10px] text-muted-foreground mt-1">Comma-separated list of file extensions to discover</p>
          </div>
        </div>
      </div>

      {/* ZAP Configuration */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">ZAP Configuration</h3>
        <div className="space-y-3 max-w-md">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Attack Strength</label>
            <select
              value={zapAttackStrength}
              onChange={e => setZapAttackStrength(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            >
              {ZAP_STRENGTH_OPTIONS.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setZapSpiderEnabled(!zapSpiderEnabled)}
              className={cn(
                'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
                zapSpiderEnabled ? 'bg-primary' : 'bg-muted-foreground/30',
              )}
            >
              <span
                className={cn(
                  'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform',
                  zapSpiderEnabled ? 'translate-x-4' : 'translate-x-0',
                )}
              />
            </button>
            <label className="text-sm">Spider Enabled</label>
          </div>
        </div>
      </div>

      {/* Proxy Configuration */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Proxy Configuration</h3>
        <p className="text-[10px] text-muted-foreground mb-3">
          Route exploit payloads through an external proxy (Burp Suite, ZAP) for traffic inspection
        </p>
        <div className="space-y-3 max-w-md">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setExploitProxyEnabled(!exploitProxyEnabled)}
              className={cn(
                'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
                exploitProxyEnabled ? 'bg-primary' : 'bg-muted-foreground/30',
              )}
            >
              <span
                className={cn(
                  'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform',
                  exploitProxyEnabled ? 'translate-x-4' : 'translate-x-0',
                )}
              />
            </button>
            <label className="text-sm">Proxy Enabled</label>
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Proxy URL</label>
            <input
              type="text"
              placeholder="http://host.docker.internal:8080"
              value={exploitProxy}
              onChange={e => setExploitProxy(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setExploitProxy('http://host.docker.internal:8080')}
              className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted/50"
            >
              Burp (8080)
            </button>
            <button
              type="button"
              onClick={() => setExploitProxy('http://host.docker.internal:8090')}
              className="px-2 py-0.5 text-xs border border-border rounded hover:bg-muted/50"
            >
              ZAP (8090)
            </button>
            <span className="border-l border-border h-4" />
            <button
              type="button"
              disabled={!exploitProxy.trim() || proxyTest === 'testing'}
              onClick={async () => {
                setProxyTest('testing')
                setProxyTestMsg('')
                try {
                  const res = await apiFetch<{ ok: boolean; status_code?: number; elapsed_ms?: number; error?: string }>(
                    '/settings/test-proxy',
                    { method: 'POST', body: JSON.stringify({ proxy_url: exploitProxy.trim() }) },
                  )
                  if (res.ok) {
                    setProxyTest('ok')
                    setProxyTestMsg(`Connected (${res.status_code}, ${res.elapsed_ms}ms)`)
                  } else {
                    setProxyTest('fail')
                    setProxyTestMsg(res.error ?? 'Unknown error')
                  }
                } catch (e) {
                  setProxyTest('fail')
                  setProxyTestMsg((e as Error).message)
                }
                setTimeout(() => { setProxyTest('idle'); setProxyTestMsg('') }, 5000)
              }}
              className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded hover:bg-muted/50 disabled:opacity-50"
            >
              {proxyTest === 'testing' ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Test Proxy'}
            </button>
            {proxyTest === 'ok' && (
              <span className="flex items-center gap-1 text-xs text-green-500">
                <CheckCircle2 className="h-3 w-3" /> {proxyTestMsg}
              </span>
            )}
            {proxyTest === 'fail' && (
              <span className="flex items-center gap-1 text-xs text-red-400">
                <XCircle className="h-3 w-3" /> {proxyTestMsg}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Block Local Scans */}
      <div>
        <h3 className="text-sm font-semibold mb-1">Block Local Scans</h3>
        <p className="text-xs text-muted-foreground mb-2">
          When enabled, ALL active scans (nmap, nuclei, web scans, etc.) are <strong>blocked unless routed through a proxy/tunnel</strong>.
          Passive OSINT tools (subfinder, dnsx, crtsh) are exempt. Use this to prevent accidentally scanning targets
          from your local IP instead of through a provisioned attack node.
        </p>
        <BlockLocalScansToggle />
      </div>

      {/* Burp Suite API */}
      <BurpApiConfig />

      {/* AI Chat */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-1">AI Chat</h3>
        <p className="text-[10px] text-muted-foreground mb-3">
          System prompt prepended to every AI chat conversation. Instructs the model to prioritize dashboard tools and scan data.
        </p>
        <div className="space-y-3 max-w-xl">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">System Prompt</label>
            <textarea
              value={chatSystemPrompt}
              onChange={e => setChatSystemPrompt(e.target.value)}
              rows={4}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-y font-mono"
              placeholder="e.g. Focus on web application vulnerabilities. Always suggest OWASP references."
            />
            <p className="text-[10px] text-muted-foreground mt-1">
              This is prepended before the built-in pentest assistant prompt. Clear to remove the custom instructions.
            </p>
          </div>
        </div>
      </div>

      {/* LLM Backend */}
      <LlmBackendSection backend={llmBackend} onBackendChange={setLlmBackend} />

      {/* Node Cleanup Maintenance */}
      <NodeCleanupSection />

      {/* Save + System Info */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          className="px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
        >
          Save All Settings
        </button>
        {saved && <span className="text-xs text-green-500">Saved!</span>}
      </div>

      {/* Alpha Testing */}
      <AlphaTestingToggle />

      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">System Info</h3>
        <div className="space-y-1 text-sm">
          <p><span className="text-muted-foreground">Dashboard:</span> Pentest Dashboard {BUILD_VERSION}</p>
        </div>
      </div>
    </div>
  )
}

// ─── helpers ────────────────────────────────────────
// DB constraint: domain, ip, cidr, asn, url
function detectTargetType(value: string): string {
  if (/^https?:\/\//i.test(value)) return 'url'
  if (/\/\d{1,3}$/.test(value)) return 'cidr'
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(value)) return 'ip'
  if (/^AS\d+$/i.test(value)) return 'asn'
  return 'domain'
}

function parseTargetLines(text: string) {
  return text
    .split(/[\r\n]+/)
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith('#'))
}

// ─── Scope Tab (moved to Engagements page) ──────────
function ScopeTab() {
  return (
    <div className="bg-card border border-border rounded-lg p-6 text-center space-y-3">
      <p className="text-sm text-muted-foreground">
        Scope management has moved to the <strong>Engagements</strong> page.
      </p>
      <p className="text-xs text-muted-foreground">
        Scopes are now managed under each engagement. Go to Engagements, select an engagement, and click the <strong>Scope</strong> tab to manage targets.
      </p>
      <a href="/engagements" className="inline-flex items-center gap-2 px-4 py-2 text-sm rounded bg-primary text-primary-foreground hover:bg-primary/90">
        Go to Engagements
      </a>
    </div>
  )
}

/* eslint-disable @typescript-eslint/no-unused-vars */
function ScopeTab_Legacy() {
  const scopeNames = useScopeNames()
  const [selectedScope, setSelectedScope] = useState('')
  const scopeData = useScope(selectedScope)
  const addToScope = useAddToScope()
  const removeFromScope = useRemoveFromScope()

  // Create-scope form state
  const [showCreate, setShowCreate] = useState(false)
  const [newScopeName, setNewScopeName] = useState('')
  const [newTargetsText, setNewTargetsText] = useState('')
  const [createStatus, setCreateStatus] = useState<'idle' | 'saving' | 'done' | 'error'>('idle')
  const [createMsg, setCreateMsg] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const names = scopeNames.data?.names ?? []
  const targets = scopeData.data?.targets ?? []

  const handleRemoveTarget = (targetValue: string) => {
    if (!selectedScope) return
    removeFromScope.mutate({ name: selectedScope, targets: [targetValue] })
  }

  const handleDeleteScope = () => {
    if (!selectedScope || targets.length === 0) return
    const allTargets = targets.map(t => t.target)
    removeFromScope.mutate({ name: selectedScope, targets: allTargets }, {
      onSuccess: () => setSelectedScope(''),
    })
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const text = reader.result as string
      setNewTargetsText(prev => (prev ? prev + '\n' + text : text))
    }
    reader.readAsText(file)
    // reset so the same file can be re-selected
    e.target.value = ''
  }

  const parsedTargets = useMemo(() => parseTargetLines(newTargetsText), [newTargetsText])

  const handleCreateScope = () => {
    const name = newScopeName.trim()
    if (!name) { setCreateMsg('Scope name is required'); setCreateStatus('error'); return }
    if (parsedTargets.length === 0) { setCreateMsg('Add at least one target'); setCreateStatus('error'); return }

    const targetsPayload = parsedTargets.map(t => ({
      target: t,
      target_type: detectTargetType(t),
      source: 'manual',
    }))

    setCreateStatus('saving')
    addToScope.mutate({ name, targets: targetsPayload }, {
      onSuccess: (data) => {
        setCreateStatus('done')
        setCreateMsg(`Added ${data.added} target${data.added !== 1 ? 's' : ''} to "${name}"`)
        setNewScopeName('')
        setNewTargetsText('')
        setSelectedScope(name)
        setTimeout(() => { setCreateStatus('idle'); setCreateMsg(''); setShowCreate(false) }, 2000)
      },
      onError: (err) => {
        setCreateStatus('error')
        setCreateMsg((err as Error).message)
      },
    })
  }

  return (
    <div className="space-y-4">
      {/* Create / Add panel */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold">Create / Add to Scope</h3>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className={cn(
              'flex items-center gap-1 px-2 py-1 text-xs rounded-md border transition-colors',
              showCreate
                ? 'border-primary text-primary bg-primary/10'
                : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/50',
            )}
          >
            <Plus className="h-3 w-3" />
            {showCreate ? 'Hide' : 'New Scope'}
          </button>
        </div>

        {showCreate && (
          <div className="space-y-3">
            <div className="flex gap-3 items-end">
              <div className="flex-1 max-w-xs">
                <label className="block text-xs text-muted-foreground mb-1">Scope Name</label>
                <input
                  type="text"
                  placeholder="e.g. acme-external"
                  value={newScopeName}
                  onChange={e => setNewScopeName(e.target.value)}
                  className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                />
              </div>
              <div className="flex-1 max-w-xs">
                <label className="block text-xs text-muted-foreground mb-1">Or add to existing scope</label>
                <select
                  value={newScopeName}
                  onChange={e => setNewScopeName(e.target.value)}
                  className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
                >
                  <option value="">— type a new name above —</option>
                  {names.map(s => (
                    <option key={s.name} value={s.name}>{s.name} ({s.target_count})</option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs text-muted-foreground">Targets (one per line)</label>
                <div className="flex items-center gap-2">
                  {parsedTargets.length > 0 && (
                    <span className="text-[10px] text-muted-foreground">
                      {parsedTargets.length} target{parsedTargets.length !== 1 ? 's' : ''} parsed
                    </span>
                  )}
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,.csv,.list"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border rounded-md hover:bg-muted/50 text-muted-foreground hover:text-foreground"
                  >
                    <Upload className="h-3 w-3" />
                    Import .txt
                  </button>
                </div>
              </div>
              <textarea
                placeholder={"192.168.1.0/24\n10.0.0.1\nhttps://api.example.com\napp.example.com\n# lines starting with # are ignored"}
                value={newTargetsText}
                onChange={e => setNewTargetsText(e.target.value)}
                rows={8}
                className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary resize-y font-mono"
              />
              <p className="text-[10px] text-muted-foreground mt-0.5">
                IPs, CIDRs, hostnames, host:port, or full URLs. Lines starting with # are ignored.
              </p>
            </div>

            {/* Preview parsed targets */}
            {parsedTargets.length > 0 && (
              <div className="overflow-auto max-h-[150px] border border-border/50 rounded-md">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="px-2 py-1">Target</th>
                      <th className="px-2 py-1 w-24">Detected Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsedTargets.slice(0, 50).map((t, i) => (
                      <tr key={i} className="border-b border-border/30">
                        <td className="px-2 py-0.5 font-mono">{t}</td>
                        <td className="px-2 py-0.5 text-muted-foreground">{detectTargetType(t)}</td>
                      </tr>
                    ))}
                    {parsedTargets.length > 50 && (
                      <tr><td colSpan={2} className="px-2 py-1 text-muted-foreground">...and {parsedTargets.length - 50} more</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            <div className="flex items-center gap-3">
              <button
                onClick={handleCreateScope}
                disabled={createStatus === 'saving'}
                className="px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
              >
                {createStatus === 'saving' ? 'Saving...' : 'Create / Add Targets'}
              </button>
              {createMsg && (
                <span className={cn('text-xs', createStatus === 'error' ? 'text-red-400' : 'text-green-500')}>
                  {createMsg}
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Scope browser */}
      <div className="flex gap-4 min-h-[400px]">
        {/* Left sidebar — scope list */}
        <div className="w-56 shrink-0 bg-card border border-border rounded-lg p-3">
          <h3 className="text-sm font-semibold mb-2">Scopes</h3>
          {scopeNames.isLoading ? (
            <p className="text-xs text-muted-foreground">Loading...</p>
          ) : names.length === 0 ? (
            <p className="text-xs text-muted-foreground">No scopes yet. Create one above.</p>
          ) : (
            <div className="space-y-1">
              {names.map(s => (
                <button
                  key={s.name}
                  onClick={() => setSelectedScope(s.name)}
                  className={cn(
                    'w-full text-left px-2 py-1.5 rounded-md text-sm transition-colors',
                    selectedScope === s.name
                      ? 'bg-primary/10 text-primary border border-primary/30'
                      : 'hover:bg-muted/50 text-foreground',
                  )}
                >
                  <div className="font-medium truncate">{s.name}</div>
                  <div className="text-[10px] text-muted-foreground">{s.target_count} targets</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Right — scope detail */}
        <div className="flex-1 bg-card border border-border rounded-lg p-4">
          {!selectedScope ? (
            <p className="text-sm text-muted-foreground">Select a scope to view its targets</p>
          ) : scopeData.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading targets...</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold">{selectedScope}</h3>
                  <p className="text-xs text-muted-foreground">
                    {targets.length} target{targets.length !== 1 ? 's' : ''}
                  </p>
                </div>
                <button
                  onClick={handleDeleteScope}
                  disabled={removeFromScope.isPending}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-red-400 border border-red-400/30 rounded-md hover:bg-red-400/10 disabled:opacity-50"
                >
                  <Trash2 className="h-3 w-3" />
                  Delete Scope
                </button>
              </div>

              {targets.length === 0 ? (
                <p className="text-xs text-muted-foreground">No targets in this scope</p>
              ) : (
                <div className="overflow-auto max-h-[500px]">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-left text-xs text-muted-foreground">
                        <th className="pb-2 pr-3">Target</th>
                        <th className="pb-2 pr-3">Type</th>
                        <th className="pb-2 pr-3">Source</th>
                        <th className="pb-2 pr-3">Added</th>
                        <th className="pb-2 w-16"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {targets.map(t => (
                        <tr key={t.id} className="border-b border-border/50 hover:bg-muted/30">
                          <td className="py-1.5 pr-3 font-mono text-xs">{t.target}</td>
                          <td className="py-1.5 pr-3 text-xs text-muted-foreground">{t.target_type}</td>
                          <td className="py-1.5 pr-3 text-xs text-muted-foreground">{t.source}</td>
                          <td className="py-1.5 pr-3 text-xs text-muted-foreground">
                            {t.added_at ? new Date(t.added_at).toLocaleDateString() : '-'}
                          </td>
                          <td className="py-1.5">
                            <button
                              onClick={() => handleRemoveTarget(t.target)}
                              disabled={removeFromScope.isPending}
                              className="text-red-400 hover:text-red-300 disabled:opacity-50"
                              title="Remove target"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── ZAP Add-ons Tab ────────────────────────────────
function ZapAddonsTab() {
  const { data, isLoading, error, refetch, isFetching } = useZapAddons()
  const installAddon = useInstallAddon()
  const uninstallAddon = useUninstallAddon()
  const [search, setSearch] = useState('')
  const [pendingId, setPendingId] = useState<string | null>(null)

  const filteredAvailable = useMemo(() => {
    if (!data?.available) return []
    if (!search.trim()) return data.available
    const q = search.toLowerCase()
    return data.available.filter(
      (a: ZapAddon) =>
        a.id?.toLowerCase().includes(q) ||
        a.name?.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q),
    )
  }, [data?.available, search])

  const handleInstall = async (id: string) => {
    setPendingId(id)
    try {
      await installAddon.mutateAsync(id)
    } finally {
      setPendingId(null)
    }
  }

  const handleUninstall = async (id: string) => {
    setPendingId(id)
    try {
      await uninstallAddon.mutateAsync(id)
    } finally {
      setPendingId(null)
    }
  }

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading ZAP add-ons...</p>
  }
  if (error) {
    return (
      <div className="space-y-2">
        <p className="text-sm text-red-400">Failed to load ZAP add-ons: {(error as Error).message}</p>
        <button onClick={() => refetch()} className="text-xs text-primary hover:underline">Retry</button>
      </div>
    )
  }

  const installed = data?.installed ?? []

  return (
    <div className="space-y-6">
      {/* Header with refresh */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {data?.installed_count ?? 0} installed, {data?.available_count ?? 0} available in marketplace
        </p>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1 px-2 py-1 text-xs border border-border rounded-md hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw className={cn('h-3 w-3', isFetching && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Installed Add-ons */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-3">Installed Add-ons</h3>
        {installed.length === 0 ? (
          <p className="text-xs text-muted-foreground">No add-ons installed</p>
        ) : (
          <div className="overflow-auto max-h-[350px]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="pb-2 pr-3">Name</th>
                  <th className="pb-2 pr-3">ID</th>
                  <th className="pb-2 pr-3">Version</th>
                  <th className="pb-2 w-24"></th>
                </tr>
              </thead>
              <tbody>
                {installed.map((a: ZapAddon) => (
                  <tr key={a.id} className="border-b border-border/50 hover:bg-muted/30">
                    <td className="py-1.5 pr-3 text-xs">{a.name || a.id}</td>
                    <td className="py-1.5 pr-3 text-xs font-mono text-muted-foreground">{a.id}</td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground">{a.version ?? '-'}</td>
                    <td className="py-1.5">
                      <button
                        onClick={() => handleUninstall(a.id)}
                        disabled={pendingId === a.id}
                        className="flex items-center gap-1 px-2 py-0.5 text-xs text-red-400 border border-red-400/30 rounded hover:bg-red-400/10 disabled:opacity-50"
                      >
                        <X className="h-3 w-3" />
                        {pendingId === a.id ? 'Removing...' : 'Uninstall'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Available Add-ons (Marketplace) */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold">Available Add-ons</h3>
          <div className="relative w-64">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="text"
              placeholder="Filter add-ons..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-7 pr-3 py-1 text-xs bg-muted rounded-md border border-border outline-none focus:border-primary"
            />
          </div>
        </div>
        {filteredAvailable.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            {search ? 'No matching add-ons' : 'No additional add-ons available'}
          </p>
        ) : (
          <div className="overflow-auto max-h-[400px]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="pb-2 pr-3">Name</th>
                  <th className="pb-2 pr-3">ID</th>
                  <th className="pb-2 pr-3 hidden md:table-cell">Description</th>
                  <th className="pb-2 pr-3">Version</th>
                  <th className="pb-2 w-24"></th>
                </tr>
              </thead>
              <tbody>
                {filteredAvailable.map((a: ZapAddon) => (
                  <tr key={a.id} className="border-b border-border/50 hover:bg-muted/30">
                    <td className="py-1.5 pr-3 text-xs">{a.name || a.id}</td>
                    <td className="py-1.5 pr-3 text-xs font-mono text-muted-foreground">{a.id}</td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground hidden md:table-cell max-w-[250px] truncate">
                      {a.description ?? ''}
                    </td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground">{a.version ?? '-'}</td>
                    <td className="py-1.5">
                      <button
                        onClick={() => handleInstall(a.id)}
                        disabled={pendingId === a.id}
                        className="flex items-center gap-1 px-2 py-0.5 text-xs text-green-400 border border-green-400/30 rounded hover:bg-green-400/10 disabled:opacity-50"
                      >
                        <Download className="h-3 w-3" />
                        {pendingId === a.id ? 'Installing...' : 'Install'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── API Keys Tab ────────────────────────────────────

const API_KEY_SERVICES = [
  { key: 'do_api_token', label: 'DigitalOcean', description: 'API token for droplet provisioning (Nodes page)' },
  { key: 'aws_access_key_id', label: 'AWS Access Key ID', description: 'AWS IAM access key for EC2 provisioning' },
  { key: 'aws_secret_access_key', label: 'AWS Secret Access Key', description: 'AWS IAM secret key for EC2 provisioning' },
  { key: 'shodan_api_key', label: 'Shodan', description: 'Shodan search engine API' },
  { key: 'greyhatwarfare_api_key', label: 'GreyHatWarfare', description: 'Bucket/key search API' },
  { key: 'censys_api_id', label: 'Censys API ID', description: 'Censys search API ID' },
  { key: 'censys_api_secret', label: 'Censys API Secret', description: 'Censys search API secret' },
  { key: 'pdcp_api_key', label: 'Chaos / PDCP', description: 'ProjectDiscovery Cloud Platform' },
  { key: 'nvd_api_key', label: 'NVD (NIST)', description: 'National Vulnerability Database API key — increases rate limit from 5 to 50 req/30s. Get one free at https://nvd.nist.gov/developers/request-an-api-key' },
  { key: 'certspotter_api_key', label: 'Certspotter (Sectigo)', description: 'Fallback CT log source used when crt.sh is degraded. Works without a key (100 issuances/day, 1 req/s); a free Sectigo account key raises the quota to 5000/day. Sign up at https://sslmate.com/account/api_credentials' },
] as const

function ApiKeyRow({ keyName, label, description, storedMasked, updatedAt }: {
  keyName: string
  label: string
  description: string
  storedMasked: string | null
  updatedAt: string | null
}) {
  const [value, setValue] = useState('')
  const [visible, setVisible] = useState(false)
  const [status, setStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const upsert = useUpsertApiKey()
  const remove = useDeleteApiKey()

  const handleSave = async () => {
    if (!value.trim()) return
    setStatus('saving')
    try {
      await upsert.mutateAsync({ keyName, value: value.trim() })
      setValue('')
      setVisible(false)
      setStatus('saved')
      setTimeout(() => setStatus('idle'), 2000)
    } catch {
      setStatus('error')
      setTimeout(() => setStatus('idle'), 3000)
    }
  }

  const handleDelete = async () => {
    setStatus('saving')
    try {
      await remove.mutateAsync(keyName)
      setValue('')
      setStatus('idle')
    } catch {
      setStatus('error')
      setTimeout(() => setStatus('idle'), 3000)
    }
  }

  const isStored = !!storedMasked

  return (
    <div className="flex items-start gap-4 py-3 border-b border-border/50 last:border-0">
      <div className="w-40 shrink-0">
        <div className="text-sm font-medium">{label}</div>
        <div className="text-[10px] text-muted-foreground">{description}</div>
        {isStored && updatedAt && (
          <div className="text-[10px] text-muted-foreground mt-0.5">
            Updated {new Date(updatedAt).toLocaleDateString()}
          </div>
        )}
      </div>
      <div className="flex-1 flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <input
            type={visible ? 'text' : 'password'}
            placeholder={isStored ? storedMasked : 'Enter API key...'}
            value={value}
            onChange={e => setValue(e.target.value)}
            className="w-full bg-muted rounded-md px-3 py-1.5 pr-8 text-sm border border-border outline-none focus:border-primary font-mono"
          />
          <button
            type="button"
            onClick={() => setVisible(!visible)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </button>
        </div>
        <button
          onClick={handleSave}
          disabled={!value.trim() || status === 'saving'}
          className="px-3 py-1.5 text-xs font-medium rounded-md border border-primary text-primary hover:bg-primary/10 disabled:opacity-50"
        >
          {status === 'saving' ? 'Saving...' : isStored ? 'Update' : 'Save'}
        </button>
        {isStored && (
          <button
            onClick={handleDelete}
            disabled={status === 'saving'}
            className="px-2 py-1.5 text-xs text-red-400 border border-red-400/30 rounded-md hover:bg-red-400/10 disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}
        {status === 'saved' && <span className="text-xs text-green-500">Saved!</span>}
        {status === 'error' && <span className="text-xs text-red-400">Failed</span>}
      </div>
    </div>
  )
}

function ApiKeysTab() {
  const { data, isLoading, error } = useApiKeys()

  const storedKeys = useMemo(() => {
    const map: Record<string, { masked_value: string; updated_at: string | null }> = {}
    for (const k of data?.keys ?? []) {
      map[k.key] = { masked_value: k.masked_value, updated_at: k.updated_at }
    }
    return map
  }, [data])

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading API keys...</p>
  }
  if (error) {
    return <p className="text-sm text-red-400">Failed to load API keys: {(error as Error).message}</p>
  }

  return (
    <div className="space-y-4">
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold mb-1">API Keys</h3>
        <p className="text-[10px] text-muted-foreground mb-4">
          Configure API keys for external services used by scanners. Keys stored here override environment variables.
        </p>
        {API_KEY_SERVICES.map(svc => {
          const stored = storedKeys[svc.key]
          return (
            <ApiKeyRow
              key={svc.key}
              keyName={svc.key}
              label={svc.label}
              description={svc.description}
              storedMasked={stored?.masked_value ?? null}
              updatedAt={stored?.updated_at ?? null}
            />
          )
        })}
      </div>

      {/* GitHub Search Toggle */}
      <div className="border-t border-border pt-4 mt-4">
        <h3 className="text-sm font-semibold mb-1">GitHub PoC Search</h3>
        <p className="text-xs text-muted-foreground mb-2">
          When enabled, the AI Check pipeline searches GitHub for PoC/exploit repos matching the software product + version + CVEs.
          Requires a GitHub PAT above for better rate limits (30/min vs 10/min unauthenticated).
        </p>
        <GithubSearchToggle />
      </div>
    </div>
  )
}

function GithubSearchToggle() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    apiFetch<{ value: string }>('/settings/config/github_search_enabled')
      .then(r => setEnabled(r?.value?.toLowerCase() !== 'false'))
      .catch(() => setEnabled(true))
  }, [])

  const toggle = async () => {
    const next = !enabled
    setSaving(true)
    try {
      await apiFetch('/settings/config/github_search_enabled', {
        method: 'PUT', body: JSON.stringify({ value: String(next) }),
      })
      setEnabled(next)
    } catch { /* ignore */ }
    setSaving(false)
  }

  if (enabled === null) return <span className="text-xs text-muted-foreground">Loading...</span>

  return (
    <div className="flex items-center gap-3">
      <button type="button" onClick={toggle} disabled={saving}
        className={cn(
          'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
          enabled ? 'bg-primary' : 'bg-muted-foreground/30',
        )}>
        <span className={cn(
          'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform',
          enabled ? 'translate-x-4' : 'translate-x-0',
        )} />
      </button>
      <span className={cn('text-sm', enabled ? 'text-foreground' : 'text-muted-foreground')}>
        {enabled ? 'Enabled — GitHub searched during AI Check pipeline' : 'Disabled — GitHub search skipped'}
      </span>
    </div>
  )
}


// ─── Database Tab ──────────────────────────────────────

interface DbConfig {
  remote_db_host: string
  remote_db_ssh_user: string
  remote_db_ssh_key: string
  remote_db_port: number
  remote_db_user: string
  remote_db_password: string
}

interface DbStatus {
  mode: string
  config: DbConfig
  containers: { db_tunnel: string; postgres: string }
  error?: string
}

function DatabaseTab() {
  const [status, setStatus] = useState<DbStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [switching, setSwitching] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; message?: string; error?: string; target?: string; mode?: string } | null>(null)
  const [switchResult, setSwitchResult] = useState<{
    ok: boolean
    error?: string
    mode?: string
    pruning?: string[]
    pruning_status?: string
  } | null>(null)
  const [preflighting, setPreflighting] = useState(false)
  const [preflightResult, setPreflightResult] = useState<{ ok: boolean; checks: Record<string, { status: string; detail: string }> } | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [comparing, setComparing] = useState(false)
  const [compareResult, setCompareResult] = useState<{
    ok: boolean
    error?: string
    mode?: string
    comparison?: Array<{
      table: string
      local_count: number
      remote_count: number
      diff: number
      local_latest: string | null
      remote_latest: string | null
    }>
    local?: { ok: boolean; sync?: { max_lsn: number; log_entries: number } }
    remote?: { ok: boolean; sync?: { max_lsn: number; log_entries: number } }
  } | null>(null)

  const [form, setForm] = useState<DbConfig>({
    remote_db_host: '',
    remote_db_ssh_user: 'azureuser',
    remote_db_ssh_key: 'remote_db.pem',
    remote_db_port: 5432,
    remote_db_user: 'app',
    remote_db_password: '',
  })
  const [remoteDbEnabled, setRemoteDbEnabled] = useState(false)

  const fetchStatus = async () => {
    setLoading(true)
    try {
      const data = await apiFetch<DbStatus>('/settings/database')
      setStatus(data)
      if (data.config && Object.keys(data.config).length > 0) {
        setForm({
          remote_db_host: data.config.remote_db_host || '',
          remote_db_ssh_user: data.config.remote_db_ssh_user || 'azureuser',
          remote_db_ssh_key: data.config.remote_db_ssh_key || 'remote_db.pem',
          remote_db_port: data.config.remote_db_port || 5432,
          remote_db_user: data.config.remote_db_user || 'app',
          remote_db_password: data.config.remote_db_password || '',
        })
        // Enable remote DB if we have a host configured
        setRemoteDbEnabled(!!(data.config.remote_db_host && data.config.remote_db_host.trim()))
      }
    } catch {
      setStatus(null)
    } finally {
      setLoading(false)
    }
  }

  useState(() => { fetchStatus() })

  const saveConfig = async () => {
    setSaving(true)
    try {
      await apiFetch('/settings/database', {
        method: 'POST',
        body: JSON.stringify(form),
      })
      await fetchStatus()
    } finally {
      setSaving(false)
    }
  }

  const switchMode = async (mode: string) => {
    setSwitching(true)
    setSwitchResult(null)
    try {
      const res = await apiFetch<{
        ok: boolean
        error?: string
        mode?: string
        pruning?: string[]
        pruning_status?: string
      }>(
        `/settings/database/switch/${mode}`,
        { method: 'POST' }
      )
      setSwitchResult(res)
      if (res.ok) {
        // The backend force-recreates DB-consumer containers async (rag-api,
        // BFF, scan-recommender, scanners) to flush stale psycopg2 pools.
        // pentest-dashboard itself is in that list, so the fetch below
        // races the restart -- poll a few times so we catch the new
        // status once the BFF is back up.  Errors are swallowed; the
        // last successful poll wins.
        const pollTimes = [8000, 15000, 25000]
        pollTimes.forEach(t => setTimeout(() => fetchStatus().catch(() => {}), t))
      }
    } catch (e: any) {
      setSwitchResult({ ok: false, error: e.message })
    } finally {
      setSwitching(false)
    }
  }

  const toggleRemoteDb = async (enabled: boolean) => {
    setSaving(true)
    try {
      await apiFetch('/settings/database/toggle-remote', {
        method: 'POST',
        body: JSON.stringify({ enabled, config: form }),
      })
      setRemoteDbEnabled(enabled)
      await fetchStatus()
    } catch (e: any) {
      // If it fails, revert the toggle
      setRemoteDbEnabled(!enabled)
    } finally {
      setSaving(false)
    }
  }

  const testConnection = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await apiFetch<{ ok: boolean; message?: string; error?: string; target?: string; mode?: string }>(
        '/settings/database/test',
        { method: 'POST' }
      )
      setTestResult(res)
    } catch (e: any) {
      setTestResult({ ok: false, error: e.message })
    } finally {
      setTesting(false)
    }
  }

  const runPreflight = async () => {
    setPreflighting(true)
    setPreflightResult(null)
    try {
      const res = await apiFetch<{ ok: boolean; checks: Record<string, { status: string; detail: string }> }>(
        '/settings/database/preflight',
        { method: 'POST' }
      )
      setPreflightResult(res)
    } catch (e: any) {
      setPreflightResult({ ok: false, checks: { error: { status: 'fail', detail: e.message } } })
    } finally {
      setPreflighting(false)
    }
  }

  const runCompare = async () => {
    setComparing(true)
    setCompareResult(null)
    try {
      const res = await apiFetch<typeof compareResult>('/settings/database/compare')
      setCompareResult(res)
    } catch (e: any) {
      setCompareResult({ ok: false, error: e.message })
    } finally {
      setComparing(false)
    }
  }

  const isRemote = status?.mode === 'remote' || status?.mode === 'remote_direct'
  const isDirect = status?.mode === 'remote_direct'
  const isTunnel = status?.mode === 'remote'

  const containerBadge = (s: string) => {
    if (s === 'running') return <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/20 text-green-400">running</span>
    if (s === 'not_found') return <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-500/20 text-zinc-400">not found</span>
    return <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400">{s}</span>
  }

  if (loading) {
    return <div className="flex items-center gap-2 text-muted-foreground py-8"><Loader2 className="w-4 h-4 animate-spin" /> Loading database configuration...</div>
  }

  return (
    <div className="space-y-4">
      {/* Current Mode Card */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={cn(
              'w-10 h-10 rounded-lg flex items-center justify-center',
              isRemote ? 'bg-blue-500/20' : 'bg-green-500/20'
            )}>
              {isRemote ? <Wifi className="w-5 h-5 text-blue-400" /> : <Database className="w-5 h-5 text-green-400" />}
            </div>
            <div>
              <h3 className="text-sm font-semibold">Database Mode</h3>
              <p className="text-xs text-muted-foreground">
                {isDirect ? 'Connected to remote database via direct SSL' : isTunnel ? 'Connected to remote database via SSH tunnel' : 'Using local PostgreSQL container'}
              </p>
            </div>
          </div>
          <span className={cn(
            'px-3 py-1 rounded-full text-xs font-medium',
            isDirect ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' :
            isTunnel ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
            'bg-green-500/20 text-green-400 border border-green-500/30'
          )}>
            {isDirect ? 'DIRECT SSL' : isTunnel ? 'SSH TUNNEL' : 'LOCAL'}
          </span>
        </div>

        {/* Container Status */}
        <div className="grid grid-cols-2 gap-3 mb-4">
          <div className="bg-muted/30 rounded p-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">PostgreSQL</span>
              {containerBadge(status?.containers?.postgres || 'unknown')}
            </div>
          </div>
          <div className="bg-muted/30 rounded p-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">{isDirect ? 'Direct Proxy' : 'SSH Tunnel'}</span>
              {containerBadge(status?.containers?.db_tunnel || 'not_found')}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => switchMode('local')}
            disabled={switching || !isRemote}
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-colors',
              !isRemote
                ? 'bg-green-500/20 text-green-400 border border-green-500/30 cursor-default'
                : 'bg-muted hover:bg-muted/80 text-foreground border border-border'
            )}
          >
            <Database className="w-3.5 h-3.5" /> Switch to Local
          </button>
          <button
            onClick={() => switchMode('remote')}
            disabled={switching || isTunnel}
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-colors',
              isTunnel
                ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30 cursor-default'
                : 'bg-muted hover:bg-muted/80 text-foreground border border-border'
            )}
          >
            <ArrowRightLeft className="w-3.5 h-3.5" /> Remote Tunnel
          </button>
          <button
            onClick={() => switchMode('remote_direct')}
            disabled={switching || isDirect}
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-colors',
              isDirect
                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30 cursor-default'
                : 'bg-muted hover:bg-muted/80 text-foreground border border-border'
            )}
          >
            <Shield className="w-3.5 h-3.5" /> Remote Direct
          </button>
          <button
            onClick={runPreflight}
            disabled={preflighting}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
          >
            {preflighting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wifi className="w-3.5 h-3.5" />}
            Test SSH Tunnel
          </button>
          <button
            onClick={runCompare}
            disabled={comparing}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30"
          >
            {comparing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <BarChart3 className="w-3.5 h-3.5" />}
            Compare Databases
          </button>
          <button
            onClick={testConnection}
            disabled={testing}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium bg-muted hover:bg-muted/80 border border-border ml-auto"
          >
            {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Server className="w-3.5 h-3.5" />}
            Test DB Connection
          </button>
          <button
            onClick={fetchStatus}
            className="flex items-center gap-1 px-2 py-1.5 rounded text-xs bg-muted hover:bg-muted/80 border border-border"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {switching && (
          <div className="flex items-center gap-2 mt-3 text-xs text-yellow-400">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Switching database mode... This may take a minute while containers restart.
          </div>
        )}

        {preflighting && (
          <div className="flex items-center gap-2 mt-3 text-xs text-yellow-400">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Running pre-flight checks... Testing SSH connectivity and database access.
          </div>
        )}

        {switchResult && (
          <div className={cn('mt-3 text-xs flex flex-col gap-1', switchResult.ok ? 'text-green-400' : 'text-red-400')}>
            <div className="flex items-center gap-1.5">
              {switchResult.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
              {switchResult.ok ? 'Mode switched successfully. Services are restarting.' : switchResult.error}
            </div>
            {switchResult.ok && switchResult.pruning && switchResult.pruning.length > 0 && (
              <div className="ml-5 text-[10.5px] text-yellow-300/90 flex items-start gap-1.5">
                <Loader2 className="w-3 h-3 mt-0.5 animate-spin shrink-0" />
                <span>
                  Pruning {switchResult.pruning.length} DB-consumer container(s) so connection pools reconnect cleanly:{' '}
                  <span className="font-mono text-yellow-200/80">{switchResult.pruning.join(', ')}</span>.
                  This page may briefly fail to load while pentest-dashboard restarts.
                </span>
              </div>
            )}
          </div>
        )}

        {testResult && (
          <div className={cn('mt-3 text-xs flex flex-col gap-0.5', testResult.ok ? 'text-green-400' : 'text-red-400')}>
            <div className="flex items-center gap-1.5">
              {testResult.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
              <span>{testResult.ok ? testResult.message : testResult.error}</span>
            </div>
            {testResult.target && (
              <div className="ml-5 text-[10px] uppercase tracking-wider opacity-70">
                target: <span className="font-mono normal-case opacity-100">{testResult.target}</span>
                {testResult.mode && <span className="ml-2 opacity-70">[mode: {testResult.mode}]</span>}
              </div>
            )}
          </div>
        )}

        {comparing && (
          <div className="flex items-center gap-2 mt-3 text-xs text-purple-400">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Comparing databases... This may take a moment if creating a temporary tunnel.
          </div>
        )}

        {/* Database Comparison Results */}
        {compareResult && (
          <div className={cn('mt-3 border rounded-lg p-3', compareResult.ok ? 'border-purple-500/30 bg-purple-500/5' : 'border-red-500/30 bg-red-500/5')}>
            <div className="flex items-center gap-2 mb-3">
              <BarChart3 className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-semibold text-purple-400">Database Comparison</span>
              {compareResult.mode && (
                <span className="text-[10px] text-muted-foreground ml-auto">Current mode: {compareResult.mode}</span>
              )}
            </div>
            {compareResult.error && !compareResult.ok ? (
              <div className="text-xs text-red-400 flex items-center gap-1.5">
                <XCircle className="w-3.5 h-3.5" />
                {compareResult.error}
              </div>
            ) : compareResult.comparison ? (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-1.5 pr-3 text-muted-foreground font-medium">Table</th>
                        <th className="text-right py-1.5 px-3 text-green-400 font-medium">Local</th>
                        <th className="text-right py-1.5 px-3 text-blue-400 font-medium">Remote</th>
                        <th className="text-right py-1.5 px-3 text-muted-foreground font-medium">Diff</th>
                        <th className="text-right py-1.5 pl-3 text-muted-foreground font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {compareResult.comparison.map(row => {
                        const synced = row.diff === 0
                        const localMore = row.diff > 0
                        return (
                          <tr key={row.table} className="border-b border-border/50">
                            <td className="py-1.5 pr-3 font-mono text-[11px]">{row.table}</td>
                            <td className="py-1.5 px-3 text-right tabular-nums">{row.local_count}</td>
                            <td className="py-1.5 px-3 text-right tabular-nums">{row.remote_count}</td>
                            <td className={cn(
                              'py-1.5 px-3 text-right tabular-nums font-medium',
                              synced ? 'text-muted-foreground' : localMore ? 'text-green-400' : 'text-blue-400'
                            )}>
                              {row.diff > 0 ? `+${row.diff}` : row.diff === 0 ? '=' : row.diff}
                            </td>
                            <td className="py-1.5 pl-3 text-right">
                              {synced ? (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/20 text-green-400">synced</span>
                              ) : localMore ? (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400">local ahead</span>
                              ) : (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">remote ahead</span>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                {/* Summary row */}
                {(() => {
                  const totalLocal = compareResult.comparison.reduce((s, r) => s + r.local_count, 0)
                  const totalRemote = compareResult.comparison.reduce((s, r) => s + r.remote_count, 0)
                  const outOfSync = compareResult.comparison.filter(r => r.diff !== 0).length
                  return (
                    <div className="flex items-center gap-4 mt-3 pt-2 border-t border-border/50 text-[11px] text-muted-foreground">
                      <span>Local: <strong className="text-green-400">{totalLocal}</strong> rows</span>
                      <span>Remote: <strong className="text-blue-400">{totalRemote}</strong> rows</span>
                      {outOfSync > 0 ? (
                        <span className="text-yellow-400">{outOfSync} table{outOfSync > 1 ? 's' : ''} out of sync</span>
                      ) : (
                        <span className="text-green-400">All tables synced</span>
                      )}
                      {compareResult.local?.sync && (
                        <span className="ml-auto">Local LSN: {compareResult.local.sync.max_lsn}</span>
                      )}
                      {compareResult.remote?.sync && (
                        <span>Remote LSN: {compareResult.remote.sync.max_lsn}</span>
                      )}
                    </div>
                  )
                })()}
                {/* Sync action hint */}
                {compareResult.comparison.some(r => r.diff !== 0) && (
                  <div className="mt-2 text-[11px] text-muted-foreground">
                    Use the <a href="/sync" className="text-primary hover:underline">Sync Dashboard</a> to push or pull changes between databases.
                  </div>
                )}
              </>
            ) : null}
          </div>
        )}

        {/* Pre-flight Results */}
        {preflightResult && (
          <div className={cn('mt-3 border rounded-lg p-3', preflightResult.ok ? 'border-green-500/30 bg-green-500/5' : 'border-red-500/30 bg-red-500/5')}>
            <div className="flex items-center gap-2 mb-2">
              {preflightResult.ok ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
              <span className={cn('text-xs font-semibold', preflightResult.ok ? 'text-green-400' : 'text-red-400')}>
                {preflightResult.ok ? 'All pre-flight checks passed — ready to switch to remote' : 'Pre-flight checks failed — fix issues before switching'}
              </span>
            </div>
            <div className="space-y-1.5">
              {Object.entries(preflightResult.checks).map(([name, check]) => {
                const label: Record<string, string> = {
                  ssh_key: 'SSH Key',
                  ssh_connect: 'SSH Connection',
                  tunnel_container: 'Tunnel Container',
                  tcp_5432: 'TCP Port 5432',
                  postgres_ready: 'PostgreSQL Ready',
                }
                return (
                  <div key={name} className="flex items-center gap-2">
                    {check.status === 'pass' ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                    ) : check.status === 'fail' ? (
                      <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    ) : (
                      <div className="w-3.5 h-3.5 rounded-full border border-zinc-500 shrink-0" />
                    )}
                    <span className="text-[11px] text-muted-foreground w-32 shrink-0">{label[name] || name}</span>
                    <span className={cn('text-[11px]', check.status === 'pass' ? 'text-green-400' : check.status === 'fail' ? 'text-red-400' : 'text-muted-foreground')}>
                      {check.detail}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Remote Configuration Card */}
      <div className="bg-card border border-border rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-semibold mb-1">Remote Database Configuration</h3>
            <p className="text-[10px] text-muted-foreground">
              Configure the remote PostgreSQL server. <strong>Remote Tunnel</strong> routes through SSH (requires SSH key). <strong>Remote Direct</strong> connects via SSL (requires port 5432 open + SSL enabled on the server). Save before switching.
            </p>
          </div>
          <div className="flex items-center gap-2 ml-4">
            <button
              onClick={() => toggleRemoteDb(!remoteDbEnabled)}
              disabled={saving}
              className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-colors',
                remoteDbEnabled
                  ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/30'
              )}
            >
              {saving ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : remoteDbEnabled ? (
                <PowerOff className="w-3.5 h-3.5" />
              ) : (
                <Power className="w-3.5 h-3.5" />
              )}
              {remoteDbEnabled ? 'Disable Remote DB' : 'Enable Remote DB'}
            </button>
          </div>
        </div>

        {remoteDbEnabled ? (
          <div className="mb-4 p-2 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400">
            ✓ Remote database settings are active and available for use
          </div>
        ) : (
          <div className="mb-4 p-2 bg-yellow-500/10 border border-yellow-500/30 rounded text-xs text-yellow-400">
            ⚠ Remote database settings are disabled (commented out in .env) - configuration is preserved but not active
          </div>
        )}

        {remoteDbEnabled && (
          <>
          <div className="grid grid-cols-2 gap-3">
            <div>
            <label className="block text-[11px] text-muted-foreground mb-1">VPS Host / IP</label>
            <input
              type="text"
              value={form.remote_db_host}
              onChange={e => setForm(f => ({ ...f, remote_db_host: e.target.value }))}
              placeholder="db.example.com or 203.0.113.10"
              className="w-full px-2.5 py-1.5 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <p className="text-[10px] text-muted-foreground mt-0.5">Public IP or hostname of the remote VPS</p>
          </div>
          <div>
            <label className="block text-[11px] text-muted-foreground mb-1">SSH User</label>
            <input
              type="text"
              value={form.remote_db_ssh_user}
              onChange={e => setForm(f => ({ ...f, remote_db_ssh_user: e.target.value }))}
              placeholder="azureuser"
              className="w-full px-2.5 py-1.5 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="block text-[11px] text-muted-foreground mb-1">SSH Key File</label>
            <input
              type="text"
              value={form.remote_db_ssh_key}
              onChange={e => setForm(f => ({ ...f, remote_db_ssh_key: e.target.value }))}
              placeholder="remote_db.pem"
              className="w-full px-2.5 py-1.5 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <p className="text-[10px] text-muted-foreground mt-0.5">Filename in ssh-keys/ directory</p>
          </div>
          <div>
            <label className="block text-[11px] text-muted-foreground mb-1">Database Port</label>
            <input
              type="number"
              value={form.remote_db_port}
              onChange={e => setForm(f => ({ ...f, remote_db_port: parseInt(e.target.value) || 5432 }))}
              className="w-full px-2.5 py-1.5 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="block text-[11px] text-muted-foreground mb-1">Database User</label>
            <input
              type="text"
              value={form.remote_db_user}
              onChange={e => setForm(f => ({ ...f, remote_db_user: e.target.value }))}
              placeholder="app"
              className="w-full px-2.5 py-1.5 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div className="col-span-2">
            <label className="block text-[11px] text-muted-foreground mb-1">Database Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={form.remote_db_password}
                onChange={e => setForm(f => ({ ...f, remote_db_password: e.target.value }))}
                placeholder="Enter remote database password"
                className="w-full px-2.5 py-1.5 pr-8 rounded bg-muted border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        <div className="flex justify-end mt-4">
          <button
            onClick={saveConfig}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-1.5 rounded text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
            Save Configuration
          </button>
        </div>
          </>
        )}

        {!remoteDbEnabled && (
          <div className="text-center py-8 text-muted-foreground">
            <Power className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">Enable remote database settings to configure</p>
            <p className="text-xs">Configuration is preserved when disabled</p>
          </div>
        )}
      </div>

      {/* Setup Guide Card */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-5">
        <h3 className="text-sm font-semibold">Setup Guide</h3>

        {/* SSH Tunnel Mode (default for VPS instances behind a firewall) */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-semibold">SSH Tunnel</span>
            <span className="text-[11px] text-muted-foreground">
              VPS behind a firewall, only SSH (port 22) reachable. Port 5432 stays private.
            </span>
          </div>
          <div className="text-xs text-muted-foreground space-y-2">
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">1.</span>
              <span>Provision VPS: Run <code className="px-1 py-0.5 bg-muted rounded text-[10px]">scripts/vps/setup-remote-db.sh</code> on the remote server</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">2.</span>
              <span>Place your SSH key (e.g. <code className="px-1 py-0.5 bg-muted rounded text-[10px]">remote_db.pem</code>) in the <code className="px-1 py-0.5 bg-muted rounded text-[10px]">ssh-keys/</code> directory</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">3.</span>
              <span>Fill in the form above: <strong>VPS Host</strong>, <strong>SSH User</strong>, <strong>SSH Key File</strong>, <strong>DB Port</strong> (5432), <strong>DB User</strong>, <strong>DB Password</strong>, then click Save</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">4.</span>
              <span>Click "Test SSH Tunnel" to verify connectivity</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">5.</span>
              <span>Click "Switch to Remote" to activate the SSH tunnel</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">6.</span>
              <span>Optional: Run <code className="px-1 py-0.5 bg-muted rounded text-[10px]">scripts/migrate-db-to-remote.sh</code> to copy local data to remote</span>
            </div>
          </div>
        </div>

        {/* Direct SSL Mode (cloud-managed Postgres, RDS, Aurora, etc.) */}
        <div className="pt-4 border-t border-border/50">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 font-semibold">Direct SSL</span>
            <span className="text-[11px] text-muted-foreground">
              Postgres reachable on port 5432 with TLS (cloud-managed, RDS, Aurora, Supabase, self-hosted with cert).
            </span>
          </div>
          <div className="text-xs text-muted-foreground space-y-2">
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">1.</span>
              <span>
                Confirm port <code className="px-1 py-0.5 bg-muted rounded text-[10px]">5432</code> is reachable from this host
                {' '}and the server has SSL enabled (<code className="px-1 py-0.5 bg-muted rounded text-[10px]">ssl = on</code> in <code className="px-1 py-0.5 bg-muted rounded text-[10px]">postgresql.conf</code> for self-hosted; managed services have SSL on by default).
              </span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">2.</span>
              <span>
                Form fields above — fill these in, <strong>leave SSH fields blank</strong> (Direct SSL doesn't tunnel):
                <ul className="ml-5 mt-1 list-disc text-[11px]">
                  <li><strong>VPS Host / IP</strong>: the Postgres server's hostname or IP (e.g. <code className="px-1 py-0.5 bg-muted rounded text-[10px]">db.example.com</code> or <code className="px-1 py-0.5 bg-muted rounded text-[10px]">my-cluster.cluster-xyz.us-east-1.rds.amazonaws.com</code>)</li>
                  <li><strong>SSH User / SSH Key File</strong>: leave blank or default</li>
                  <li><strong>DB Port</strong>: <code className="px-1 py-0.5 bg-muted rounded text-[10px]">5432</code> (or your custom port)</li>
                  <li><strong>DB User</strong>: usually <code className="px-1 py-0.5 bg-muted rounded text-[10px]">app</code></li>
                  <li><strong>DB Password</strong>: the password set on the remote DB</li>
                </ul>
              </span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">3.</span>
              <span>
                Click <strong>Save</strong> to persist the connection config.
              </span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">4.</span>
              <div className="flex-1">
                Edit <code className="px-1 py-0.5 bg-muted rounded text-[10px]">.env</code> at the repo root so the rag-api container points at the remote DB instead of the local container:
                <pre className="mt-1 p-2 bg-muted/60 rounded text-[10.5px] font-mono leading-snug overflow-x-auto">{`# Comment out the local Postgres profile so docker-compose doesn't
# start rag-postgres locally:
COMPOSE_PROFILES=         # was: local-db

POSTGRES_HOST=db.example.com      # the same VPS Host you entered above
POSTGRES_PORT=5432
POSTGRES_USER=app
POSTGRES_PASSWORD=<the DB password>
POSTGRES_DB=scans

# DSN with sslmode=require so the driver rejects unencrypted fallback.
# Use sslmode=verify-full if you have the server cert in /certs/.
DB_DSN=postgresql://app:<PASSWORD>@db.example.com:5432/scans?sslmode=require`}</pre>
              </div>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">5.</span>
              <span>
                Recreate the affected containers so they read the new <code className="px-1 py-0.5 bg-muted rounded text-[10px]">.env</code>:{' '}
                <code className="px-1 py-0.5 bg-muted rounded text-[10px]">docker compose up -d --force-recreate rag-api pentest-dashboard</code>
                {' '}(<code className="px-1 py-0.5 bg-muted rounded text-[10px]">restart</code> alone won't pick up env_file changes).
              </span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">6.</span>
              <span>Click <strong>"Test DB Connection"</strong> above to verify SSL handshake + auth succeed. Green checkmark = ready.</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">7.</span>
              <span>Click <strong>"Switch to Direct"</strong> to mark Direct SSL as the active mode.</span>
            </div>
            <div className="flex gap-2">
              <span className="text-primary font-mono font-bold">8.</span>
              <span>Optional: run <code className="px-1 py-0.5 bg-muted rounded text-[10px]">scripts/migrate-db-to-remote.sh</code> to seed the remote DB from your local data.</span>
            </div>
            <div className="mt-3 px-3 py-2 rounded border border-amber-500/30 bg-amber-500/5">
              <div className="text-[11px] text-amber-300 font-medium mb-0.5">Heads-up</div>
              <div className="text-[11px] text-amber-200/80">
                Direct SSL exposes port 5432 to the network. Use IP allowlisting on the DB server's firewall + a strong <code className="px-1 py-0.5 bg-muted rounded text-[10px]">scram-sha-256</code> password (the rag-postgres image enforces this by default). Prefer SSH Tunnel mode when only a single operator workstation needs access.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Test Result Body ── */
function TestResultBody({ result }: { result: Record<string, unknown> }) {
  const r = (result.result && typeof result.result === 'object') ? result.result as Record<string, unknown> : null
  const hasRawOutput = !!(r && r.raw_output)
  return (
    <div className="max-h-80 overflow-auto">
      {r?.command ? (
        <div className="px-3 py-1 border-b border-border bg-muted/20">
          <span className="text-[10px] text-muted-foreground">Command: </span>
          <code className="text-[10px] text-foreground">{String(r.command)}</code>
        </div>
      ) : null}
      {r?.duration_s !== undefined ? (
        <div className="px-3 py-0.5 border-b border-border bg-muted/10">
          <span className="text-[10px] text-muted-foreground">Duration: {String(r.duration_s)}s</span>
        </div>
      ) : null}
      {hasRawOutput ? (
        <pre className="px-3 py-2 text-[11px] font-mono text-foreground whitespace-pre-wrap break-all">
          {String(r!.raw_output)}
        </pre>
      ) : null}
      {r?.stderr ? (
        <div className="px-3 py-1 border-t border-border">
          <span className="text-[10px] text-red-400">stderr: </span>
          <pre className="text-[10px] font-mono text-red-300 whitespace-pre-wrap">{String(r.stderr)}</pre>
        </div>
      ) : null}
      {result.error ? (
        <div className="px-3 py-2 text-xs text-red-400">{String(result.error)}</div>
      ) : null}
      {!result.error && !hasRawOutput ? (
        <pre className="px-3 py-2 text-[10px] font-mono text-muted-foreground whitespace-pre-wrap">
          {JSON.stringify(result, null, 2).slice(0, 5000)}
        </pre>
      ) : null}
    </div>
  )
}

/* ── Tool Options Tab ── */
function ToolOptionsTab() {
  const { toolOverrides, setToolOverride, clearToolOverride, clearAllToolOverrides } = useScanDefaultsStore()
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [showCli, setShowCli] = useState<Record<string, boolean>>({})
  // Quick test state
  const [testJob, setTestJob] = useState<{ scanId: string; jobId: string; status: string; result?: Record<string, unknown> } | null>(null)
  const [testTarget, setTestTarget] = useState('')
  const [testingScan, setTestingScan] = useState<string | null>(null)

  const toggle = (cat: string) => setCollapsed(prev => ({ ...prev, [cat]: !prev[cat] }))
  const toggleCli = (scanId: string) => setShowCli(prev => ({ ...prev, [scanId]: !prev[scanId] }))

  const overrideCount = Object.values(toolOverrides).reduce((n, o) => n + Object.keys(o).length, 0)

  // Quick test: launch scan with no_ingest=true, then poll for results
  const launchQuickTest = async (scanId: string) => {
    if (!testTarget.trim()) return
    setTestingScan(scanId)
    setTestJob(null)
    try {
      // Build params from fields + overrides
      const fields = SCAN_FIELDS[scanId] || []
      const scanOverrides = toolOverrides[scanId] || {}
      const params: Record<string, unknown> = { no_ingest: true }

      // Fill first target-like field with testTarget
      const targetField = fields.find(f => TARGET_FIELD_KEYS.has(f.key))
      if (targetField) {
        params[targetField.key] = testTarget
      }

      // Apply overrides for non-target fields
      for (const f of fields) {
        if (!TARGET_FIELD_KEYS.has(f.key)) {
          params[f.key] = scanOverrides[f.key] || f.placeholder
        }
      }

      const resp = await apiFetch<{ job_id: string }>(`/scans/${scanId}`, {
        method: 'POST',
        body: JSON.stringify(params),
      })
      const jobId = resp.job_id
      setTestJob({ scanId, jobId, status: 'queued' })

      // Poll for completion
      const poll = async () => {
        for (let i = 0; i < 60; i++) {
          await new Promise(r => setTimeout(r, 2000))
          try {
            const job = await apiFetch<Record<string, unknown>>(`/scans/${jobId}`)
            const status = (job.status as string) || 'unknown'
            if (status === 'completed' || status === 'failed') {
              setTestJob({ scanId, jobId, status, result: job })
              setTestingScan(null)
              return
            }
            setTestJob({ scanId, jobId, status })
          } catch {
            break
          }
        }
        setTestingScan(null)
      }
      poll()
    } catch (err) {
      setTestJob({ scanId, jobId: '', status: 'error', result: { error: String(err) } })
      setTestingScan(null)
    }
  }

  return (
    <div className="space-y-4">
      {/* Profile selector */}
      <ProfileSelector />

      {/* Tool Updates */}
      <ToolUpdates />

      {/* Wordlist Paths */}
      <WordlistSettings />

      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Override default field values for scan tools. Overrides auto-fill when launching scans.
          {overrideCount > 0 && <span className="ml-2 text-primary font-medium">{overrideCount} override{overrideCount !== 1 ? 's' : ''} active</span>}
        </p>
        {overrideCount > 0 && (
          <button
            onClick={clearAllToolOverrides}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-destructive/10 text-destructive rounded hover:bg-destructive/20"
          >
            <RotateCcw size={12} /> Reset All
          </button>
        )}
      </div>

      {/* Quick test target input */}
      <div className="flex items-center gap-2 p-2 rounded bg-muted/30 border border-border">
        <label className="text-xs text-muted-foreground whitespace-nowrap">Test Target:</label>
        <input
          type="text"
          value={testTarget}
          onChange={e => setTestTarget(e.target.value)}
          placeholder="e.g. 192.168.1.1, example.com, http://target"
          className="flex-1 px-2 py-1 text-xs rounded bg-background border border-border"
        />
        <span className="text-[10px] text-muted-foreground">Used for Quick Test (no ingestion)</span>
      </div>

      {/* Quick test result modal */}
      {testJob && testJob.result && (
        <div className="border border-border rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-3 py-2 bg-muted/50">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Test Result: {testJob.scanId}</span>
              <span className={cn(
                'text-[10px] px-1.5 py-0.5 rounded',
                testJob.status === 'completed' ? 'bg-green-500/15 text-green-400 border border-green-500/30' :
                testJob.status === 'failed' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
              )}>
                {testJob.status.toUpperCase()}
              </span>
              {(() => {
                const r = testJob.result?.result as Record<string, unknown> | undefined
                return r && typeof r === 'object' && r.findings_count !== undefined ? (
                  <span className="text-xs text-muted-foreground">
                    {String(r.findings_count)} findings (not ingested)
                  </span>
                ) : null
              })()}
            </div>
            <button onClick={() => setTestJob(null)} className="p-1 text-muted-foreground hover:text-foreground">
              <X size={14} />
            </button>
          </div>
          <TestResultBody result={testJob.result} />
        </div>
      )}

      {SCAN_CATEGORIES.map(cat => {
        const toolsWithOptions = cat.scans.filter(scan => {
          const fields = SCAN_FIELDS[scan.id]
          const cliOpts = TOOL_CLI_OPTIONS[scan.id]
          return (fields && fields.some(f => !TARGET_FIELD_KEYS.has(f.key))) || (cliOpts && cliOpts.length > 0)
        })
        if (toolsWithOptions.length === 0) return null

        const isCollapsed = collapsed[cat.name]

        return (
          <div key={cat.name} className="border border-border rounded-lg overflow-hidden">
            <button
              onClick={() => toggle(cat.name)}
              className="w-full flex items-center gap-2 px-3 py-2 bg-muted/50 hover:bg-muted text-left text-sm font-medium"
            >
              {isCollapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
              {cat.name}
              <span className="text-xs text-muted-foreground font-normal">{cat.desc}</span>
            </button>

            {!isCollapsed && (
              <div className="divide-y divide-border">
                {toolsWithOptions.map(scan => {
                  const fields = (SCAN_FIELDS[scan.id] || []).filter(f => !TARGET_FIELD_KEYS.has(f.key))
                  const scanOverrides = toolOverrides[scan.id] || {}
                  const cliOpts = TOOL_CLI_OPTIONS[scan.id] || []

                  return (
                    <div key={scan.id} className="px-3 py-2 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{scan.label}</span>
                        <span className="text-xs text-muted-foreground">{scan.desc}</span>
                        <div className="flex gap-1 ml-auto">
                          {scan.proxy === false && <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">NO PROXY</span>}
                          {scan.proxy === true && <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">PROXY</span>}
                          {scan.touchesTarget && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">TOUCHES TARGET</span>}
                          {scan.passive && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/30">PASSIVE</span>}
                          {scan.remote && <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">REMOTE</span>}
                          {/* Quick Test button */}
                          <button
                            disabled={!testTarget.trim() || testingScan === scan.id}
                            onClick={() => launchQuickTest(scan.id)}
                            className={cn(
                              'text-[10px] px-2 py-0.5 rounded border flex items-center gap-1',
                              testingScan === scan.id
                                ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30 cursor-wait'
                                : testTarget.trim()
                                  ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/25 cursor-pointer'
                                  : 'bg-muted text-muted-foreground border-border cursor-not-allowed',
                            )}
                            title={testTarget.trim() ? 'Run with current overrides, skip DB ingestion' : 'Enter a test target above first'}
                          >
                            {testingScan === scan.id ? <Loader2 size={10} className="animate-spin" /> : <Zap size={10} />}
                            {testingScan === scan.id ? 'Testing...' : 'Quick Test'}
                          </button>
                        </div>
                      </div>
                      {/* Scan parameter overrides */}
                      {fields.length > 0 && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                          {fields.map(field => {
                            const hasOverride = field.key in scanOverrides
                            const value = scanOverrides[field.key] ?? ''
                            return (
                              <div key={field.key} className="flex items-center gap-1">
                                <div className="flex-1">
                                  <label className="text-[11px] text-muted-foreground">{field.label}</label>
                                  <input
                                    type={field.type === 'number' ? 'text' : field.type}
                                    value={value}
                                    placeholder={field.placeholder}
                                    onChange={e => {
                                      if (e.target.value) {
                                        setToolOverride(scan.id, field.key, e.target.value)
                                      } else {
                                        clearToolOverride(scan.id, field.key)
                                      }
                                    }}
                                    className={cn(
                                      'w-full px-2 py-1 text-xs rounded bg-background border',
                                      hasOverride ? 'border-primary' : 'border-border',
                                    )}
                                  />
                                </div>
                                {hasOverride && (
                                  <button
                                    onClick={() => clearToolOverride(scan.id, field.key)}
                                    className="mt-4 p-1 text-muted-foreground hover:text-foreground"
                                    title="Reset to default"
                                  >
                                    <RotateCcw size={12} />
                                  </button>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      )}
                      {/* CLI flags — editable where a default exists */}
                      {cliOpts.length > 0 && (
                        <div>
                          <button
                            onClick={() => toggleCli(scan.id)}
                            className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
                          >
                            {showCli[scan.id] ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                            CLI Flags ({cliOpts.length})
                          </button>
                          {showCli[scan.id] && (
                            <div className="mt-1 rounded bg-muted/30 border border-border overflow-hidden">
                              <table className="w-full text-[11px]">
                                <thead>
                                  <tr className="border-b border-border bg-muted/50">
                                    <th className="text-left px-2 py-1 font-medium text-muted-foreground w-28">Flag</th>
                                    <th className="text-left px-2 py-1 font-medium text-muted-foreground">Description</th>
                                    <th className="text-left px-2 py-1 font-medium text-muted-foreground w-48">Value</th>
                                    <th className="w-6" />
                                  </tr>
                                </thead>
                                <tbody>
                                  {cliOpts.map((opt, i) => {
                                    // Determine the override key: paramKey for scan-field-mapped options, _cli_ prefix for CLI-only
                                    const overrideKey = opt.paramKey || (opt.defaultValue ? `_cli_${opt.flag.replace(/[^a-zA-Z0-9]/g, '_')}` : null)
                                    const hasOverride = overrideKey ? overrideKey in scanOverrides : false
                                    const currentValue = overrideKey ? (scanOverrides[overrideKey] ?? '') : ''
                                    const isEditable = !!opt.defaultValue

                                    return (
                                      <tr key={i} className={cn(i % 2 === 0 ? '' : 'bg-muted/20', hasOverride && 'bg-primary/5')}>
                                        <td className="px-2 py-0.5 font-mono text-primary whitespace-nowrap">{opt.flag}</td>
                                        <td className="px-2 py-0.5 text-foreground">{opt.desc}</td>
                                        <td className="px-2 py-0.5">
                                          {isEditable && overrideKey ? (
                                            <input
                                              type="text"
                                              value={currentValue}
                                              placeholder={opt.defaultValue}
                                              onChange={e => {
                                                if (e.target.value) {
                                                  setToolOverride(scan.id, overrideKey, e.target.value)
                                                } else {
                                                  clearToolOverride(scan.id, overrideKey)
                                                }
                                              }}
                                              className={cn(
                                                'w-full px-1.5 py-0.5 text-[11px] rounded bg-background border font-mono',
                                                hasOverride ? 'border-primary text-primary' : 'border-border text-muted-foreground',
                                              )}
                                            />
                                          ) : (
                                            <span className="font-mono text-muted-foreground">—</span>
                                          )}
                                        </td>
                                        <td className="px-1 py-0.5">
                                          {hasOverride && overrideKey ? (
                                            <button
                                              onClick={() => clearToolOverride(scan.id, overrideKey)}
                                              className="p-0.5 text-muted-foreground hover:text-foreground"
                                              title="Reset to default"
                                            >
                                              <RotateCcw size={10} />
                                            </button>
                                          ) : null}
                                        </td>
                                      </tr>
                                    )
                                  })}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── MCP Servers Tab ────────────────────────────────
function McpServersTab() {
  const { data, isLoading, refetch } = useMcpServers()
  const { data: mcpToolsData } = useQuery({
    queryKey: ['agent-mcp-tools'],
    queryFn: () => apiFetch<{ total_discovered: number; registered_for_agents: number; servers: Record<string, number>; tools: { name: string; server: string; description: string }[] }>('/agent-mcp-tools'),
    staleTime: 30000,
  })
  const addServer = useAddMcpServer()
  const toggleServer = useToggleMcpServer()
  const deleteServer = useDeleteMcpServer()
  const updateMcpo = useUpdateMcpoConfig()
  const [showAdd, setShowAdd] = useState(false)
  const [showTools, setShowTools] = useState(false)
  const [form, setForm] = useState({
    name: '', description: '', source: 'npm' as string,
    package: '', path: '', repo: '', entry: 'server.py',
    transport: 'stdio' as string, port: 9030,
    env: '' as string, args: '' as string, enabled: true,
  })

  const servers = data?.servers ?? []
  const builtIn = servers.filter(s => s.builtin)
  const thirdParty = servers.filter(s => !s.builtin)

  const handleAdd = () => {
    const envObj: Record<string, string> = {}
    form.env.split('\n').filter(Boolean).forEach(line => {
      const [k, ...v] = line.split('=')
      if (k) envObj[k.trim()] = v.join('=').trim()
    })
    addServer.mutate({
      name: form.name, description: form.description,
      source: form.source, package: form.package,
      path: form.path, repo: form.repo, entry: form.entry,
      transport: form.transport, port: form.port,
      env: envObj, args: form.args ? form.args.split(' ') : [],
      enabled: form.enabled,
    } as any, {
      onSuccess: () => {
        setShowAdd(false)
        setForm({ name: '', description: '', source: 'npm', package: '', path: '', repo: '', entry: 'server.py', transport: 'stdio', port: 9030, env: '', args: '', enabled: true })
      },
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Manage built-in and third-party MCP tool servers. Third-party servers (npm, pip, GitHub) are automatically bridged via stdio-to-HTTP.
        </p>
        <div className="flex gap-2">
          <button onClick={() => updateMcpo.mutate()} className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 flex items-center gap-1">
            <RefreshCw className={cn('w-3 h-3', updateMcpo.isPending && 'animate-spin')} /> Update MCPO Config
          </button>
          <button onClick={() => refetch()} className="px-3 py-1.5 text-xs bg-secondary text-secondary-foreground rounded hover:bg-secondary/80">
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Built-in Servers */}
      <div>
        <h3 className="text-sm font-semibold mb-2">Built-in Servers (8)</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
          {builtIn.map(srv => (
            <div key={srv.name} className="border border-border rounded p-3 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className={cn('w-2 h-2 rounded-full', srv.healthy ? 'bg-green-500' : 'bg-red-500')} />
                  <span className="text-sm font-medium">{srv.name}</span>
                </div>
                <span className="text-xs text-muted-foreground">Port {srv.port} {srv.tools ? `• ${srv.tools} tools` : ''}</span>
              </div>
              <span className="text-xs text-green-600 font-medium">Active</span>
            </div>
          ))}
        </div>
      </div>

      {/* Third-party Servers */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold">Third-Party Servers ({thirdParty.length})</h3>
          <button onClick={() => setShowAdd(!showAdd)} className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 flex items-center gap-1">
            <Plus className="w-3 h-3" /> Add Server
          </button>
        </div>

        {showAdd && (
          <div className="border border-border rounded p-4 mb-3 space-y-3 bg-card">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium">Name</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="burpsuite-mcp" />
              </div>
              <div>
                <label className="text-xs font-medium">Description</label>
                <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="Burp Suite MCP integration" />
              </div>
              <div>
                <label className="text-xs font-medium">Source</label>
                <select value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded">
                  <option value="npm">npm (npx)</option>
                  <option value="pip">pip (python -m)</option>
                  <option value="github">GitHub (clone)</option>
                  <option value="local">Local script</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium">Transport</label>
                <select value={form.transport} onChange={e => setForm(f => ({ ...f, transport: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded">
                  <option value="stdio">stdio (auto-bridged)</option>
                  <option value="streamable-http">streamable-http (native)</option>
                </select>
              </div>
              {(form.source === 'npm' || form.source === 'pip') && (
                <div>
                  <label className="text-xs font-medium">Package</label>
                  <input value={form.package} onChange={e => setForm(f => ({ ...f, package: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="@anthropic/burpsuite-mcp" />
                </div>
              )}
              {form.source === 'local' && (
                <div>
                  <label className="text-xs font-medium">Path</label>
                  <input value={form.path} onChange={e => setForm(f => ({ ...f, path: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="/app/third_party/custom.py" />
                </div>
              )}
              {form.source === 'github' && (
                <>
                  <div>
                    <label className="text-xs font-medium">Repo URL</label>
                    <input value={form.repo} onChange={e => setForm(f => ({ ...f, repo: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="https://github.com/user/mcp-tool" />
                  </div>
                  <div>
                    <label className="text-xs font-medium">Entry Point</label>
                    <input value={form.entry} onChange={e => setForm(f => ({ ...f, entry: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="server.py" />
                  </div>
                </>
              )}
              <div>
                <label className="text-xs font-medium">Port</label>
                <input type="number" value={form.port} onChange={e => setForm(f => ({ ...f, port: parseInt(e.target.value) || 9030 }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" />
              </div>
              <div>
                <label className="text-xs font-medium">Args (space-separated)</label>
                <input value={form.args} onChange={e => setForm(f => ({ ...f, args: e.target.value }))} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded" placeholder="/data" />
              </div>
            </div>
            <div>
              <label className="text-xs font-medium">Environment Variables (KEY=VALUE, one per line)</label>
              <textarea value={form.env} onChange={e => setForm(f => ({ ...f, env: e.target.value }))} rows={3} className="w-full mt-1 px-2 py-1.5 text-sm bg-background border border-border rounded font-mono" placeholder={"BURP_API_URL=http://host.docker.internal:1337\nBURP_API_KEY=your-key"} />
            </div>
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                Enable immediately
              </label>
              <div className="flex gap-2">
                <button onClick={() => setShowAdd(false)} className="px-3 py-1.5 text-xs bg-secondary text-secondary-foreground rounded">Cancel</button>
                <button onClick={handleAdd} disabled={!form.name || addServer.isPending} className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50">
                  {addServer.isPending ? 'Adding...' : 'Add Server'}
                </button>
              </div>
            </div>
            {addServer.isError && (
              <p className="text-xs text-red-500">{(addServer.error as any)?.message || 'Failed to add server'}</p>
            )}
          </div>
        )}

        {thirdParty.length === 0 && !showAdd && (
          <p className="text-sm text-muted-foreground italic py-4">No third-party MCP servers configured. Click "Add Server" to import tools from npm, pip, GitHub, or Claude Desktop.</p>
        )}

        <div className="space-y-2">
          {thirdParty.map(srv => (
            <div key={srv.name} className="border border-border rounded p-3 flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className={cn('w-2 h-2 rounded-full', srv.healthy ? 'bg-green-500' : srv.enabled ? 'bg-yellow-500' : 'bg-gray-500')} />
                  <span className="text-sm font-medium">{srv.name}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-secondary rounded">{srv.source}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-secondary rounded">{srv.transport}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  Port {srv.port} {srv.description ? `• ${srv.description}` : ''} {srv.package ? `• ${srv.package}` : ''}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleServer.mutate(srv.name)}
                  className={cn('px-2 py-1 text-xs rounded flex items-center gap-1', srv.enabled ? 'bg-green-600/20 text-green-400 hover:bg-green-600/30' : 'bg-secondary text-muted-foreground hover:bg-secondary/80')}
                >
                  {srv.enabled ? <><Power className="w-3 h-3" /> Enabled</> : <><PowerOff className="w-3 h-3" /> Disabled</>}
                </button>
                <button onClick={() => deleteServer.mutate(srv.name)} className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Import from Claude Desktop */}
      <div className="border border-border rounded p-4 bg-card">
        <h3 className="text-sm font-semibold mb-2">Import from Claude Desktop Config</h3>
        <p className="text-xs text-muted-foreground mb-3">
          Paste your Claude Desktop <code className="text-xs bg-secondary px-1 rounded">claude_desktop_config.json</code> MCP server block to import it as a third-party server.
        </p>
        <ClaudeDesktopImporter onImport={(srv) => {
          addServer.mutate(srv as any, { onSuccess: () => updateMcpo.mutate() })
        }} />
      </div>

      {/* Imported Tools */}
      {mcpToolsData && mcpToolsData.registered_for_agents > 0 && (
        <div className="border border-border rounded-lg overflow-hidden">
          <button
            onClick={() => setShowTools(!showTools)}
            className="w-full px-4 py-2.5 flex items-center gap-2 hover:bg-accent/30 transition-colors"
          >
            <span className="text-sm font-medium">Imported Tools in Chat</span>
            <span className="text-xs text-muted-foreground">
              {mcpToolsData.registered_for_agents} tools from {Object.keys(mcpToolsData.servers).length} servers
            </span>
            <ChevronDown className={cn('h-3.5 w-3.5 ml-auto text-muted-foreground transition-transform', showTools ? 'rotate-180' : '')} />
          </button>
          {showTools && (
            <div className="border-t border-border max-h-[400px] overflow-y-auto">
              {Object.entries(mcpToolsData.servers).map(([server, count]) => (
                <div key={server}>
                  <div className="px-4 py-1.5 bg-muted/30 text-xs font-medium flex items-center justify-between">
                    <span>{server}</span>
                    <span className="text-muted-foreground">{count} tools</span>
                  </div>
                  {mcpToolsData.tools.filter(t => t.server === server).map(t => (
                    <div key={t.name} className="px-4 py-1 text-xs flex gap-2 border-t border-border/50">
                      <span className="font-mono font-medium min-w-[180px]">{t.name}</span>
                      <span className="text-muted-foreground truncate">{t.description}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {updateMcpo.isSuccess && (
        <p className="text-xs text-green-500">MCPO config updated. Restart MCPO container to apply changes.</p>
      )}
    </div>
  )
}

function ClaudeDesktopImporter({ onImport }: { onImport: (srv: any) => void }) {
  const [json, setJson] = useState('')
  const [error, setError] = useState('')
  const [nextPort, setNextPort] = useState(9030)
  const { data } = useMcpServers()

  const usedPorts = (data?.servers ?? []).map(s => s.port)

  const handleParse = () => {
    setError('')
    try {
      const parsed = JSON.parse(json)
      // Expect either { "mcpServers": { "name": { ... } } } or { "name": { "command": "...", "args": [...] } }
      const servers = parsed.mcpServers || parsed
      const entries = Object.entries(servers)
      if (entries.length === 0) { setError('No servers found in JSON'); return }

      let port = nextPort
      while (usedPorts.includes(port)) port++

      for (const [name, config] of entries) {
        const cfg = config as any
        const command = cfg.command || ''
        const args = cfg.args || []
        const env = cfg.env || {}

        let source = 'local'
        let pkg = ''
        let path = ''
        if (command === 'npx' || command.includes('npx')) {
          source = 'npm'
          pkg = args[0] || ''
        } else if (command === 'python' || command === 'python3') {
          if (args[0] === '-m') {
            source = 'pip'
            pkg = args[1] || ''
          } else {
            source = 'local'
            path = args[0] || ''
          }
        } else if (command === 'node') {
          source = 'local'
          path = args[0] || ''
        }

        while (usedPorts.includes(port)) port++

        onImport({
          name,
          description: `Imported from Claude Desktop`,
          source,
          package: pkg,
          path,
          transport: 'stdio',
          port,
          env,
          args: source === 'npm' ? args.slice(1) : source === 'pip' ? args.slice(2) : args.slice(1),
          enabled: true,
        })
        port++
      }
      setJson('')
    } catch {
      setError('Invalid JSON — paste the mcpServers block from claude_desktop_config.json')
    }
  }

  return (
    <div className="space-y-2">
      <textarea
        value={json}
        onChange={e => setJson(e.target.value)}
        rows={5}
        className="w-full px-2 py-1.5 text-xs bg-background border border-border rounded font-mono"
        placeholder={'{\n  "mcpServers": {\n    "burpsuite": {\n      "command": "npx",\n      "args": ["@anthropic/burpsuite-mcp"],\n      "env": { "BURP_API_URL": "http://localhost:1337" }\n    }\n  }\n}'}
      />
      <div className="flex items-center gap-2">
        <button onClick={handleParse} disabled={!json.trim()} className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50">
          Import Servers
        </button>
        {error && <span className="text-xs text-red-500">{error}</span>}
      </div>
    </div>
  )
}

// ─── Scan Concurrency Setting ───────────────────────
function ScanConcurrencySetting() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['scan-limits'],
    queryFn: () => apiFetch<{ active: number; max: number; available: number; pending_queue: number }>('/scans/limits'),
  })
  const [maxVal, setMaxVal] = useState<number | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (data?.max != null && maxVal === null) setMaxVal(data.max)
  }, [data?.max])

  const update = useMutation({
    mutationFn: (newMax: number) =>
      apiFetch<{ ok: boolean; max: number }>('/scans/limits', {
        method: 'PUT',
        body: JSON.stringify({ max: newMax }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-limits'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3">Scan Concurrency</h3>
      <div className="space-y-3 max-w-xl">
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Max Concurrent Scans (1–50)</label>
          <div className="flex items-center gap-3">
            <input
              type="number"
              min={1}
              max={50}
              value={maxVal ?? data?.max ?? 5}
              onChange={e => setMaxVal(Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
              className="w-24 bg-muted rounded-md px-3 py-1.5 text-sm border border-border outline-none focus:border-primary"
            />
            <input
              type="range"
              min={1}
              max={20}
              value={maxVal ?? data?.max ?? 5}
              onChange={e => setMaxVal(parseInt(e.target.value))}
              className="flex-1"
            />
            <button
              onClick={() => maxVal != null && update.mutate(maxVal)}
              disabled={update.isPending || maxVal === data?.max}
              className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
            >
              {update.isPending ? 'Saving...' : 'Apply'}
            </button>
            {saved && <span className="text-xs text-green-500">Saved</span>}
          </div>
          <p className="text-[10px] text-muted-foreground mt-1">
            Controls how many scans run simultaneously. Excess scans are queued and auto-dispatched as slots open. Resets to env default on container restart.
          </p>
        </div>
      </div>
    </div>
  )
}

// ─── Scan Profile Selector ──────────────────────────
// ─── Alpha Testing Toggle ───────────────────────────
function AlphaTestingToggle() {
  const { alphaTestingEnabled, setAlphaTesting } = useUIStore()

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold">Alpha Testing Features</h3>
        <label className="flex items-center gap-2 cursor-pointer">
          <span className="text-xs text-muted-foreground">{alphaTestingEnabled ? 'Enabled' : 'Disabled'}</span>
          <button
            onClick={() => setAlphaTesting(!alphaTestingEnabled)}
            className={cn(
              'relative w-10 h-5 rounded-full transition-colors',
              alphaTestingEnabled ? 'bg-primary' : 'bg-muted',
            )}
          >
            <span className={cn(
              'absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',
              alphaTestingEnabled && 'translate-x-5',
            )} />
          </button>
        </label>
      </div>
      <p className="text-[10px] text-muted-foreground mb-3">
        Enable experimental features that are still in development. These may be incomplete or unstable.
      </p>
      <div className="space-y-1">
        {ALPHA_FEATURES.map(f => (
          <div key={f.id} className="flex items-center gap-2 py-0.5">
            <span className={cn(
              'w-2 h-2 rounded-full',
              alphaTestingEnabled ? 'bg-green-500' : 'bg-muted-foreground/30',
            )} />
            <span className={cn('text-xs', alphaTestingEnabled ? 'text-foreground' : 'text-muted-foreground')}>
              {f.label}
            </span>
            {!alphaTestingEnabled && <span className="text-[9px] text-muted-foreground/50">(hidden)</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

function ProfileSelector({ onProfileChange }: { onProfileChange?: (name: string) => void }) {
  const store = useScanDefaultsStore()
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')

  const profileNames = Object.keys(store.profiles)
  const activeP = store.profiles[store.activeProfile]

  const handleSwitch = (name: string) => {
    store.setActiveProfile(name)
    onProfileChange?.(name)
  }

  const handleSave = () => {
    if (!newName.trim()) return
    const key = newName.trim().toLowerCase().replace(/\s+/g, '_')
    store.saveProfile(key, newDesc.trim())
    setShowSaveDialog(false)
    setNewName('')
    setNewDesc('')
  }

  const handleDelete = (name: string) => {
    if (!window.confirm(`Delete profile "${name}"?`)) return
    store.deleteProfile(name)
    onProfileChange?.(store.activeProfile)
  }

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold">Scan Profile</h3>
        <button
          onClick={() => setShowSaveDialog(true)}
          className="px-2.5 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 flex items-center gap-1"
        >
          <Plus className="h-3 w-3" /> Save as New Profile
        </button>
      </div>

      {/* Profile cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-3">
        {profileNames.map(name => {
          const p = store.profiles[name]
          const isActive = store.activeProfile === name
          return (
            <button
              key={name}
              onClick={() => handleSwitch(name)}
              className={cn(
                'text-left p-3 rounded-lg border transition-colors',
                isActive
                  ? 'border-primary bg-primary/10'
                  : 'border-border hover:border-primary/50 hover:bg-accent/30',
              )}
            >
              <div className="flex items-center justify-between">
                <span className={cn('text-sm font-medium', isActive && 'text-primary')}>
                  {name}
                </span>
                <div className="flex items-center gap-1">
                  {isActive && <CheckCircle2 className="h-3.5 w-3.5 text-primary" />}
                  {p.builtin && <span className="text-[9px] text-muted-foreground bg-muted px-1 rounded">built-in</span>}
                  {!p.builtin && (
                    <button
                      onClick={e => { e.stopPropagation(); handleDelete(name) }}
                      className="p-0.5 text-muted-foreground hover:text-red-400"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
              <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{p.description}</p>
              <div className="flex gap-2 mt-1.5 text-[10px] text-muted-foreground">
                <span>Rate: {p.defaults.defaultRate || '—'}</span>
                <span>Ports: {p.defaults.defaultPorts?.slice(0, 20) || '—'}</span>
                <span>ZAP: {p.defaults.zapAttackStrength}</span>
              </div>
            </button>
          )
        })}
      </div>

      {/* Save as new dialog */}
      {showSaveDialog && (
        <div className="border border-border rounded-lg p-3 bg-muted/30 space-y-2">
          <p className="text-xs text-muted-foreground">Save current settings as a new profile:</p>
          <div className="flex gap-2">
            <input
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="Profile name"
              className="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded"
            />
            <input
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              placeholder="Description (optional)"
              className="flex-1 px-2 py-1.5 text-sm bg-background border border-border rounded"
            />
          </div>
          <div className="flex gap-2">
            <button onClick={handleSave} disabled={!newName.trim()} className="px-3 py-1 text-xs bg-primary text-primary-foreground rounded disabled:opacity-50">Save</button>
            <button onClick={() => setShowSaveDialog(false)} className="px-3 py-1 text-xs bg-secondary text-secondary-foreground rounded">Cancel</button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Tool Updates ───────────────────────────────────
function ToolUpdates() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['updatable-tools'],
    queryFn: () => apiFetch<{ tools: Array<{ id: string; label: string; description: string; version: string }> }>('/settings/updatable-tools'),
  })
  const [updating, setUpdating] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, { ok: boolean; message: string }>>({})

  const handleUpdate = async (toolId: string) => {
    setUpdating(toolId)
    try {
      const resp = await apiFetch<{ ok: boolean; stdout?: string; stderr?: string; error?: string }>(`/settings/update-tool/${toolId}`, { method: 'POST' })
      const msg = resp.ok
        ? (resp.stdout || 'Updated successfully').slice(-200)
        : (resp.error || 'Update failed')
      setResults(prev => ({ ...prev, [toolId]: { ok: resp.ok, message: msg } }))
      refetch()
    } catch (e) {
      setResults(prev => ({ ...prev, [toolId]: { ok: false, message: String(e) } }))
    }
    setUpdating(null)
  }

  const tools = data?.tools ?? []
  if (isLoading || tools.length === 0) return null

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold flex items-center gap-1.5">
          <Download className="h-3.5 w-3.5" /> Tool Updates
        </h3>
        <button onClick={() => refetch()} className="text-muted-foreground hover:text-foreground">
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>
      <p className="text-[10px] text-muted-foreground mb-3">Update tool databases and binaries without rebuilding containers.</p>
      <div className="space-y-2">
        {tools.map(tool => (
          <div key={tool.id} className="flex items-center gap-3 p-2 rounded border border-border bg-muted/10">
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium">{tool.label}</div>
              <div className="text-[10px] text-muted-foreground">{tool.description}</div>
              {tool.version && (
                <div className="text-[9px] text-muted-foreground font-mono mt-0.5 truncate">{tool.version.split('\n').pop()}</div>
              )}
            </div>
            <button
              onClick={() => handleUpdate(tool.id)}
              disabled={updating === tool.id}
              className="px-3 py-1.5 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 shrink-0 flex items-center gap-1"
            >
              {updating === tool.id ? <><Loader2 className="h-3 w-3 animate-spin" /> Updating...</> : <><Download className="h-3 w-3" /> Update</>}
            </button>
            {results[tool.id] && (
              <span className={cn('text-[10px] shrink-0', results[tool.id].ok ? 'text-green-500' : 'text-red-500')}>
                {results[tool.id].ok ? 'Done' : 'Failed'}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}


function BurpApiConfig() {
  const { data: status } = useBurpStatus()
  const connected = status?.connected ?? false

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold">Burp Suite REST API</h3>
        <span className={cn(
          'text-[10px] px-2 py-0.5 rounded-full border font-medium',
          connected ? 'text-green-400 border-green-500/30 bg-green-500/10' : 'text-muted-foreground border-border',
        )}>
          {connected ? 'Connected' : 'Not connected'}
        </span>
      </div>
      <p className="text-[10px] text-muted-foreground mb-3">
        Connect to Burp Suite Professional for headless scanning. Set <code className="font-mono bg-muted px-1 rounded">BURP_API_URL</code> and <code className="font-mono bg-muted px-1 rounded">BURP_API_KEY</code> in your environment.
      </p>
      <div className="space-y-2 text-xs text-muted-foreground">
        <div className="bg-muted/30 border border-border rounded p-3 space-y-1.5">
          <p className="font-medium text-foreground">Setup Instructions:</p>
          <ol className="list-decimal list-inside space-y-1">
            <li>Enable Burp REST API: <code className="font-mono bg-muted px-1 rounded text-[10px]">Settings &gt; Suite &gt; REST API &gt; Enable</code></li>
            <li>Note the API port (default 1337) and optionally set an API key</li>
            <li>Set environment variables on the dashboard container:
              <pre className="mt-1 bg-muted rounded p-2 text-[10px] font-mono">BURP_API_URL=http://host.docker.internal:1337{'\n'}BURP_API_KEY=your-api-key-here{'\n'}BURP_PROXY_URL=http://host.docker.internal:8080</pre>
            </li>
            <li>Restart the dashboard container</li>
            <li>Use the <strong>Burp Suite</strong> scan type in the Scan Launcher, or enable <strong>"Route through Burp"</strong> toggle on any web scan</li>
          </ol>
        </div>
        {connected && status?.url && (
          <p className="text-green-400 text-[10px]">Connected to {status.url}</p>
        )}
        {!connected && status?.error && (
          <p className="text-orange-400 text-[10px]">{status.error}</p>
        )}
      </div>
    </div>
  )
}


// ---------- LLM Backend ----------

const LLM_BACKENDS = [
  { value: '', label: 'Default (env var)' },
  { value: 'ollama', label: 'Ollama (local)' },
  { value: 'openai', label: 'OpenAI (ChatGPT)' },
  { value: 'anthropic', label: 'Anthropic (Claude)' },
  { value: 'azure', label: 'Azure OpenAI' },
  { value: 'vllm', label: 'vLLM (local)' },
]

function LlmBackendSection({ backend, onBackendChange }: { backend: string; onBackendChange: (v: string) => void }) {
  const [llmSettings, setLlmSettings] = useState<Record<string, string>>({})
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [azureEndpoint, setAzureEndpoint] = useState('')
  const [testResult, setTestResult] = useState<{ ok: boolean; response?: string; error?: string } | null>(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)

  // Load current settings from server
  useEffect(() => {
    apiFetch<Record<string, string>>('/settings/llm').then(data => {
      setLlmSettings(data)
      if (!backend && data.backend) {
        onBackendChange(data.backend)
      }
    }).catch(() => {})
  }, [])

  // Sync model/key fields when backend changes
  useEffect(() => {
    if (backend === 'openai') {
      setModel(llmSettings.openai_model || 'gpt-4o')
    } else if (backend === 'anthropic') {
      setModel(llmSettings.anthropic_model || 'claude-sonnet-4-20250514')
    } else if (backend === 'azure') {
      setModel(llmSettings.azure_model || 'gpt-4o')
      setAzureEndpoint(llmSettings.azure_endpoint || '')
    }
    setApiKey('')  // never prefill keys
    setTestResult(null)
  }, [backend, llmSettings])

  const handleSaveKeys = async () => {
    setSaving(true)
    try {
      const body: Record<string, string> = { backend }
      if (backend === 'openai') {
        if (apiKey) body.openai_api_key = apiKey
        body.openai_model = model
      } else if (backend === 'anthropic') {
        if (apiKey) body.anthropic_api_key = apiKey
        body.anthropic_model = model
      } else if (backend === 'azure') {
        if (apiKey) body.azure_api_key = apiKey
        body.azure_model = model
        body.azure_endpoint = azureEndpoint
      }
      await apiFetch('/settings/llm', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    } catch { /* ignore */ }
    setSaving(false)
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await apiFetch<{ ok: boolean; response?: string; error?: string; model?: string }>('/settings/llm/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backend: backend || 'ollama' }),
      })
      setTestResult(res)
    } catch (e) {
      setTestResult({ ok: false, error: String(e) })
    }
    setTesting(false)
  }

  const needsApiKey = ['openai', 'anthropic', 'azure'].includes(backend)
  const needsEndpoint = backend === 'azure'

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-1">LLM Backend</h3>
      <p className="text-[10px] text-muted-foreground mb-3">
        Select the LLM provider for the AI chat panel. API keys are stored server-side in the database.
        {llmSettings.env_backend && (
          <span className="ml-1">Current env default: <code className="text-primary">{llmSettings.env_backend}</code></span>
        )}
      </p>

      <div className="space-y-3 max-w-xl">
        {/* Backend Selector */}
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Provider</label>
          <select
            value={backend}
            onChange={e => onBackendChange(e.target.value)}
            className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border"
          >
            {LLM_BACKENDS.map(b => (
              <option key={b.value} value={b.value}>{b.label}</option>
            ))}
          </select>
        </div>

        {/* Model */}
        {needsApiKey && (
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Model</label>
            <input
              value={model}
              onChange={e => setModel(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border font-mono"
              placeholder={backend === 'anthropic' ? 'claude-sonnet-4-20250514' : 'gpt-4o'}
            />
          </div>
        )}

        {/* Azure Endpoint */}
        {needsEndpoint && (
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Azure Endpoint</label>
            <input
              value={azureEndpoint}
              onChange={e => setAzureEndpoint(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border font-mono"
              placeholder="https://your-resource.openai.azure.com"
            />
          </div>
        )}

        {/* API Key */}
        {needsApiKey && (
          <div>
            <label className="block text-xs text-muted-foreground mb-1">
              API Key
              {llmSettings[`${backend === 'azure' ? 'azure' : backend}_api_key`] && (
                <span className="ml-2 text-green-500">(saved: {llmSettings[`${backend === 'azure' ? 'azure' : backend}_api_key`]})</span>
              )}
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              className="w-full bg-muted rounded-md px-3 py-1.5 text-sm border border-border font-mono"
              placeholder="Enter new API key (leave blank to keep existing)"
            />
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2">
          {needsApiKey && (
            <button
              onClick={handleSaveKeys}
              disabled={saving}
              className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-medium disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save API Key & Model'}
            </button>
          )}
          <button
            onClick={handleTest}
            disabled={testing}
            className="px-3 py-1.5 bg-muted border border-border rounded-md text-xs font-medium disabled:opacity-50"
          >
            {testing ? 'Testing...' : 'Test Connection'}
          </button>
        </div>

        {/* Test Result */}
        {testResult && (
          <div className={`text-xs p-2 rounded ${testResult.ok ? 'bg-green-900/30 text-green-300' : 'bg-red-900/30 text-red-300'}`}>
            {testResult.ok ? (
              <span>Connected — response: "{testResult.response}"</span>
            ) : (
              <span>Failed: {testResult.error}</span>
            )}
          </div>
        )}

        {/* Info note */}
        <p className="text-[10px] text-muted-foreground">
          Chat backend changes take effect immediately. Scan recommender and other background services use the env var and require a container restart.
        </p>
      </div>
    </div>
  )
}


/* ── Wordlist Settings ── */
const WORDLIST_KEYS = [
  { key: 'wordlist_usernames', label: 'Usernames', placeholder: '/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt', description: 'Used by hydra, medusa, kerbrute, smtp-user-enum' },
  { key: 'wordlist_passwords', label: 'Passwords', placeholder: '/usr/share/wordlists/rockyou.txt', description: 'Used by hydra, medusa, ncrack, crowbar' },
  { key: 'wordlist_dirs', label: 'Directories', placeholder: '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt', description: 'Used by gobuster, feroxbuster, ffuf, dirsearch' },
  { key: 'wordlist_subdomains', label: 'Subdomains', placeholder: '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt', description: 'Used by subfinder, dnsenum, gobuster dns' },
]

function WordlistSettings() {
  const [paths, setPaths] = useState<Record<string, string>>({})
  const [saved, setSaved] = useState<Record<string, boolean>>({})
  const [checkResults, setCheckResults] = useState<Record<string, { exists: boolean; node: string }[]>>({})
  const [checking, setChecking] = useState(false)

  // Load saved values on mount
  useEffect(() => {
    for (const wl of WORDLIST_KEYS) {
      apiFetch<{ value: string }>(`/settings/config/${wl.key}`).then(
        r => setPaths(prev => ({ ...prev, [wl.key]: r.value }))
      ).catch(() => {})
    }
  }, [])

  const save = async (key: string, value: string) => {
    await apiFetch(`/settings/config/${key}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value }),
    })
    setSaved(prev => ({ ...prev, [key]: true }))
    setTimeout(() => setSaved(prev => ({ ...prev, [key]: false })), 2000)
  }

  const checkFiles = async () => {
    setChecking(true)
    setCheckResults({})
    try {
      const resp = await apiFetch<{ results: Record<string, { exists: boolean; node: string }[]> }>('/wordlist-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paths: Object.fromEntries(
          WORDLIST_KEYS.map(wl => [wl.key, paths[wl.key] || wl.placeholder])
        )}),
      })
      setCheckResults(resp.results || {})
    } catch { /* ignore */ }
    setChecking(false)
  }

  return (
    <div className="border border-border rounded-lg p-4 bg-card space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Wordlist Paths</h3>
          <p className="text-[10px] text-muted-foreground">File paths on remote nodes for brute force and discovery tools. Leave blank for defaults.</p>
        </div>
        <button onClick={checkFiles} disabled={checking}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 disabled:opacity-50">
          {checking ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
          Check on Nodes
        </button>
      </div>
      <div className="space-y-2">
        {WORDLIST_KEYS.map(wl => (
          <div key={wl.key} className="space-y-1">
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium w-24">{wl.label}</label>
              <input
                value={paths[wl.key] || ''}
                onChange={e => setPaths(prev => ({ ...prev, [wl.key]: e.target.value }))}
                onBlur={() => { if (paths[wl.key]) save(wl.key, paths[wl.key]) }}
                placeholder={wl.placeholder}
                className="flex-1 px-2 py-1 text-xs font-mono rounded bg-muted border border-border"
              />
              {saved[wl.key] && <CheckCircle2 size={14} className="text-green-400" />}
            </div>
            <div className="flex items-center gap-2 ml-24 pl-2">
              <span className="text-[10px] text-muted-foreground">{wl.description}</span>
              {checkResults[wl.key]?.map((r, i) => (
                <span key={i} className={cn('text-[10px] px-1 rounded', r.exists ? 'text-green-400 bg-green-500/10' : 'text-red-400 bg-red-500/10')}>
                  {r.node}: {r.exists ? 'found' : 'missing'}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}


// ─── Scan Timeouts Tab ───────────────────────────────
const SCAN_TIMEOUT_FIELDS: { key: string; label: string; help: string }[] = [
  { key: 'scan_timeout_nmap',          label: 'Nmap (after masscan)',    help: 'TCP nmap fallback / batch service detection' },
  { key: 'scan_timeout_nmap_proxied',  label: 'Nmap (via SOCKS proxy)',  help: 'nmap -sT --proxies; usually slowest path' },
  { key: 'scan_timeout_nmap_service',  label: 'Nmap (ad-hoc service)',   help: 'Single-target service / version detection' },
  { key: 'scan_timeout_nmap_udp',      label: 'Nmap UDP scan',           help: 'UDP scans are inherently slow due to filtering' },
  { key: 'scan_timeout_nmap_smb',      label: 'Nmap SMB vuln scripts',   help: 'samba CVE checks on 139/445' },
  { key: 'scan_timeout_nmap_resume',   label: 'Nmap --resume',           help: 'Resume window for picking up an interrupted scan' },
  { key: 'scan_timeout_full',          label: 'Full scan composite',     help: 'Per-batch nmap timeout inside a full scan' },
  { key: 'scan_timeout_masscan',       label: 'Masscan (informational)', help: 'Masscan has no internal timeout — value not enforced' },
]

function ScanTimeoutsTab() {
  type TimeoutResp = { timeouts: Record<string, number>; defaults: Record<string, number> }
  const [data, setData] = useState<TimeoutResp | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  const load = async () => {
    try {
      const r = await apiFetch<TimeoutResp>('/settings/scan-timeouts')
      setData(r)
      setDraft(Object.fromEntries(Object.entries(r.timeouts).map(([k, v]) => [k, String(v)])))
      setMsg(null)
    } catch (e) {
      setMsg({ kind: 'err', text: `Load failed: ${String(e)}` })
    }
  }
  useEffect(() => { load() }, [])

  const save = async () => {
    setSaving(true); setMsg(null)
    try {
      const timeouts: Record<string, number> = {}
      for (const [k, v] of Object.entries(draft)) {
        const n = Number(v)
        if (!Number.isFinite(n) || n < 0) {
          setMsg({ kind: 'err', text: `Invalid value for ${k}: must be integer >=0` })
          setSaving(false)
          return
        }
        timeouts[k] = Math.floor(n)
      }
      await apiFetch('/settings/scan-timeouts', {
        method: 'PUT',
        body: JSON.stringify({ timeouts }),
      })
      setMsg({ kind: 'ok', text: 'Scan timeouts saved.' })
      await load()
    } catch (e) {
      setMsg({ kind: 'err', text: `Save failed: ${String(e)}` })
    } finally {
      setSaving(false)
    }
  }

  const resetToDefaults = () => {
    if (!data) return
    setDraft(Object.fromEntries(Object.entries(data.defaults).map(([k, v]) => [k, String(v)])))
  }

  return (
    <div className="space-y-4">
      <div className="text-xs text-muted-foreground">
        Default subprocess timeouts (seconds) for long-running port scans. <strong>0</strong> means &ldquo;use the
        env-compiled default&rdquo;. Values are persisted in <code>app_settings</code> and consulted by the
        scanner; per-job <code>timeout_seconds</code> on the Launch Scan form still overrides these defaults.
      </div>

      {msg && (
        <div className={cn('text-xs px-3 py-2 rounded border',
          msg.kind === 'ok' ? 'border-green-500/50 text-green-400 bg-green-500/10'
                            : 'border-red-500/50 text-red-400 bg-red-500/10')}>
          {msg.text}
        </div>
      )}

      {!data ? (
        <div className="text-xs text-muted-foreground">Loading…</div>
      ) : (
        <div className="space-y-2">
          {SCAN_TIMEOUT_FIELDS.map(f => (
            <div key={f.key} className="grid grid-cols-[220px_120px_1fr_120px] items-center gap-3">
              <label className="text-sm font-medium" title={f.key}>{f.label}</label>
              <input
                type="number"
                min={0}
                value={draft[f.key] ?? ''}
                onChange={e => setDraft({ ...draft, [f.key]: e.target.value })}
                className="px-2 py-1 text-sm font-mono rounded bg-muted border border-border"
              />
              <span className="text-xs text-muted-foreground">{f.help}</span>
              <span className="text-[10px] text-muted-foreground font-mono text-right">
                default: {data.defaults[f.key] ?? 0}s
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 pt-2">
        <button
          onClick={save}
          disabled={saving || !data}
          className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        <button
          onClick={resetToDefaults}
          disabled={!data}
          className="px-3 py-1.5 text-sm border border-border rounded disabled:opacity-50"
        >
          Reset to defaults
        </button>
      </div>
    </div>
  )
}


// ─── LLM Tuning Tab ─────────────────────────────────
type TuningEntry = { value: number; default: number; min: number; max: number; help: string; source: string }

function LLMTuningTab() {
  const [data, setData] = useState<Record<string, TuningEntry> | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  const load = async () => {
    try {
      const r = await apiFetch<{ tuning: Record<string, TuningEntry> }>('/settings/llm-tuning')
      setData(r.tuning)
      setDraft(Object.fromEntries(Object.entries(r.tuning).map(([k, v]) => [k, String(v.value)])))
      setMsg(null)
    } catch (e) {
      setMsg({ kind: 'err', text: `Load failed: ${String(e)}` })
    }
  }
  useEffect(() => { load() }, [])

  const save = async () => {
    if (!data) return
    setSaving(true); setMsg(null)
    try {
      const tuning: Record<string, number> = {}
      for (const [k, v] of Object.entries(draft)) {
        const n = Number(v)
        const meta = data[k]
        if (!Number.isFinite(n)) {
          setMsg({ kind: 'err', text: `${k}: must be a number` }); setSaving(false); return
        }
        if (meta && (n < meta.min || n > meta.max)) {
          setMsg({ kind: 'err', text: `${k}: must be between ${meta.min} and ${meta.max}` }); setSaving(false); return
        }
        tuning[k] = n
      }
      await apiFetch('/settings/llm-tuning', {
        method: 'PUT', body: JSON.stringify({ tuning }),
      })
      setMsg({ kind: 'ok', text: 'LLM tuning saved. Takes effect within 60s (cache TTL).' })
      await load()
    } catch (e) {
      setMsg({ kind: 'err', text: `Save failed: ${String(e)}` })
    } finally { setSaving(false) }
  }

  const resetToDefaults = () => {
    if (!data) return
    setDraft(Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v.default)])))
  }

  const LABELS: Record<string, { label: string; eli5: string }> = {
    'llm.temperature':    { label: 'Temperature',     eli5: 'How creative vs factual. Lower = sticks to facts. Higher = more creative but may make stuff up.' },
    'llm.top_p':          { label: 'Top P',            eli5: 'How many word choices to consider. Lower = safer picks. 0.85 = considers top 85% probable words.' },
    'llm.top_k':          { label: 'Top K',            eli5: 'Maximum word options at each step. 40 = only pick from the 40 most likely words.' },
    'llm.repeat_penalty': { label: 'Repeat Penalty',   eli5: 'Prevents saying the same thing twice. 1.0 = off. 1.1 = mild penalty. Higher = avoids repetition more.' },
    'llm.num_ctx':        { label: 'Context Window',   eli5: 'How much of the conversation the AI remembers (in tokens). Bigger = remembers more, but uses more RAM.' },
    'llm.num_predict':    { label: 'Max Output',       eli5: 'Maximum length of each reply. 4096 tokens is about 3000 words.' },
    'llm.seed':           { label: 'Seed',             eli5: 'Set to 0 for random output. Set to any other number to get the same answer every time (useful for debugging).' },
  }

  return (
    <div className="space-y-4">
      <div className="text-xs text-muted-foreground space-y-1">
        <p><strong>These settings control how the AI generates responses.</strong> Lower temperature and top_p reduce hallucination (making things up). Higher values produce more creative but less reliable output.</p>
        <p>Changes take effect within 60 seconds. All backends (Ollama, OpenAI, Anthropic, Azure) respect temperature + top_p. Ollama additionally uses top_k, repeat_penalty, num_ctx, and seed.</p>
      </div>

      {msg && (
        <div className={cn('text-xs px-3 py-2 rounded border',
          msg.kind === 'ok' ? 'border-green-500/50 text-green-400 bg-green-500/10'
                            : 'border-red-500/50 text-red-400 bg-red-500/10')}>
          {msg.text}
        </div>
      )}

      {!data ? (
        <div className="text-xs text-muted-foreground">Loading...</div>
      ) : (
        <div className="space-y-3">
          {Object.entries(data).map(([key, meta]) => {
            const info = LABELS[key] || { label: key, eli5: meta.help }
            const isCustom = meta.source === 'custom'
            return (
              <div key={key} className="grid grid-cols-[180px_120px_1fr] items-start gap-3">
                <div>
                  <label className="text-sm font-medium block">{info.label}</label>
                  {isCustom && <span className="text-[9px] text-primary">(customized)</span>}
                </div>
                <div>
                  <input
                    type="number"
                    step={key.includes('temperature') || key.includes('top_p') || key.includes('repeat') ? 0.05 : 1}
                    min={meta.min}
                    max={meta.max}
                    value={draft[key] ?? ''}
                    onChange={e => setDraft({ ...draft, [key]: e.target.value })}
                    className="w-full px-2 py-1 text-sm font-mono rounded bg-muted border border-border"
                  />
                  <div className="text-[9px] text-muted-foreground mt-0.5">
                    range: {meta.min}–{meta.max} | default: {meta.default}
                  </div>
                </div>
                <p className="text-xs text-muted-foreground pt-1">{info.eli5}</p>
              </div>
            )
          })}
        </div>
      )}

      <div className="flex items-center gap-2 pt-2">
        <button onClick={save} disabled={saving || !data}
          className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded disabled:opacity-50">
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button onClick={resetToDefaults} disabled={!data}
          className="px-3 py-1.5 text-sm border border-border rounded disabled:opacity-50">
          Reset to anti-hallucination defaults
        </button>
      </div>

      {/* Per-agent model selection */}
      <div className="pt-6 mt-6 border-t border-border">
        <AgentModelsSection />
      </div>
    </div>
  )
}


// ─── Per-agent model selection (LLM Tuning) ───────────
type AgentModelEntry = {
  id: string
  name: string
  description: string
  current_model: string
  source: string  // 'custom' | 'default' | 'env:NAME'
  default_model: string
  env_chain: string[]
  auto_enabled?: boolean
  auto_capable?: boolean
}

function AgentModelsSection() {
  const [agents, setAgents] = useState<AgentModelEntry[] | null>(null)
  const [available, setAvailable] = useState<string[]>([])
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  const load = async () => {
    try {
      const r = await apiFetch<{ agents: AgentModelEntry[]; available_models: string[] }>(
        '/settings/agent-models'
      )
      setAgents(r.agents)
      setAvailable(r.available_models || [])
      setDraft(Object.fromEntries(r.agents.map(a => [a.id, a.source === 'custom' ? a.current_model : ''])))
    } catch (e) {
      setMsg({ kind: 'err', text: `Load failed: ${String(e)}` })
    }
  }
  useEffect(() => { load() }, [])

  const saveOne = async (agent_id: string) => {
    setSaving(agent_id); setMsg(null)
    try {
      const model = (draft[agent_id] || '').trim()
      await apiFetch(`/settings/agent-models/${agent_id}`, {
        method: 'PUT',
        body: JSON.stringify({ model: model || null }),
      })
      setMsg({ kind: 'ok', text: `Saved model for ${agent_id}` })
      await load()
    } catch (e) {
      setMsg({ kind: 'err', text: `Save failed: ${String(e)}` })
    } finally { setSaving(null) }
  }

  const toggleAuto = async (agent: AgentModelEntry) => {
    const next = !agent.auto_enabled
    if (next) {
      // Confirm before enabling. Vault import writes credentials; cloud
      // triage spends LLM tokens on every ingest. Operator should opt in
      // explicitly so it isn't surprising in a shared environment.
      const note = agent.id === 'vault_import_agent'
        ? 'Vault Import will INSERT credentials into the vault automatically after each MicroBurst ingest. Continue?'
        : agent.id === 'cloud_triage_agent'
        ? 'Cloud Triage will run an LLM call after each ingest to re-rank cloud recommendations. Continue?'
        : `Enable auto-run for ${agent.name}?`
      if (!window.confirm(note)) return
    }
    setSaving(agent.id); setMsg(null)
    try {
      await apiFetch(`/settings/agent-models/${agent.id}/auto`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: next }),
      })
      setMsg({ kind: 'ok', text: `Auto-run ${next ? 'enabled' : 'disabled'} for ${agent.name}` })
      await load()
    } catch (e) {
      setMsg({ kind: 'err', text: `Toggle failed: ${String(e)}` })
    } finally { setSaving(null) }
  }

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-semibold">Agent Models</h3>
        <p className="text-xs text-muted-foreground mt-0.5">
          Pick a different LLM per agent. Empty = use the configured default
          (env var or fallback). Changes take effect immediately for new runs.
          Available models come from your Ollama install.
        </p>
      </div>

      {msg && (
        <div className={cn('text-xs px-3 py-2 rounded border',
          msg.kind === 'ok' ? 'border-green-500/50 text-green-400 bg-green-500/10'
                            : 'border-red-500/50 text-red-400 bg-red-500/10')}>
          {msg.text}
        </div>
      )}

      {!agents ? (
        <div className="text-xs text-muted-foreground">Loading…</div>
      ) : (
        <div className="space-y-2">
          {agents.map(a => {
            const isCustom = a.source === 'custom'
            const draftVal = draft[a.id] ?? ''
            const dirty = (isCustom ? a.current_model : '') !== draftVal
            return (
              <div key={a.id} className="grid grid-cols-[260px_1fr_auto] items-start gap-3 p-3 bg-muted/20 rounded border border-border">
                <div>
                  <label className="text-sm font-medium block">{a.name}</label>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{a.description}</p>
                  <div className="mt-1 flex items-center gap-1 text-[10px]">
                    <span className="text-muted-foreground">resolves to:</span>
                    <span className="font-mono text-primary">{a.current_model}</span>
                    <span className={cn(
                      'px-1 py-0.5 rounded border',
                      a.source === 'custom' ? 'bg-purple-500/15 text-purple-300 border-purple-500/30'
                        : a.source === 'default' ? 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30'
                        : 'bg-blue-500/15 text-blue-400 border-blue-500/30',
                    )}>{a.source}</span>
                  </div>
                  {a.auto_capable && (
                    <div className="mt-2 flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => toggleAuto(a)}
                        disabled={saving === a.id}
                        className={cn(
                          'relative inline-flex h-5 w-9 items-center rounded-full border transition-colors',
                          a.auto_enabled
                            ? 'bg-green-500/30 border-green-500/60'
                            : 'bg-zinc-700/40 border-zinc-600',
                        )}
                        title={a.auto_enabled
                          ? 'Auto-run is ON. Click to disable.'
                          : 'Auto-run is OFF. Click to enable.'}
                      >
                        <span className={cn(
                          'inline-block h-3 w-3 rounded-full bg-white transition-transform',
                          a.auto_enabled ? 'translate-x-5' : 'translate-x-1',
                        )} />
                      </button>
                      <span className="text-[10px] text-muted-foreground">
                        Auto-run {a.auto_enabled ? <span className="text-green-400">on</span> : <span className="text-zinc-500">off</span>}
                        {a.id === 'vault_import_agent' && ' · imports secrets after MicroBurst ingest'}
                        {a.id === 'cloud_triage_agent' && ' · re-ranks recommendations after ingest'}
                      </span>
                    </div>
                  )}
                </div>
                <div>
                  <input
                    type="text"
                    value={draftVal}
                    onChange={e => setDraft(d => ({ ...d, [a.id]: e.target.value }))}
                    placeholder={`(empty = default: ${a.default_model})`}
                    list={`agent-models-${a.id}`}
                    className="w-full px-2 py-1 text-xs bg-card border border-border rounded font-mono"
                  />
                  <datalist id={`agent-models-${a.id}`}>
                    {available.map(m => <option key={m} value={m} />)}
                  </datalist>
                  <p className="text-[10px] text-muted-foreground mt-1">
                    env chain: {a.env_chain.join(' → ')} → default
                  </p>
                </div>
                <button
                  onClick={() => saveOne(a.id)}
                  disabled={saving === a.id || !dirty}
                  className="px-3 py-1 text-xs bg-primary text-primary-foreground rounded disabled:opacity-50 self-start"
                  title={isCustom && !draftVal ? 'Clear override (revert to default)' : 'Save'}
                >
                  {saving === a.id ? 'Saving…' : (isCustom && !draftVal ? 'Clear' : 'Save')}
                </button>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}


// ─── Block Local Scans Toggle ─────────────────────────
function BlockLocalScansToggle() {
  const [blocked, setBlocked] = useState<boolean | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch<{ value: string }>('/settings/config/block_local_scans').catch(() => null)
        setBlocked(r ? r.value?.toLowerCase() === 'true' : false)
      } catch { setBlocked(false) }
    })()
  }, [])

  const toggle = async () => {
    const next = !blocked
    setSaving(true)
    try {
      await apiFetch('/settings/config/block_local_scans', {
        method: 'PUT',
        body: JSON.stringify({ value: String(next) }),
      })
      setBlocked(next)
    } catch { /* ignore */ }
    setSaving(false)
  }

  if (blocked === null) return <span className="text-xs text-muted-foreground">Loading...</span>

  return (
    <div className="flex items-center gap-3">
      <button
        type="button"
        onClick={toggle}
        disabled={saving}
        className={cn(
          'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
          blocked ? 'bg-red-500' : 'bg-muted-foreground/30',
        )}
      >
        <span className={cn(
          'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform',
          blocked ? 'translate-x-4' : 'translate-x-0',
        )} />
      </button>
      <span className={cn('text-sm font-medium', blocked ? 'text-red-400' : 'text-muted-foreground')}>
        {blocked ? 'Blocked — all scans require a proxy/tunnel' : 'Off — scans run directly from local'}
      </span>
    </div>
  )
}


// ─── Exploit Watcher Tab ───────────────────────────────
function ExploitWatcherTab() {
  const { data: settings, isLoading } = useExploitWatcherSettings()
  const updateSettings = useUpdateExploitWatcherSettings()
  const [formData, setFormData] = useState<Partial<ExploitWatcherSettings>>({})
  const [saved, setSaved] = useState<Record<string, boolean>>({})

  useEffect(() => {
    if (settings) {
      setFormData(settings)
    }
  }, [settings])

  const handleSave = async (key: keyof ExploitWatcherSettings, value: any) => {
    try {
      await updateSettings.mutateAsync({ [key]: value })
      setSaved(prev => ({ ...prev, [key]: true }))
      setTimeout(() => setSaved(prev => ({ ...prev, [key]: false })), 2000)
    } catch (error) {
      console.error('Failed to save setting:', error)
    }
  }

  const handleChange = (key: keyof ExploitWatcherSettings, value: any) => {
    setFormData(prev => ({ ...prev, [key]: value }))
  }

  if (isLoading || !formData) {
    return <div className="text-sm text-muted-foreground">Loading exploit watcher settings...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold mb-2">Exploit Watcher Configuration</h3>
        <p className="text-sm text-muted-foreground mb-4">
          Configure the automated exploit recommendation engine. The exploit watcher monitors vulnerabilities and automatically searches for matching exploits from ExploitDB and Metasploit.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Enabled Toggle */}
        <div className="space-y-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.enabled ?? true}
              onChange={(e) => {
                const enabled = e.target.checked
                handleChange('enabled', enabled)
                handleSave('enabled', enabled)
              }}
              className="rounded border-border"
            />
            <div>
              <span className="text-sm font-medium">Enable Exploit Watcher</span>
              {saved.enabled && <CheckCircle2 size={14} className="inline ml-1 text-green-400" />}
            </div>
          </label>
          <p className="text-xs text-muted-foreground ml-6">
            Automatically monitor for new vulnerabilities and suggest exploits
          </p>
        </div>

        {/* Poll Interval */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Poll Interval (seconds)</label>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min="30"
              max="300"
              value={formData.poll_interval ?? 60}
              onChange={(e) => handleChange('poll_interval', parseInt(e.target.value))}
              onBlur={(e) => handleSave('poll_interval', parseInt(e.target.value))}
              className="w-20 px-2 py-1 text-sm rounded bg-muted border border-border"
            />
            {saved.poll_interval && <CheckCircle2 size={14} className="text-green-400" />}
          </div>
          <p className="text-xs text-muted-foreground">
            How often to check for new vulnerabilities (30-300 seconds)
          </p>
        </div>

        {/* Lookback Window */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Lookback Window (minutes)</label>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min="60"
              max="10080"
              value={formData.lookback_minutes ?? 4320}
              onChange={(e) => handleChange('lookback_minutes', parseInt(e.target.value))}
              onBlur={(e) => handleSave('lookback_minutes', parseInt(e.target.value))}
              className="w-24 px-2 py-1 text-sm rounded bg-muted border border-border"
            />
            <span className="text-xs text-muted-foreground">
              ({Math.round((formData.lookback_minutes ?? 4320) / 60)} hours)
            </span>
            {saved.lookback_minutes && <CheckCircle2 size={14} className="text-green-400" />}
          </div>
          <p className="text-xs text-muted-foreground">
            How far back to look for vulnerabilities (1-168 hours)
          </p>
        </div>

        {/* Confidence Threshold */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Minimum Confidence</label>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min="0.1"
              max="1.0"
              step="0.05"
              value={formData.min_confidence ?? 0.35}
              onChange={(e) => handleChange('min_confidence', parseFloat(e.target.value))}
              onBlur={(e) => handleSave('min_confidence', parseFloat(e.target.value))}
              className="w-20 px-2 py-1 text-sm rounded bg-muted border border-border"
            />
            <span className="text-xs text-muted-foreground">
              ({Math.round((formData.min_confidence ?? 0.35) * 100)}%)
            </span>
            {saved.min_confidence && <CheckCircle2 size={14} className="text-green-400" />}
          </div>
          <p className="text-xs text-muted-foreground">
            Minimum confidence score required to suggest an exploit (0.1-1.0)
          </p>
        </div>

        {/* Max Exploits */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Max Exploits per Vulnerability</label>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min="1"
              max="10"
              value={formData.max_exploits_per_vuln ?? 2}
              onChange={(e) => handleChange('max_exploits_per_vuln', parseInt(e.target.value))}
              onBlur={(e) => handleSave('max_exploits_per_vuln', parseInt(e.target.value))}
              className="w-16 px-2 py-1 text-sm rounded bg-muted border border-border"
            />
            {saved.max_exploits_per_vuln && <CheckCircle2 size={14} className="text-green-400" />}
          </div>
          <p className="text-xs text-muted-foreground">
            Maximum number of exploits to suggest per vulnerability (1-10)
          </p>
        </div>
      </div>

      {/* Current Status */}
      <div className="mt-6 p-4 bg-muted/50 rounded-lg">
        <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
          <Shield size={16} />
          Current Configuration Summary
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <span className="text-muted-foreground">Status:</span>
            <div className={cn('font-medium', formData.enabled ? 'text-green-400' : 'text-yellow-400')}>
              {formData.enabled ? 'Enabled' : 'Disabled'}
            </div>
          </div>
          <div>
            <span className="text-muted-foreground">Poll Every:</span>
            <div className="font-medium">{formData.poll_interval}s</div>
          </div>
          <div>
            <span className="text-muted-foreground">Lookback:</span>
            <div className="font-medium">{Math.round((formData.lookback_minutes ?? 4320) / 60)}h</div>
          </div>
          <div>
            <span className="text-muted-foreground">Min Confidence:</span>
            <div className="font-medium">{Math.round((formData.min_confidence ?? 0.35) * 100)}%</div>
          </div>
        </div>
      </div>
    </div>
  )
}


// ─── Node Cleanup Section ─────────────────────────────────
function NodeCleanupSection() {
  const { data: analysis, isLoading, refetch } = useNodeAnalysis()
  const nodeCleanup = useNodeCleanup()
  const [cleanupOptions, setCleanupOptions] = useState<CleanupOptions>({
    remove_offline: false,
    remove_error: false,
    remove_inactive_wg: false,
    remove_orphaned_wg: false
  })
  const [showConfirm, setShowConfirm] = useState(false)
  const [lastResults, setLastResults] = useState<any>(null)

  const handleOptionChange = (key: keyof CleanupOptions, value: boolean) => {
    setCleanupOptions(prev => ({ ...prev, [key]: value }))
  }

  const executeCleanup = async () => {
    if (!Object.values(cleanupOptions).some(Boolean)) {
      return // Nothing selected
    }

    try {
      const results = await nodeCleanup.mutateAsync(cleanupOptions)
      setLastResults(results)
      setShowConfirm(false)
      // Reset options after successful cleanup
      setCleanupOptions({
        remove_offline: false,
        remove_error: false,
        remove_inactive_wg: false,
        remove_orphaned_wg: false
      })
      // Refetch analysis to get updated counts
      refetch()
    } catch (error) {
      console.error('Cleanup failed:', error)
      setLastResults({
        success: [],
        failed: [`Error: ${error}`],
        summary: 'Cleanup operation failed'
      })
      setShowConfirm(false)
    }
  }

  if (isLoading || !analysis) {
    return (
      <div className="space-y-4">
        <div>
          <h3 className="text-base font-semibold mb-2">Node Cleanup & Maintenance</h3>
          <div className="text-sm text-muted-foreground flex items-center gap-2">
            <Loader2 size={16} className="animate-spin" />
            Loading node analysis...
          </div>
        </div>
      </div>
    )
  }

  const hasCleanupNeeded = analysis.offline_count > 0 ||
                          analysis.error_count > 0 ||
                          analysis.inactive_wg_count > 0 ||
                          analysis.orphaned_count > 0

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-base font-semibold mb-2">Node Cleanup & Maintenance</h3>
        <p className="text-sm text-muted-foreground">
          Analyze and clean up problematic remote nodes and WireGuard peers to maintain system health.
        </p>
      </div>

      {/* Analysis Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 p-3 rounded-lg">
          <div className="text-lg font-semibold">{analysis.total_nodes}</div>
          <div className="text-xs text-muted-foreground">Total Nodes</div>
        </div>
        <div className="bg-muted/50 p-3 rounded-lg">
          <div className="text-lg font-semibold">{analysis.total_wg_peers}</div>
          <div className="text-xs text-muted-foreground">WG Peers</div>
        </div>
        <div className="bg-muted/50 p-3 rounded-lg">
          <div className="text-lg font-semibold text-yellow-500">
            {analysis.offline_count + analysis.error_count + analysis.stale_count}
          </div>
          <div className="text-xs text-muted-foreground">Problem Nodes</div>
        </div>
        <div className="bg-muted/50 p-3 rounded-lg">
          <div className="text-lg font-semibold text-orange-500">
            {analysis.inactive_wg_count + analysis.orphaned_count}
          </div>
          <div className="text-xs text-muted-foreground">Problem WG</div>
        </div>
      </div>

      {/* Detailed Status */}
      {hasCleanupNeeded && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium">Issues Found:</h4>
          <div className="grid grid-cols-2 gap-3 text-sm">
            {analysis.offline_count > 0 && (
              <div className="text-yellow-600">• {analysis.offline_count} offline nodes</div>
            )}
            {analysis.error_count > 0 && (
              <div className="text-red-600">• {analysis.error_count} error nodes</div>
            )}
            {analysis.stale_count > 0 && (
              <div className="text-orange-600">• {analysis.stale_count} stale nodes</div>
            )}
            {analysis.inactive_wg_count > 0 && (
              <div className="text-yellow-600">• {analysis.inactive_wg_count} inactive WG peers</div>
            )}
            {analysis.duplicate_count > 0 && (
              <div className="text-blue-600">• {analysis.duplicate_count} duplicate IPs</div>
            )}
            {analysis.orphaned_count > 0 && (
              <div className="text-purple-600">• {analysis.orphaned_count} orphaned WG peers</div>
            )}
          </div>
        </div>
      )}

      {/* Cleanup Options */}
      {hasCleanupNeeded && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium">Cleanup Options:</h4>
          <div className="space-y-2">
            {analysis.offline_count > 0 && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.remove_offline}
                  onChange={(e) => handleOptionChange('remove_offline', e.target.checked)}
                  className="rounded border-border"
                />
                <span className="text-sm">Remove {analysis.offline_count} offline nodes</span>
              </label>
            )}
            {analysis.error_count > 0 && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.remove_error}
                  onChange={(e) => handleOptionChange('remove_error', e.target.checked)}
                  className="rounded border-border"
                />
                <span className="text-sm">Remove {analysis.error_count} error nodes</span>
              </label>
            )}
            {analysis.inactive_wg_count > 0 && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.remove_inactive_wg}
                  onChange={(e) => handleOptionChange('remove_inactive_wg', e.target.checked)}
                  className="rounded border-border"
                />
                <span className="text-sm">Remove {analysis.inactive_wg_count} inactive WireGuard peers</span>
              </label>
            )}
            {analysis.orphaned_count > 0 && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={cleanupOptions.remove_orphaned_wg}
                  onChange={(e) => handleOptionChange('remove_orphaned_wg', e.target.checked)}
                  className="rounded border-border"
                />
                <span className="text-sm">Remove {analysis.orphaned_count} orphaned WireGuard peers</span>
              </label>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowConfirm(true)}
              disabled={!Object.values(cleanupOptions).some(Boolean) || nodeCleanup.isPending}
              className="px-3 py-1.5 bg-red-600 text-white rounded-md text-sm font-medium hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {nodeCleanup.isPending ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Trash2 size={14} />
              )}
              Execute Cleanup
            </button>
            <button
              onClick={() => refetch()}
              className="px-3 py-1.5 bg-muted text-muted-foreground rounded-md text-sm font-medium hover:bg-muted/80 flex items-center gap-2"
            >
              <RefreshCw size={14} />
              Refresh Analysis
            </button>
          </div>
        </div>
      )}

      {!hasCleanupNeeded && (
        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 size={16} className="text-green-600" />
            <span className="text-sm font-medium text-green-600">All nodes and WireGuard peers are healthy!</span>
          </div>
        </div>
      )}

      {/* Confirmation Dialog */}
      {showConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-background border border-border rounded-lg p-6 max-w-md">
            <h3 className="text-lg font-semibold mb-2">Confirm Cleanup</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Are you sure you want to execute the following cleanup operations? This action cannot be undone.
            </p>
            <ul className="text-sm space-y-1 mb-4">
              {cleanupOptions.remove_offline && <li>• Remove offline nodes</li>}
              {cleanupOptions.remove_error && <li>• Remove error nodes</li>}
              {cleanupOptions.remove_inactive_wg && <li>• Remove inactive WireGuard peers</li>}
              {cleanupOptions.remove_orphaned_wg && <li>• Remove orphaned WireGuard peers</li>}
            </ul>
            <div className="flex items-center gap-2 justify-end">
              <button
                onClick={() => setShowConfirm(false)}
                className="px-3 py-1.5 bg-muted text-muted-foreground rounded-md text-sm font-medium hover:bg-muted/80"
              >
                Cancel
              </button>
              <button
                onClick={executeCleanup}
                className="px-3 py-1.5 bg-red-600 text-white rounded-md text-sm font-medium hover:bg-red-700"
              >
                Execute Cleanup
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Last Results */}
      {lastResults && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Last Cleanup Results:</h4>
          <div className="bg-muted/50 rounded-lg p-3 text-sm">
            <div className="font-medium mb-2">{lastResults.summary}</div>
            {lastResults.success?.length > 0 && (
              <div className="text-green-600">
                <div className="font-medium">Success ({lastResults.success.length}):</div>
                <ul className="list-disc ml-4">
                  {lastResults.success.map((item: string, i: number) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            {lastResults.failed?.length > 0 && (
              <div className="text-red-600 mt-2">
                <div className="font-medium">Failed ({lastResults.failed.length}):</div>
                <ul className="list-disc ml-4">
                  {lastResults.failed.map((item: string, i: number) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}


// ─── Settings Search Component ───────────────────────────────
interface SearchResult {
  tab: SettingsTab
  tabLabel: string
  title: string
  description: string
  keywords: string[]
}

function SearchResults({ query, onNavigate }: {
  query: string;
  onNavigate: (tab: SettingsTab) => void
}) {
  const searchTerms = query.toLowerCase().split(' ').filter(Boolean)

  // Define all searchable settings
  const allSettings: SearchResult[] = [
    // General Tab
    {
      tab: 'general',
      tabLabel: 'General',
      title: 'Proxy Configuration',
      description: 'Configure Burp Suite and ZAP proxy settings for scans',
      keywords: ['proxy', 'burp', 'zap', 'http', 'socks', 'tunnel']
    },
    {
      tab: 'general',
      tabLabel: 'General',
      title: 'Docker Host IP',
      description: 'Configure host IP for Docker container communication',
      keywords: ['docker', 'host', 'ip', 'network', 'container']
    },

    // Exploit Watcher Tab
    {
      tab: 'exploit-watcher',
      tabLabel: 'Exploit Watcher',
      title: 'Exploit Confidence Threshold',
      description: 'Minimum confidence required to suggest exploits (0.1-1.0)',
      keywords: ['exploit', 'confidence', 'threshold', 'minimum', 'watcher', 'suggestions']
    },
    {
      tab: 'exploit-watcher',
      tabLabel: 'Exploit Watcher',
      title: 'Max Exploits per Vulnerability',
      description: 'Maximum number of exploits to suggest per vulnerability',
      keywords: ['exploit', 'maximum', 'per', 'vulnerability', 'limit', 'suggestions']
    },
    {
      tab: 'exploit-watcher',
      tabLabel: 'Exploit Watcher',
      title: 'Exploit Poll Interval',
      description: 'How often to check for new vulnerabilities (30-300 seconds)',
      keywords: ['exploit', 'poll', 'interval', 'frequency', 'check', 'scan']
    },
    {
      tab: 'exploit-watcher',
      tabLabel: 'Exploit Watcher',
      title: 'Exploit Lookback Window',
      description: 'How far back to look for vulnerabilities (1-168 hours)',
      keywords: ['exploit', 'lookback', 'window', 'hours', 'timeframe', 'history']
    },
    {
      tab: 'exploit-watcher',
      tabLabel: 'Exploit Watcher',
      title: 'Enable Exploit Watcher',
      description: 'Automatically monitor for new vulnerabilities and suggest exploits',
      keywords: ['exploit', 'enable', 'disable', 'automatic', 'monitoring', 'watcher']
    },

    // API Keys Tab
    {
      tab: 'api-keys',
      tabLabel: 'API Keys',
      title: 'Cloud Provider Keys',
      description: 'Manage API keys for AWS, Azure, GCP, and other cloud providers',
      keywords: ['api', 'keys', 'cloud', 'aws', 'azure', 'gcp', 'credentials']
    },

    // Tool Options Tab
    {
      tab: 'tool-options',
      tabLabel: 'Tool Options',
      title: 'Scan Timeouts',
      description: 'Configure timeout settings for various scanning tools',
      keywords: ['timeout', 'scan', 'tools', 'duration', 'time', 'limit']
    },
    {
      tab: 'tool-options',
      tabLabel: 'Tool Options',
      title: 'Wordlist Paths',
      description: 'Configure wordlist file paths for brute force and discovery tools',
      keywords: ['wordlist', 'paths', 'brute', 'force', 'discovery', 'files']
    },

    // Scan Timeouts Tab
    {
      tab: 'scan-timeouts',
      tabLabel: 'Scan Timeouts',
      title: 'Nmap Timeouts',
      description: 'Configure timeout settings for Nmap scans',
      keywords: ['nmap', 'timeout', 'port', 'scan', 'service', 'detection']
    },
    {
      tab: 'scan-timeouts',
      tabLabel: 'Scan Timeouts',
      title: 'Nuclei Timeouts',
      description: 'Configure timeout settings for Nuclei vulnerability scans',
      keywords: ['nuclei', 'timeout', 'vulnerability', 'template', 'scan']
    },

    // LLM Tuning Tab
    {
      tab: 'llm-tuning',
      tabLabel: 'LLM Tuning',
      title: 'Agent Model Selection',
      description: 'Configure AI models for different agent types',
      keywords: ['llm', 'model', 'agent', 'ai', 'tuning', 'selection', 'gemma', 'qwen']
    },

    // Scope Tab
    {
      tab: 'scope',
      tabLabel: 'Scope',
      title: 'Target Scope',
      description: 'Define in-scope targets and IP ranges for testing',
      keywords: ['scope', 'target', 'ip', 'range', 'cidr', 'domain', 'in-scope']
    },

    // Database Tab
    {
      tab: 'database',
      tabLabel: 'Database',
      title: 'Database Configuration',
      description: 'Manage database settings and maintenance',
      keywords: ['database', 'postgres', 'connection', 'maintenance', 'backup']
    }
  ]

  // Filter settings based on search terms
  const filteredSettings = allSettings.filter(setting => {
    const searchableText = [
      setting.title,
      setting.description,
      setting.tabLabel,
      ...setting.keywords
    ].join(' ').toLowerCase()

    return searchTerms.every(term => searchableText.includes(term))
  })

  const highlightText = (text: string) => {
    let highlightedText = text
    searchTerms.forEach(term => {
      const regex = new RegExp(`(${term})`, 'gi')
      highlightedText = highlightedText.replace(regex, '<mark class="bg-yellow-200 text-yellow-900 px-0.5 rounded">$1</mark>')
    })
    return highlightedText
  }

  if (filteredSettings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>No settings found for "{query}"</p>
        <p className="text-sm mt-1">Try searching for: proxy, exploit, timeout, api, scope, model</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="text-sm text-muted-foreground">
        Found {filteredSettings.length} setting{filteredSettings.length !== 1 ? 's' : ''} matching "{query}"
      </div>

      {filteredSettings.map((setting, index) => (
        <div
          key={index}
          onClick={() => onNavigate(setting.tab)}
          className="p-3 border border-border rounded-lg cursor-pointer hover:border-primary/50 transition-colors"
        >
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="font-medium"
                  dangerouslySetInnerHTML={{ __html: highlightText(setting.title) }}
                />
                <span className="px-2 py-0.5 text-xs bg-muted rounded text-muted-foreground">
                  {setting.tabLabel}
                </span>
              </div>
              <p
                className="text-sm text-muted-foreground"
                dangerouslySetInnerHTML={{ __html: highlightText(setting.description) }}
              />
            </div>
            <ArrowRightLeft className="h-4 w-4 text-muted-foreground ml-2" />
          </div>
        </div>
      ))}
    </div>
  )
}
