import { useState } from 'react'
import {
  useKBServices,
  useKBService,
  useUpsertKBService,
  useDeleteKBOverride,
  type KBServiceSummary,
} from '@/api/kb'

function SourceBadge({ source }: { source: string }) {
  const colors: Record<string, string> = {
    yaml: 'bg-blue-500/20 text-blue-400',
    override: 'bg-amber-500/20 text-amber-400',
    both: 'bg-green-500/20 text-green-400',
  }
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${colors[source] || 'bg-muted text-muted-foreground'}`}>
      {source}
    </span>
  )
}

function ServiceDetail({ name, onClose }: { name: string; onClose: () => void }) {
  const { data, isLoading } = useKBService(name)
  const deleteMut = useDeleteKBOverride()

  if (isLoading) return <p className="text-sm text-muted-foreground p-4">Loading...</p>
  if (!data) return <p className="text-sm text-muted-foreground p-4">Not found</p>

  const d = data.data
  return (
    <div className="border border-border rounded-lg bg-card p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-bold">{data.name}</h3>
          <SourceBadge source={data.source} />
        </div>
        <div className="flex gap-2">
          {(data.source === 'override' || data.source === 'both') && (
            <button
              onClick={() => { deleteMut.mutate(name); onClose() }}
              className="text-xs px-2 py-1 rounded border border-border hover:bg-destructive/20 text-destructive"
            >
              Remove Override
            </button>
          )}
          <button onClick={onClose} className="text-xs px-2 py-1 rounded border border-border hover:bg-accent">
            Close
          </button>
        </div>
      </div>

      {d.description && <p className="text-xs text-muted-foreground">{d.description}</p>}

      {d.ports && d.ports.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Ports</h4>
          <div className="flex flex-wrap gap-1">
            {d.ports.map(p => (
              <span key={p} className="px-1.5 py-0.5 bg-muted rounded text-xs font-mono">{p}</span>
            ))}
          </div>
        </div>
      )}

      {d.tools && d.tools.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Tools ({d.tools.length})</h4>
          <div className="space-y-1">
            {d.tools.map((t, i) => (
              <div key={i} className="text-xs bg-muted/30 rounded p-2">
                <span className="font-medium">{t.name}</span>
                {t.purpose && <span className="text-muted-foreground"> &mdash; {t.purpose}</span>}
                {t.command && (
                  <pre className="mt-1 text-[11px] font-mono text-primary bg-muted/50 rounded px-2 py-1 overflow-x-auto">
                    {t.command}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {d.metasploit && d.metasploit.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Metasploit Modules ({d.metasploit.length})</h4>
          <div className="space-y-1">
            {d.metasploit.map((m, i) => (
              <div key={i} className="text-xs bg-muted/30 rounded p-2">
                <code className="font-mono text-primary">{m.module}</code>
                {m.purpose && <span className="text-muted-foreground ml-2">{m.purpose}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {d.nuclei_tags && d.nuclei_tags.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Nuclei Tags</h4>
          <div className="flex flex-wrap gap-1">
            {d.nuclei_tags.map(t => (
              <span key={t} className="px-1.5 py-0.5 bg-primary/10 text-primary rounded text-xs">{t}</span>
            ))}
          </div>
        </div>
      )}

      {d.common_vulns && d.common_vulns.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold mb-1">Common Vulnerabilities</h4>
          <div className="space-y-1">
            {d.common_vulns.map((v, i) => (
              <div key={i} className="text-xs text-muted-foreground">
                {typeof v === 'string' ? v : JSON.stringify(v)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function AddServiceForm({ onDone }: { onDone: () => void }) {
  const upsert = useUpsertKBService()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [ports, setPorts] = useState('')
  const [toolName, setToolName] = useState('')
  const [toolCmd, setToolCmd] = useState('')
  const [toolPurpose, setToolPurpose] = useState('')
  const [tools, setTools] = useState<{ name: string; command: string; purpose: string }[]>([])

  const addTool = () => {
    if (!toolName) return
    setTools(prev => [...prev, { name: toolName, command: toolCmd, purpose: toolPurpose }])
    setToolName('')
    setToolCmd('')
    setToolPurpose('')
  }

  const submit = () => {
    if (!name.trim()) return
    const parsedPorts = ports
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p))
    upsert.mutate(
      {
        name: name.trim().toLowerCase(),
        data: {
          description: desc,
          ports: parsedPorts,
          tools,
          metasploit: [],
          nuclei_tags: [],
          common_vulns: [],
        },
      },
      { onSuccess: onDone },
    )
  }

  return (
    <div className="border border-border rounded-lg bg-card p-4 space-y-3">
      <h3 className="text-sm font-bold">Add New Service</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <input
          placeholder="Service name (e.g. redis)"
          value={name}
          onChange={e => setName(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
        <input
          placeholder="Ports (e.g. 6379)"
          value={ports}
          onChange={e => setPorts(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
        <input
          placeholder="Description"
          value={desc}
          onChange={e => setDesc(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-xs"
        />
      </div>

      {/* Inline add tool */}
      <div className="border-t border-border pt-2">
        <p className="text-xs font-medium mb-1">Tools</p>
        <div className="flex gap-1 flex-wrap">
          {tools.map((t, i) => (
            <span key={i} className="px-1.5 py-0.5 bg-muted rounded text-xs">
              {t.name}
              <button onClick={() => setTools(prev => prev.filter((_, idx) => idx !== i))} className="ml-1 text-destructive">&times;</button>
            </span>
          ))}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-1 mt-1">
          <input placeholder="Tool name" value={toolName} onChange={e => setToolName(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <input placeholder="Command" value={toolCmd} onChange={e => setToolCmd(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <input placeholder="Purpose" value={toolPurpose} onChange={e => setToolPurpose(e.target.value)}
            className="h-7 rounded border border-border bg-background px-2 text-xs" />
          <button onClick={addTool}
            className="h-7 px-2 text-xs rounded border border-border hover:bg-accent">Add Tool</button>
        </div>
      </div>

      <div className="flex gap-2 pt-1">
        <button onClick={submit} disabled={upsert.isPending || !name.trim()}
          className="h-8 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
          Save Service
        </button>
        <button onClick={onDone}
          className="h-8 px-3 text-xs rounded-md border border-border hover:bg-accent">
          Cancel
        </button>
      </div>
    </div>
  )
}

export default function KnowledgeBase() {
  const { data, isLoading } = useKBServices()
  const [selected, setSelected] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [search, setSearch] = useState('')

  const services = (data?.services || []).filter(
    s =>
      !search ||
      s.name.includes(search.toLowerCase()) ||
      s.description.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Knowledge Base</h2>
        <div className="flex items-center gap-2">
          <input
            placeholder="Search services..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-8 w-48 rounded-md border border-border bg-background px-2 text-xs"
          />
          <button
            onClick={() => { setShowAdd(true); setSelected(null) }}
            className="h-8 px-3 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/90"
          >
            Add Service
          </button>
        </div>
      </div>

      {showAdd && <AddServiceForm onDone={() => setShowAdd(false)} />}
      {selected && <ServiceDetail name={selected} onClose={() => setSelected(null)} />}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        {isLoading ? (
          <p className="text-sm text-muted-foreground p-4">Loading knowledge base...</p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-3 py-2 font-medium">Service</th>
                <th className="text-left px-3 py-2 font-medium">Ports</th>
                <th className="text-center px-3 py-2 font-medium">Tools</th>
                <th className="text-center px-3 py-2 font-medium">MSF</th>
                <th className="text-center px-3 py-2 font-medium">Nuclei</th>
                <th className="text-left px-3 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {services.map((svc: KBServiceSummary) => (
                <tr
                  key={svc.name}
                  onClick={() => { setSelected(svc.name); setShowAdd(false) }}
                  className="border-b border-border hover:bg-muted/20 cursor-pointer"
                >
                  <td className="px-3 py-2 font-medium">{svc.name}</td>
                  <td className="px-3 py-2 text-muted-foreground font-mono">
                    {svc.ports.slice(0, 5).join(', ')}{svc.ports.length > 5 ? '...' : ''}
                  </td>
                  <td className="px-3 py-2 text-center">{svc.tool_count}</td>
                  <td className="px-3 py-2 text-center">{svc.msf_count}</td>
                  <td className="px-3 py-2 text-center">{svc.nuclei_tags.length}</td>
                  <td className="px-3 py-2"><SourceBadge source={svc.source} /></td>
                </tr>
              ))}
              {services.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-muted-foreground">
                    {search ? 'No services match your search' : 'No services loaded'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {data?.count ?? 0} services loaded from YAML knowledge base + database overrides
      </p>
    </div>
  )
}
