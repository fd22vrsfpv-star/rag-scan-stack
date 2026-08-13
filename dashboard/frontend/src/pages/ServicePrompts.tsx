import { useState } from 'react'
import PageHelp from '@/components/PageHelp'
import {
  useServicePrompts, useResolvePrompts,
  useCreateServicePrompt, useUpdateServicePrompt, useDeleteServicePrompt,
  describeSelector,
  type ServicePrompt, type ServicePromptInput, type SelectorType,
} from '@/api/servicePrompts'
import { useKBServices } from '@/api/kb'
import { WalkthroughDraftPanel } from '@/components/common/WalkthroughDraftPanel'
import { cn } from '@/lib/utils'
import { Plus, Trash2, Pencil, FlaskConical, BookOpen, X } from 'lucide-react'

const SELECTOR_LABELS: Record<SelectorType, string> = {
  port_service: 'Service on port',
  tech: 'Technology',
  port: 'Port',
  service: 'Service',
}

// Technologies the knowledge base already recognises from httpx/whatweb output
// (knowledge/service_tools.yaml → tech_signatures). Offered as suggestions, not
// a closed list — a rule for anything else still resolves if detection reports it.
const KNOWN_TECH = [
  'wordpress', 'drupal', 'joomla', 'magento', 'tomcat', 'jboss', 'weblogic',
  'jenkins', 'gitlab', 'grafana', 'phpmyadmin', 'jira', 'confluence',
  'springboot', 'iis', 'apache', 'nginx',
]

const EMPTY: ServicePromptInput = {
  selector_type: 'service',
  title: '',
  prompt: '',
  service: '',
  tech: '',
  port: null,
  training_notes: '',
  priority: 100,
  enabled: true,
}

/* ────────────── Editor modal ────────────── */

function PromptEditor({ existing, onClose }: { existing: ServicePrompt | null; onClose: () => void }) {
  const create = useCreateServicePrompt()
  const update = useUpdateServicePrompt()
  const { data: kbServices } = useKBServices()
  const [err, setErr] = useState('')
  const [form, setForm] = useState<ServicePromptInput>(
    existing
      ? {
          selector_type: existing.selector_type,
          title: existing.title,
          prompt: existing.prompt,
          service: existing.service ?? '',
          tech: existing.tech ?? '',
          port: existing.port,
          training_notes: existing.training_notes ?? '',
          priority: existing.priority,
          enabled: existing.enabled,
        }
      : { ...EMPTY },
  )

  const needsService = form.selector_type === 'service' || form.selector_type === 'port_service'
  const needsPort = form.selector_type === 'port' || form.selector_type === 'port_service'
  const needsTech = form.selector_type === 'tech'
  const busy = create.isPending || update.isPending

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    const body: ServicePromptInput = {
      ...form,
      service: needsService ? (form.service || '').trim().toLowerCase() : null,
      tech: needsTech ? (form.tech || '').trim().toLowerCase() : null,
      port: needsPort ? Number(form.port) || null : null,
    }
    try {
      if (existing) await update.mutateAsync({ id: existing.id, body })
      else await create.mutateAsync(body)
      onClose()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <form onSubmit={submit}
        className="bg-card border border-border rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border sticky top-0 bg-card">
          <h3 className="font-semibold text-sm">{existing ? 'Edit rule' : 'New rule'}</h3>
          <button type="button" onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-4 space-y-3">
          <div className="flex gap-3 flex-wrap">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Applies to</label>
              <select
                value={form.selector_type}
                onChange={e => setForm(f => ({ ...f, selector_type: e.target.value as SelectorType }))}
                className="bg-muted rounded px-2 py-1.5 text-sm border border-border"
              >
                {(Object.keys(SELECTOR_LABELS) as SelectorType[]).map(k => (
                  <option key={k} value={k}>{SELECTOR_LABELS[k]}</option>
                ))}
              </select>
            </div>
            {needsService && (
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Service</label>
                <input
                  list="kb-service-names" required
                  value={form.service ?? ''}
                  onChange={e => setForm(f => ({ ...f, service: e.target.value }))}
                  placeholder="http"
                  className="bg-muted rounded px-2 py-1.5 text-sm border border-border w-40"
                />
                <datalist id="kb-service-names">
                  {(kbServices?.services ?? []).map(s => <option key={s.name} value={s.name} />)}
                </datalist>
              </div>
            )}
            {needsTech && (
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Technology</label>
                <input
                  list="known-tech-names" required
                  value={form.tech ?? ''}
                  onChange={e => setForm(f => ({ ...f, tech: e.target.value }))}
                  placeholder="wordpress"
                  className="bg-muted rounded px-2 py-1.5 text-sm border border-border w-44"
                />
                <datalist id="known-tech-names">
                  {KNOWN_TECH.map(t => <option key={t} value={t} />)}
                </datalist>
              </div>
            )}
            {needsPort && (
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Port</label>
                <input
                  type="number" min={1} max={65535} required
                  value={form.port ?? ''}
                  onChange={e => setForm(f => ({ ...f, port: Number(e.target.value) }))}
                  placeholder="8080"
                  className="bg-muted rounded px-2 py-1.5 text-sm border border-border w-28"
                />
              </div>
            )}
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Priority</label>
              <input
                type="number"
                value={form.priority ?? 100}
                onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))}
                title="Lower runs first among rules of the same specificity"
                className="bg-muted rounded px-2 py-1.5 text-sm border border-border w-24"
              />
            </div>
            <label className="flex items-center gap-2 text-sm self-end pb-1.5">
              <input type="checkbox" checked={form.enabled ?? true}
                onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
                className="rounded border-border" />
              Enabled
            </label>
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Title</label>
            <input
              required value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              placeholder="Internal 8080 apps"
              className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              Prompt — injected into the AI's tool-selection context
            </label>
            <textarea
              rows={4} value={form.prompt}
              onChange={e => setForm(f => ({ ...f, prompt: e.target.value }))}
              placeholder="Port 8080 here is internal Tomcat. Always probe /manager/html and try default creds before any nuclei run."
              className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border font-mono text-xs"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground mb-1 block">
              Training notes (markdown, optional) — indexed into the knowledge base and
              retrieved as context when this service is found
            </label>
            <textarea
              rows={6} value={form.training_notes ?? ''}
              onChange={e => setForm(f => ({ ...f, training_notes: e.target.value }))}
              placeholder={'## Tomcat on 8080\n- Check /manager/html and /host-manager/html\n- Default creds: tomcat:tomcat, admin:admin'}
              className="w-full bg-muted rounded px-2 py-1.5 text-sm border border-border font-mono text-xs"
            />
          </div>

          {err && <p className="text-xs text-red-400 break-words">{err}</p>}
        </div>

        <div className="flex justify-end gap-2 px-4 py-3 border-t border-border sticky bottom-0 bg-card">
          <button type="button" onClick={onClose}
            className="px-3 py-1.5 text-xs border border-border rounded">Cancel</button>
          <button type="submit" disabled={busy}
            className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded disabled:opacity-50">
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </div>
  )
}

/* ────────────── Test panel ────────────── */

function TestPanel() {
  const [service, setService] = useState('http')
  const [port, setPort] = useState('8080')
  const [tech, setTech] = useState('')
  const [run, setRun] = useState(false)
  const { data, isFetching } = useResolvePrompts(service, port, tech, run)

  return (
    <div className="bg-card border border-border rounded-lg p-3 space-y-2">
      <h3 className="text-sm font-semibold flex items-center gap-1.5">
        <FlaskConical className="h-4 w-4" /> Test what the AI would receive
      </h3>
      <p className="text-xs text-muted-foreground">
        Runs the exact same resolution the AI uses, so this is what actually gets injected —
        not an approximation. Technology is normally detected from httpx/whatweb output;
        enter it here to preview what a web scan against that stack would receive.
      </p>
      <div className="flex gap-2 items-end flex-wrap">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Service</label>
          <input value={service} onChange={e => setService(e.target.value)} placeholder="http"
            className="bg-muted rounded px-2 py-1 text-sm border border-border w-32" />
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Port</label>
          <input value={port} onChange={e => setPort(e.target.value)} placeholder="8080"
            className="bg-muted rounded px-2 py-1 text-sm border border-border w-24" />
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">
            Technology <span className="text-[9px]">(comma-sep)</span>
          </label>
          <input value={tech} onChange={e => setTech(e.target.value)} placeholder="wordpress"
            className="bg-muted rounded px-2 py-1 text-sm border border-border w-40" />
        </div>
        <button onClick={() => setRun(true)} disabled={!service && !port && !tech}
          className="px-3 py-1 text-xs bg-primary text-primary-foreground rounded disabled:opacity-50">
          {isFetching ? 'Resolving…' : 'Resolve'}
        </button>
      </div>

      {run && data && (
        <div className="space-y-2 pt-1">
          <p className="text-xs text-muted-foreground">
            {data.matched.length} rule{data.matched.length === 1 ? '' : 's'} matched
            {data.matched.length > 1 && ' (most specific first)'}
          </p>
          {data.guidance_block ? (
            <pre className="bg-muted/50 rounded p-2 text-[10px] whitespace-pre-wrap overflow-x-auto max-h-48">
              {data.guidance_block.trim()}
            </pre>
          ) : (
            <p className="text-xs text-muted-foreground italic">
              No rules match — the AI's prompt is unchanged for this service/port.
            </p>
          )}
          {data.training_context && (
            <pre className="bg-muted/50 rounded p-2 text-[10px] whitespace-pre-wrap overflow-x-auto max-h-48">
              {data.training_context.trim()}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

/* ────────────── Page ────────────── */

export default function ServicePrompts() {
  const { data, isLoading } = useServicePrompts()
  const del = useDeleteServicePrompt()
  const [editing, setEditing] = useState<ServicePrompt | null>(null)
  const [showEditor, setShowEditor] = useState(false)

  const prompts = data?.prompts ?? []

  const openNew = () => { setEditing(null); setShowEditor(true) }
  const openEdit = (p: ServicePrompt) => { setEditing(p); setShowEditor(true) }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-semibold">Service Prompts</h1>
          <p className="text-xs text-muted-foreground">
            Teach the AI what to do for specific ports and services
          </p>
        </div>
        <button onClick={openNew}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs">
          <Plus className="h-3 w-3" /> New rule
        </button>
      </div>

      <PageHelp id="service-prompts" title="How service prompts work">
        <ul className="list-disc pl-4 space-y-0.5">
          <li><strong>Prompts steer tool selection</strong> — when the AI decides which scans to run
            against a discovered service, any matching rule is injected into its context and
            overrides the general rules.</li>
          <li><strong>Training notes become retrievable knowledge</strong> — markdown you write here
            is chunked, embedded, and stored in the knowledge base, then retrieved whenever that
            service or port is seen.</li>
          <li><strong>Most specific wins</strong> — a “service on port” rule is applied ahead of a
            “port” rule, which is applied ahead of a “service” rule. All matching rules are
            included, so broad and narrow guidance compose rather than one hiding the other.
            Priority only breaks ties within the same specificity (lower runs first).</li>
          <li><strong>No rules means no change</strong> — services you haven’t written rules for
            behave exactly as before.</li>
          <li><strong>Worked example</strong> — “SNMP on 161” as a <em>service on port</em> rule
            telling the AI to try default community strings before anything else, plus a broader
            “SNMP anywhere” <em>service</em> rule that still fires when SNMP turns up on a
            non-standard port. Both are injected, most specific first. See
            {' '}<code>knowledge/seed_prompts.example.yaml</code>.</li>
          <li><strong>Bulk loading</strong> — <code>./scripts/import-knowledge.sh --file seed.yaml</code>
            {' '}creates or updates rules and training docs from one file, so re-running is safe.
            Add <code>--dry-run</code> to preview what would change.</li>
          <li><strong>Drafting from a walkthrough</strong> — the panel above (or
            {' '}<code>./scripts/walkthrough-to-seed.sh writeup.md</code>) reads a lab writeup and
            extracts the technique that would still apply to a <em>different</em> host. It never
            writes directly: proposals containing anything box-specific — credentials, flag values,
            hashes, lab IPs — arrive flagged and unticked. Vendor defaults often trip that check
            legitimately, so read the reason before discarding. Steer what it extracts with the
            Extraction prompt editor (it governs URL imports too), or a per-run focus.</li>
        </ul>
      </PageHelp>

      {/* Collapsed by default — drafting is occasional, testing is routine. */}
      <details className="bg-card border border-border rounded-lg">
        <summary className="px-3 py-2 text-xs font-semibold cursor-pointer hover:bg-muted/30">
          Draft rules from a walkthrough or URL
        </summary>
        <div className="p-2 pt-0">
          <WalkthroughDraftPanel />
        </div>
      </details>

      <TestPanel />

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        {isLoading ? (
          <p className="p-4 text-xs text-muted-foreground">Loading…</p>
        ) : prompts.length === 0 ? (
          <div className="p-6 text-center space-y-2">
            <BookOpen className="h-6 w-6 mx-auto text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No rules yet.</p>
            <p className="text-xs text-muted-foreground">
              Add one to give the AI specific instructions for a port or service.
            </p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-muted/30">
              <tr className="border-b border-border text-left">
                <th className="px-3 py-2 font-medium">Applies to</th>
                <th className="px-3 py-2 font-medium">Title</th>
                <th className="px-3 py-2 font-medium">Prompt</th>
                <th className="px-3 py-2 font-medium w-20">Priority</th>
                <th className="px-3 py-2 font-medium w-24">Training</th>
                <th className="px-3 py-2 font-medium w-20">Status</th>
                <th className="px-3 py-2 font-medium w-20"></th>
              </tr>
            </thead>
            <tbody>
              {prompts.map(p => (
                <tr key={p.id} className="border-b border-border/50 hover:bg-muted/20">
                  <td className="px-3 py-2 font-mono text-[11px] whitespace-nowrap">
                    {describeSelector(p)}
                  </td>
                  <td className="px-3 py-2">{p.title}</td>
                  <td className="px-3 py-2 text-muted-foreground max-w-md truncate" title={p.prompt}>
                    {p.prompt}
                  </td>
                  <td className="px-3 py-2">{p.priority}</td>
                  <td className="px-3 py-2">
                    {p.training_notes ? (
                      <span className={cn(
                        'px-1.5 py-0.5 rounded text-[10px]',
                        p.rag_ingested_at
                          ? 'bg-green-500/10 text-green-400'
                          : 'bg-yellow-500/10 text-yellow-400',
                      )} title={p.rag_ingested_at
                        ? `Indexed ${p.rag_ingested_at}`
                        : 'Saved, but not yet indexed into the knowledge base'}>
                        {p.rag_ingested_at ? 'indexed' : 'pending'}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className={cn(
                      'px-1.5 py-0.5 rounded text-[10px]',
                      p.enabled ? 'bg-green-500/10 text-green-400' : 'bg-muted text-muted-foreground',
                    )}>
                      {p.enabled ? 'enabled' : 'disabled'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 justify-end">
                      <button onClick={() => openEdit(p)} title="Edit"
                        className="p-1 hover:text-primary"><Pencil className="h-3 w-3" /></button>
                      <button
                        onClick={() => {
                          if (confirm(`Delete rule "${p.title}"?${p.training_notes ? '\n\nIts training notes will also be removed from the knowledge base.' : ''}`)) {
                            del.mutate(p.id)
                          }
                        }}
                        title="Delete"
                        className="p-1 hover:text-destructive"><Trash2 className="h-3 w-3" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showEditor && (
        <PromptEditor existing={editing} onClose={() => { setShowEditor(false); setEditing(null) }} />
      )}
    </div>
  )
}
