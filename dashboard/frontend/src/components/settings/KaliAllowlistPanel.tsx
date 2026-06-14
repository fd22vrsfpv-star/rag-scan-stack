import { useEffect, useState } from 'react'
import { ShieldCheck, Loader2, Save } from 'lucide-react'
import InfoTip from '@/components/InfoTip'

/**
 * Settings panel for the Kali tool allowlist. The effective list comes from the
 * node_manager registry + fallback set; operators can ADD tools (extra) or
 * REMOVE tools (deny) here without a code change/rebuild. Persisted in
 * app_settings.kali_tool_allowlist; the Kali listener picks it up within ~60s.
 * Metasploit can't be added (always denied for safety).
 */
export default function KaliAllowlistPanel() {
  const [allowed, setAllowed] = useState<string[]>([])
  const [extra, setExtra] = useState('')
  const [deny, setDeny] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const [a, cfg] = await Promise.all([
        fetch('/api/tools/allowed').then(r => r.json()).catch(() => ({})),
        fetch('/api/settings/config/kali_tool_allowlist').then(r => r.json()).catch(() => ({})),
      ])
      setAllowed((a?.tools || []).slice().sort())
      let parsed: { extra?: string[]; deny?: string[] } = {}
      try { parsed = cfg?.value ? JSON.parse(cfg.value) : {} } catch { parsed = {} }
      setExtra((parsed.extra || []).join(', '))
      setDeny((parsed.deny || []).join(', '))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setSaving(true)
    setMsg(null)
    const toList = (s: string) =>
      s.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
    try {
      const value = JSON.stringify({ extra: toList(extra), deny: toList(deny) })
      const r = await fetch('/api/settings/config/kali_tool_allowlist', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setMsg('Saved — the Kali listener applies it within ~60s.')
      setTimeout(load, 1500)
    } catch (e) {
      setMsg(`Save failed: ${String(e)}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-4 h-4 text-green-400" />
        <h3 className="text-sm font-semibold inline-flex items-center gap-1">
          Kali Tool Allowlist
          <InfoTip side="bottom" text={
            <>
              Tools the internal Kali container is allowed to install/run. The base
              list is the node_manager registry + fallback set. Add ad-hoc tools in
              <b> Allow</b> (installed via <code>apt</code> by name) or block tools in
              <b> Deny</b> — no code change or rebuild. Metasploit is always denied
              (it runs in its own container via the Exploit Manager).
            </>
          } />
        </h3>
        <span className="text-xs text-muted-foreground ml-auto">
          {loading ? '' : `${allowed.length} allowed`}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label className="text-xs text-muted-foreground space-y-1">
          <span className="flex items-center gap-1">Allow (add) — comma separated
            <InfoTip text="Extra tools to allow beyond the registry, e.g. enum4linux-ng, lftp. Installed via apt by name on demand." />
          </span>
          <input
            value={extra}
            onChange={e => setExtra(e.target.value)}
            placeholder="enum4linux-ng, lftp, impacket-smbclient"
            className="w-full h-8 px-2 rounded border border-border bg-background text-foreground font-mono text-xs"
          />
        </label>
        <label className="text-xs text-muted-foreground space-y-1">
          <span className="flex items-center gap-1">Deny (block) — comma separated
            <InfoTip text="Tools to remove from the allowlist even if the registry has them." />
          </span>
          <input
            value={deny}
            onChange={e => setDeny(e.target.value)}
            placeholder="sqlmap"
            className="w-full h-8 px-2 rounded border border-border bg-background text-foreground font-mono text-xs"
          />
        </label>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          Save allowlist
        </button>
        {msg && <span className="text-xs text-muted-foreground">{msg}</span>}
      </div>

      {!loading && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer hover:text-foreground">Effective allowlist ({allowed.length})</summary>
          <div className="mt-2 flex flex-wrap gap-1">
            {allowed.map(t => (
              <span key={t} className="px-1.5 py-0.5 rounded bg-muted/50 border border-border font-mono">{t}</span>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}
