import { useRef, useState } from 'react'
import {
  useConvertWalkthrough, useCreateServicePrompt,
  useWalkthroughPrompt, useSetWalkthroughPrompt, useConvertUrl,
  type ServicePromptInput, type WalkthroughConversion, type UrlConversion,
} from '@/api/servicePrompts'
import { cn } from '@/lib/utils'
import { Wand2, Upload, AlertTriangle, Settings2, X, Link2, Download } from 'lucide-react'

/**
 * Draft rules from a pentest walkthrough.
 *
 * Nothing is written until the operator ticks an entry and clicks Accept.
 * Entries the backend flagged as possibly box-specific (credentials, flags,
 * lab IPs) start UNCHECKED with their reason shown — the whole point of the
 * review gate is that this content steers live scanning.
 */
export function WalkthroughDraftPanel() {
  const convert = useConvertWalkthrough()
  const convertUrl = useConvertUrl()
  const createPrompt = useCreateServicePrompt()
  const { data: guiding } = useWalkthroughPrompt()
  const saveGuiding = useSetWalkthroughPrompt()
  const fileRef = useRef<HTMLInputElement>(null)

  const [content, setContent] = useState('')
  const [filename, setFilename] = useState('')
  const [focus, setFocus] = useState('')
  const [mode, setMode] = useState<'text' | 'url'>('text')
  const [url, setUrl] = useState('')
  const [depth, setDepth] = useState(0)
  const [allowInternal, setAllowInternal] = useState(false)
  const [result, setResult] = useState<WalkthroughConversion | UrlConversion | null>(null)
  const [accepted, setAccepted] = useState<Set<number>>(new Set())
  const [err, setErr] = useState('')
  const [applied, setApplied] = useState<{ ok: number; failed: number } | null>(null)
  const [showGuiding, setShowGuiding] = useState(false)
  const [guidingDraft, setGuidingDraft] = useState('')

  const flaggedIdx = new Map<number, string[]>(
    (result?.flagged ?? []).filter(f => f.kind === 'prompt').map(f => [f.index, f.reasons]),
  )

  const run = async () => {
    setErr(''); setResult(null); setApplied(null); setAccepted(new Set())
    try {
      const r = mode === 'url'
        ? await convertUrl.mutateAsync({
            url: url.trim(), depth, max_pages: depth >= 1 ? 5 : 1,
            allow_internal: allowInternal, focus: focus || undefined,
            make_playbook: true,
          })
        : await convert.mutateAsync({
            content, filename: filename || undefined, focus: focus || undefined,
          })
      setResult(r)
      // Pre-tick only the clean entries; flagged ones require a deliberate click.
      const clean = new Set<number>()
      r.prompts.forEach((_, i) => {
        if (!r.flagged.some(f => f.kind === 'prompt' && f.index === i)) clean.add(i)
      })
      setAccepted(clean)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }

  const applyAccepted = async () => {
    if (!result) return
    let ok = 0, failed = 0
    for (const i of [...accepted].sort((a, b) => a - b)) {
      try {
        await createPrompt.mutateAsync(result.prompts[i] as ServicePromptInput)
        ok++
      } catch { failed++ }
    }
    setApplied({ ok, failed })
  }

  const onFile = async (f: File) => {
    setContent(await f.text())
    setFilename(f.name.replace(/\.[^.]+$/, ''))
  }

  return (
    <div className="bg-card border border-border rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="text-sm font-semibold flex items-center gap-1.5">
          <Wand2 className="h-4 w-4" /> Draft rules from a walkthrough or URL
        </h3>
        <button
          onClick={() => { setShowGuiding(!showGuiding); setGuidingDraft(guiding?.prompt ?? '') }}
          className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground"
        >
          <Settings2 className="h-3 w-3" />
          {guiding?.using_custom
            ? 'Extraction prompt (customised)'
            : 'Extraction prompt'}
        </button>
      </div>

      <p className="text-xs text-muted-foreground">
        Paste a writeup or give a URL. Extracts the technique that would still apply to a{' '}
        <em>different</em> host running the same service. Nothing is saved until you accept it —
        entries containing anything that looks box-specific are flagged and left unticked.
        The <strong>Extraction prompt</strong> above controls how both are read.
      </p>

      {showGuiding && (
        <div className="border border-border rounded p-2 space-y-1.5 bg-muted/20">
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted-foreground">
              Governs <strong>both</strong> paths — pasted/uploaded walkthroughs and pages
              fetched from a URL. It decides what counts as reusable technique, how many rules
              to emit for a catalogue vs a single-box narrative, and what to discard as
              box-specific. Clear the box and save to restore the shipped default
              ({guiding?.default_path}).
            </p>
            <button onClick={() => setShowGuiding(false)} className="text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          </div>
          <textarea
            rows={8}
            value={guidingDraft}
            onChange={e => setGuidingDraft(e.target.value)}
            className="w-full bg-muted rounded px-2 py-1 text-[10px] font-mono border border-border"
          />
          <div className="flex gap-2">
            <button
              onClick={() => saveGuiding.mutate(guidingDraft)}
              disabled={saveGuiding.isPending}
              className="px-2 py-1 text-[10px] bg-primary text-primary-foreground rounded disabled:opacity-50"
            >
              {saveGuiding.isPending ? 'Saving…' : 'Save override'}
            </button>
            <button
              onClick={() => { setGuidingDraft(''); saveGuiding.mutate('') }}
              className="px-2 py-1 text-[10px] border border-border rounded"
            >
              Reset to default
            </button>
          </div>
        </div>
      )}

      <div className="flex gap-1">
        {(['text', 'url'] as const).map(m => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={cn(
              'px-2 py-1 text-[10px] rounded border transition-colors',
              mode === m ? 'bg-primary text-primary-foreground border-primary'
                         : 'bg-muted border-border hover:border-primary/50',
            )}
          >
            {m === 'text' ? 'Paste or upload' : 'From a URL'}
          </button>
        ))}
      </div>

      {mode === 'url' ? (
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5">
            <Link2 className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://docs.example.com/some-exploitability-guide/"
              className="flex-1 bg-muted rounded px-2 py-1.5 text-xs border border-border font-mono"
            />
          </div>
          <div className="flex items-center gap-3 flex-wrap text-[10px] text-muted-foreground">
            <label className="flex items-center gap-1">
              Follow links:
              <select
                value={depth}
                onChange={e => setDepth(Number(e.target.value))}
                className="bg-muted rounded px-1.5 py-0.5 border border-border"
              >
                <option value={0}>this page only</option>
                <option value={1}>+ same-site links (max 5)</option>
              </select>
            </label>
            <label className="flex items-center gap-1" title="Private, loopback and cloud-metadata addresses are refused unless this is set.">
              <input
                type="checkbox"
                checked={allowInternal}
                onChange={e => setAllowInternal(e.target.checked)}
                className="rounded border-border"
              />
              Allow internal addresses
            </label>
          </div>
          {allowInternal && (
            <p className="text-[10px] text-yellow-400">
              Internal-address checks relaxed for this run. Only do this for a source you
              deliberately intend to fetch, such as an internal wiki.
            </p>
          )}
        </div>
      ) : (
        <textarea
          rows={6}
          value={content}
          onChange={e => setContent(e.target.value)}
          placeholder="Paste a walkthrough here, or upload a markdown file…"
          className="w-full bg-muted rounded px-2 py-1.5 text-xs border border-border font-mono"
        />
      )}

      <div className="flex items-end gap-2 flex-wrap">
        {mode === 'text' && (
          <button
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-1 px-2 py-1 text-[10px] border border-border rounded"
          >
            <Upload className="h-3 w-3" /> Upload file
          </button>
        )}
        <input
          ref={fileRef} type="file" className="hidden" accept=".md,.txt,.markdown"
          onChange={e => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = '' }}
        />
        <div className="flex-1 min-w-[12rem]">
          <label className="text-[10px] text-muted-foreground block mb-0.5">
            Focus (optional) — narrows this run only
          </label>
          <input
            value={focus}
            onChange={e => setFocus(e.target.value)}
            placeholder="e.g. Active Directory only"
            className="w-full bg-muted rounded px-2 py-1 text-xs border border-border"
          />
        </div>
        <button
          onClick={run}
          disabled={(mode === 'url' ? !url.trim() : !content.trim()) || convert.isPending || convertUrl.isPending}
          className="px-3 py-1.5 bg-primary text-primary-foreground rounded text-xs disabled:opacity-50"
        >
          {(convert.isPending || convertUrl.isPending) ? 'Drafting…' : 'Draft rules'}
        </button>
      </div>

      {(convert.isPending || convertUrl.isPending) && (
        <p className="text-[10px] text-muted-foreground">
          Running the walkthrough through the model — this usually takes a minute or two.
        </p>
      )}
      {err && (
        <p className="text-xs text-red-400 break-words">{err}</p>
      )}

      {result && (
        <div className="space-y-2 pt-1">
          {'pages' in result && (
            <div className="text-[10px] text-muted-foreground space-y-1">
              <p>
                Fetched {result.pages.length} page{result.pages.length === 1 ? '' : 's'}
                {result.pages[0] && ` — ${result.pages[0].chars.toLocaleString()} characters of text`}
              </p>
              {result.fetch_errors?.length > 0 && (
                <p className="text-yellow-400">
                  {result.fetch_errors.length} sub-page(s) could not be fetched
                </p>
              )}
              {result.playbook_markdown && (
                <button
                  onClick={() => {
                    const blob = new Blob([result.playbook_markdown], { type: 'text/markdown' })
                    const a = document.createElement('a')
                    a.href = URL.createObjectURL(blob)
                    a.download = result.playbook_filename
                    a.click()
                    URL.revokeObjectURL(a.href)
                  }}
                  className="flex items-center gap-1 px-2 py-1 border border-border rounded hover:border-primary/50"
                  title="knowledge/ is mounted read-only, so save this yourself into knowledge/playbooks/ and re-ingest"
                >
                  <Download className="h-3 w-3" />
                  Download playbook ({Math.round(result.playbook_markdown.length / 1024)} KB)
                  — save to knowledge/playbooks/
                </button>
              )}
            </div>
          )}
          <p className="text-xs text-muted-foreground">
            {result.prompts.length} rule{result.prompts.length === 1 ? '' : 's'} drafted
            {result.model && ` by ${result.model}`}
            {result.existing_considered.length > 0 &&
              ` · ${result.existing_considered.length} existing rule(s) considered to avoid duplicates`}
          </p>

          {result.prompts.length === 0 && (
            <p className="text-xs text-muted-foreground italic">
              Nothing generalizable was found. That is a legitimate outcome for a walkthrough
              that is mostly box-specific narrative.
            </p>
          )}

          {result.prompts.map((p, i) => {
            const reasons = flaggedIdx.get(i)
            return (
              <label
                key={i}
                className={cn(
                  'flex gap-2 items-start p-2 rounded border cursor-pointer',
                  reasons ? 'border-yellow-500/40 bg-yellow-500/5' : 'border-border hover:border-primary/40',
                )}
              >
                <input
                  type="checkbox"
                  checked={accepted.has(i)}
                  onChange={e => {
                    const next = new Set(accepted)
                    e.target.checked ? next.add(i) : next.delete(i)
                    setAccepted(next)
                  }}
                  className="mt-0.5 rounded border-border"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-xs font-medium">{p.title}</span>
                    <span className="text-[9px] font-mono text-muted-foreground">
                      {p.selector_type}
                      {p.service ? ` · ${p.service}` : ''}
                      {p.tech ? ` · ${p.tech}` : ''}
                      {p.port ? ` · ${p.port}` : ''}
                    </span>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-3">{p.prompt}</p>
                  {reasons && (
                    <p className="text-[10px] text-yellow-400 mt-1 flex items-start gap-1">
                      <AlertTriangle className="h-3 w-3 shrink-0 mt-px" />
                      <span>
                        Looks box-specific — {reasons.join('; ')}. Accept only if this is genuinely
                        reusable (vendor defaults often are).
                      </span>
                    </p>
                  )}
                </div>
              </label>
            )
          })}

          {result.rejected.length > 0 && (
            <details className="text-[10px] text-muted-foreground">
              <summary className="cursor-pointer">
                {result.rejected.length} entr(ies) discarded as malformed
              </summary>
              <ul className="list-disc pl-4 mt-1">
                {result.rejected.map((r, i) => (
                  <li key={i}>{r.entry} — {r.reason}</li>
                ))}
              </ul>
            </details>
          )}

          {result.prompts.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                onClick={applyAccepted}
                disabled={accepted.size === 0 || createPrompt.isPending}
                className="px-3 py-1.5 bg-green-600 text-white rounded text-xs disabled:opacity-50"
              >
                {createPrompt.isPending ? 'Saving…' : `Accept ${accepted.size} rule(s)`}
              </button>
              {applied && (
                <span className="text-[10px] text-green-400">
                  saved {applied.ok}
                  {applied.failed > 0 && ` · ${applied.failed} failed (duplicate selector?)`}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
