// Saved-prompt picker for the chat panel. Operator picks a preset, the
// rendered prompt drops into their input (they can edit before sending).
// "Save current as preset" lives at the bottom of the dropdown.

import { useState } from 'react'
import { Bookmark, BookmarkPlus, Loader2, Search, Trash2 } from 'lucide-react'
import {
  useChatPresets,
  useCreateChatPreset,
  useDeleteChatPreset,
  bumpChatPresetUse,
  renderChatPreset,
  type ChatPreset,
} from '@/api/chatPresets'
import { useEngagements } from '@/api/engagements'
import { useUIStore } from '@/stores/ui'
import { cn } from '@/lib/utils'

interface Props {
  // Called with the resolved prompt text when a preset is picked.
  onPick: (rendered: string, preset: ChatPreset) => void
  // Optional — passed in to enable the "save current as preset" affordance.
  // When omitted, only the picker shows.
  currentInput?: string
}

export function ChatPresetsPicker({ onPick, currentInput }: Props) {
  const engagementId = useUIStore(s => s.selectedEngagementId)
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [picking, setPicking] = useState<string | null>(null)
  const [showSave, setShowSave] = useState(false)

  const { data, isLoading } = useChatPresets({ engagement_id: engagementId, search })
  const createMut = useCreateChatPreset()
  const deleteMut = useDeleteChatPreset()
  // Read engagements so we can substitute {engagement} with the human-readable
  // name even when the preset is global (engagement_id=NULL). The render
  // endpoint auto-resolves {engagement} from preset.engagement_id only when
  // the preset is scoped — for global presets, the chat-side selector wins.
  const { data: engData } = useEngagements()
  const engagementName = engagementId
    ? (engData?.engagements?.find(e => e.id === engagementId)?.name ?? null)
    : null

  const presets = data?.results ?? []

  const grouped: Record<string, ChatPreset[]> = {}
  for (const p of presets) {
    const k = p.category || 'general'
    if (!grouped[k]) grouped[k] = []
    grouped[k].push(p)
  }

  const onSelect = async (p: ChatPreset) => {
    setPicking(p.id)
    try {
      // Inline the currently-selected engagement name into {engagement} so
      // the LLM gets a concrete scope string instead of the literal token.
      // Falls back to "(no engagement selected)" if the operator is on
      // "All Engagements" — better than leaving "{engagement}" in the prompt
      // where small models try to interpret it as a tool variable.
      const vars: Record<string, string> = {}
      vars.engagement = engagementName ?? '(no engagement selected — operator viewing All Engagements)'
      const res = await renderChatPreset(p.id, vars)
      onPick(res.rendered, p)
      bumpChatPresetUse(p.id)
      setOpen(false)
    } finally {
      setPicking(null)
    }
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
        title="Saved chat prompts"
      >
        <Bookmark className="h-3 w-3" />
        Saved Queries
      </button>

      {open && (
        <div
          className="absolute bottom-full left-0 z-50 mb-2 w-[28rem] rounded-md border border-zinc-700 bg-zinc-900 shadow-lg"
          onMouseLeave={() => { setOpen(false); setShowSave(false) }}
        >
          <div className="flex items-center gap-2 border-b border-zinc-700 p-2">
            <Search className="h-3 w-3 text-zinc-500" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search saved prompts…"
              className="flex-1 bg-transparent text-xs text-zinc-200 outline-none placeholder:text-zinc-600"
              autoFocus
            />
          </div>

          <div className="max-h-72 overflow-y-auto">
            {isLoading && (
              <div className="flex items-center gap-2 p-3 text-xs text-zinc-500">
                <Loader2 className="h-3 w-3 animate-spin" /> Loading…
              </div>
            )}
            {!isLoading && presets.length === 0 && (
              <div className="p-3 text-xs text-zinc-500">
                No saved prompts yet. Type a prompt and click "Save as preset" to add one.
              </div>
            )}
            {Object.entries(grouped).map(([cat, items]) => (
              <div key={cat}>
                <div className="bg-zinc-800/40 px-3 py-1 text-[10px] uppercase tracking-wider text-zinc-500">
                  {cat}
                </div>
                {items.map(p => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => onSelect(p)}
                    disabled={picking === p.id}
                    className="group flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-zinc-800 disabled:opacity-50"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 text-xs font-medium text-zinc-200">
                        {p.title}
                        {p.engagement_id == null && (
                          <span className="rounded bg-zinc-700/60 px-1 text-[9px] uppercase text-zinc-400">global</span>
                        )}
                        {p.use_count > 0 && (
                          <span className="text-[10px] text-zinc-600">×{p.use_count}</span>
                        )}
                      </div>
                      {p.description && (
                        <div className="mt-0.5 truncate text-[10px] text-zinc-500">{p.description}</div>
                      )}
                    </div>
                    {picking === p.id ? (
                      <Loader2 className="mt-0.5 h-3 w-3 animate-spin text-zinc-400" />
                    ) : (
                      <button
                        onClick={e => {
                          e.stopPropagation()
                          if (confirm(`Delete preset "${p.title}"?`)) deleteMut.mutate(p.id)
                        }}
                        className="invisible mt-0.5 text-zinc-600 hover:text-red-400 group-hover:visible"
                        title="Delete"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    )}
                  </button>
                ))}
              </div>
            ))}
          </div>

          {currentInput !== undefined && (
            <div className="border-t border-zinc-700 p-2">
              {!showSave ? (
                <button
                  type="button"
                  onClick={() => setShowSave(true)}
                  disabled={!currentInput.trim()}
                  className="flex w-full items-center justify-center gap-1.5 rounded bg-zinc-800 px-2 py-1.5 text-xs text-zinc-300 hover:bg-zinc-700 disabled:opacity-40"
                >
                  <BookmarkPlus className="h-3 w-3" />
                  Save current input as preset
                </button>
              ) : (
                <SavePresetForm
                  initialPrompt={currentInput}
                  engagementId={engagementId}
                  onCancel={() => setShowSave(false)}
                  onSubmit={async (input) => {
                    await createMut.mutateAsync({ ...input, engagement_id: engagementId })
                    setShowSave(false)
                  }}
                  busy={createMut.isPending}
                />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Curated tool list shown in the save form. Group A is read-only (the
// recommended default for orchestration prompts); group B is launchers
// the operator can add when the workflow legitimately needs to start a
// new scan. Anything not in this list still works via API/SQL — this UI
// just covers the common cases.
const SAVE_FORM_TOOL_GROUPS: { label: string; tools: { name: string; hint: string }[] }[] = [
  {
    label: 'Read-only (recommended)',
    tools: [
      { name: 'get_assets',         hint: 'list / filter assets' },
      { name: 'search_recon',       hint: 'subdomains, DNS, certs, headers' },
      { name: 'search_findings',    hint: 'web + microburst + parser results' },
      { name: 'search_identities',  hint: 'azure_user / group / dirsync' },
      { name: 'get_open_ports',     hint: 'open ports per asset' },
      { name: 'get_vulns',          hint: 'CVE / vuln rows' },
      { name: 'search_exploits',    hint: 'exploit-db lookup' },
      { name: 'search_sitemap',     hint: 'discovered URLs / methods' },
      { name: 'search_params',      hint: 'discovered request params' },
      { name: 'get_content_intel',  hint: 'content extractor results' },
      { name: 'read_uploaded_file', hint: 'pull operator-attached files' },
    ],
  },
  {
    label: 'Scan launchers (only add when needed)',
    tools: [
      { name: 'start_subfinder',     hint: 'launches subdomain enum' },
      { name: 'start_dnsx',          hint: 'launches DNS resolution' },
      { name: 'start_httpx_probe',   hint: 'launches HTTP probe' },
      { name: 'start_nmap_scan',     hint: 'launches port scan' },
      { name: 'start_nuclei_scan',   hint: 'launches vuln template scan' },
      { name: 'start_web_scan',      hint: 'launches gobuster + ZAP' },
      { name: 'start_crtsh',         hint: 'launches CT log search' },
    ],
  },
]

function SavePresetForm({
  initialPrompt,
  engagementId,
  onSubmit,
  onCancel,
  busy,
}: {
  initialPrompt: string
  engagementId: string | null
  onSubmit: (input: { title: string; description?: string; category?: string; prompt_template: string; tags?: string[]; allowed_tools?: string[] | null }) => Promise<void>
  onCancel: () => void
  busy: boolean
}) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [category, setCategory] = useState('general')
  const [scope, setScope] = useState<'global' | 'engagement'>(engagementId ? 'engagement' : 'global')
  // null means "no restriction" (matches the DB column default). When the
  // operator picks any tool, we switch to an explicit Set so the allowlist
  // is enforced by the chat backend.
  const [restrictTools, setRestrictTools] = useState(false)
  const [allowedToolNames, setAllowedToolNames] = useState<Set<string>>(
    () => new Set(['get_assets', 'search_recon', 'search_findings', 'search_identities']),
  )

  const toggleTool = (name: string) => {
    setAllowedToolNames(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  return (
    <div className="space-y-1.5">
      <input
        type="text"
        placeholder="Title (e.g. AWS infra → user pivot)"
        value={title}
        onChange={e => setTitle(e.target.value)}
        className="w-full rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-200"
        autoFocus
      />
      <input
        type="text"
        placeholder="Description (one line, optional)"
        value={description}
        onChange={e => setDescription(e.target.value)}
        className="w-full rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-200"
      />
      <div className="flex gap-1.5">
        <select
          value={category}
          onChange={e => setCategory(e.target.value)}
          className="flex-1 rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-200"
        >
          <option value="general">general</option>
          <option value="recon">recon</option>
          <option value="cloud">cloud</option>
          <option value="identity">identity</option>
          <option value="exploit">exploit</option>
          <option value="reporting">reporting</option>
        </select>
        <select
          value={scope}
          onChange={e => setScope(e.target.value as 'global' | 'engagement')}
          disabled={!engagementId}
          className="rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-200 disabled:opacity-40"
          title={engagementId ? '' : 'Select an engagement to save engagement-scoped'}
        >
          <option value="global">global</option>
          <option value="engagement">this engagement</option>
        </select>
      </div>
      {/* Allowed-tools allowlist — null = no restriction (legacy). When the
          operator opts in, we send the explicit Set so the chat backend
          enforces it (catalog filter + dispatcher allow/deny). */}
      <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer pt-1">
        <input
          type="checkbox"
          checked={restrictTools}
          onChange={e => setRestrictTools(e.target.checked)}
          className="accent-blue-500"
        />
        Restrict tool catalog (recommended for orchestration prompts)
      </label>
      {restrictTools && (
        <div className="rounded border border-zinc-700 bg-zinc-900/60 p-1.5 max-h-40 overflow-y-auto space-y-1">
          {SAVE_FORM_TOOL_GROUPS.map(g => (
            <div key={g.label}>
              <div className="text-[9px] uppercase tracking-wider text-zinc-500 mb-0.5">{g.label}</div>
              <div className="flex flex-wrap gap-1">
                {g.tools.map(t => {
                  const on = allowedToolNames.has(t.name)
                  return (
                    <button
                      key={t.name}
                      type="button"
                      onClick={() => toggleTool(t.name)}
                      title={t.hint}
                      className={cn(
                        'px-1.5 py-0.5 rounded text-[10px] font-mono border transition-colors',
                        on
                          ? 'border-blue-500/60 bg-blue-500/15 text-blue-300'
                          : 'border-zinc-700 bg-zinc-800 text-zinc-400 hover:border-zinc-500',
                      )}
                    >
                      {on ? '✓ ' : ''}{t.name}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
          <div className="text-[9px] text-zinc-500 pt-1">
            Calls to tools outside this list will be refused with a structured error
            (the model can read it and adapt). Leave the box unchecked to allow all tools.
          </div>
        </div>
      )}
      <div className="flex gap-1.5">
        <button
          onClick={onCancel}
          className="flex-1 rounded bg-zinc-800 px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-700"
          disabled={busy}
        >
          Cancel
        </button>
        <button
          onClick={() => {
            if (!title.trim()) return
            onSubmit({
              title: title.trim(),
              description: description.trim() || undefined,
              category,
              prompt_template: initialPrompt,
              allowed_tools: restrictTools ? Array.from(allowedToolNames) : null,
            })
          }}
          disabled={!title.trim() || busy || (restrictTools && allowedToolNames.size === 0)}
          className="flex-1 rounded bg-blue-600 px-2 py-1 text-xs text-white hover:bg-blue-500 disabled:opacity-40"
        >
          {busy ? <Loader2 className="mx-auto h-3 w-3 animate-spin" /> : 'Save'}
        </button>
      </div>
    </div>
  )
}
