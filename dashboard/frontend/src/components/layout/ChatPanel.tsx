import { useState, useRef, useEffect, useCallback } from 'react'
import { X, Send, Trash2, Square, Paperclip, Loader2, ExternalLink, PanelRightOpen, AppWindow } from 'lucide-react'
import { useUIStore } from '@/stores/ui'
import { useChatStore } from '@/stores/chat'
import { useChatStream } from '@/hooks/useChatStream'
import { useOllamaStatus, useActiveModel } from '@/api/reports'
import { apiUrl } from '@/api/client'
import ReactMarkdown from 'react-markdown'
import { CodeBlock } from '@/components/common/CodeBlock'
import { ChatPresetsPicker } from '@/components/ChatPresetsPicker'
import { useEngagements } from '@/api/engagements'
import { cn } from '@/lib/utils'

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024  // 10 MB
const MIN_DOCKED = 320
const MAX_DOCKED = 900
const MIN_FLOAT_W = 360
const MIN_FLOAT_H = 320
const TOOL_RESULT_MAX_CHARS = 32_000  // big enough for list_groups returning thousands of rows

/**
 * Render a tool result as plain text. MCP tools return
 * `{content: [{type: "text", text: "..."}]}`; the inner string already
 * carries real newlines, so we display it verbatim. Anything else gets
 * JSON.stringify'd. Without this unwrap, JSON.stringify escapes every
 * newline to a `\n` literal and the result becomes a single long line.
 */
function formatToolResult(r: unknown): string {
  if (r === undefined || r === null) return ''
  if (typeof r === 'string') return r.slice(0, TOOL_RESULT_MAX_CHARS)
  if (typeof r === 'object') {
    const obj = r as Record<string, unknown>
    // MCP standard envelope
    const content = obj.content as Array<{ type?: string; text?: string }> | undefined
    if (Array.isArray(content) && content[0]?.type === 'text' && typeof content[0]?.text === 'string') {
      return content[0].text.slice(0, TOOL_RESULT_MAX_CHARS)
    }
    // Bare {result: "..."} envelopes used by some local tools
    if (typeof obj.result === 'string') return obj.result.slice(0, TOOL_RESULT_MAX_CHARS)
  }
  try {
    return JSON.stringify(r, null, 2).slice(0, TOOL_RESULT_MAX_CHARS)
  } catch {
    return String(r).slice(0, TOOL_RESULT_MAX_CHARS)
  }
}

export function ChatPanel() {
  const { chatOpen, setChatOpen, selectedEngagementId, setSelectedEngagement } = useUIStore()
  const { data: engData } = useEngagements()
  const engagements = engData?.engagements?.filter(e => e.status !== 'archived') ?? []
  const { messages, isStreaming, toolCalls, model, setModel, profile, setProfile, clearMessages,
          pendingInput, setPendingInput,
          attachedFiles, addAttachedFile, removeAttachedFile,
          activeAllowedTools, activePresetLabel, setActivePreset,
          mode, setMode, floatRect, setFloatRect, dockedWidth, setDockedWidth } = useChatStore()
  const { send, cancel } = useChatStream()
  const { data: ollama } = useOllamaStatus()
  const { data: activeModelData } = useActiveModel()
  const [input, setInput] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Sync chat model with global active model from DB
  useEffect(() => {
    if (activeModelData?.model && activeModelData.model !== model) {
      setModel(activeModelData.model)
    }
  }, [activeModelData?.model])

  // Resize the textarea whenever `input` changes — covers preset picks,
  // pending-input injections, and clearing after send (where onChange does
  // not fire because the value change came from outside).
  useEffect(() => {
    const ta = textareaRef.current
    if (!ta) return
    ta.style.height = 'auto'
    ta.style.height = Math.min(ta.scrollHeight, 240) + 'px'
  }, [input])

  // Auto-send pending input (e.g. from Diagnostic Log Pull "Send to Chat")
  useEffect(() => {
    if (chatOpen && pendingInput && !isStreaming) {
      const text = pendingInput
      setPendingInput(null)
      send(text)
    }
  }, [chatOpen, pendingInput])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, toolCalls])

  // ── Drag (floating mode header) ──
  const dragOffset = useRef<{ dx: number; dy: number } | null>(null)
  const onHeaderPointerDown = useCallback((e: React.PointerEvent) => {
    if (mode !== 'floating') return
    // Don't start drag from buttons / inputs in the header
    const t = e.target as HTMLElement
    if (t.closest('button,select,input')) return
    dragOffset.current = { dx: e.clientX - floatRect.x, dy: e.clientY - floatRect.y }
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }, [mode, floatRect.x, floatRect.y])
  const onHeaderPointerMove = useCallback((e: React.PointerEvent) => {
    if (!dragOffset.current) return
    const x = Math.max(0, Math.min(window.innerWidth - 100, e.clientX - dragOffset.current.dx))
    const y = Math.max(0, Math.min(window.innerHeight - 40, e.clientY - dragOffset.current.dy))
    setFloatRect({ x, y })
  }, [setFloatRect])
  const onHeaderPointerUp = useCallback((e: React.PointerEvent) => {
    if (dragOffset.current) {
      dragOffset.current = null
      try { (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId) } catch { /* ignore */ }
    }
  }, [])

  // ── Drag (docked mode left-edge resizer) ──
  const resizeStart = useRef<{ startX: number; startW: number } | null>(null)
  const onResizerPointerDown = useCallback((e: React.PointerEvent) => {
    resizeStart.current = { startX: e.clientX, startW: dockedWidth }
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }, [dockedWidth])
  const onResizerPointerMove = useCallback((e: React.PointerEvent) => {
    if (!resizeStart.current) return
    const delta = resizeStart.current.startX - e.clientX  // dragging LEFT widens the panel
    setDockedWidth(resizeStart.current.startW + delta)
  }, [setDockedWidth])
  const onResizerPointerUp = useCallback((e: React.PointerEvent) => {
    if (resizeStart.current) {
      resizeStart.current = null
      try { (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId) } catch { /* ignore */ }
    }
  }, [])

  // ── Floating-mode size persistence (CSS resize handle) ──
  // We use a ResizeObserver to write floatRect.w/h back to the store as the user
  // drags the bottom-right corner (native CSS `resize: both`).
  const floatBodyRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (mode !== 'floating' || !floatBodyRef.current) return
    const el = floatBodyRef.current
    const ro = new ResizeObserver(entries => {
      for (const entry of entries) {
        const w = Math.round(entry.contentRect.width)
        const h = Math.round(entry.contentRect.height)
        if (w >= MIN_FLOAT_W && h >= MIN_FLOAT_H && (w !== floatRect.w || h !== floatRect.h)) {
          setFloatRect({ w, h })
        }
      }
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [mode, floatRect.w, floatRect.h, setFloatRect])

  // If mode got stuck on 'window' from a popup session, auto-reset to floating
  // (the persist middleware saved 'window' → parent rehydrated it but isn't on /chat-popout)
  useEffect(() => {
    if (mode === 'window' && !window.location.pathname.includes('chat-popout')) {
      setMode('floating')
    }
  }, [mode, setMode])

  if (!chatOpen) return null

  const handleSend = () => {
    if (!input.trim() || isStreaming) return
    send(input.trim())
    setInput('')
  }

  const handleFilePick = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''  // allow re-uploading the same name
    if (!file) return
    setUploadError(null)
    if (file.size > MAX_UPLOAD_BYTES) {
      setUploadError(`File too large (max ${MAX_UPLOAD_BYTES / 1024 / 1024} MB)`)
      return
    }
    setUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      // Use evidence_type=file, source=chat-upload so they're filterable later
      const params = new URLSearchParams({
        evidence_type: 'file',
        title: file.name,
        uploaded_by: 'chat',
      })
      const resp = await fetch(apiUrl(`/evidence/upload?${params}`), {
        method: 'POST',
        body: form,
      })
      if (!resp.ok) {
        const txt = await resp.text().catch(() => '')
        throw new Error(`upload ${resp.status}: ${txt.slice(0, 200)}`)
      }
      const data = await resp.json()
      const id = data.id || data.evidence_id || data.evidenceId
      if (!id) throw new Error('upload returned no id')
      addAttachedFile({
        id: String(id),
        name: file.name,
        content_type: file.type || 'application/octet-stream',
        size: file.size,
      })
    } catch (err) {
      setUploadError(String((err as Error).message || err))
    } finally {
      setUploading(false)
    }
  }

  const formatBytes = (n: number) =>
    n < 1024 ? `${n} B` :
    n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` :
    `${(n / 1024 / 1024).toFixed(1)} MB`

  // ── Mode-aware container styles ──
  const isFloating = mode === 'floating'
  const isWindow = mode === 'window'  // standalone popup page — fill parent
  const containerClass = isWindow
    ? 'h-full w-full bg-card flex flex-col'
    : isFloating
      ? 'fixed z-[60] border border-border bg-card flex flex-col rounded-lg shadow-2xl overflow-hidden'
      : 'border-l border-border bg-card flex flex-col relative'
  const containerStyle: React.CSSProperties = isWindow
    ? {}
    : isFloating
      ? {
          left: floatRect.x,
          top: floatRect.y,
          width: floatRect.w,
          height: floatRect.h,
          minWidth: MIN_FLOAT_W,
          minHeight: MIN_FLOAT_H,
          resize: 'both',  // bottom-right corner native handle
          overflow: 'hidden',
        }
      : { width: Math.max(MIN_DOCKED, Math.min(MAX_DOCKED, dockedWidth)), flex: '0 0 auto' }

  return (
    <aside ref={floatBodyRef} className={containerClass} style={containerStyle}>
      {/* Docked-mode left-edge resizer (only in regular docked mode) */}
      {!isFloating && !isWindow && (
        <div
          onPointerDown={onResizerPointerDown}
          onPointerMove={onResizerPointerMove}
          onPointerUp={onResizerPointerUp}
          className="absolute left-0 top-0 bottom-0 w-1 cursor-ew-resize hover:bg-primary/30 z-10"
          title="Drag to resize"
        />
      )}
      {/* Header (also drag handle in floating mode) */}
      <div
        className={cn(
          'flex items-center justify-between px-3 py-2 border-b border-border',
          isFloating && 'cursor-move select-none',
        )}
        onPointerDown={onHeaderPointerDown}
        onPointerMove={onHeaderPointerMove}
        onPointerUp={onHeaderPointerUp}
        onPointerCancel={onHeaderPointerUp}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">AI Chat</span>
          <select
            value={model}
            onChange={e => setModel(e.target.value)}
            className="text-xs bg-muted rounded px-1.5 py-0.5 border-0"
            title="Select LLM model"
          >
            {ollama?.available_models && ollama.available_models.length > 0 ? (
              ollama.available_models.map(m => (
                <option key={m.name} value={m.name}>
                  {m.name} ({m.size_human})
                </option>
              ))
            ) : (
              <option value={model}>{model}</option>
            )}
          </select>
          <select
            value={profile}
            onChange={e => setProfile(e.target.value)}
            className="text-xs bg-muted rounded px-1.5 py-0.5 border-0"
            title="Tool profile"
          >
            <option value="recon">Recon</option>
            <option value="web">Web</option>
            <option value="osint">OSINT</option>
            <option value="exploit">Exploit</option>
            <option value="analysis">Analysis</option>
            <option value="credentials">Credentials</option>
            <option value="mcp">MCP / Third-Party</option>
            <option value="all">All Tools</option>
          </select>
          {/* Engagement scope — same source of truth as the TopBar selector
              (useUIStore.selectedEngagementId). Surfacing it inside the chat
              header lets the operator change scope without leaving the panel,
              and makes it obvious what {engagement} resolves to in saved
              prompts. */}
          <select
            value={selectedEngagementId ?? ''}
            onChange={e => {
              const eid = e.target.value || null
              const eng = engagements.find(en => en.id === eid)
              setSelectedEngagement(eid, eng?.scope_name ?? null)
            }}
            className="text-xs bg-muted rounded px-1.5 py-0.5 border-0 max-w-[160px]"
            title="Engagement scope — populates {engagement} in saved prompts"
          >
            <option value="">All Engagements</option>
            {engagements.map(e => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={clearMessages} className="p-1 text-muted-foreground hover:text-foreground" title="Clear chat">
            <Trash2 className="h-3.5 w-3.5" />
          </button>
          {!isWindow && (
            <button
              onClick={() => setMode(isFloating ? 'docked' : 'floating')}
              className="p-1 text-muted-foreground hover:text-foreground"
              title={isFloating ? 'Dock to sidebar' : 'Pop out (drag header to move, bottom-right corner to resize)'}
            >
              {isFloating
                ? <PanelRightOpen className="h-3.5 w-3.5" />
                : <ExternalLink className="h-3.5 w-3.5" />}
            </button>
          )}
          {!isWindow && (
            <button
              onClick={() => {
                // Open a separate browser window. The new window mounts ChatPopout
                // and forces mode='window'. State syncs via BroadcastChannel.
                const w = Math.min(800, window.screen.availWidth - 100)
                const h = Math.min(900, window.screen.availHeight - 100)
                const left = Math.max(0, window.screen.availWidth - w - 60)
                const top = 60
                const features = `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes,location=no,menubar=no,toolbar=no,status=no`
                const popup = window.open('/chat-popout', 'rag-chat-popout', features)
                if (popup) {
                  // Close in-page chat so we don't have two visible at once
                  setChatOpen(false)
                  popup.focus()
                } else {
                  alert('Popup blocked — please allow popups for this site.')
                }
              }}
              className="p-1 text-muted-foreground hover:text-foreground"
              title="Open in independent browser window (resizable, separate from main UI)"
            >
              <AppWindow className="h-3.5 w-3.5" />
            </button>
          )}
          {!isWindow && (
            <button onClick={() => setChatOpen(false)} className="p-1 text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-3">
        {messages.length === 0 && (
          <div className="text-center text-muted-foreground text-xs mt-8">
            <p className="mb-2">Ask about your pentest findings, launch scans, or get recommendations.</p>
            <p className="text-[10px]">The AI can use tools to query data and start scans.</p>
          </div>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            className={cn(
              'text-sm rounded-lg px-3 py-2',
              msg.role === 'user'
                ? 'bg-primary/10 ml-8'
                : 'bg-muted mr-4',
            )}
          >
            {msg.role === 'user' ? (
              <p className="whitespace-pre-wrap">{msg.content}</p>
            ) : (
              <div className="prose prose-invert prose-sm max-w-none">
                <ReactMarkdown components={{ pre: CodeBlock }}>
                  {msg.content}
                </ReactMarkdown>
              </div>
            )}
          </div>
        ))}

        {/* Tool calls in progress */}
        {toolCalls.map((tc, i) => (
          <div key={i} className="border border-border rounded-md px-3 py-2 text-xs">
            <div className="flex items-center gap-2 text-muted-foreground">
              <div className={cn(
                'h-2 w-2 rounded-full',
                tc.status === 'executing' ? 'bg-yellow-500 animate-pulse' : 'bg-green-500',
              )} />
              <span className="font-mono">{tc.name}</span>
            </div>
            {tc.arguments && Object.keys(tc.arguments).length > 0 && (
              <pre className="mt-1 text-[10px] text-muted-foreground overflow-x-auto">
                {JSON.stringify(tc.arguments, null, 2)}
              </pre>
            )}
            {tc.result !== undefined && (
              <details className="mt-1">
                <summary className="cursor-pointer text-muted-foreground">Result</summary>
                <pre className="mt-1 text-[10px] overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap break-words">
                  {formatToolResult(tc.result)}
                </pre>
              </details>
            )}
          </div>
        ))}

        {isStreaming && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            <span>Thinking...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-border p-2">
        {/* Attached file chips */}
        {(attachedFiles.length > 0 || uploadError) && (
          <div className="mb-1.5 flex flex-wrap gap-1">
            {attachedFiles.map(f => (
              <span key={f.id}
                className="inline-flex items-center gap-1 bg-primary/10 text-primary border border-primary/30 rounded px-1.5 py-0.5 text-[10px]"
                title={`${f.content_type} • ${formatBytes(f.size)} • id ${f.id}`}>
                <Paperclip className="h-2.5 w-2.5" />
                <span className="max-w-[160px] truncate">{f.name}</span>
                <button onClick={() => removeAttachedFile(f.id)}
                        className="hover:text-destructive ml-0.5"
                        title="Remove attachment">
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
            {uploadError && (
              <span className="text-[10px] text-red-400">{uploadError}</span>
            )}
          </div>
        )}
        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            onChange={handleFilePick}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading || isStreaming}
            className="p-1.5 rounded-md bg-muted text-muted-foreground hover:text-foreground disabled:opacity-50"
            title="Attach file for the LLM to analyze"
          >
            {uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Paperclip className="h-4 w-4" />}
          </button>
          <ChatPresetsPicker
            currentInput={input}
            onPick={(rendered, preset) => {
              setInput(rendered)
              // Activate preset's tool allowlist for the next chat send.
              // null/empty allowed_tools means "no restriction".
              if (preset.allowed_tools && preset.allowed_tools.length > 0) {
                setActivePreset(preset.allowed_tools, preset.title)
              } else {
                setActivePreset(null, null)
              }
            }}
          />
          {activeAllowedTools && activeAllowedTools.length > 0 && (
            <div className="flex items-center gap-1 text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5"
                 title={`Tool allowlist active from preset "${activePresetLabel}". Only these tools can be called: ${activeAllowedTools.join(', ')}`}>
              <span className="font-mono uppercase tracking-wider">locked: {activePresetLabel}</span>
              <button
                type="button"
                onClick={() => setActivePreset(null, null)}
                className="opacity-70 hover:opacity-100 ml-1"
                title="Clear preset tool restriction"
              >×</button>
            </div>
          )}
          <textarea
            ref={textareaRef}
            value={input}
            onChange={e => {
              setInput(e.target.value)
              // Auto-resize: shrink to one line, then grow to fit content (cap ~10 lines)
              const ta = e.currentTarget
              ta.style.height = 'auto'
              ta.style.height = Math.min(ta.scrollHeight, 240) + 'px'
            }}
            onKeyDown={e => {
              // Enter sends; Shift+Enter inserts a newline. Multi-line paste
              // works as-is (textarea preserves newlines, unlike <input>).
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                handleSend()
              }
            }}
            rows={1}
            placeholder={attachedFiles.length > 0 ? "Ask about the attached file…" : "Ask about findings, launch scans... (Shift+Enter for newline)"}
            className="flex-1 bg-muted rounded-md px-3 py-1.5 text-sm border-0 outline-none placeholder:text-muted-foreground resize-none leading-relaxed"
            disabled={isStreaming}
          />
          {isStreaming ? (
            <button onClick={cancel} className="p-1.5 rounded-md bg-destructive text-destructive-foreground">
              <Square className="h-4 w-4" />
            </button>
          ) : (
            <button onClick={handleSend} className="p-1.5 rounded-md bg-primary text-primary-foreground" disabled={!input.trim()}>
              <Send className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </aside>
  )
}
