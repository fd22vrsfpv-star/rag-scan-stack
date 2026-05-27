import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { ChatMessage, ToolCallEvent } from '@/lib/types'

export interface ChatAttachedFile {
  id: string
  name: string
  content_type: string
  size: number
}

export type ChatMode = 'docked' | 'floating' | 'window'  // 'window' = standalone popup page
export interface ChatRect { x: number; y: number; w: number; h: number }

interface ChatState {
  messages: ChatMessage[]
  isStreaming: boolean
  model: string
  profile: string
  toolCalls: ToolCallEvent[]
  pendingInput: string | null
  attachedFiles: ChatAttachedFile[]
  // Active tool allowlist + display label, set when the operator picks a
  // saved query that has allowed_tools configured. The chat backend then
  // restricts both the model's tool catalog AND the dispatcher to this list.
  // null means no restriction.
  activeAllowedTools: string[] | null
  activePresetLabel: string | null
  // Layout — persisted to localStorage so the user's preference survives reloads
  mode: ChatMode
  floatRect: ChatRect
  dockedWidth: number
  addMessage: (msg: ChatMessage) => void
  appendToLast: (text: string) => void
  setStreaming: (s: boolean) => void
  setModel: (m: string) => void
  setProfile: (p: string) => void
  addToolCall: (tc: ToolCallEvent) => void
  updateLastToolCall: (result: unknown) => void
  clearMessages: () => void
  setPendingInput: (text: string | null) => void
  addAttachedFile: (f: ChatAttachedFile) => void
  removeAttachedFile: (id: string) => void
  clearAttachedFiles: () => void
  setActivePreset: (allowed: string[] | null, label: string | null) => void
  setMode: (m: ChatMode) => void
  setFloatRect: (r: Partial<ChatRect>) => void
  setDockedWidth: (w: number) => void
}

const DEFAULT_FLOAT_RECT: ChatRect = { x: 80, y: 80, w: 480, h: 600 }
const DEFAULT_DOCKED_WIDTH = 384  // matches old w-96

export const useChatStore = create<ChatState>()(
  persist(
    (set) => ({
      messages: [],
      isStreaming: false,
      model: 'qwen2.5:32b',
      profile: 'recon',
      toolCalls: [],
      addMessage: (msg) => set(s => ({ messages: [...s.messages, msg], toolCalls: [] })),
      appendToLast: (text) =>
        set(s => {
          const msgs = [...s.messages]
          const last = msgs[msgs.length - 1]
          if (last?.role === 'assistant') {
            msgs[msgs.length - 1] = { ...last, content: last.content + text }
          } else {
            msgs.push({ role: 'assistant', content: text })
          }
          return { messages: msgs }
        }),
      setStreaming: (isStreaming) => set({ isStreaming }),
      setModel: (model) => set({ model }),
      setProfile: (profile) => set({ profile }),
      addToolCall: (tc) => set(s => ({ toolCalls: [...s.toolCalls, tc] })),
      updateLastToolCall: (result) =>
        set(s => {
          const tcs = [...s.toolCalls]
          if (tcs.length > 0) {
            tcs[tcs.length - 1] = { ...tcs[tcs.length - 1], result, status: 'done' }
          }
          return { toolCalls: tcs }
        }),
      clearMessages: () => set({ messages: [], toolCalls: [], pendingInput: null, attachedFiles: [] }),
      pendingInput: null,
      setPendingInput: (text) => set({ pendingInput: text }),
      attachedFiles: [],
      addAttachedFile: (f) => set(s => ({ attachedFiles: [...s.attachedFiles, f] })),
      removeAttachedFile: (id) => set(s => ({ attachedFiles: s.attachedFiles.filter(x => x.id !== id) })),
      clearAttachedFiles: () => set({ attachedFiles: [] }),
      activeAllowedTools: null,
      activePresetLabel: null,
      setActivePreset: (allowed, label) => set({ activeAllowedTools: allowed, activePresetLabel: label }),
      // Layout — default to floating (popped out) so chat doesn't squeeze the main view.
      mode: 'floating' as ChatMode,
      floatRect: DEFAULT_FLOAT_RECT,
      dockedWidth: DEFAULT_DOCKED_WIDTH,
      setMode: (mode) => set({ mode }),
      setFloatRect: (r) => set(s => ({ floatRect: { ...s.floatRect, ...r } })),
      setDockedWidth: (w) => set({ dockedWidth: Math.max(300, Math.min(1200, Math.round(w))) }),
    }),
    {
      name: 'chat-layout',
      version: 3,  // v3: fix 'window' mode persisting and breaking parent chat
      // Don't persist transient/large state — only the user's layout preference
      partialize: (s) => ({
        // Never persist 'window' mode — it's only valid inside /chat-popout.
        // If window was the last mode, restore to floating on next page load.
        mode: s.mode === 'window' ? 'floating' : s.mode,
        floatRect: s.floatRect,
        dockedWidth: s.dockedWidth,
        model: s.model,
        profile: s.profile,
      }),
      migrate: (persisted: unknown, version: number) => {
        const state = (persisted as Record<string, unknown>) || {}
        if (version < 2) {
          state.mode = 'floating'
        }
        if (version < 3) {
          // v3: 'window' mode should never survive across page loads
          if (state.mode === 'window') state.mode = 'floating'
        }
        return state
      },
    },
  ),
)

// ── Cross-window sync (parent ↔ pop-out) ────────────────────────────
// The popup window is a separate browser context, so it has its own copy of
// the zustand store. We mirror the volatile fields across via BroadcastChannel
// so both windows show the same conversation in real time.
const SYNC_CHANNEL = 'rag-chat-sync'
type SyncPayload = Pick<ChatState,
  'messages' | 'isStreaming' | 'toolCalls' | 'attachedFiles' | 'pendingInput' | 'model' | 'profile'>

let _bc: BroadcastChannel | null = null
let _suppressBroadcast = false
if (typeof window !== 'undefined' && typeof BroadcastChannel !== 'undefined') {
  try {
    _bc = new BroadcastChannel(SYNC_CHANNEL)
    _bc.onmessage = (ev: MessageEvent<SyncPayload>) => {
      if (!ev.data) return
      _suppressBroadcast = true
      try {
        useChatStore.setState(ev.data)
      } finally {
        _suppressBroadcast = false
      }
    }
    let lastSent = ''
    useChatStore.subscribe((s) => {
      if (_suppressBroadcast || !_bc) return
      const payload: SyncPayload = {
        messages: s.messages,
        isStreaming: s.isStreaming,
        toolCalls: s.toolCalls,
        attachedFiles: s.attachedFiles,
        pendingInput: s.pendingInput,
        model: s.model,
        profile: s.profile,
      }
      // Cheap dirty-check to avoid postMessage storms during streaming
      const sig = `${payload.messages.length}:${payload.toolCalls.length}:${payload.isStreaming}:${payload.attachedFiles.length}`
        + `:${payload.messages[payload.messages.length - 1]?.content.length ?? 0}`
      if (sig === lastSent) return
      lastSent = sig
      try { _bc.postMessage(payload) } catch { /* channel may be closed */ }
    })
  } catch {
    _bc = null
  }
}
