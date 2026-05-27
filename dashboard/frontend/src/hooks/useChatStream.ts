import { useRef, useCallback } from 'react'
import { streamChat } from '@/api/chat'
import { useChatStore } from '@/stores/chat'
import { useScanDefaultsStore } from '@/stores/scanDefaults'

export function useChatStream() {
  const abortRef = useRef<AbortController | null>(null)
  const store = useChatStore()

  const send = useCallback(
    async (text: string, context?: Record<string, unknown>) => {
      const userMsg = { role: 'user' as const, content: text }
      store.addMessage(userMsg)
      store.setStreaming(true)

      abortRef.current = new AbortController()

      const allMessages = [...store.messages, userMsg]
      const defaults = useScanDefaultsStore.getState()
      const systemPrompt = defaults.chatSystemPrompt
      const llmBackend = defaults.llmBackend

      await streamChat(
        allMessages,
        store.model,
        context,
        {
          onText: (t) => store.appendToLast(t),
          onToolCall: (tc) => store.addToolCall(tc),
          onToolResult: (tc) => store.updateLastToolCall(tc.result),
          onDone: () => store.setStreaming(false),
          onError: (err) => {
            store.appendToLast(`\n\nError: ${err}`)
            store.setStreaming(false)
          },
        },
        abortRef.current.signal,
        store.profile,
        systemPrompt,
        llmBackend || undefined,
        store.attachedFiles.map(f => ({
          id: f.id, name: f.name, content_type: f.content_type, size: f.size,
        })),
        store.activeAllowedTools,
      )
    },
    [store],
  )

  const cancel = useCallback(() => {
    abortRef.current?.abort()
    store.setStreaming(false)
  }, [store])

  return { send, cancel }
}
