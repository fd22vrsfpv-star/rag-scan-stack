import { apiUrl } from './client'
import type { ChatMessage, ToolCallEvent } from '@/lib/types'

export interface ChatStreamCallbacks {
  onText: (text: string) => void
  onToolCall: (tc: ToolCallEvent) => void
  onToolResult: (tc: ToolCallEvent) => void
  onDone: () => void
  onError: (err: string) => void
}

export interface AttachedFileRef {
  id: string
  name: string
  content_type?: string
  size?: number
}

export async function streamChat(
  messages: ChatMessage[],
  model: string | undefined,
  context: Record<string, unknown> | undefined,
  callbacks: ChatStreamCallbacks,
  signal?: AbortSignal,
  profile?: string,
  systemPrompt?: string,
  backend?: string,
  attachedFiles?: AttachedFileRef[],
  // Per-request tool allowlist — set by the saved-query picker so the BFF
  // narrows the model's tool catalog AND the dispatcher rejects calls
  // outside the list.
  allowedTools?: string[] | null,
) {
  const resp = await fetch(apiUrl('/chat'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: messages.map(m => ({ role: m.role, content: m.content })),
      model,
      context,
      profile,
      system_prompt: systemPrompt || undefined,
      backend: backend || undefined,
      attached_files: attachedFiles && attachedFiles.length > 0 ? attachedFiles : undefined,
      allowed_tools: allowedTools && allowedTools.length > 0 ? allowedTools : undefined,
    }),
    signal,
  })

  if (!resp.ok) {
    callbacks.onError(`Chat error: ${resp.status}`)
    return
  }

  const reader = resp.body?.getReader()
  if (!reader) return

  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''

    for (const line of lines) {
      if (line.startsWith('event: ')) {
        const eventType = line.slice(7).trim()
        // Next line should be data:
        continue
      }
      if (line.startsWith('data: ')) {
        try {
          const data = JSON.parse(line.slice(6))
          // Parse based on the surrounding event type or data content
          if (data.content !== undefined) {
            callbacks.onText(data.content)
          } else if (data.name && data.status === 'executing') {
            callbacks.onToolCall({ name: data.name, arguments: data.arguments, status: 'executing' })
          } else if (data.name && data.result !== undefined) {
            callbacks.onToolResult({ name: data.name, arguments: {}, result: data.result, status: 'done' })
          } else if (data.total_rounds !== undefined) {
            callbacks.onDone()
          }
        } catch {
          // Skip non-JSON data lines
        }
      }
    }
  }
  callbacks.onDone()
}
