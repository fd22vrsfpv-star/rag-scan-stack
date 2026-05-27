// React Query hooks for chat presets — saved operator prompts.
// Backend is BFF /api/chat-presets/* (proxies rag-api /chat-presets).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiUrl } from './client'

export interface ChatPreset {
  id: string
  engagement_id: string | null
  title: string
  category: string | null
  description: string | null
  prompt_template: string
  placeholders: string[]
  tags: string[]
  // null means no restriction; an array (even empty) means the chat must
  // ONLY call tools whose names appear in this list.
  allowed_tools: string[] | null
  created_by: string | null
  created_at: string | null
  last_used_at: string | null
  use_count: number
}

export interface PresetCreateInput {
  title: string
  prompt_template: string
  engagement_id?: string | null
  category?: string
  description?: string
  placeholders?: string[]
  tags?: string[]
  allowed_tools?: string[] | null
  created_by?: string
}

export interface PresetPatchInput {
  title?: string
  prompt_template?: string
  category?: string
  description?: string
  placeholders?: string[]
  tags?: string[]
  allowed_tools?: string[] | null
}

const KEY = 'chat-presets'

export function useChatPresets(params: {
  engagement_id?: string | null
  category?: string
  search?: string
} = {}) {
  const qs = new URLSearchParams()
  if (params.engagement_id) qs.set('engagement_id', params.engagement_id)
  if (params.category) qs.set('category', params.category)
  if (params.search) qs.set('search', params.search)
  return useQuery({
    queryKey: [KEY, 'list', qs.toString()],
    queryFn: async () => {
      const r = await fetch(apiUrl(`/chat-presets?${qs.toString()}`))
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<{ count: number; results: ChatPreset[] }>
    },
    refetchInterval: 60_000,
  })
}

export function useCreateChatPreset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: PresetCreateInput) => {
      const r = await fetch(apiUrl('/chat-presets'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<ChatPreset>
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: [KEY] }),
  })
}

export function useUpdateChatPreset(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: PresetPatchInput) => {
      const r = await fetch(apiUrl(`/chat-presets/${id}`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!r.ok) throw new Error(await r.text())
      return r.json() as Promise<ChatPreset>
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: [KEY] }),
  })
}

export function useDeleteChatPreset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const r = await fetch(apiUrl(`/chat-presets/${id}`), { method: 'DELETE' })
      if (!r.ok) throw new Error(await r.text())
      return r.json()
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: [KEY] }),
  })
}

// Render a preset: substitutes placeholders and returns the resolved prompt.
// vars override any auto-resolved values (e.g. engagement name).
export async function renderChatPreset(
  id: string,
  vars: Record<string, string | number | null | undefined> = {},
): Promise<{ id: string; title: string; rendered: string; vars_used: Record<string, unknown> }> {
  const r = await fetch(apiUrl(`/chat-presets/${id}/render`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vars }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

// Bump the use counter / last_used_at; fire-and-forget after the operator
// actually sends the rendered prompt to the chat.
export async function bumpChatPresetUse(id: string): Promise<void> {
  try {
    await fetch(apiUrl(`/chat-presets/${id}/use`), { method: 'POST' })
  } catch {
    /* non-fatal */
  }
}
