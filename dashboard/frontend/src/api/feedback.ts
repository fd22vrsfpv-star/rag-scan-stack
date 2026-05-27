import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Feedback } from '@/lib/types'

export function useFeedbackList(limit = 50) {
  return useQuery({
    queryKey: ['feedback', limit],
    queryFn: () => apiFetch<Feedback[]>(`/feedback?limit=${limit}`),
  })
}

export function useCreateFeedback() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { rating: number; comment?: string; session_id?: string; context?: Record<string, unknown> }) =>
      apiFetch('/feedback', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['feedback'] }),
  })
}

export function useExportFeedback() {
  return useQuery({
    queryKey: ['feedback-export'],
    queryFn: () => apiFetch<unknown>('/feedback/export'),
    enabled: false,
  })
}
