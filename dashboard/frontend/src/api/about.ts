import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

// ── Doc listing ──

export interface DocFile {
  name: string
  size: number
}

export function useDocs() {
  return useQuery({
    queryKey: ['about-docs'],
    queryFn: () => apiFetch<{ docs: DocFile[] }>('/about/docs'),
  })
}

export function useDocContent(filename: string | null) {
  return useQuery({
    queryKey: ['about-doc', filename],
    queryFn: () => apiFetch<{ name: string; content: string }>(`/about/docs/${filename}`),
    enabled: !!filename,
  })
}

// ── MCP Tools ──

export interface McpToolParam {
  name: string
  type: string
  description: string
}

export interface McpTool {
  name: string
  description: string
  params: McpToolParam[]
}

export interface McpServer {
  file: string
  name: string
  port: number
  tool_count: number
  tools: McpTool[]
  builtin?: boolean
  description?: string
  source?: string
  transport?: string
  url?: string
}

export function useMcpTools() {
  return useQuery({
    queryKey: ['about-mcp-tools'],
    queryFn: () => apiFetch<{ servers: McpServer[]; total_tools: number }>('/about/mcp-tools'),
  })
}
