import { create } from 'zustand'

const OPEN_GROUPS_KEY = 'sidebar-open-groups'
const ENGAGEMENT_KEY = 'selected-engagement'
const SCOPE_KEY = 'selected-scope'
const DEFAULT_NODE_KEY = 'default-node-id'
const ALPHA_KEY = 'alpha-testing-enabled'
const DEFAULT_OPEN_GROUPS = ['operations', 'intelligence']

function loadOpenGroups(): string[] {
  try {
    const stored = localStorage.getItem(OPEN_GROUPS_KEY)
    if (stored) return JSON.parse(stored)
  } catch { /* ignore */ }
  return DEFAULT_OPEN_GROUPS
}

function saveOpenGroups(groups: string[]) {
  localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify(groups))
}

// Alpha testing features — hidden from menus unless enabled
export const ALPHA_FEATURES = [
  { id: 'api-tester', route: '/api-tester', label: 'API Tester' },
  { id: 'feedback', route: '/feedback', label: 'Feedback' },
  { id: 'export-burp-xml', route: '', label: 'Export Burp XML' },
  { id: 'export-zap-xml', route: '', label: 'Export ZAP XML' },
  { id: 'msf-sessions', route: '', label: 'MSF Sessions' },
  { id: 'n8n-workflows', route: '', label: 'N8N Workflows' },
  { id: 'swagger-docs', route: '', label: 'Swagger Docs' },
  { id: 'kong-gateway', route: '', label: 'Kong Gateway' },
  { id: 'vllm', route: '', label: 'vLLM' },
  { id: 'sliver-c2', route: '', label: 'Sliver C2' },
  { id: 'chisel-server', route: '', label: 'Chisel Server' },
] as const

export const ALPHA_LABELS = new Set(ALPHA_FEATURES.map(f => f.label))

export const ALPHA_ROUTES: Set<string> = new Set(ALPHA_FEATURES.filter(f => f.route).map(f => f.route))

interface UIState {
  sidebarCollapsed: boolean
  chatOpen: boolean
  alphaTestingEnabled: boolean
  selectedEngagementId: string | null
  selectedScopeName: string | null
  defaultNodeId: string | null
  openNavGroups: string[]
  toggleSidebar: () => void
  toggleChat: () => void
  setChatOpen: (open: boolean) => void
  setAlphaTesting: (enabled: boolean) => void
  setSelectedEngagement: (id: string | null, scopeName?: string | null) => void
  setSelectedScope: (name: string | null) => void
  setDefaultNode: (id: string | null) => void
  toggleNavGroup: (id: string) => void
  openNavGroup: (id: string) => void
  notifications: Array<{ id: string; message: string; type: 'success' | 'error' | 'info'; ts: number }>
  addNotification: (message: string, type?: 'success' | 'error' | 'info') => void
  dismissNotification: (id: string) => void
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  chatOpen: false,
  alphaTestingEnabled: localStorage.getItem(ALPHA_KEY) === 'true',
  selectedEngagementId: localStorage.getItem(ENGAGEMENT_KEY) || null,
  selectedScopeName: localStorage.getItem(SCOPE_KEY) || null,
  defaultNodeId: localStorage.getItem(DEFAULT_NODE_KEY) || null,
  openNavGroups: loadOpenGroups(),
  toggleSidebar: () => set(s => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  toggleChat: () => set(s => ({ chatOpen: !s.chatOpen })),
  setChatOpen: (open) => set({ chatOpen: open }),
  setAlphaTesting: (enabled) => {
    localStorage.setItem(ALPHA_KEY, String(enabled))
    set({ alphaTestingEnabled: enabled })
  },
  setSelectedEngagement: (id, scopeName) => {
    if (id) localStorage.setItem(ENGAGEMENT_KEY, id)
    else localStorage.removeItem(ENGAGEMENT_KEY)
    // Always clear scope when engagement changes — prevents stale scope from wrong engagement
    if (scopeName) localStorage.setItem(SCOPE_KEY, scopeName)
    else localStorage.removeItem(SCOPE_KEY)
    set({ selectedEngagementId: id, selectedScopeName: scopeName ?? null })
  },
  setSelectedScope: (name) => {
    if (name) localStorage.setItem(SCOPE_KEY, name)
    else localStorage.removeItem(SCOPE_KEY)
    set({ selectedScopeName: name })
  },
  setDefaultNode: (id) => {
    if (id) localStorage.setItem(DEFAULT_NODE_KEY, id)
    else localStorage.removeItem(DEFAULT_NODE_KEY)
    set({ defaultNodeId: id })
  },
  toggleNavGroup: (id) => set(s => {
    const next = s.openNavGroups.includes(id)
      ? s.openNavGroups.filter(g => g !== id)
      : [...s.openNavGroups, id]
    saveOpenGroups(next)
    return { openNavGroups: next }
  }),
  openNavGroup: (id) => set(s => {
    if (s.openNavGroups.includes(id)) return s
    const next = [...s.openNavGroups, id]
    saveOpenGroups(next)
    return { openNavGroups: next }
  }),

  // ── Notifications ──
  notifications: [] as Array<{ id: string; message: string; type: 'success' | 'error' | 'info'; ts: number }>,
  addNotification: (message: string, type: 'success' | 'error' | 'info' = 'info') => set(s => ({
    notifications: [...s.notifications, { id: Math.random().toString(36).slice(2), message, type, ts: Date.now() }].slice(-5),
  })),
  dismissNotification: (id: string) => set(s => ({
    notifications: s.notifications.filter(n => n.id !== id),
  })),
}))
