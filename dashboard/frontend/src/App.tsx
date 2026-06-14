import { lazy, Suspense, Component, type ReactNode } from 'react'
import { BUILD_VERSION } from '@/lib/constants'
if (typeof window !== 'undefined') (window as any).__BUILD__ = BUILD_VERSION
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'

const Dashboard = lazy(() => import('@/pages/Dashboard'))
const ScanLauncher = lazy(() => import('@/pages/ScanLauncher'))
const ScanMonitor = lazy(() => import('@/pages/ScanMonitor'))
const ScanDetail = lazy(() => import('@/pages/ScanDetail'))
const AssetBrowser = lazy(() => import('@/pages/AssetBrowser'))
const FindingsExplorer = lazy(() => import('@/pages/FindingsExplorer'))
const ExploitManager = lazy(() => import('@/pages/ExploitManager'))
const Reports = lazy(() => import('@/pages/Reports'))
const Feedback = lazy(() => import('@/pages/Feedback'))
const Maintenance = lazy(() => import('@/pages/Maintenance'))
const AgentSessions = lazy(() => import('@/pages/AgentSessions'))
const AIAgents = lazy(() => import('@/pages/AIAgents'))
const Services = lazy(() => import('@/pages/Services'))
const KnowledgeBase = lazy(() => import('@/pages/KnowledgeBase'))
const ReconExplorer = lazy(() => import('@/pages/ReconExplorer'))
const Settings = lazy(() => import('@/pages/Settings'))
const Nodes = lazy(() => import('@/pages/Nodes'))
const Engagements = lazy(() => import('@/pages/Engagements'))
const ScopeIntelligence = lazy(() => import('@/pages/ScopeIntelligence'))
const OpSec = lazy(() => import('@/pages/OpSec'))
const FollowUps = lazy(() => import('@/pages/FollowUps'))
const Recommendations = lazy(() => import('@/pages/Recommendations'))
const AttackMap = lazy(() => import('@/pages/AttackMap'))
const KbOverrides = lazy(() => import('@/pages/KbOverrides'))
const ApiTester = lazy(() => import('@/pages/ApiTester'))
const DeltaCompare = lazy(() => import('@/pages/DeltaCompare'))
const About = lazy(() => import('@/pages/About'))
const ChatPopout = lazy(() => import('@/pages/ChatPopout'))
const PipelineMonitor = lazy(() => import('@/pages/PipelineMonitor'))
const CloudPosture = lazy(() => import('@/pages/CloudPosture'))
const SyncDashboard = lazy(() => import('@/pages/SyncDashboard'))
const ContentIntel = lazy(() => import('@/pages/ContentIntel'))
const News = lazy(() => import('@/pages/News'))
const UsersPopout = lazy(() => import('@/pages/UsersPopout'))
const UsersDetailPopout = lazy(() => import('@/pages/UsersDetailPopout'))
const ReconPopout = lazy(() => import('@/pages/ReconPopout'))
const Diagnostics = lazy(() => import('@/pages/Diagnostics'))
const TargetedRecon = lazy(() => import('@/pages/TargetedRecon'))
const Users = lazy(() => import('@/pages/Users'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function Loading() {
  return (
    <div className="flex items-center justify-center h-32">
      <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

// True if the error looks like a stale-chunk failure after a rebuild —
// Vite emits dynamic imports that throw a TypeError "error loading
// dynamically imported module: ..." when the chunk file no longer exists.
function isStaleChunkError(err: any): boolean {
  if (!err) return false
  const msg = String(err?.message || err || '').toLowerCase()
  return msg.includes('dynamically imported module')
      || msg.includes('failed to fetch dynamically imported module')
      || msg.includes('importing a module script failed')
      || (msg.includes('chunk') && msg.includes('failed'))
      || err?.name === 'ChunkLoadError'
}

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; error: Error | null; reloading: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false, error: null, reloading: false }
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error, reloading: false }
  }
  componentDidCatch(error: Error) {
    // Auto-reload on a stale chunk — the running JS bundle references a
    // chunk hash that the rebuilt server no longer serves. We try once;
    // if a sentinel cookie shows we already reloaded for this session
    // we don't loop, just show the error UI.
    if (isStaleChunkError(error) && !sessionStorage.getItem('__stale_chunk_reloaded')) {
      sessionStorage.setItem('__stale_chunk_reloaded', String(Date.now()))
      this.setState({ reloading: true })
      // Hard reload to bypass any in-memory module map
      setTimeout(() => window.location.reload(), 250)
    }
  }
  render() {
    if (this.state.reloading) {
      return (
        <div className="flex flex-col items-center justify-center h-64 gap-3 text-center">
          <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-muted-foreground">Dashboard was updated — reloading…</p>
        </div>
      )
    }
    if (this.state.hasError) {
      const stale = isStaleChunkError(this.state.error)
      return (
        <div className="flex flex-col items-center justify-center h-64 gap-4 text-center">
          <h2 className="text-xl font-semibold text-red-400">
            {stale ? 'Dashboard out of sync' : 'Something went wrong'}
          </h2>
          <p className="text-sm text-zinc-400 max-w-md">
            {stale
              ? 'The page references a JS chunk the server no longer has — usually after a deploy. Reload to fetch the new build.'
              : this.state.error?.message}
          </p>
          <div className="flex gap-2">
            <button
              className="px-4 py-2 bg-primary text-primary-foreground rounded text-sm"
              onClick={() => { sessionStorage.removeItem('__stale_chunk_reloaded'); window.location.reload() }}
            >
              Reload
            </button>
            <button
              className="px-4 py-2 bg-zinc-700 hover:bg-zinc-600 rounded text-sm"
              onClick={() => this.setState({ hasError: false, error: null })}
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  return (
    <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Standalone chat popup — sibling of AppShell so no Sidebar/TopBar render */}
          <Route path="chat-popout" element={<Suspense fallback={<Loading />}><ChatPopout /></Suspense>} />
          {/* Page popouts — full-window workspaces for second-monitor use */}
          <Route path="users-popout" element={<Suspense fallback={<Loading />}><UsersPopout /></Suspense>} />
          <Route path="users-popout/:id" element={<Suspense fallback={<Loading />}><UsersDetailPopout /></Suspense>} />
          <Route path="recon-popout" element={<Suspense fallback={<Loading />}><ReconPopout /></Suspense>} />
          <Route element={<AppShell />}>
            <Route index element={<Suspense fallback={<Loading />}><Dashboard /></Suspense>} />
            <Route path="scans/launch" element={<Suspense fallback={<Loading />}><ScanLauncher /></Suspense>} />
            <Route path="scans/:jobId" element={<Suspense fallback={<Loading />}><ScanDetail /></Suspense>} />
            <Route path="scans" element={<Suspense fallback={<Loading />}><ScanMonitor /></Suspense>} />
            <Route path="agents" element={<Suspense fallback={<Loading />}><AIAgents /></Suspense>} />
            <Route path="agent-sessions" element={<Suspense fallback={<Loading />}><AgentSessions /></Suspense>} />
            <Route path="agent-sessions/:sessionId" element={<Suspense fallback={<Loading />}><AgentSessions /></Suspense>} />
            <Route path="assets" element={<Suspense fallback={<Loading />}><AssetBrowser /></Suspense>} />
            <Route path="findings" element={<Suspense fallback={<Loading />}><FindingsExplorer /></Suspense>} />
            <Route path="follow-ups" element={<Suspense fallback={<Loading />}><FollowUps /></Suspense>} />
            <Route path="recommendations" element={<Suspense fallback={<Loading />}><Recommendations /></Suspense>} />
            <Route path="attack-map" element={<Suspense fallback={<Loading />}><AttackMap /></Suspense>} />
            <Route path="settings/kb-overrides" element={<Suspense fallback={<Loading />}><KbOverrides /></Suspense>} />
            <Route path="recon" element={<Suspense fallback={<Loading />}><ReconExplorer /></Suspense>} />
            <Route path="users" element={<Suspense fallback={<Loading />}><Users /></Suspense>} />
            <Route path="exploits" element={<Suspense fallback={<Loading />}><ExploitManager /></Suspense>} />
            <Route path="reports" element={<Suspense fallback={<Loading />}><Reports /></Suspense>} />
            <Route path="feedback" element={<Suspense fallback={<Loading />}><Feedback /></Suspense>} />
            <Route path="maintenance" element={<Suspense fallback={<Loading />}><Maintenance /></Suspense>} />
            <Route path="knowledge" element={<Suspense fallback={<Loading />}><KnowledgeBase /></Suspense>} />
            <Route path="services" element={<Suspense fallback={<Loading />}><Services /></Suspense>} />
            <Route path="nodes" element={<Suspense fallback={<Loading />}><Nodes /></Suspense>} />
            <Route path="settings" element={<Suspense fallback={<Loading />}><Settings /></Suspense>} />
            <Route path="engagements" element={<Suspense fallback={<Loading />}><Engagements /></Suspense>} />
            <Route path="scope-intel" element={<Navigate to="/recon" replace />} />
            <Route path="opsec" element={<Suspense fallback={<Loading />}><OpSec /></Suspense>} />
            <Route path="api-tester" element={<Suspense fallback={<Loading />}><ApiTester /></Suspense>} />
            <Route path="delta" element={<Suspense fallback={<Loading />}><DeltaCompare /></Suspense>} />
            <Route path="cloud-posture" element={<Suspense fallback={<Loading />}><CloudPosture /></Suspense>} />
            <Route path="content-intel" element={<Suspense fallback={<Loading />}><ContentIntel /></Suspense>} />
            <Route path="news" element={<Suspense fallback={<Loading />}><News /></Suspense>} />
            <Route path="sync" element={<Suspense fallback={<Loading />}><SyncDashboard /></Suspense>} />
            <Route path="targeted-recon" element={<Suspense fallback={<Loading />}><TargetedRecon /></Suspense>} />
            <Route path="diagnostics" element={<Suspense fallback={<Loading />}><Diagnostics /></Suspense>} />
            <Route path="pipelines" element={<Suspense fallback={<Loading />}><PipelineMonitor /></Suspense>} />
            <Route path="pipelines/:pipelineId" element={<Suspense fallback={<Loading />}><PipelineMonitor /></Suspense>} />
            <Route path="about" element={<Suspense fallback={<Loading />}><About /></Suspense>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
    </ErrorBoundary>
  )
}
