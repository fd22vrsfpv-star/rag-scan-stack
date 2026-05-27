import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import {
  useApiCollections, useApiEndpoints, useImportDir, useImportUrl, useDeleteCollection,
  useTestSessions, useCreateSession, useUpdateSession, useDeleteSession,
  useExecuteTest, useTestHistory, useSendToPipeline, useCaptureAuth,
  useClearHistory, useCommonParams, useRunAll, useCollectionToScope,
  useParamConfigs, useSaveParamConfig, useUpdateParamConfig, useDeleteParamConfig, useImportParamConfigs,
  type ApiCollection, type ApiEndpoint, type TestSession, type TestResult,
  type CommonParam, type RunAllResult, type ParamConfig,
} from '@/api/apiTester'
import {
  FileJson, Upload, Trash2, Play, Send, Key, ChevronRight, ChevronDown,
  Loader2, Clock, AlertCircle, CheckCircle, RefreshCw, Plus, Settings, X, Link, FolderOpen,
  Wand2, PlayCircle, Eraser, Layers, Target, Save, Download, FolderInput,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const METHOD_COLOR: Record<string, string> = {
  GET: 'bg-green-500/15 text-green-400 border-green-500/30',
  POST: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  PUT: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  PATCH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  DELETE: 'bg-red-500/15 text-red-400 border-red-500/30',
  HEAD: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  OPTIONS: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const STATUS_COLOR = (code: number | null) => {
  if (!code) return 'text-gray-400'
  if (code < 300) return 'text-green-400'
  if (code < 400) return 'text-yellow-400'
  if (code < 500) return 'text-orange-400'
  return 'text-red-400'
}

// ── Guess test values based on parameter name/type ──
function guessValue(name: string, type: string, format: string): string {
  const n = name.toLowerCase()
  // IDs
  if (n === 'id' || n.endsWith('_id') || n.endsWith('id')) return crypto.randomUUID()
  if (n === 'environment_id' || n === 'environmentid') return '00000000-0000-0000-0000-000000000001'
  // Pagination
  if (n === 'limit' || n === 'page_size' || n === 'pagesize') return '10'
  if (n === 'offset' || n === 'skip' || n === 'page') return '0'
  // Sorting
  if (n === 'sort' || n === 'order_by' || n === 'orderby') return 'created_at'
  if (n === 'order' || n === 'direction') return 'desc'
  // Search/filter
  if (n === 'q' || n === 'query' || n === 'search') return 'pentest'
  if (n === 'filter' || n === 'status') return 'active'
  // Dates
  if (n.includes('date') || n.includes('_at') || format === 'date-time') return new Date().toISOString()
  if (format === 'date') return new Date().toISOString().split('T')[0]
  // URLs
  if (n === 'url' || n === 'callback_url' || n === 'redirect_uri') return 'https://example.com'
  // Email
  if (n === 'email' || n.includes('email')) return 'pentest@example.com'
  // Names
  if (n === 'name' || n === 'title' || n === 'label') return 'Pentest Value'
  if (n === 'description' || n === 'message' || n === 'body' || n === 'content') return 'Pentest description'
  // Auth
  if (n === 'api_key' || n === 'apikey') return 'pentest-api-key'
  if (n === 'token') return 'pentest-token'
  // Booleans
  if (type === 'boolean') return 'true'
  // Numbers
  if (type === 'integer' || type === 'number') return '1'
  // Default string
  return 'pentest'
}

type PageView = 'tester' | 'config' | 'run-all'

export default function ApiTester() {
  const [pageView, setPageView] = useState<PageView>('tester')

  // Collection/endpoint state
  const { data: collectionsData, isLoading: loadingCollections } = useApiCollections()
  const [selectedCollectionId, setSelectedCollectionId] = useState<string | null>(null)
  const [expandedCollections, setExpandedCollections] = useState<Set<string>>(new Set())
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null)
  const [endpointSearch, setEndpointSearch] = useState('')

  // Session state
  const { data: sessionsData } = useTestSessions()
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)

  // Auth bar state
  const [jwtToken, setJwtToken] = useState('')
  const [proxyUrl, setProxyUrl] = useState('http://host.docker.internal:8080')
  const [showAuthModal, setShowAuthModal] = useState(false)
  const [authHeader, setAuthHeader] = useState('Authorization: Bearer')

  // Param form state
  const [paramValues, setParamValues] = useState<Record<string, string>>({})
  const [bodyJson, setBodyJson] = useState('{}')
  const [customHeaders, setCustomHeaders] = useState<Record<string, string>>({})

  // Common params / variables state (shared across endpoints)
  const [commonVars, setCommonVars] = useState<Record<string, string>>({})

  // Response state
  const [lastResult, setLastResult] = useState<TestResult | null>(null)

  // Mutations
  const importDir = useImportDir()
  const importUrl = useImportUrl()
  const deleteCollection = useDeleteCollection()

  // Import URL state
  const [swaggerUrl, setSwaggerUrl] = useState('')
  const createSession = useCreateSession()
  const updateSession = useUpdateSession()
  const deleteSession = useDeleteSession()
  const executeTest = useExecuteTest()
  const sendToPipeline = useSendToPipeline()
  const captureAuth = useCaptureAuth()
  const clearHistory = useClearHistory()
  const runAll = useRunAll()
  const collectionToScope = useCollectionToScope()
  const [scopeNameInput, setScopeNameInput] = useState('')
  const [showScopeInput, setShowScopeInput] = useState(false)

  const collections = collectionsData?.collections || []
  const sessions = sessionsData?.sessions || []
  const activeSession = sessions.find(s => s.id === activeSessionId) || null
  const selectedCollection = collections.find(c => c.id === selectedCollectionId) || null

  // Fetch endpoints for expanded collections
  const { data: endpointsData } = useApiEndpoints(
    selectedCollectionId,
    endpointSearch ? { search: endpointSearch } : undefined,
  )
  const endpoints = endpointsData?.endpoints || []

  // History for active session + selected endpoint
  const { data: historyData } = useTestHistory(
    activeSessionId,
    selectedEndpoint?.id,
  )
  const history = historyData?.history || []

  // Group endpoints by tag
  const groupedEndpoints = useMemo(() => {
    const groups: Record<string, ApiEndpoint[]> = {}
    for (const ep of endpoints) {
      const tag = ep.tags?.[0] || 'Untagged'
      if (!groups[tag]) groups[tag] = []
      groups[tag].push(ep)
    }
    return groups
  }, [endpoints])

  // Toggle collection expand
  const toggleExpand = (id: string) => {
    setExpandedCollections(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
    setSelectedCollectionId(id)
  }

  // Select endpoint and reset param form
  const selectEndpoint = (ep: ApiEndpoint) => {
    setSelectedEndpoint(ep)
    setPageView('tester')
    // Pre-fill from common vars
    const initial: Record<string, string> = {}
    for (const p of ep.parameters || []) {
      initial[p.name] = commonVars[p.name] || ''
    }
    setParamValues(initial)
    // Pre-fill body from common vars
    if (ep.request_body?.fields?.length) {
      const bodyObj: Record<string, string> = {}
      for (const f of ep.request_body.fields) {
        bodyObj[f.name] = commonVars[f.name] || ''
      }
      setBodyJson(JSON.stringify(bodyObj, null, 2))
    } else {
      setBodyJson('{}')
    }
    setLastResult(null)
  }

  // Execute the selected endpoint
  const handleExecute = () => {
    if (!selectedEndpoint || !activeSessionId) return
    let parsedBody: Record<string, any> | undefined
    try {
      const parsed = JSON.parse(bodyJson)
      if (Object.keys(parsed).length > 0) parsedBody = parsed
    } catch { /* ignore */ }

    // Build auth header
    const headers: Record<string, string> = { ...customHeaders }
    if (jwtToken && authHeader) {
      const [headerName, ...prefixParts] = authHeader.split(':')
      const prefix = prefixParts.join(':').trim()
      headers[headerName.trim()] = prefix ? `${prefix} ${jwtToken}` : jwtToken
    }

    executeTest.mutate({
      session_id: activeSessionId,
      endpoint_id: selectedEndpoint.id,
      params: paramValues,
      body: parsedBody,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
    }, {
      onSuccess: (data) => {
        setLastResult(data.result)
      },
    })
  }

  // Create/update session with current auth settings
  const handleSaveSession = () => {
    if (activeSessionId) {
      updateSession.mutate({
        id: activeSessionId,
        jwt_token: jwtToken,
        proxy_url: proxyUrl,
        variables: commonVars,
      })
    } else {
      createSession.mutate({
        name: `Session ${new Date().toLocaleString()}`,
        jwt_token: jwtToken,
        proxy_url: proxyUrl,
        variables: commonVars,
      }, {
        onSuccess: (data) => {
          setActiveSessionId(data.session.id)
        },
      })
    }
  }

  // Auth capture modal state
  const [authMode, setAuthMode] = useState('popup_login')
  const [authUrl, setAuthUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [loginPopup, setLoginPopup] = useState<Window | null>(null)
  const [popupStatus, setPopupStatus] = useState<'idle' | 'waiting' | 'done'>('idle')

  const handleCaptureAuth = () => {
    if (authMode === 'popup_login') {
      // Open login page in popup, user logs in, copies token
      const popup = window.open(authUrl, 'auth_login', 'width=1100,height=800,scrollbars=yes')
      setLoginPopup(popup)
      setPopupStatus('waiting')
      return
    }
    captureAuth.mutate({
      login_url: authUrl,
      mode: authMode,
      client_id: clientId || undefined,
      client_secret: clientSecret || undefined,
    }, {
      onSuccess: (data) => {
        if (data.ok && data.access_token) {
          setJwtToken(data.access_token)
          setShowAuthModal(false)
          if (activeSessionId) {
            updateSession.mutate({ id: activeSessionId, jwt_token: data.access_token })
          }
        }
      },
    })
  }

  // Handle reading token from clipboard
  const handlePasteToken = async () => {
    try {
      const text = await navigator.clipboard.readText()
      const trimmed = text.trim().replace(/^Bearer\s+/i, '')
      if (trimmed) {
        setJwtToken(trimmed)
        setPopupStatus('done')
        setShowAuthModal(false)
        loginPopup?.close()
        setLoginPopup(null)
        if (activeSessionId) {
          updateSession.mutate({ id: activeSessionId, jwt_token: trimmed })
        }
      }
    } catch {
      // Clipboard API not available — user can paste manually
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Auth Bar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-card/50 flex-wrap">
        <Key className="h-4 w-4 text-muted-foreground shrink-0" />
        <input
          className="w-48 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
          placeholder="Auth header format"
          value={authHeader}
          onChange={e => setAuthHeader(e.target.value)}
          title="Auth header name:prefix — e.g. Authorization: Bearer"
        />
        <input
          className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono min-w-[200px]"
          placeholder="JWT / Bearer Token"
          value={jwtToken}
          onChange={e => setJwtToken(e.target.value)}
        />
        <input
          className="w-56 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
          placeholder="Proxy URL (Burp)"
          value={proxyUrl}
          onChange={e => setProxyUrl(e.target.value)}
        />
        <button
          onClick={() => {
            // Auto-fill auth URL from collection metadata
            const ac = selectedCollection?.auth_config
            if (!authUrl) {
              if (ac?.authorization_url) {
                // OAuth2 with explicit authorization URL
                setAuthUrl(ac.authorization_url)
                setAuthMode('popup_login')
              } else if (selectedCollection?.source_url) {
                // Swagger UI page — user logs in there
                setAuthUrl(selectedCollection.source_url)
                setAuthMode('popup_login')
              } else if (ac?.token_url) {
                setAuthUrl(ac.token_url)
                setAuthMode('client_credentials')
              }
            }
            // Auto-set auth header format from spec
            if (selectedCollection?.auth_type === 'apiKey' && ac?.scheme_name) {
              setAuthHeader(`Authorization: Bearer`)
            }
            setPopupStatus('idle')
            setShowAuthModal(true)
          }}
          className="px-2 py-1 text-xs rounded bg-primary/10 text-primary hover:bg-primary/20"
        >
          Get Token
        </button>
        <button
          onClick={handleSaveSession}
          className="px-2 py-1 text-xs rounded bg-accent text-foreground hover:bg-accent/80"
        >
          {activeSessionId ? 'Update Session' : 'New Session'}
        </button>
        {/* Session selector */}
        <select
          className="bg-background border border-border rounded px-2 py-1 text-xs"
          value={activeSessionId || ''}
          onChange={e => {
            const sid = e.target.value
            setActiveSessionId(sid || null)
            const sess = sessions.find(s => s.id === sid)
            if (sess) {
              setJwtToken(sess.jwt_token || '')
              setProxyUrl(sess.proxy_url || 'http://host.docker.internal:8080')
              if (sess.variables && typeof sess.variables === 'object') {
                setCommonVars(sess.variables as Record<string, string>)
              }
            }
          }}
        >
          <option value="">No session</option>
          {sessions.map(s => (
            <option key={s.id} value={s.id}>{s.name || s.id.slice(0, 8)}</option>
          ))}
        </select>
        {/* Session management buttons */}
        {activeSessionId && (
          <>
            <button
              onClick={() => { if (confirm('Clear all history for this session?')) clearHistory.mutate(activeSessionId) }}
              className="px-2 py-1 text-xs rounded text-yellow-400 border border-yellow-400/30 hover:bg-yellow-400/10"
              title="Clear session history"
            >
              <Eraser className="h-3 w-3" />
            </button>
            <button
              onClick={() => {
                if (confirm('Delete this session and all its history?')) {
                  deleteSession.mutate(activeSessionId)
                  setActiveSessionId(null)
                  setJwtToken('')
                }
              }}
              className="px-2 py-1 text-xs rounded text-red-400 border border-red-400/30 hover:bg-red-400/10"
              title="Delete session"
            >
              <Trash2 className="h-3 w-3" />
            </button>
          </>
        )}
      </div>

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Panel: Collections + Endpoints */}
        <div className="w-72 border-r border-border flex flex-col overflow-hidden">
          {/* Import section */}
          <div className="px-3 py-2 border-b border-border space-y-2">
            <div className="flex items-center gap-1">
              <Link className="h-3 w-3 text-muted-foreground shrink-0" />
              <input
                className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
                placeholder="Swagger URL to import..."
                value={swaggerUrl}
                onChange={e => setSwaggerUrl(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && swaggerUrl.trim()) {
                    importUrl.mutate(swaggerUrl.trim())
                  }
                }}
              />
              <button
                onClick={() => swaggerUrl.trim() && importUrl.mutate(swaggerUrl.trim())}
                disabled={importUrl.isPending || !swaggerUrl.trim()}
                className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
              >
                {importUrl.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Upload className="h-3 w-3" />}
              </button>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => importDir.mutate()}
                disabled={importDir.isPending}
                className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-accent text-foreground hover:bg-accent/80 disabled:opacity-50 shrink-0"
                title="Import all JSON files from import/swagger/ directory"
              >
                {importDir.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <FolderOpen className="h-3 w-3" />}
                Dir
              </button>
              <input
                className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs"
                placeholder="Search endpoints..."
                value={endpointSearch}
                onChange={e => setEndpointSearch(e.target.value)}
              />
            </div>
          </div>

          {/* Import feedback */}
          {importUrl.isSuccess && (
            <div className="px-3 py-1 text-xs text-green-400 bg-green-500/10">
              Imported: {importUrl.data.endpoint_count} endpoints
            </div>
          )}
          {importUrl.isError && (
            <div className="px-3 py-1 text-xs text-red-400 bg-red-500/10">
              {(importUrl.error as Error).message}
            </div>
          )}
          {importDir.isSuccess && (
            <div className="px-3 py-1 text-xs text-green-400 bg-green-500/10">
              Imported {importDir.data.total} collections
            </div>
          )}

          {/* View toggle buttons */}
          <div className="flex border-b border-border">
            {([
              ['tester', 'Tester'],
              ['config', 'Config'],
              ['run-all', 'Run All'],
            ] as [PageView, string][]).map(([v, label]) => (
              <button
                key={v}
                onClick={() => setPageView(v)}
                className={cn(
                  'flex-1 py-1.5 text-xs font-medium transition-colors',
                  pageView === v ? 'border-b-2 border-primary text-primary' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Selected collection host bar */}
          {selectedCollection && (
            <div className="px-3 py-1.5 border-b border-border bg-primary/5 space-y-1">
              <div className="flex items-center justify-between">
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Host</div>
                <div className="flex items-center gap-1">
                  {selectedCollection.auth_type && selectedCollection.auth_type !== 'none' && (
                    <span className="text-[10px] px-1 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                      {selectedCollection.auth_type}
                    </span>
                  )}
                  <button
                    onClick={() => {
                      const name = selectedCollection.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '')
                      setScopeNameInput(name)
                      setShowScopeInput(true)
                    }}
                    className="text-[10px] px-1 py-0.5 rounded bg-primary/10 text-primary hover:bg-primary/20"
                    title="Add all endpoints to a scan scope"
                  >
                    + Scope
                  </button>
                </div>
              </div>
              <div className="text-xs font-mono text-primary truncate" title={selectedCollection.base_url}>
                {selectedCollection.base_url || 'No base URL'}
              </div>
              {(selectedCollection.source_url || selectedCollection.auth_config?.token_url) && (
                <button
                  onClick={() => {
                    const ac = selectedCollection.auth_config
                    if (ac?.authorization_url) {
                      setAuthUrl(ac.authorization_url)
                    } else if (selectedCollection.source_url) {
                      setAuthUrl(selectedCollection.source_url)
                    } else if (ac?.token_url) {
                      setAuthUrl(ac.token_url)
                    }
                    setAuthMode(selectedCollection.source_url ? 'popup_login' : 'client_credentials')
                    setShowAuthModal(true)
                  }}
                  className="text-[10px] text-primary hover:underline truncate block"
                  title="Click to open login / get token"
                >
                  {selectedCollection.source_url || selectedCollection.auth_config?.token_url}
                </button>
              )}
            </div>
          )}

          {/* Collection tree */}
          <div className="flex-1 overflow-y-auto py-1">
            {loadingCollections && (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            )}
            {collections.map(coll => (
              <div key={coll.id}>
                <button
                  onClick={() => toggleExpand(coll.id)}
                  className={cn(
                    'w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-accent/50 text-left',
                    selectedCollectionId === coll.id && 'bg-accent/30',
                  )}
                >
                  {expandedCollections.has(coll.id)
                    ? <ChevronDown className="h-3 w-3 shrink-0" />
                    : <ChevronRight className="h-3 w-3 shrink-0" />}
                  <FileJson className="h-3 w-3 shrink-0 text-primary" />
                  <span className="truncate flex-1">{coll.source_file}</span>
                  <span className="text-muted-foreground">{coll.endpoint_count}</span>
                  <button
                    onClick={e => { e.stopPropagation(); deleteCollection.mutate(coll.id) }}
                    className="text-muted-foreground hover:text-red-400"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </button>

                {expandedCollections.has(coll.id) && selectedCollectionId === coll.id && (
                  <div className="ml-4 border-l border-border">
                    {Object.entries(groupedEndpoints).map(([tag, eps]) => (
                      <div key={tag}>
                        <div className="px-2 py-0.5 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                          {tag}
                        </div>
                        {eps.map(ep => (
                          <button
                            key={ep.id}
                            onClick={() => selectEndpoint(ep)}
                            className={cn(
                              'w-full flex items-center gap-1.5 px-2 py-1 text-xs hover:bg-accent/50 text-left',
                              selectedEndpoint?.id === ep.id && 'bg-primary/10',
                            )}
                          >
                            <span className={cn(
                              'px-1 py-0.5 rounded text-[10px] font-bold border shrink-0',
                              METHOD_COLOR[ep.method] || METHOD_COLOR.GET,
                            )}>
                              {ep.method}
                            </span>
                            <span className="truncate font-mono text-[11px]">{ep.path}</span>
                          </button>
                        ))}
                      </div>
                    ))}
                    {endpoints.length === 0 && (
                      <div className="px-3 py-2 text-xs text-muted-foreground">No endpoints found</div>
                    )}
                  </div>
                )}
              </div>
            ))}

            {!loadingCollections && collections.length === 0 && (
              <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                No API collections imported yet.
                <br />Paste a swagger URL above, or click "Dir"
                <br />to import from <code className="text-primary">import/swagger/</code>
              </div>
            )}
          </div>
        </div>

        {/* Right Panel */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {pageView === 'config' && selectedCollectionId ? (
            <ConfigPanel
              collectionId={selectedCollectionId}
              collectionName={selectedCollection?.source_file?.replace(/\.(json|yaml|yml)$/i, '') || selectedCollection?.name || ''}
              commonVars={commonVars}
              setCommonVars={setCommonVars}
              authHeader={authHeader}
              setAuthHeader={setAuthHeader}
            />
          ) : pageView === 'run-all' && selectedCollectionId ? (
            <RunAllPanel
              collectionId={selectedCollectionId}
              sessionId={activeSessionId}
              commonVars={commonVars}
              authHeader={authHeader}
              jwtToken={jwtToken}
              runAll={runAll}
            />
          ) : !selectedEndpoint ? (
            <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
              Select an endpoint from the left panel
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* Endpoint Header */}
              <div className="flex items-center gap-3">
                <span className={cn(
                  'px-2 py-1 rounded text-sm font-bold border',
                  METHOD_COLOR[selectedEndpoint.method] || METHOD_COLOR.GET,
                )}>
                  {selectedEndpoint.method}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="font-mono text-sm">{selectedEndpoint.path}</span>
                  {selectedCollection?.base_url && (
                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                      {selectedCollection.base_url}{selectedEndpoint.path}
                    </div>
                  )}
                </div>
                {selectedEndpoint.operation_id && (
                  <span className="text-xs text-muted-foreground shrink-0">({selectedEndpoint.operation_id})</span>
                )}
              </div>
              {selectedEndpoint.summary && (
                <p className="text-xs text-muted-foreground">{selectedEndpoint.summary}</p>
              )}

              {/* Parameters Form */}
              {selectedEndpoint.parameters.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">Parameters</h3>
                  <div className="grid grid-cols-1 gap-2">
                    {selectedEndpoint.parameters.map(p => (
                      <div key={`${p.in}-${p.name}`} className="flex items-center gap-2">
                        <span className="text-[10px] px-1 py-0.5 rounded bg-accent text-muted-foreground w-12 text-center shrink-0">
                          {p.in}
                        </span>
                        <label className="text-xs w-40 truncate shrink-0" title={p.description}>
                          {p.name}
                          {p.required && <span className="text-red-400 ml-0.5">*</span>}
                        </label>
                        <input
                          className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
                          placeholder={p.type + (p.format ? ` (${p.format})` : '')}
                          value={paramValues[p.name] || ''}
                          onChange={e => setParamValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                        />
                        <button
                          onClick={() => {
                            const v = guessValue(p.name, p.type, p.format || '')
                            setParamValues(prev => ({ ...prev, [p.name]: v }))
                          }}
                          className="text-muted-foreground hover:text-primary shrink-0"
                          title="Guess test value"
                        >
                          <Wand2 className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Request Body */}
              {selectedEndpoint.request_body && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                    Request Body
                    {selectedEndpoint.request_body.schema_name && (
                      <span className="ml-2 font-normal text-muted-foreground">
                        ({selectedEndpoint.request_body.schema_name})
                      </span>
                    )}
                  </h3>
                  <textarea
                    className="w-full h-32 bg-background border border-border rounded px-2 py-1 text-xs font-mono resize-y"
                    value={bodyJson}
                    onChange={e => setBodyJson(e.target.value)}
                  />
                  {selectedEndpoint.request_body.fields.length > 0 && (
                    <div className="text-[10px] text-muted-foreground">
                      Fields: {selectedEndpoint.request_body.fields.map(f =>
                        `${f.name} (${f.type}${f.required ? ', required' : ''})`
                      ).join(', ')}
                    </div>
                  )}
                </div>
              )}

              {/* Execute Button */}
              <div className="flex items-center gap-2">
                <button
                  onClick={handleExecute}
                  disabled={!activeSessionId || executeTest.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                >
                  {executeTest.isPending
                    ? <Loader2 className="h-4 w-4 animate-spin" />
                    : <Play className="h-4 w-4" />}
                  Execute
                </button>

                {selectedCollectionId && (
                  <button
                    onClick={() => sendToPipeline.mutate({ collection_id: selectedCollectionId })}
                    disabled={sendToPipeline.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-foreground text-sm hover:bg-accent/80 disabled:opacity-50"
                  >
                    <Send className="h-4 w-4" />
                    Send to Pipeline
                  </button>
                )}

                {selectedCollectionId && (
                  <button
                    onClick={() => {
                      if (!showScopeInput && selectedCollection) {
                        const name = selectedCollection.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '')
                        setScopeNameInput(name)
                      }
                      setShowScopeInput(v => !v)
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent text-foreground text-sm hover:bg-accent/80"
                  >
                    <Target className="h-4 w-4" />
                    Add to Scope
                  </button>
                )}

                {!activeSessionId && (
                  <span className="text-xs text-yellow-400">Create a session first</span>
                )}

                {sendToPipeline.isSuccess && (
                  <span className="text-xs text-green-400">
                    Sent {sendToPipeline.data.urls_sent} URLs
                  </span>
                )}

                {collectionToScope.isSuccess && (
                  <span className="text-xs text-green-400">
                    Added {collectionToScope.data.added}/{collectionToScope.data.total} to scope "{collectionToScope.data.scope_name}"
                  </span>
                )}
              </div>

              {/* Scope name input */}
              {showScopeInput && selectedCollectionId && (
                <div className="flex items-center gap-2 p-2 rounded border border-border bg-muted/30">
                  <label className="text-xs text-muted-foreground whitespace-nowrap">Scope name:</label>
                  <input
                    value={scopeNameInput}
                    onChange={e => setScopeNameInput(e.target.value)}
                    placeholder="e.g. my_api_scope"
                    className="flex-1 bg-background border border-border rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={() => {
                      if (!scopeNameInput.trim() || !selectedCollectionId) return
                      collectionToScope.mutate(
                        { collection_id: selectedCollectionId, scope_name: scopeNameInput.trim() },
                        { onSuccess: () => setShowScopeInput(false) },
                      )
                    }}
                    disabled={!scopeNameInput.trim() || collectionToScope.isPending}
                    className="flex items-center gap-1 px-3 py-1 rounded bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                  >
                    {collectionToScope.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Target className="h-3 w-3" />}
                    Create
                  </button>
                  <button onClick={() => setShowScopeInput(false)} className="text-muted-foreground hover:text-foreground">
                    <X className="h-4 w-4" />
                  </button>
                </div>
              )}

              {/* Response Viewer */}
              {lastResult && (
                <div className="space-y-2 border border-border rounded p-3">
                  <div className="flex items-center gap-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider">Response</h3>
                    <span className={cn('text-sm font-bold', STATUS_COLOR(lastResult.status_code))}>
                      {lastResult.status_code || 'ERR'}
                    </span>
                    {lastResult.duration_ms != null && (
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {lastResult.duration_ms}ms
                      </span>
                    )}
                    {lastResult.error && (
                      <span className="text-xs text-red-400 flex items-center gap-1">
                        <AlertCircle className="h-3 w-3" /> {lastResult.error}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-muted-foreground font-mono truncate">
                    {lastResult.url}
                  </div>
                  {lastResult.response_body && (
                    <pre className="bg-background border border-border rounded p-2 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap">
                      {tryFormatJson(lastResult.response_body)}
                    </pre>
                  )}
                </div>
              )}

              {executeTest.isError && (
                <div className="text-xs text-red-400 flex items-center gap-1">
                  <AlertCircle className="h-3 w-3" />
                  {(executeTest.error as Error).message}
                </div>
              )}

              {/* History */}
              {history.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                    History ({history.length})
                  </h3>
                  <div className="space-y-1">
                    {history.map((h, i) => (
                      <button
                        key={h.id}
                        onClick={() => setLastResult(h)}
                        className={cn(
                          'w-full flex items-center gap-2 px-2 py-1 rounded text-xs hover:bg-accent/50 text-left',
                          lastResult?.id === h.id && 'bg-accent/30',
                        )}
                      >
                        <span className="text-muted-foreground w-4">#{history.length - i}</span>
                        <span className={cn('font-bold', STATUS_COLOR(h.status_code))}>
                          {h.status_code || 'ERR'}
                        </span>
                        <span className="font-mono truncate flex-1">{h.method} {h.url}</span>
                        <span className="text-muted-foreground">
                          {h.duration_ms != null ? `${h.duration_ms}ms` : '-'}
                        </span>
                        <span className="text-muted-foreground text-[10px]">
                          {new Date(h.created_at).toLocaleTimeString()}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Responses spec */}
              {Object.keys(selectedEndpoint.responses).length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">Expected Responses</h3>
                  <div className="space-y-1">
                    {Object.entries(selectedEndpoint.responses).map(([code, r]) => (
                      <div key={code} className="flex items-center gap-2 text-xs">
                        <span className={cn('font-bold', STATUS_COLOR(parseInt(code)))}>{code}</span>
                        <span className="text-muted-foreground">{r.description}</span>
                        {r.schema_name && (
                          <span className="text-primary text-[10px]">{r.schema_name}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Auth Capture Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-6 w-[520px] space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Get Auth Token</h2>
              <button onClick={() => { setShowAuthModal(false); setPopupStatus('idle') }}>
                <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground">Mode</label>
                <select
                  className="w-full bg-background border border-border rounded px-2 py-1 text-xs mt-1"
                  value={authMode}
                  onChange={e => setAuthMode(e.target.value)}
                >
                  <option value="popup_login">Browser Login (popup)</option>
                  <option value="client_credentials">OAuth2 Client Credentials</option>
                  <option value="intercept">Network Intercept (headless)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-muted-foreground">
                  {authMode === 'popup_login' ? 'Login / Swagger UI URL' : 'Token URL'}
                </label>
                <input
                  className="w-full bg-background border border-border rounded px-2 py-1 text-xs font-mono mt-1"
                  placeholder="https://..."
                  value={authUrl}
                  onChange={e => setAuthUrl(e.target.value)}
                />
              </div>

              {authMode === 'client_credentials' && (
                <>
                  <div>
                    <label className="text-xs text-muted-foreground">Client ID</label>
                    <input
                      className="w-full bg-background border border-border rounded px-2 py-1 text-xs font-mono mt-1"
                      value={clientId}
                      onChange={e => setClientId(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Client Secret</label>
                    <input
                      type="password"
                      className="w-full bg-background border border-border rounded px-2 py-1 text-xs font-mono mt-1"
                      value={clientSecret}
                      onChange={e => setClientSecret(e.target.value)}
                    />
                  </div>
                </>
              )}

              {/* Popup login flow — instructions + paste */}
              {authMode === 'popup_login' && popupStatus === 'waiting' && (
                <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 p-3 space-y-2">
                  <p className="text-xs text-yellow-300 font-medium">Login window opened</p>
                  <ol className="text-[10px] text-muted-foreground space-y-1 list-decimal list-inside">
                    <li>Log in through the auth flow in the popup window</li>
                    <li>Once logged in, click the <strong>Authorize</strong> button on the swagger page</li>
                    <li>Copy the <strong>Bearer token</strong> value from the Authorization header</li>
                    <li>Come back here and paste it below, or click <strong>Read Clipboard</strong></li>
                  </ol>
                  <div className="flex gap-2 mt-2">
                    <input
                      className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
                      placeholder="Paste Bearer token here..."
                      onChange={e => {
                        const val = e.target.value.trim().replace(/^Bearer\s+/i, '')
                        if (val.length > 20) {
                          setJwtToken(val)
                          setPopupStatus('done')
                          loginPopup?.close()
                          setLoginPopup(null)
                          if (activeSessionId) updateSession.mutate({ id: activeSessionId, jwt_token: val })
                        }
                      }}
                    />
                    <button
                      onClick={handlePasteToken}
                      className="px-2 py-1 text-xs rounded bg-primary/10 text-primary hover:bg-primary/20 whitespace-nowrap"
                    >
                      Read Clipboard
                    </button>
                  </div>
                </div>
              )}

              {popupStatus === 'done' && (
                <div className="flex items-center gap-1 text-xs text-green-400">
                  <CheckCircle className="h-3 w-3" /> Token captured and applied
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 justify-end">
              {captureAuth.isPending && <Loader2 className="h-4 w-4 animate-spin text-primary" />}
              {captureAuth.isError && (
                <span className="text-xs text-red-400">{(captureAuth.error as Error).message}</span>
              )}
              {captureAuth.isSuccess && !captureAuth.data.ok && (
                <span className="text-xs text-red-400">{captureAuth.data.error || 'No token captured'}</span>
              )}
              {captureAuth.isSuccess && captureAuth.data.ok && (
                <span className="text-xs text-green-400 flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" /> Token captured
                </span>
              )}
              <button
                onClick={handleCaptureAuth}
                disabled={(authMode !== 'popup_login' && captureAuth.isPending) || !authUrl}
                className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 disabled:opacity-50"
              >
                {authMode === 'popup_login'
                  ? (popupStatus === 'waiting' ? 'Reopen Login' : 'Open Login Page')
                  : 'Capture'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Config Panel: Common Parameters ──

function ConfigPanel({
  collectionId, collectionName, commonVars, setCommonVars, authHeader, setAuthHeader,
}: {
  collectionId: string
  collectionName: string
  commonVars: Record<string, string>
  setCommonVars: (v: Record<string, string>) => void
  authHeader: string
  setAuthHeader: (v: string) => void
}) {
  const { data, isLoading } = useCommonParams(collectionId)
  const { data: configsData } = useParamConfigs(collectionId)
  const saveConfig = useSaveParamConfig()
  const updateConfig = useUpdateParamConfig()
  const deleteConfig = useDeleteParamConfig()
  const importConfigs = useImportParamConfigs()
  const params = data?.params ?? []
  const savedConfigs = configsData?.configs ?? []

  const [saveName, setSaveName] = useState(collectionName)
  const [activeConfigId, setActiveConfigId] = useState<string | null>(null)
  const [configMsg, setConfigMsg] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Auto-load most recent saved config when collection changes
  useEffect(() => {
    setSaveName(collectionName)
    setActiveConfigId(null)
  }, [collectionId, collectionName])

  // When saved configs load, auto-load the most recent one if nothing is active
  useEffect(() => {
    if (savedConfigs.length > 0 && !activeConfigId) {
      const latest = savedConfigs[0] // already sorted by updated_at DESC
      setCommonVars(latest.config || {})
      if (latest.auth_header) setAuthHeader(latest.auth_header)
      setActiveConfigId(latest.id)
      setSaveName(latest.name)
    }
  }, [savedConfigs.length]) // eslint-disable-line react-hooks/exhaustive-deps

  // Debounced auto-save when values change
  const autoSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const handleAutoSave = useCallback(() => {
    if (autoSaveTimer.current) clearTimeout(autoSaveTimer.current)
    autoSaveTimer.current = setTimeout(() => {
      const name = saveName.trim() || collectionName
      if (!name) return
      const hasValues = Object.keys(commonVars).some(k => commonVars[k])
      if (!hasValues) return
      if (activeConfigId) {
        updateConfig.mutate({ id: activeConfigId, name, config: commonVars, auth_header: authHeader })
      } else {
        saveConfig.mutate(
          { collection_id: collectionId, name, config: commonVars, auth_header: authHeader },
          { onSuccess: (d) => setActiveConfigId(d.id) },
        )
      }
    }, 1500)
  }, [activeConfigId, commonVars, authHeader, saveName, collectionId, collectionName]) // eslint-disable-line react-hooks/exhaustive-deps

  // Trigger auto-save when commonVars or authHeader change (skip initial mount)
  const mountedRef = useRef(false)
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    handleAutoSave()
    return () => { if (autoSaveTimer.current) clearTimeout(autoSaveTimer.current) }
  }, [commonVars, authHeader]) // eslint-disable-line react-hooks/exhaustive-deps

  const groupedByLocation = useMemo(() => {
    const groups: Record<string, CommonParam[]> = {}
    for (const p of params) {
      const loc = p.in
      if (!groups[loc]) groups[loc] = []
      groups[loc].push(p)
    }
    return groups
  }, [params])

  const locationOrder = ['path', 'header', 'query', 'body']

  const handleSave = () => {
    const name = saveName.trim()
    if (!name) return
    if (activeConfigId) {
      updateConfig.mutate({ id: activeConfigId, name, config: commonVars, auth_header: authHeader }, {
        onSuccess: () => { setConfigMsg('Updated!'); setTimeout(() => setConfigMsg(''), 2000) },
      })
    } else {
      saveConfig.mutate({ collection_id: collectionId, name, config: commonVars, auth_header: authHeader }, {
        onSuccess: (d) => { setActiveConfigId(d.id); setConfigMsg('Saved!'); setTimeout(() => setConfigMsg(''), 2000) },
      })
    }
  }

  const handleLoad = (cfg: ParamConfig) => {
    setCommonVars(cfg.config || {})
    if (cfg.auth_header) setAuthHeader(cfg.auth_header)
    setActiveConfigId(cfg.id)
    setSaveName(cfg.name)
    setConfigMsg(`Loaded "${cfg.name}"`)
    setTimeout(() => setConfigMsg(''), 2000)
  }

  const handleExport = () => {
    const exportData = {
      collection_id: collectionId,
      exported_at: new Date().toISOString(),
      configs: savedConfigs.map(c => ({ name: c.name, config: c.config, auth_header: c.auth_header })),
    }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `param-configs-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string)
        const configs = data.configs || [data]
        importConfigs.mutate({ collection_id: collectionId, configs }, {
          onSuccess: (d) => { setConfigMsg(`Imported ${d.imported} config(s)`); setTimeout(() => setConfigMsg(''), 3000) },
        })
      } catch {
        setConfigMsg('Invalid JSON file')
        setTimeout(() => setConfigMsg(''), 3000)
      }
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Settings className="h-4 w-4" /> Common Parameters Configuration
        </h3>
        <span className="text-xs text-muted-foreground">{params.length} parameters across all endpoints</span>
      </div>

      <p className="text-xs text-muted-foreground">
        Set values once here — they auto-fill into every endpoint and are used by "Run All".
        Configurations are persisted in the database and can be exported/imported as JSON.
      </p>

      {/* Save / Load / Import / Export bar */}
      <div className="bg-card border border-border rounded-lg p-3 space-y-3">
        <h4 className="text-xs font-semibold">Saved Configurations ({savedConfigs.length})</h4>

        {/* Load existing configs */}
        {savedConfigs.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {savedConfigs.map(cfg => (
              <div key={cfg.id} className="flex items-center gap-1">
                <button
                  onClick={() => handleLoad(cfg)}
                  className={cn(
                    'px-2 py-1 text-xs rounded border',
                    activeConfigId === cfg.id
                      ? 'bg-primary text-primary-foreground border-primary'
                      : 'border-border hover:bg-accent/50 text-foreground'
                  )}
                >
                  {cfg.name}
                </button>
                <button
                  onClick={() => {
                    if (confirm(`Delete config "${cfg.name}"?`)) {
                      deleteConfig.mutate(cfg.id)
                      if (activeConfigId === cfg.id) { setActiveConfigId(null); setSaveName('') }
                    }
                  }}
                  className="text-muted-foreground hover:text-red-400"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Save current */}
        <div className="flex items-center gap-2">
          <input
            className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs"
            placeholder="Configuration name..."
            value={saveName}
            onChange={e => setSaveName(e.target.value)}
          />
          <button
            onClick={handleSave}
            disabled={!saveName.trim() || saveConfig.isPending || updateConfig.isPending}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
          >
            <Save className="h-3 w-3" /> {activeConfigId ? 'Update' : 'Save'}
          </button>
          <button
            onClick={handleExport}
            disabled={savedConfigs.length === 0}
            className="flex items-center gap-1 px-2 py-1 text-xs border border-border rounded hover:bg-accent/50 disabled:opacity-50"
            title="Export all configs as JSON"
          >
            <Download className="h-3 w-3" /> Export
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1 px-2 py-1 text-xs border border-border rounded hover:bg-accent/50"
            title="Import configs from JSON"
          >
            <FolderInput className="h-3 w-3" /> Import
          </button>
          <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={handleImportFile} />
        </div>

        <div className="flex items-center gap-2">
          {configMsg && <span className="text-xs text-green-500">{configMsg}</span>}
          {activeConfigId && <span className="text-[10px] text-muted-foreground">Auto-saving enabled</span>}
        </div>
      </div>

      {/* Auth header config */}
      <div className="bg-card border border-border rounded-lg p-3 space-y-2">
        <h4 className="text-xs font-semibold">Auth Header</h4>
        <div className="flex items-center gap-2">
          <input
            className="w-64 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
            value={authHeader}
            onChange={e => setAuthHeader(e.target.value)}
            placeholder="Authorization: Bearer"
          />
          <span className="text-[10px] text-muted-foreground">
            Format: HeaderName: Prefix (token is appended after prefix)
          </span>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center gap-2 py-8 justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">Loading parameters...</span>
        </div>
      ) : (
        locationOrder.map(loc => {
          const locParams = groupedByLocation[loc]
          if (!locParams?.length) return null
          return (
            <div key={loc} className="bg-card border border-border rounded-lg p-3 space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded bg-accent text-muted-foreground text-[10px]">{loc}</span>
                Parameters ({locParams.length})
              </h4>
              <div className="space-y-1.5">
                {locParams.map(p => (
                  <div key={`${p.in}:${p.name}`} className="flex items-center gap-2">
                    <label className="text-xs w-44 truncate shrink-0 font-mono" title={p.description || p.name}>
                      {p.name}
                      {p.required && <span className="text-red-400 ml-0.5">*</span>}
                    </label>
                    <input
                      className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono"
                      placeholder={p.type + (p.format ? ` (${p.format})` : '')}
                      value={commonVars[p.name] || ''}
                      onChange={e => setCommonVars({ ...commonVars, [p.name]: e.target.value })}
                    />
                    <button
                      onClick={() => {
                        const v = guessValue(p.name, p.type, p.format)
                        setCommonVars({ ...commonVars, [p.name]: v })
                      }}
                      className="text-muted-foreground hover:text-primary shrink-0"
                      title="Guess test value"
                    >
                      <Wand2 className="h-3.5 w-3.5" />
                    </button>
                    <span className="text-[10px] text-muted-foreground w-20 shrink-0 text-right">
                      {p.used_in.length} endpoint{p.used_in.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )
        })
      )}

      {/* Guess all button */}
      {params.length > 0 && (
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              const guessed: Record<string, string> = { ...commonVars }
              for (const p of params) {
                if (!guessed[p.name]) {
                  guessed[p.name] = guessValue(p.name, p.type, p.format)
                }
              }
              setCommonVars(guessed)
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary/10 text-primary text-xs hover:bg-primary/20"
          >
            <Wand2 className="h-3.5 w-3.5" />
            Guess All Empty Values
          </button>
          <button
            onClick={() => setCommonVars({})}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-muted-foreground border border-border hover:bg-accent/50"
          >
            <Eraser className="h-3.5 w-3.5" />
            Clear All
          </button>
        </div>
      )}

      {/* Param usage details */}
      {params.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer hover:text-foreground">Parameter usage details</summary>
          <div className="mt-2 space-y-1 max-h-60 overflow-y-auto">
            {params.map(p => (
              <div key={`${p.in}:${p.name}`} className="flex gap-2">
                <span className="font-mono w-40 shrink-0 truncate">{p.name}</span>
                <span className="text-muted-foreground truncate">
                  {p.used_in.join(', ')}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}

// ── Run All Panel ──

function RunAllPanel({
  collectionId, sessionId, commonVars, authHeader, jwtToken, runAll,
}: {
  collectionId: string
  sessionId: string | null
  commonVars: Record<string, string>
  authHeader: string
  jwtToken: string
  runAll: ReturnType<typeof useRunAll>
}) {
  const results = runAll.data?.results ?? []

  const handleRunAll = () => {
    if (!sessionId) return
    // Build custom headers from auth header config
    const headers: Record<string, string> = {}
    if (jwtToken && authHeader) {
      const [headerName, ...prefixParts] = authHeader.split(':')
      const prefix = prefixParts.join(':').trim()
      headers[headerName.trim()] = prefix ? `${prefix} ${jwtToken}` : jwtToken
    }

    runAll.mutate({
      session_id: sessionId,
      collection_id: collectionId,
      variables: Object.keys(commonVars).length > 0 ? commonVars : undefined,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
    })
  }

  const executed = results.filter(r => r.status === 'ok')
  const skipped = results.filter(r => r.status === 'skipped')
  const successes = executed.filter(r => r.status_code && r.status_code < 400)
  const errors = executed.filter(r => !r.status_code || r.status_code >= 400)

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <PlayCircle className="h-4 w-4" /> Run All Endpoints
        </h3>
        {!sessionId && (
          <span className="text-xs text-yellow-400">Create a session first</span>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        Execute every endpoint in this collection using session auth and common parameter values from Config.
        Endpoints with unresolved path parameters will be skipped.
      </p>

      <div className="flex items-center gap-2">
        <button
          onClick={handleRunAll}
          disabled={!sessionId || runAll.isPending}
          className="flex items-center gap-1.5 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
        >
          {runAll.isPending
            ? <Loader2 className="h-4 w-4 animate-spin" />
            : <PlayCircle className="h-4 w-4" />}
          {runAll.isPending ? 'Running...' : 'Run All Endpoints'}
        </button>

        {Object.keys(commonVars).length === 0 && (
          <span className="text-xs text-muted-foreground">
            Tip: Set common values in Config tab first
          </span>
        )}
      </div>

      {/* Summary */}
      {runAll.data && (
        <div className="grid grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-lg p-3 text-center">
            <div className="text-xl font-bold">{runAll.data.total}</div>
            <div className="text-[10px] text-muted-foreground">Total</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-green-400">{successes.length}</div>
            <div className="text-[10px] text-muted-foreground">Success</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-red-400">{errors.length}</div>
            <div className="text-[10px] text-muted-foreground">Errors</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-yellow-400">{skipped.length}</div>
            <div className="text-[10px] text-muted-foreground">Skipped</div>
          </div>
        </div>
      )}

      {runAll.isError && (
        <div className="text-xs text-red-400 flex items-center gap-1">
          <AlertCircle className="h-3 w-3" />
          {(runAll.error as Error).message}
        </div>
      )}

      {/* Results table */}
      {results.length > 0 && (
        <div className="overflow-auto max-h-[500px] border border-border rounded-lg">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground bg-card/50 sticky top-0">
                <th className="py-2 px-3 font-medium">Method</th>
                <th className="py-2 px-3 font-medium">Path</th>
                <th className="py-2 px-3 font-medium">Status</th>
                <th className="py-2 px-3 font-medium">Time</th>
                <th className="py-2 px-3 font-medium">Result</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} className="border-b border-border/50 hover:bg-accent/30">
                  <td className="py-1.5 px-3">
                    <span className={cn(
                      'px-1 py-0.5 rounded text-[10px] font-bold border',
                      METHOD_COLOR[r.method] || METHOD_COLOR.GET,
                    )}>
                      {r.method}
                    </span>
                  </td>
                  <td className="py-1.5 px-3 font-mono truncate max-w-[300px]">{r.path}</td>
                  <td className="py-1.5 px-3">
                    {r.status === 'skipped' ? (
                      <span className="text-yellow-400">SKIP</span>
                    ) : (
                      <span className={cn('font-bold', STATUS_COLOR(r.status_code ?? null))}>
                        {r.status_code || 'ERR'}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-3 text-muted-foreground">
                    {r.duration_ms != null ? `${r.duration_ms}ms` : '-'}
                  </td>
                  <td className="py-1.5 px-3 text-muted-foreground truncate max-w-[200px]">
                    {r.reason || r.error || (r.status_code && r.status_code < 400 ? 'OK' : '')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function tryFormatJson(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2)
  } catch {
    return str
  }
}
