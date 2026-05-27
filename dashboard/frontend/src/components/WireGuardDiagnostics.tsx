import React, { useState, useEffect } from 'react'
import { RefreshCw, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'

interface DiagnosticResult {
  component: string
  status: 'healthy' | 'warning' | 'error'
  message: string
  details?: string
}

export function WireGuardDiagnostics() {
  const [diagnostics, setDiagnostics] = useState<DiagnosticResult[]>([])
  const [isRunning, setIsRunning] = useState(false)

  const runDiagnostics = async () => {
    setIsRunning(true)
    const results: DiagnosticResult[] = []

    try {
      // Test WireGuard server status
      try {
        const wgResponse = await fetch('/api/services/status')
        if (wgResponse.ok) {
          results.push({
            component: 'WireGuard Server',
            status: 'healthy',
            message: 'Running on port 51820 (SSL)',
          })
        } else {
          results.push({
            component: 'WireGuard Server',
            status: 'error',
            message: `HTTP ${wgResponse.status}: Not accessible`,
            details: 'Start with: docker compose --profile optional up -d wg-server',
          })
        }
      } catch (err) {
        results.push({
          component: 'WireGuard Server',
          status: 'error',
          message: 'Connection failed',
          details: 'Check if WireGuard server container is running',
        })
      }

      // Test database connectivity via HTTPS
      try {
        const dbResponse = await fetch('/api/wg/peers')
        if (dbResponse.ok) {
          results.push({
            component: 'Database Connection',
            status: 'healthy',
            message: 'Database accessible',
          })
        } else if (dbResponse.status === 500) {
          results.push({
            component: 'Database Connection',
            status: 'error',
            message: 'Internal server error',
            details: 'Node manager or database connection failed',
          })
        } else {
          results.push({
            component: 'Database Connection',
            status: 'warning',
            message: `HTTP ${dbResponse.status}: ${dbResponse.statusText}`,
          })
        }
      } catch (err) {
        results.push({
          component: 'Database Connection',
          status: 'error',
          message: 'Connection failed',
          details: 'Check if PostgreSQL is running',
        })
      }

      // Test node manager
      try {
        const nmResponse = await fetch('/api/nodes')
        if (nmResponse.ok) {
          results.push({
            component: 'Node Manager',
            status: 'healthy',
            message: 'API responding',
          })
        } else {
          results.push({
            component: 'Node Manager',
            status: 'warning',
            message: 'API issues detected',
          })
        }
      } catch (err) {
        results.push({
          component: 'Node Manager',
          status: 'error',
          message: 'Not responding',
          details: 'Check docker compose ps node-manager',
        })
      }

    } catch (error) {
      results.push({
        component: 'System',
        status: 'error',
        message: 'Diagnostic failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      })
    }

    setDiagnostics(results)
    setIsRunning(false)
  }

  useEffect(() => {
    runDiagnostics()
  }, [])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />
      default: return null
    }
  }

  const hasErrors = diagnostics.some(d => d.status === 'error')
  const hasWarnings = diagnostics.some(d => d.status === 'warning')

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">WireGuard System Diagnostics</h3>
        <button
          onClick={runDiagnostics}
          disabled={isRunning}
          className="px-3 py-1 text-sm border border-border rounded-md hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isRunning ? 'animate-spin' : ''}`} />
          {isRunning ? 'Running...' : 'Refresh'}
        </button>
      </div>

      {hasErrors && (
        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
          <div className="flex items-center gap-2 text-red-500">
            <XCircle className="h-4 w-4" />
            <span className="text-sm">Critical issues detected. WireGuard peer creation may fail.</span>
          </div>
        </div>
      )}

      {hasWarnings && !hasErrors && (
        <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <div className="flex items-center gap-2 text-yellow-500">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-sm">Some components have issues. Check details below.</span>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {diagnostics.map((diagnostic, index) => (
          <div
            key={index}
            className="flex items-start gap-3 p-3 border border-border rounded-lg"
          >
            {getStatusIcon(diagnostic.status)}
            <div className="flex-1">
              <div className="font-medium">{diagnostic.component}</div>
              <div className="text-sm text-muted-foreground">{diagnostic.message}</div>
              {diagnostic.details && (
                <div className="text-xs text-muted-foreground mt-1 font-mono">
                  {diagnostic.details}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {diagnostics.length === 0 && isRunning && (
        <div className="text-center text-muted-foreground py-8">
          Running diagnostics...
        </div>
      )}
    </div>
  )
}