/**
 * Per-row audit panel for AssetBrowser → Credentials.
 *
 * Renders the rich audit trail captured by the credential-check path
 * (nmap_scanner/cred_checker.py).  Backend data shape lives in
 * api/assets.ts (CredentialAudit).
 *
 * Backstory: the credential-check `/jobs/credential-check` runner
 * captures every (username, masked password) attempt against a port,
 * labels failures by mode (kex_mismatch / connection_error /
 * auth_failed / timeout / unknown), records whether SSH-KEX-legacy
 * fallback to nmap was triggered, and emits a one-line summary.  PR
 * #25 plumbed this into credential_findings.metadata.audit; this
 * component renders it so operators don't have to read SQL to see
 * "we tried 8 creds, all 8 failed at KEX because the target uses
 * legacy SSH algorithms".
 *
 * Absent-audit case: brutus-runner rows have no `audit` field (brutus
 * is a Go binary that doesn't expose per-attempt detail).  The
 * AssetBrowser caller decides whether to render this panel at all
 * based on `credential.metadata.audit` existence.
 */

import { useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, XCircle } from 'lucide-react'
import type { CredentialAudit, CredentialAttempt, CredentialMethodAudit } from '@/api/assets'

interface Props {
  audit: CredentialAudit
}

// Failure modes get distinct colors so an operator scanning a long
// attempts list can see at a glance which failures were "wrong creds"
// (auth_failed = grey, expected) vs. "couldn't even handshake"
// (kex_mismatch / connection_error = red, actionable).
const FAILURE_MODE_BADGE: Record<string, string> = {
  kex_mismatch:     'bg-red-500/15 text-red-300 border-red-500/30',
  connection_error: 'bg-red-500/15 text-red-300 border-red-500/30',
  timeout:          'bg-orange-500/15 text-orange-300 border-orange-500/30',
  auth_failed:      'bg-gray-500/15 text-gray-300 border-gray-500/30',
  unknown:          'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
}

const FAILURE_MODE_LABEL: Record<string, string> = {
  kex_mismatch:     'KEX mismatch',
  connection_error: 'no connection',
  timeout:          'timeout',
  auth_failed:      'auth failed',
  unknown:          'unknown',
}

export function CredentialAuditPanel({ audit }: Props) {
  const [methodsExpanded, setMethodsExpanded] = useState<Set<string>>(new Set())

  const toggleMethod = (key: string) => {
    setMethodsExpanded(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  return (
    <div className="mt-2 pt-2 border-t border-border/50 space-y-3 text-[11px]">
      {/* Summary headline — first thing the operator reads */}
      <div className="flex items-start gap-2">
        <div className="flex-1">
          <div className="text-muted-foreground">Audit summary</div>
          <div className="text-foreground italic">{audit.summary || '(no summary)'}</div>
        </div>
        <div className="flex flex-wrap gap-1 shrink-0">
          {audit.kex_legacy_detected && (
            <span className="px-1.5 py-0.5 rounded text-[10px] border bg-red-500/15 text-red-300 border-red-500/30"
                  title="SSH key-exchange failed before any password could be tested. Target uses legacy ssh-rsa / ssh-dss algorithms (e.g. OpenSSH < 7.0, Metasploitable2).">
              KEX legacy
            </span>
          )}
          {audit.fell_back_to_nmap && (
            <span className="px-1.5 py-0.5 rounded text-[10px] border bg-amber-500/15 text-amber-300 border-amber-500/30"
                  title="hydra returned 0 valid credentials so the runner automatically retried with nmap's NSE brute scripts (which negotiate legacy KEX correctly)">
              nmap fallback
            </span>
          )}
          {(audit.methods_used || []).map(m => (
            <span key={m} className="px-1.5 py-0.5 rounded text-[10px] border bg-blue-500/15 text-blue-300 border-blue-500/30 font-mono">
              {m}
            </span>
          ))}
        </div>
      </div>

      {/* Source + counts */}
      <div className="grid grid-cols-3 gap-x-4 gap-y-1 text-muted-foreground">
        <div>Source: <span className="text-foreground font-mono">{audit.credential_source || '(unknown)'}</span></div>
        <div>Tested: <span className="text-foreground">{audit.credentials_tested ?? '?'} (user, pass) pairs</span></div>
        <div>Users / passwords: <span className="text-foreground">{(audit.users_tried || []).length} / {(audit.passwords_tried_masked || []).length}</span></div>
      </div>

      {/* Users + passwords tried */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="text-muted-foreground mb-1">Usernames tried</div>
          <div className="flex flex-wrap gap-1">
            {(audit.users_tried || []).length === 0
              ? <span className="text-muted-foreground italic">(none)</span>
              : (audit.users_tried || []).map(u => (
                  <span key={u} className="px-1.5 py-0.5 rounded text-[10px] border border-border bg-muted/30 font-mono">{u}</span>
                ))}
          </div>
        </div>
        <div>
          <div className="text-muted-foreground mb-1">Passwords tried (masked)</div>
          <div className="flex flex-wrap gap-1">
            {(audit.passwords_tried_masked || []).length === 0
              ? <span className="text-muted-foreground italic">(none)</span>
              : (audit.passwords_tried_masked || []).map((p, i) => (
                  <span key={`${p}-${i}`} className="px-1.5 py-0.5 rounded text-[10px] border border-border bg-muted/30 font-mono">{p}</span>
                ))}
          </div>
        </div>
      </div>

      {/* Per-method per-attempt detail */}
      <div className="space-y-1.5">
        <div className="text-muted-foreground">Per-method attempts</div>
        {(audit.method_audits || []).map((ma, idx) => (
          <MethodAttemptsBlock
            key={`${ma.method}-${idx}`}
            audit={ma}
            expanded={methodsExpanded.has(`${ma.method}-${idx}`)}
            onToggle={() => toggleMethod(`${ma.method}-${idx}`)}
          />
        ))}
        {(!audit.method_audits || audit.method_audits.length === 0) && (
          <div className="text-muted-foreground italic">(no per-method audit available)</div>
        )}
      </div>
    </div>
  )
}

interface MethodAttemptsBlockProps {
  audit: CredentialMethodAudit
  expanded: boolean
  onToggle: () => void
}

function MethodAttemptsBlock({ audit, expanded, onToggle }: MethodAttemptsBlockProps) {
  const attempts = audit.attempts || []
  const successes = attempts.filter(a => a.success).length
  const failures = attempts.length - successes

  return (
    <div className="border border-border/50 rounded">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-2 py-1 hover:bg-muted/30 text-left"
      >
        {expanded ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
        <span className="font-mono font-medium text-blue-400">{audit.method}</span>
        {audit.script && <span className="text-muted-foreground text-[10px]">({audit.script})</span>}
        <span className="text-muted-foreground text-[10px] ml-auto">
          {successes > 0 && <span className="text-green-400">{successes} ok</span>}
          {successes > 0 && failures > 0 && ' / '}
          {failures > 0 && <span className="text-red-400/80">{failures} fail</span>}
          {attempts.length === 0 && <span className="italic">no attempts recorded</span>}
        </span>
        {audit.kex_legacy_detected && (
          <span className="px-1 py-0.5 rounded text-[9px] border bg-red-500/15 text-red-300 border-red-500/30 flex items-center gap-0.5">
            <AlertTriangle className="h-2.5 w-2.5" /> KEX legacy
          </span>
        )}
      </button>
      {expanded && attempts.length > 0 && (
        <div className="border-t border-border/50 max-h-64 overflow-y-auto">
          <table className="w-full text-[10px]">
            <thead className="bg-muted/30 text-muted-foreground">
              <tr>
                <th className="text-left px-2 py-1 font-medium">Username</th>
                <th className="text-left px-2 py-1 font-medium">Password</th>
                <th className="text-left px-2 py-1 font-medium">Result</th>
                <th className="text-left px-2 py-1 font-medium">Failure mode</th>
                <th className="text-left px-2 py-1 font-medium">Error excerpt</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a, i) => (
                <AttemptRow key={i} attempt={a} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AttemptRow({ attempt }: { attempt: CredentialAttempt }) {
  return (
    <tr className="border-t border-border/30 hover:bg-muted/10">
      <td className="px-2 py-1 font-mono">{attempt.username || '(empty)'}</td>
      <td className="px-2 py-1 font-mono text-muted-foreground">{attempt.password_masked || '(empty)'}</td>
      <td className="px-2 py-1">
        {attempt.success ? (
          <span className="inline-flex items-center gap-1 text-green-400">
            <CheckCircle2 className="h-3 w-3" /> valid
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-red-400/80">
            <XCircle className="h-3 w-3" /> fail
          </span>
        )}
      </td>
      <td className="px-2 py-1">
        {attempt.failure_mode ? (
          <span className={`px-1.5 py-0.5 rounded text-[9px] border ${FAILURE_MODE_BADGE[attempt.failure_mode] || FAILURE_MODE_BADGE.unknown}`}>
            {FAILURE_MODE_LABEL[attempt.failure_mode] || attempt.failure_mode}
          </span>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </td>
      <td className="px-2 py-1 text-muted-foreground truncate max-w-[260px]" title={attempt.error_excerpt || ''}>
        {attempt.error_excerpt || '—'}
      </td>
    </tr>
  )
}
