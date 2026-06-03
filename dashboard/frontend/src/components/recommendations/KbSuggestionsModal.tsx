/**
 * KB Tool Suggestions modal.
 *
 * Triggered from the AssetBrowser PortDetailDialog via "Suggest from KB".
 * Fetches structured tool suggestions for the selected (service, port)
 * from the knowledge base via /api/rag/tools/recommend, and lets the
 * operator promote any suggestion into a stored scan_recommendations row
 * with source='kb_manual' so it flows through the same dispatch loop as
 * auto-generated recs.
 *
 * The auto-rec generator (scan_recommender/scan_recommender.py) already
 * runs on every ingest, so most port→tool mappings will already exist.
 * This surface exists for cases where:
 *   - the operator wants a tool the rules don't pick (e.g. a CTF-specific
 *     scanner with no entry in service_tools.yaml)
 *   - the operator wants to see the KB's RAG context for "why this tool"
 *   - the auto-generator hasn't run yet for a newly-detected port
 */

import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { X, Plus, Loader2, BookOpen, Check } from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  useKbToolRecommend,
  useAddScanRecommendation,
  type KbToolSuggestion,
} from '@/api/assets'

interface KbSuggestionsModalProps {
  ip: string
  port: number
  service?: string
  onClose: () => void
}

export function KbSuggestionsModal({ ip, port, service, onClose }: KbSuggestionsModalProps) {
  const { data, isLoading, error } = useKbToolRecommend(service, port)
  const addMutation = useAddScanRecommendation()
  // Track which suggestions have been added so we can render a green check
  // instead of the Add button.  Keyed by tool name to handle the dedup case
  // (server says created=false but UI still wants to confirm "it's there").
  const [added, setAdded] = useState<Record<string, 'created' | 'existed'>>({})

  const handleAdd = (tool: KbToolSuggestion) => {
    addMutation.mutate(
      {
        ip,
        port,
        service,
        scanner: tool.name,
        action: tool.purpose,
        script: tool.command || undefined,
        priority: 50,
      },
      {
        onSuccess: (res) => {
          setAdded(prev => ({
            ...prev,
            [tool.name]: res.created ? 'created' : 'existed',
          }))
        },
      },
    )
  }

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-[70]" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[90vw] max-w-[700px] max-h-[85vh] overflow-y-auto bg-card border border-border rounded-lg shadow-2xl z-[80] p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-blue-400" />
              <Dialog.Title className="text-sm font-semibold">
                KB Suggestions for {service || 'unknown'}:{port}
              </Dialog.Title>
              <span className="text-[10px] text-muted-foreground font-mono">{ip}</span>
            </div>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>

          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" />
              Loading suggestions…
            </div>
          )}

          {error && (
            <div className="text-xs text-red-400 border border-red-500/30 bg-red-500/5 rounded p-2">
              Failed to load KB suggestions: {String(error)}
            </div>
          )}

          {data && data.error && (
            <div className="text-xs text-yellow-400 border border-yellow-500/30 bg-yellow-500/5 rounded p-2 mb-3">
              {data.error}
            </div>
          )}

          {data && !data.error && (
            <div className="space-y-3 text-xs">
              {data.description && (
                <p className="text-muted-foreground">{data.description}</p>
              )}

              {/* Tools list -- the primary surface; this is what the user adds */}
              <div>
                <h3 className="font-medium mb-1.5">Recommended tools</h3>
                {data.tools.length === 0 ? (
                  <p className="text-muted-foreground italic">No KB entry for this service.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {data.tools.map((tool) => {
                      const state = added[tool.name]
                      return (
                        <li key={tool.name} className="border border-border rounded p-2 space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-medium text-blue-400">{tool.name}</span>
                            <span className="text-muted-foreground flex-1">{tool.purpose}</span>
                            {state ? (
                              <span className="flex items-center gap-1 text-[10px] text-green-400">
                                <Check className="h-3 w-3" />
                                {state === 'created' ? 'Added' : 'Already in queue'}
                              </span>
                            ) : (
                              <button
                                onClick={() => handleAdd(tool)}
                                disabled={addMutation.isPending}
                                className="px-2 py-0.5 text-[10px] rounded bg-primary text-primary-foreground hover:bg-primary/90 flex items-center gap-1 disabled:opacity-50"
                              >
                                {addMutation.isPending ? (
                                  <Loader2 className="h-2.5 w-2.5 animate-spin" />
                                ) : (
                                  <Plus className="h-2.5 w-2.5" />
                                )}
                                Add
                              </button>
                            )}
                          </div>
                          {tool.command && (
                            <pre className="text-[10px] font-mono bg-muted rounded px-1.5 py-0.5 overflow-x-auto select-all text-muted-foreground">
                              {tool.command}
                            </pre>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>

              {/* Metasploit modules -- read-only reference for now; the
                  Exploit Manager owns module execution */}
              {data.metasploit && data.metasploit.length > 0 && (
                <div>
                  <h3 className="font-medium mb-1.5">Metasploit modules</h3>
                  <ul className="space-y-1 text-[11px] text-muted-foreground">
                    {data.metasploit.map((m) => (
                      <li key={m.module} className="font-mono">
                        {m.module}
                        {m.purpose && <span className="ml-2 font-sans text-[10px]">— {m.purpose}</span>}
                      </li>
                    ))}
                  </ul>
                  <p className="text-[10px] text-muted-foreground/70 mt-1">
                    Run modules from the Exploit Manager page.
                  </p>
                </div>
              )}

              {/* Nuclei tags */}
              {data.nuclei_tags && data.nuclei_tags.length > 0 && (
                <div>
                  <h3 className="font-medium mb-1.5">Nuclei tags</h3>
                  <div className="flex flex-wrap gap-1">
                    {data.nuclei_tags.map((tag) => (
                      <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded border border-border bg-muted/30 font-mono">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Common vulns */}
              {data.common_vulns && data.common_vulns.length > 0 && (
                <div>
                  <h3 className="font-medium mb-1.5">Common vulns</h3>
                  <ul className="space-y-0.5 text-[11px] text-muted-foreground list-disc pl-4">
                    {data.common_vulns.map((v) => (
                      <li key={v}>{v}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* RAG context -- a playbook excerpt for "why this tool" */}
              {data.rag_context && (
                <div>
                  <h3 className="font-medium mb-1.5">Playbook excerpt</h3>
                  <pre className="text-[10px] bg-muted/30 border border-border rounded p-2 max-h-48 overflow-y-auto whitespace-pre-wrap">
                    {data.rag_context}
                  </pre>
                </div>
              )}

              {/* Footer link to the full Recommendations page so the operator
                  can see everything they've queued + dispatched in one place */}
              <div className="pt-2 border-t border-border/50">
                <Link
                  to="/recommendations"
                  onClick={onClose}
                  className="text-[10px] text-blue-400 hover:underline"
                >
                  View all recommendations →
                </Link>
              </div>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
