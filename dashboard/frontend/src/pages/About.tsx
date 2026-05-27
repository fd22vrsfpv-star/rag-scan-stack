import { useState, useMemo } from 'react'
import { useDocs, useDocContent, useMcpTools } from '@/api/about'
import type { McpServer, McpTool } from '@/api/about'
import {
  FileText, Wrench, ChevronRight, ChevronDown, Loader2, Shield, Terminal,
  Scan, Globe2, Swords, Bot, KeyRound, Plug, Workflow, Bug, Zap, Rocket,
  BookOpen, FolderOpen,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { BUILD_VERSION } from '@/lib/constants'

const SERVER_ICONS: Record<string, React.ElementType> = {
  'Scanning': Scan,
  'Recon & OSINT': Globe2,
  'Exploits & Metasploit': Swords,
  'Sessions & Queries': Bot,
  'Credentials': KeyRound,
  'Scan Pipelines': Workflow,
  'Burp Suite': Bug,
  'ZAP Scanner': Zap,
}

type Tab = 'start' | 'docs' | 'mcp-tools'

// ── Doc categories — maps category name to filename patterns ──
const DOC_CATEGORIES: [string, RegExp][] = [
  ['Getting Started', /^(START_HERE|QUICKSTART|BETA_GUIDE|README)/i],
  ['Deployment', /^(DEPLOYMENT|SECURITY_SETUP|BACKUP|REMOTE.DB|ETH0)/i],
  ['API Reference', /^(API_ENDPOINT|HTTP_API|RAG_STACK_API|HEALTH_CHECK)/i],
  ['Architecture', /^(DATABASE_SCHEMA|COMMAND_FLOW|COMPREHENSIVE|SCHEMA_UPDATE|DIAGNOSTIC)/i],
  ['MCP & Integrations', /^(MCP_|CLAUDE_DESKTOP|LIBRECHAT|OPEN_WEBUI|TOOL_CALLING)/i],
  ['Security', /^(SECURITY|SQL_INJECTION)/i],
  ['Operations', /^(CHANGELOG|CHANGES_MADE|OS_CHANGES|PERFORMANCE|MEMORY_OPTIM)/i],
]

function categorizeDoc(name: string): string {
  for (const [cat, pattern] of DOC_CATEGORIES) {
    if (pattern.test(name)) return cat
  }
  return 'Other'
}


export default function About() {
  const [tab, setTab] = useState<Tab>('start')
  const [selectedDoc, setSelectedDoc] = useState<string | null>(null)
  const [expandedServer, setExpandedServer] = useState<string | null>(null)
  const [expandedTool, setExpandedTool] = useState<string | null>(null)
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set(['Getting Started']))

  const { data: docsData, isLoading: loadingDocs } = useDocs()
  const { data: docContent, isLoading: loadingContent } = useDocContent(
    tab === 'start' ? 'START_HERE.md' : selectedDoc,
  )
  const { data: mcpData, isLoading: loadingMcp } = useMcpTools()

  const docs = docsData?.docs ?? []
  const servers = mcpData?.servers ?? []

  // Group docs by category
  const grouped = useMemo(() => {
    const groups: Record<string, typeof docs> = {}
    for (const doc of docs) {
      // Skip internal files
      if (/^(PROMPT_LOG|Memories|CLAUDE)\./i.test(doc.name)) continue
      const cat = categorizeDoc(doc.name)
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(doc)
    }
    // Sort: defined categories first, then Other
    const order = DOC_CATEGORIES.map(([name]) => name)
    const sorted: [string, typeof docs][] = []
    for (const cat of order) {
      if (groups[cat]) sorted.push([cat, groups[cat]])
    }
    if (groups['Other']) sorted.push(['Other', groups['Other']])
    return sorted
  }, [docs])

  const toggleCat = (cat: string) => {
    setExpandedCats(prev => {
      const next = new Set(prev)
      next.has(cat) ? next.delete(cat) : next.add(cat)
      return next
    })
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-lg font-bold">Pentest Dashboard</h1>
            <p className="text-xs text-muted-foreground">Security Workflow Collector for Authorized Testing — v{BUILD_VERSION}</p>
          </div>
        </div>
        {/* Tabs */}
        <div className="flex gap-1 mt-3">
          {([
            ['start', 'Start Here', Rocket],
            ['docs', 'Documentation', BookOpen],
            ['mcp-tools', 'MCP Tools', Wrench],
          ] as [Tab, string, React.ElementType][]).map(([key, label, Icon]) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors',
                tab === key ? 'bg-primary/10 text-primary font-medium' : 'text-muted-foreground hover:bg-accent',
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
              {key === 'mcp-tools' && mcpData && (
                <span className="text-[10px] bg-muted px-1 rounded">{mcpData.total_tools}</span>
              )}
              {key === 'docs' && docs.length > 0 && (
                <span className="text-[10px] bg-muted px-1 rounded">{docs.length}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ── Start Here Tab ── */}
      {tab === 'start' && (
        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-4xl mx-auto">
            {loadingContent && (
              <div className="flex justify-center py-8">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            )}
            {docContent && <MarkdownView content={docContent.content} />}
          </div>
        </div>
      )}

      {/* ── Documentation Tab ── */}
      {tab === 'docs' && (
        <div className="flex flex-1 overflow-hidden">
          {/* Categorized sidebar */}
          <div className="w-72 border-r border-border overflow-y-auto py-2">
            {loadingDocs && (
              <div className="flex justify-center py-8">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            )}
            {grouped.map(([cat, catDocs]) => (
              <div key={cat}>
                <button
                  onClick={() => toggleCat(cat)}
                  className="w-full flex items-center gap-2 px-3 py-1.5 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide hover:bg-accent/50"
                >
                  {expandedCats.has(cat)
                    ? <ChevronDown className="h-3 w-3" />
                    : <ChevronRight className="h-3 w-3" />}
                  <FolderOpen className="h-3 w-3" />
                  {cat}
                  <span className="text-[10px] font-normal ml-auto">{catDocs.length}</span>
                </button>
                {expandedCats.has(cat) && catDocs.map(doc => (
                  <button
                    key={doc.name}
                    onClick={() => setSelectedDoc(doc.name)}
                    className={cn(
                      'w-full text-left pl-8 pr-3 py-1 text-[11px] flex items-center gap-2 hover:bg-accent transition-colors',
                      selectedDoc === doc.name ? 'bg-primary/10 text-primary font-medium' : 'text-muted-foreground',
                    )}
                  >
                    <FileText className="h-3 w-3 shrink-0" />
                    <span className="truncate">{doc.name.replace('.md', '')}</span>
                  </button>
                ))}
              </div>
            ))}
          </div>

          {/* Doc content */}
          <div className="flex-1 overflow-y-auto p-6">
            {!selectedDoc && (
              <div className="text-center text-muted-foreground py-12">
                <BookOpen className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">Select a document from the sidebar</p>
                <p className="text-xs mt-1">Documents are organized by category for easy navigation</p>
              </div>
            )}
            {loadingContent && selectedDoc && (
              <div className="flex justify-center py-8">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            )}
            {docContent && selectedDoc && (
              <div className="max-w-4xl">
                <MarkdownView content={docContent.content} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── MCP Tools Tab ── */}
      {tab === 'mcp-tools' && (
        <div className="flex-1 overflow-y-auto p-6">
          {loadingMcp && (
            <div className="flex justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          )}
          <div className="max-w-4xl space-y-4">
            {servers.map(server => (
              <McpServerCard
                key={server.file}
                server={server}
                expanded={expandedServer === server.file}
                onToggle={() => setExpandedServer(expandedServer === server.file ? null : server.file)}
                expandedTool={expandedTool}
                onToggleTool={(name) => setExpandedTool(expandedTool === name ? null : name)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


// ── Simple Markdown Renderer ──────────────────────────────────────
function MarkdownView({ content }: { content: string }) {
  const html = useMemo(() => renderMarkdown(content), [content])
  return (
    <div
      className="prose prose-sm prose-invert max-w-none
        [&_h1]:text-xl [&_h1]:font-bold [&_h1]:mb-3 [&_h1]:mt-6 [&_h1]:text-foreground [&_h1]:border-b [&_h1]:border-border [&_h1]:pb-2
        [&_h2]:text-lg [&_h2]:font-semibold [&_h2]:mb-2 [&_h2]:mt-5 [&_h2]:text-foreground
        [&_h3]:text-base [&_h3]:font-semibold [&_h3]:mb-2 [&_h3]:mt-4 [&_h3]:text-foreground
        [&_h4]:text-sm [&_h4]:font-semibold [&_h4]:mb-1 [&_h4]:mt-3 [&_h4]:text-foreground
        [&_p]:text-sm [&_p]:text-foreground/85 [&_p]:mb-2 [&_p]:leading-relaxed
        [&_ul]:text-sm [&_ul]:mb-2 [&_ul]:ml-4 [&_ul]:list-disc [&_ul]:text-foreground/85
        [&_ol]:text-sm [&_ol]:mb-2 [&_ol]:ml-4 [&_ol]:list-decimal [&_ol]:text-foreground/85
        [&_li]:mb-1 [&_li]:leading-relaxed
        [&_code]:text-xs [&_code]:font-mono [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-primary
        [&_pre]:bg-muted/50 [&_pre]:border [&_pre]:border-border [&_pre]:rounded-lg [&_pre]:p-3 [&_pre]:mb-3 [&_pre]:overflow-x-auto
        [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:text-foreground/90
        [&_blockquote]:border-l-2 [&_blockquote]:border-primary/40 [&_blockquote]:pl-3 [&_blockquote]:ml-0 [&_blockquote]:text-muted-foreground [&_blockquote]:italic
        [&_strong]:text-foreground [&_strong]:font-semibold
        [&_hr]:border-border [&_hr]:my-4
        [&_a]:text-primary [&_a]:underline
        [&_table]:text-xs [&_table]:w-full [&_table]:mb-3
        [&_th]:text-left [&_th]:px-2 [&_th]:py-1 [&_th]:border-b [&_th]:border-border [&_th]:font-semibold [&_th]:text-foreground
        [&_td]:px-2 [&_td]:py-1 [&_td]:border-b [&_td]:border-border/50 [&_td]:text-foreground/85
      "
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}

function renderMarkdown(md: string): string {
  let html = md
    // Escape HTML entities
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  // Code blocks (``` ... ```)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) =>
    `<pre><code>${code.trim()}</code></pre>`)

  // Inline code
  html = html.replace(/`([^`\n]+)`/g, '<code>$1</code>')

  // Headings
  html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>')
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>')

  // Bold and italic
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>')

  // Blockquotes
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote><p>$1</p></blockquote>')

  // Horizontal rules
  html = html.replace(/^---+$/gm, '<hr />')

  // Tables (simple: | col | col | ... with header separator)
  html = html.replace(
    /^(\|.+\|)\n(\|[\s\-:|]+\|)\n((?:\|.+\|\n?)+)/gm,
    (_m, header: string, _sep: string, body: string) => {
      const ths = header.split('|').filter(c => c.trim()).map(c => `<th>${c.trim()}</th>`).join('')
      const rows = body.trim().split('\n').map(row => {
        const tds = row.split('|').filter(c => c.trim()).map(c => `<td>${c.trim()}</td>`).join('')
        return `<tr>${tds}</tr>`
      }).join('')
      return `<table><thead><tr>${ths}</tr></thead><tbody>${rows}</tbody></table>`
    })

  // Unordered lists
  html = html.replace(/^((?:- .+\n?)+)/gm, (block) => {
    const items = block.trim().split('\n').map(l =>
      `<li>${l.replace(/^- /, '')}</li>`).join('\n')
    return `<ul>${items}</ul>`
  })

  // Ordered lists
  html = html.replace(/^((?:\d+\. .+\n?)+)/gm, (block) => {
    const items = block.trim().split('\n').map(l =>
      `<li>${l.replace(/^\d+\.\s+/, '')}</li>`).join('\n')
    return `<ol>${items}</ol>`
  })

  // Paragraphs (lines not already wrapped in block elements)
  html = html.replace(/^(?!<[hupoltb]|<\/|<hr|<blockquote)(.+)$/gm, '<p>$1</p>')

  // Clean up empty paragraphs
  html = html.replace(/<p>\s*<\/p>/g, '')

  return html
}


// ── MCP Server/Tool Cards (unchanged) ─────────────────────────────
function McpServerCard({
  server, expanded, onToggle, expandedTool, onToggleTool,
}: {
  server: McpServer
  expanded: boolean
  onToggle: () => void
  expandedTool: string | null
  onToggleTool: (name: string) => void
}) {
  const Icon = SERVER_ICONS[server.name] || (server.builtin === false ? Plug : Terminal)

  return (
    <div className="border border-border rounded-lg bg-card overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-accent/50 transition-colors text-left"
      >
        {expanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
        <Icon className="h-4 w-4 text-primary" />
        <div className="flex-1 min-w-0">
          <span className="text-sm font-semibold">{server.name}</span>
          {server.builtin === false && (
            <span className="ml-2 text-[10px] bg-purple-800 text-purple-100 px-1.5 py-0.5 rounded">
              third-party
            </span>
          )}
          {server.description && server.builtin === false && (
            <p className="text-[10px] text-muted-foreground truncate mt-0.5">{server.description}</p>
          )}
        </div>
        {server.source && server.builtin === false && (
          <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{server.source}</span>
        )}
        {server.transport && server.builtin === false && (
          <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{server.transport}</span>
        )}
        <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
          {server.tool_count} tools
        </span>
        {server.port > 0 && (
          <span className="text-[10px] text-muted-foreground font-mono">:{server.port}</span>
        )}
      </button>
      {expanded && (
        <div className="border-t border-border divide-y divide-border/50">
          {server.tools.length > 0 ? (
            server.tools.map(tool => (
              <McpToolRow key={tool.name} tool={tool} expanded={expandedTool === tool.name} onToggle={() => onToggleTool(tool.name)} />
            ))
          ) : (
            <div className="px-4 py-3 text-xs text-muted-foreground">
              {server.url ? (
                <span>External service at <code className="text-primary">{server.url}</code> — tools not introspectable from source</span>
              ) : (
                <span>No tools detected from source file</span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function McpToolRow({ tool, expanded, onToggle }: { tool: McpTool; expanded: boolean; onToggle: () => void }) {
  return (
    <div>
      <button onClick={onToggle} className="w-full flex items-start gap-3 px-4 py-2 hover:bg-accent/30 transition-colors text-left">
        <Terminal className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <div className="min-w-0 flex-1">
          <span className="text-xs font-mono font-semibold text-foreground">{tool.name}</span>
          <p className="text-[10px] text-muted-foreground leading-tight mt-0.5">{tool.description}</p>
        </div>
        {tool.params.length > 0 && (
          <span className="text-[10px] text-muted-foreground shrink-0">
            {tool.params.length} param{tool.params.length !== 1 ? 's' : ''}
          </span>
        )}
      </button>
      {expanded && tool.params.length > 0 && (
        <div className="px-4 pb-2 ml-7">
          <table className="w-full text-[10px]">
            <thead>
              <tr className="text-muted-foreground text-left">
                <th className="pr-3 py-0.5 font-medium">Parameter</th>
                <th className="pr-3 py-0.5 font-medium">Type</th>
                <th className="py-0.5 font-medium">Description</th>
              </tr>
            </thead>
            <tbody>
              {tool.params.map(p => (
                <tr key={p.name} className="border-t border-border/30">
                  <td className="pr-3 py-1 font-mono text-primary">{p.name}</td>
                  <td className="pr-3 py-1 text-muted-foreground">{p.type}</td>
                  <td className="py-1 text-foreground/80">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
