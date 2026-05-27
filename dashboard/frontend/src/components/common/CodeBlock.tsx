import { useState } from 'react'
import { Copy, Check, Download } from 'lucide-react'

const EXT_MAP: Record<string, string> = {
  python: 'py', py: 'py',
  bash: 'sh', sh: 'sh', shell: 'sh', zsh: 'sh',
  javascript: 'js', js: 'js', typescript: 'ts', ts: 'ts',
  tsx: 'tsx', jsx: 'jsx',
  json: 'json', yaml: 'yaml', yml: 'yml',
  go: 'go', rust: 'rs', java: 'java', c: 'c', cpp: 'cpp',
  ruby: 'rb', rb: 'rb', php: 'php',
  sql: 'sql', html: 'html', css: 'css',
  xml: 'xml', toml: 'toml', ini: 'ini',
  markdown: 'md', md: 'md',
  dockerfile: 'Dockerfile',
  text: 'txt',
}

function detectLang(className: string | undefined): string {
  if (!className) return ''
  const m = /language-([\w-]+)/.exec(className)
  return m ? m[1].toLowerCase() : ''
}

function extractText(node: unknown): string {
  if (typeof node === 'string') return node
  if (typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(extractText).join('')
  if (node && typeof node === 'object') {
    const props = (node as { props?: { children?: unknown } }).props
    if (props && 'children' in props) return extractText(props.children)
  }
  return ''
}

/**
 * Custom <pre> renderer for ReactMarkdown that adds Copy + Download buttons
 * to the top-right of each code block. Drop-in replacement for the default
 * <pre> element.
 */
export function CodeBlock({ children }: { children?: React.ReactNode }) {
  const [copied, setCopied] = useState(false)

  // children is normally a single <code> element
  const codeEl = Array.isArray(children) ? children[0] : children
  const className =
    (codeEl && typeof codeEl === 'object' && 'props' in codeEl)
      ? ((codeEl as { props?: { className?: string } }).props?.className)
      : undefined
  const lang = detectLang(className)
  const text = extractText(codeEl).replace(/\n$/, '')

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Fallback for older browsers / non-secure contexts
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try { document.execCommand('copy') } catch { /* ignore */ }
      ta.remove()
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }
  }

  const download = () => {
    const ext = EXT_MAP[lang] || 'txt'
    const filename = ext === 'Dockerfile' ? 'Dockerfile' : `chat-snippet.${ext}`
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="relative group my-2">
      <div className="absolute top-1 right-1 z-10 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        {lang && (
          <span className="text-[9px] font-mono px-1.5 py-0.5 bg-muted-foreground/20 text-muted-foreground rounded">
            {lang}
          </span>
        )}
        <button
          onClick={copy}
          title={copied ? 'Copied!' : 'Copy code'}
          className="p-1 rounded bg-muted-foreground/20 hover:bg-muted-foreground/40 text-muted-foreground hover:text-foreground"
        >
          {copied
            ? <Check className="h-3 w-3 text-green-400" />
            : <Copy className="h-3 w-3" />}
        </button>
        <button
          onClick={download}
          title={`Download as ${EXT_MAP[lang] ? `chat-snippet.${EXT_MAP[lang]}` : 'chat-snippet.txt'}`}
          className="p-1 rounded bg-muted-foreground/20 hover:bg-muted-foreground/40 text-muted-foreground hover:text-foreground"
        >
          <Download className="h-3 w-3" />
        </button>
      </div>
      <pre className="overflow-x-auto bg-zinc-900/80 border border-border rounded p-3 pt-6 text-xs">
        {children}
      </pre>
    </div>
  )
}
