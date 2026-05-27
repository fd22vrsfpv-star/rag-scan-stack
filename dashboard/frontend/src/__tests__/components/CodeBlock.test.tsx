import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CodeBlock } from '@/components/common/CodeBlock'

describe('CodeBlock', () => {
  it('renders code content', () => {
    render(
      <CodeBlock>
        <code>console.log("hello")</code>
      </CodeBlock>,
    )
    expect(screen.getByText('console.log("hello")')).toBeInTheDocument()
  })

  it('has a copy button', () => {
    render(
      <CodeBlock>
        <code>test code</code>
      </CodeBlock>,
    )
    const copyBtn = screen.getByTitle('Copy code')
    expect(copyBtn).toBeInTheDocument()
  })

  it('has a download button', () => {
    render(
      <CodeBlock>
        <code>test code</code>
      </CodeBlock>,
    )
    const downloadBtn = screen.getByTitle(/Download as/)
    expect(downloadBtn).toBeInTheDocument()
  })

  it('detects language from className', () => {
    render(
      <CodeBlock>
        <code className="language-python">print("hi")</code>
      </CodeBlock>,
    )
    // The language badge should render "python"
    expect(screen.getByText('python')).toBeInTheDocument()
  })

  it('renders without language badge when no className', () => {
    render(
      <CodeBlock>
        <code>plain code</code>
      </CodeBlock>,
    )
    expect(screen.getByText('plain code')).toBeInTheDocument()
    // Download title should fallback to .txt
    expect(screen.getByTitle('Download as chat-snippet.txt')).toBeInTheDocument()
  })

  it('wraps content in a pre element', () => {
    const { container } = render(
      <CodeBlock>
        <code>test</code>
      </CodeBlock>,
    )
    const pre = container.querySelector('pre')
    expect(pre).toBeInTheDocument()
  })
})
