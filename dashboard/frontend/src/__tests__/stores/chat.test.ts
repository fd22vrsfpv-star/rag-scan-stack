import { describe, it, expect, beforeEach } from 'vitest'
import { useChatStore } from '@/stores/chat'
import type { ChatMessage } from '@/lib/types'

describe('useChatStore', () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    useChatStore.setState({
      messages: [],
      isStreaming: false,
      toolCalls: [],
      pendingInput: null,
      attachedFiles: [],
      mode: 'floating',
    })
  })

  it('has correct initial state defaults', () => {
    const state = useChatStore.getState()
    expect(state.mode).toBe('floating')
    expect(state.messages).toEqual([])
    expect(state.isStreaming).toBe(false)
    expect(state.toolCalls).toEqual([])
    expect(state.pendingInput).toBeNull()
    expect(state.attachedFiles).toEqual([])
  })

  it('addMessage adds to messages array', () => {
    const msg: ChatMessage = { role: 'user', content: 'hello' }
    useChatStore.getState().addMessage(msg)
    expect(useChatStore.getState().messages).toHaveLength(1)
    expect(useChatStore.getState().messages[0]).toEqual(msg)
  })

  it('addMessage also clears toolCalls', () => {
    useChatStore.setState({ toolCalls: [{ name: 'test', args: {}, status: 'running' }] })
    useChatStore.getState().addMessage({ role: 'user', content: 'hi' })
    expect(useChatStore.getState().toolCalls).toEqual([])
  })

  it('appendToLast appends to last assistant message', () => {
    useChatStore.setState({
      messages: [{ role: 'assistant', content: 'hello' }],
    })
    useChatStore.getState().appendToLast(' world')
    expect(useChatStore.getState().messages[0].content).toBe('hello world')
  })

  it('appendToLast creates new assistant message if last is not assistant', () => {
    useChatStore.setState({
      messages: [{ role: 'user', content: 'question' }],
    })
    useChatStore.getState().appendToLast('answer')
    expect(useChatStore.getState().messages).toHaveLength(2)
    expect(useChatStore.getState().messages[1]).toEqual({
      role: 'assistant',
      content: 'answer',
    })
  })

  it('setMode changes mode', () => {
    useChatStore.getState().setMode('docked')
    expect(useChatStore.getState().mode).toBe('docked')
    useChatStore.getState().setMode('window')
    expect(useChatStore.getState().mode).toBe('window')
  })

  it('addAttachedFile adds a file', () => {
    const file = { id: 'f1', name: 'test.txt', content_type: 'text/plain', size: 100 }
    useChatStore.getState().addAttachedFile(file)
    expect(useChatStore.getState().attachedFiles).toHaveLength(1)
    expect(useChatStore.getState().attachedFiles[0]).toEqual(file)
  })

  it('removeAttachedFile removes by id', () => {
    const file1 = { id: 'f1', name: 'a.txt', content_type: 'text/plain', size: 10 }
    const file2 = { id: 'f2', name: 'b.txt', content_type: 'text/plain', size: 20 }
    useChatStore.setState({ attachedFiles: [file1, file2] })
    useChatStore.getState().removeAttachedFile('f1')
    expect(useChatStore.getState().attachedFiles).toHaveLength(1)
    expect(useChatStore.getState().attachedFiles[0].id).toBe('f2')
  })

  it('clearMessages resets messages, toolCalls, pendingInput, and attachedFiles', () => {
    useChatStore.setState({
      messages: [{ role: 'user', content: 'test' }],
      toolCalls: [{ name: 'tool', args: {}, status: 'done' }],
      pendingInput: 'pending',
      attachedFiles: [{ id: 'f1', name: 'x.txt', content_type: 'text/plain', size: 5 }],
    })
    useChatStore.getState().clearMessages()
    const state = useChatStore.getState()
    expect(state.messages).toEqual([])
    expect(state.toolCalls).toEqual([])
    expect(state.pendingInput).toBeNull()
    expect(state.attachedFiles).toEqual([])
  })

  it('setStreaming toggles streaming state', () => {
    useChatStore.getState().setStreaming(true)
    expect(useChatStore.getState().isStreaming).toBe(true)
    useChatStore.getState().setStreaming(false)
    expect(useChatStore.getState().isStreaming).toBe(false)
  })
})
