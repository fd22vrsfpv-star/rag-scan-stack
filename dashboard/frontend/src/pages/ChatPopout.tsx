import { useEffect } from 'react'
import { ChatPanel } from '@/components/layout/ChatPanel'
import { useUIStore } from '@/stores/ui'
import { useChatStore } from '@/stores/chat'

/**
 * Standalone chat page mounted at /chat-popout.
 *
 * Opened by the parent window via window.open(). Forces the chat into
 * 'window' mode so it fills the popup viewport. Conversation state
 * (messages, tool calls, attachments) syncs with the parent via the
 * BroadcastChannel set up in stores/chat.ts, so both windows show the
 * same conversation in real time.
 *
 * On close, the parent's regular ChatPanel can be re-opened (it auto-
 * restores to whichever mode was last used: docked or floating).
 */
export default function ChatPopout() {
  const setChatOpen = useUIStore(s => s.setChatOpen)
  const setMode = useChatStore(s => s.setMode)

  useEffect(() => {
    document.title = 'RAG Chat'
    setChatOpen(true)   // ensure render
    setMode('window')   // tell ChatPanel to fill the viewport
    return () => {
      // When this popup unmounts (window closing), don't change parent's mode —
      // the BroadcastChannel may still flush the last-known mode, but parent's
      // own user pref is in localStorage. Reset our local mode so reopening
      // this same browser window from a fresh tab still works as a popup.
      setMode('window')
    }
  }, [setChatOpen, setMode])

  return (
    <div className="h-screen w-screen flex bg-background">
      <ChatPanel />
    </div>
  )
}
