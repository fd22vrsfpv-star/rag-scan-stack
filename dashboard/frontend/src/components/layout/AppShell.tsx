import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { DatabaseWarning } from './DatabaseWarning'
import { ChatPanel } from './ChatPanel'
import { useUIStore } from '@/stores/ui'
import { useWebSocket } from '@/hooks/useWebSocket'

export function AppShell() {
  const setChatOpen = useUIStore(s => s.setChatOpen)
  const chatOpen = useUIStore(s => s.chatOpen)
  useWebSocket()

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === '.') {
        e.preventDefault()
        // Open chat in a new window by default (same as TopBar button)
        const w = Math.min(800, window.screen.availWidth - 100)
        const h = Math.min(900, window.screen.availHeight - 100)
        const left = Math.max(0, window.screen.availWidth - w - 60)
        const top = 60
        const features = `width=${w},height=${h},left=${left},top=${top},resizable=yes,scrollbars=yes,location=no,menubar=no,toolbar=no,status=no`
        const popup = window.open('/chat-popout', 'rag-chat-popout', features)
        if (popup) {
          setChatOpen(false)
          popup.focus()
        } else {
          setChatOpen(!chatOpen)
        }
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [setChatOpen, chatOpen])

  const notifications = useUIStore(s => s.notifications)
  const dismiss = useUIStore(s => s.dismissNotification)

  // Auto-dismiss after 8 seconds
  useEffect(() => {
    const timers = notifications.map(n =>
      setTimeout(() => dismiss(n.id), 8000)
    )
    return () => timers.forEach(clearTimeout)
  }, [notifications, dismiss])

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <TopBar />
        <DatabaseWarning />
        <main className="flex-1 overflow-y-auto p-4">
          <Outlet />
        </main>
      </div>
      <ChatPanel />
      {/* Notification toasts */}
      {notifications.length > 0 && (
        <div className="fixed top-4 right-4 z-[100] space-y-2 max-w-sm">
          {notifications.map(n => (
            <div key={n.id} onClick={() => dismiss(n.id)}
              className={`px-4 py-3 rounded-lg shadow-lg border cursor-pointer animate-in slide-in-from-right text-sm font-medium ${
                n.type === 'success' ? 'bg-green-500/20 border-green-500/50 text-green-400' :
                n.type === 'error' ? 'bg-red-500/20 border-red-500/50 text-red-400' :
                'bg-blue-500/20 border-blue-500/50 text-blue-400'
              }`}>
              {n.message}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
