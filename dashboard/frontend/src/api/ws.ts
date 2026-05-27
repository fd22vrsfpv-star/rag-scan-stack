import type { WSEvent } from '@/lib/types'

type WSCallback = (event: WSEvent) => void

class WebSocketClient {
  private ws: WebSocket | null = null
  private listeners: WSCallback[] = []
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private url: string

  constructor() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    this.url = `${proto}//${window.location.host}/ws`
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return

    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      console.log('[WS] Connected')
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer)
        this.reconnectTimer = null
      }
    }

    this.ws.onmessage = (e) => {
      try {
        const event: WSEvent = JSON.parse(e.data)
        this.listeners.forEach(cb => cb(event))
      } catch {
        // ignore non-JSON
      }
    }

    this.ws.onclose = () => {
      console.log('[WS] Disconnected, reconnecting...')
      this.reconnectTimer = setTimeout(() => this.connect(), 3000)
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  subscribe(cb: WSCallback) {
    this.listeners.push(cb)
    return () => {
      this.listeners = this.listeners.filter(l => l !== cb)
    }
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.ws?.close()
    this.ws = null
  }
}

export const wsClient = new WebSocketClient()
