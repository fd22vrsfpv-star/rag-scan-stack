import '@testing-library/jest-dom'
import { beforeEach } from 'vitest'

// ── localStorage / sessionStorage ──────────────────────
// jsdom is active here (window is an object, origin http://localhost:3000) but
// does NOT expose localStorage, so `typeof localStorage` was "undefined" at
// every path — window, globalThis and bare. Node then emitted
// "localStorage is not available because --localstorage-file was not provided"
// and zustand's persist middleware died on `localStorage.setItem`, failing all
// 19 tests in stores/scanDefaults.test.ts and stores/chat.test.ts before they
// asserted anything.
//
// A real in-memory implementation rather than a stub of no-ops: persist writes
// state and reads it back, so getItem has to return what setItem stored or the
// store silently behaves as if nothing persisted.
class MemoryStorage implements Storage {
  private store = new Map<string, string>()
  get length() { return this.store.size }
  clear() { this.store.clear() }
  getItem(key: string) { return this.store.has(key) ? this.store.get(key)! : null }
  key(index: number) { return Array.from(this.store.keys())[index] ?? null }
  removeItem(key: string) { this.store.delete(key) }
  setItem(key: string, value: string) { this.store.set(key, String(value)) }
}

for (const name of ['localStorage', 'sessionStorage'] as const) {
  const storage = new MemoryStorage()
  Object.defineProperty(window, name, { value: storage, writable: true, configurable: true })
  Object.defineProperty(globalThis, name, { value: storage, writable: true, configurable: true })
}

// Wipe between tests so persisted state cannot leak from one case into the
// next. Registered in the setup file, so it runs BEFORE any per-file
// beforeEach that seeds storage deliberately.
beforeEach(() => {
  window.localStorage.clear()
  window.sessionStorage.clear()
})

// ── Global fetch mock ──────────────────────────────────
// Returns empty JSON by default; tests can override via vi.spyOn
global.fetch = vi.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    headers: new Headers(),
  } as Response),
)

// ── window.matchMedia mock ─────────────────────────────
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// ── IntersectionObserver mock ──────────────────────────
class MockIntersectionObserver {
  readonly root = null
  readonly rootMargin = ''
  readonly thresholds: ReadonlyArray<number> = []
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
  takeRecords = vi.fn().mockReturnValue([])
}
global.IntersectionObserver = MockIntersectionObserver as unknown as typeof IntersectionObserver

// ── BroadcastChannel mock ──────────────────────────────
class MockBroadcastChannel {
  name: string
  onmessage: ((ev: MessageEvent) => void) | null = null
  onmessageerror: ((ev: MessageEvent) => void) | null = null
  constructor(name: string) { this.name = name }
  postMessage = vi.fn()
  close = vi.fn()
  addEventListener = vi.fn()
  removeEventListener = vi.fn()
  dispatchEvent = vi.fn().mockReturnValue(true)
}
global.BroadcastChannel = MockBroadcastChannel as unknown as typeof BroadcastChannel

// ── navigator.clipboard mock ───────────────────────────
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: vi.fn().mockResolvedValue(undefined),
    readText: vi.fn().mockResolvedValue(''),
  },
  writable: true,
})

// ── URL.createObjectURL / revokeObjectURL ──────────────
URL.createObjectURL = vi.fn(() => 'blob:mock-url')
URL.revokeObjectURL = vi.fn()
