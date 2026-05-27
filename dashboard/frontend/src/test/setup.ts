import '@testing-library/jest-dom'

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
