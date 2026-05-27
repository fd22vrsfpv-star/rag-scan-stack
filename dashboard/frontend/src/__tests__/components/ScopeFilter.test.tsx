import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ScopeFilter } from '@/components/common/ScopeFilter'

// Mock the scope API hook
vi.mock('@/api/scope', () => ({
  useScopeNames: () => ({
    data: {
      names: [
        { name: 'production', target_count: 5 },
        { name: 'staging', target_count: 3 },
      ],
    },
    isLoading: false,
    error: null,
  }),
}))

// Mock the UI store used by useScopeNames internally
vi.mock('@/stores/ui', () => ({
  useUIStore: (selector: (s: Record<string, unknown>) => unknown) =>
    selector({ selectedEngagementId: null }),
}))

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  )
}

describe('ScopeFilter', () => {
  let onChange: ReturnType<typeof vi.fn>

  beforeEach(() => {
    onChange = vi.fn()
  })

  it('renders "All Scopes" option', () => {
    renderWithProviders(<ScopeFilter value="" onChange={onChange} />)
    expect(screen.getByText('All Scopes')).toBeInTheDocument()
  })

  it('renders scope options from API data', () => {
    renderWithProviders(<ScopeFilter value="" onChange={onChange} />)
    expect(screen.getByText('production (5)')).toBeInTheDocument()
    expect(screen.getByText('staging (3)')).toBeInTheDocument()
  })

  it('calls onChange when selection changes', () => {
    renderWithProviders(<ScopeFilter value="" onChange={onChange} />)
    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'production' } })
    expect(onChange).toHaveBeenCalledWith('production')
  })

  it('reflects the current value prop', () => {
    renderWithProviders(<ScopeFilter value="staging" onChange={onChange} />)
    const select = screen.getByRole('combobox') as HTMLSelectElement
    expect(select.value).toBe('staging')
  })
})
