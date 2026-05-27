import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
  type ColumnResizeMode,
  type RowSelectionState,
  type Updater,
} from '@tanstack/react-table'
import { useState, useMemo } from 'react'
import { ArrowUpDown } from 'lucide-react'
import { cn } from '@/lib/utils'

interface DataTableProps<T> {
  data: T[]
  columns: ColumnDef<T, any>[]
  onRowClick?: (row: T) => void
  searchPlaceholder?: string
  globalFilter?: string
  onGlobalFilterChange?: (value: string) => void
  resizable?: boolean
  selectable?: boolean
  rowSelection?: RowSelectionState
  onRowSelectionChange?: (sel: RowSelectionState) => void
  getRowId?: (row: T) => string
}

export function DataTable<T>({
  data,
  columns,
  onRowClick,
  globalFilter,
  onGlobalFilterChange,
  resizable = false,
  selectable = false,
  rowSelection,
  onRowSelectionChange,
  getRowId,
}: DataTableProps<T>) {
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnResizeMode] = useState<ColumnResizeMode>('onChange')

  const allColumns = useMemo((): ColumnDef<T, any>[] => {
    if (!selectable) return columns
    const checkboxCol: ColumnDef<T, any> = {
      id: '_select',
      header: ({ table }) => (
        <input
          type="checkbox"
          className="accent-primary h-4 w-4 cursor-pointer"
          checked={table.getIsAllPageRowsSelected()}
          onChange={table.getToggleAllPageRowsSelectedHandler()}
        />
      ),
      cell: ({ row }) => (
        <input
          type="checkbox"
          className="accent-primary h-4 w-4 cursor-pointer"
          checked={row.getIsSelected()}
          onChange={row.getToggleSelectedHandler()}
          onClick={(e) => e.stopPropagation()}
        />
      ),
      enableSorting: false,
      size: 40,
    }
    return [checkboxCol, ...columns]
  }, [columns, selectable])

  const handleRowSelectionChange = useMemo(() => {
    if (!selectable || !onRowSelectionChange) return undefined
    return (updater: Updater<RowSelectionState>) => {
      const next = typeof updater === 'function'
        ? updater(rowSelection ?? {})
        : updater
      onRowSelectionChange(next)
    }
  }, [selectable, onRowSelectionChange, rowSelection])

  const table = useReactTable({
    data,
    columns: allColumns,
    state: {
      sorting,
      globalFilter,
      ...(selectable && rowSelection !== undefined ? { rowSelection } : {}),
    },
    onSortingChange: setSorting,
    onGlobalFilterChange,
    onRowSelectionChange: handleRowSelectionChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    ...(resizable ? { columnResizeMode, enableColumnResizing: true } : {}),
    ...(getRowId ? { getRowId: (row: T) => getRowId(row) } : {}),
    enableRowSelection: selectable,
  })

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table
          className="w-full text-sm"
          style={resizable ? { width: table.getCenterTotalSize() } : undefined}
        >
          <thead>
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id} className="border-b border-border bg-muted/50">
                {hg.headers.map(h => (
                  <th
                    key={h.id}
                    className={cn(
                      'px-3 py-2 text-left text-xs font-medium text-muted-foreground relative',
                      h.column.getCanSort() && 'cursor-pointer select-none',
                    )}
                    onClick={h.column.getToggleSortingHandler()}
                    style={resizable ? { width: h.getSize() } : (h.column.id === '_select' ? { width: 40 } : undefined)}
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {h.column.getCanSort() && <ArrowUpDown className="h-3 w-3" />}
                    </div>
                    {resizable && h.column.getCanResize() && (
                      <div
                        onMouseDown={h.getResizeHandler()}
                        onTouchStart={h.getResizeHandler()}
                        className={cn(
                          'absolute right-0 top-0 h-full w-1 cursor-col-resize select-none touch-none',
                          'hover:bg-primary/50',
                          h.column.getIsResizing() ? 'bg-primary' : 'bg-transparent',
                        )}
                      />
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <tr
                key={row.id}
                className={cn(
                  'border-b border-border/50 hover:bg-muted/30 transition-colors',
                  onRowClick && 'cursor-pointer',
                  selectable && row.getIsSelected() && 'bg-primary/10',
                )}
                onClick={() => onRowClick?.(row.original)}
              >
                {row.getVisibleCells().map(cell => (
                  <td
                    key={cell.id}
                    className="px-3 py-2"
                    style={resizable ? { width: cell.column.getSize() } : (cell.column.id === '_select' ? { width: 40 } : undefined)}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {table.getRowModel().rows.length === 0 && (
              <tr>
                <td colSpan={allColumns.length} className="px-3 py-8 text-center text-muted-foreground text-sm">
                  No data
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
