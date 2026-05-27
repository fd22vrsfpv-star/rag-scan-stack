import { useState } from 'react'
import {
  useSyncNodes,
  useSyncStatus,
  useSyncConflicts,
  useSyncChanges,
  useRegisterNode,
  usePushChanges,
  usePushToRemote,
  useResetWatermark,
  useResolveConflict,
  useSyncSchema,
} from '../api/sync'
import type { SyncConflict, SyncChange } from '../api/sync'

function StatusCard({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div className={`border rounded p-4 text-center ${color}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-sm text-gray-400">{label}</div>
    </div>
  )
}

function ConflictRow({ c, onResolve }: { c: SyncConflict; onResolve: (id: string, res: 'local_wins' | 'remote_wins') => void }) {
  return (
    <div className="bg-gray-800 border border-yellow-700 rounded p-3 mb-2">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm">
          <span className="text-yellow-400 font-medium">{c.table_name}</span>
          <span className="text-gray-500 ml-2">{c.row_id.slice(0, 8)}...</span>
        </div>
        <div className="flex gap-2">
          <button
            className="px-2 py-1 bg-blue-600 hover:bg-blue-500 rounded text-xs"
            onClick={() => onResolve(c.id, 'local_wins')}
          >
            Keep Local
          </button>
          <button
            className="px-2 py-1 bg-orange-600 hover:bg-orange-500 rounded text-xs"
            onClick={() => onResolve(c.id, 'remote_wins')}
          >
            Accept Remote
          </button>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
        <div>
          <div className="text-gray-500 mb-1">Local ({c.local_changed_at ? new Date(c.local_changed_at).toLocaleString() : '?'})</div>
          <pre className="bg-gray-900 p-2 rounded overflow-x-auto max-h-32">
            {JSON.stringify(c.local_data, null, 2)?.slice(0, 500)}
          </pre>
        </div>
        <div>
          <div className="text-gray-500 mb-1">Remote ({c.remote_changed_at ? new Date(c.remote_changed_at).toLocaleString() : '?'})</div>
          <pre className="bg-gray-900 p-2 rounded overflow-x-auto max-h-32">
            {JSON.stringify(c.remote_data, null, 2)?.slice(0, 500)}
          </pre>
        </div>
      </div>
    </div>
  )
}

function ChangeLog({ changes }: { changes: SyncChange[] }) {
  const opColor: Record<string, string> = {
    INSERT: 'text-green-400',
    UPDATE: 'text-yellow-400',
    DELETE: 'text-red-400',
  }
  return (
    <div className="space-y-1 max-h-96 overflow-y-auto">
      {changes.map((c) => (
        <div key={c.lsn} className="flex items-center gap-3 text-xs bg-gray-800/50 px-3 py-1.5 rounded">
          <span className="text-gray-600 font-mono w-12">#{c.lsn}</span>
          <span className={`font-medium w-16 ${opColor[c.operation] || 'text-gray-400'}`}>{c.operation}</span>
          <span className="text-gray-300 w-32">{c.table_name}</span>
          <span className="text-gray-500 font-mono">{c.row_id.slice(0, 8)}</span>
          <span className="text-gray-600 ml-auto">{c.changed_by}</span>
          <span className="text-gray-600">{new Date(c.changed_at).toLocaleTimeString()}</span>
        </div>
      ))}
    </div>
  )
}

export default function SyncDashboard() {
  const [tab, setTab] = useState<'status' | 'conflicts' | 'log' | 'nodes'>('status')
  const [nodeId, setNodeId] = useState('local')
  const [newNodeId, setNewNodeId] = useState('')
  const [newNodeName, setNewNodeName] = useState('')
  const [newNodeOwner, setNewNodeOwner] = useState('')

  const { data: nodesData } = useSyncNodes()
  const { data: status } = useSyncStatus(nodeId)
  const { data: conflictsData } = useSyncConflicts()
  const lastPushLsn = status?.last_push_lsn ?? 0
  const { data: changesData } = useSyncChanges(lastPushLsn, 500)

  const registerNode = useRegisterNode()
  const pushChanges = usePushChanges()
  const pushToRemote = usePushToRemote()
  const resetWatermark = useResetWatermark()
  const resolveConflict = useResolveConflict()
  const syncSchema = useSyncSchema()

  const nodes = nodesData?.nodes || []
  const conflicts = conflictsData?.conflicts || []
  const changes = changesData?.changes || []

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Sync Dashboard</h1>
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Node:</label>
          <select
            className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm"
            value={nodeId}
            onChange={(e) => setNodeId(e.target.value)}
          >
            <option value="local">local</option>
            {nodes.map((n) => (
              <option key={n.node_id} value={n.node_id}>
                {n.node_name} ({n.node_id})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-4 mb-6 border-b border-gray-700 pb-2">
        {(['status', 'conflicts', 'log', 'nodes'] as const).map((t) => (
          <button
            key={t}
            className={`pb-1 capitalize ${tab === t ? 'border-b-2 border-blue-500 text-white' : 'text-gray-400'}`}
            onClick={() => setTab(t)}
          >
            {t}
            {t === 'conflicts' && conflicts.length > 0 && (
              <span className="ml-1 bg-yellow-600 text-xs px-1.5 py-0.5 rounded-full">{conflicts.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Status Tab */}
      {tab === 'status' && status && (
        <div>
          <div className="grid grid-cols-4 gap-4 mb-6">
            <StatusCard label="Pending Push" value={status.pending_push} color="border-blue-700 bg-blue-900/20" />
            <StatusCard label="Conflicts" value={status.pending_conflicts} color={status.pending_conflicts > 0 ? 'border-yellow-700 bg-yellow-900/20' : 'border-gray-700 bg-gray-800/50'} />
            <StatusCard label="Total Log" value={status.total_log_entries} color="border-gray-700 bg-gray-800/50" />
            <StatusCard label="Max LSN" value={status.max_lsn || 0} color="border-gray-700 bg-gray-800/50" />
          </div>

          <div className="flex flex-wrap gap-3 mb-6">
            <button
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-medium disabled:opacity-50"
              disabled={pushToRemote.isPending || status.pending_push === 0}
              onClick={() => pushToRemote.mutate({ nodeId })}
            >
              {pushToRemote.isPending ? 'Syncing to Remote...' : `Sync ${status.pending_push} Changes to Remote`}
            </button>
            <button
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm font-medium disabled:opacity-50"
              disabled={resetWatermark.isPending || status.pending_push === 0}
              onClick={() => {
                if (confirm('Reset watermark? This marks all pending changes as already synced (use after pg_dump migration).'))
                  resetWatermark.mutate(nodeId)
              }}
            >
              {resetWatermark.isPending ? 'Resetting...' : 'Reset Watermark'}
            </button>
            <button
              className="px-4 py-2 bg-purple-700 hover:bg-purple-600 rounded text-sm font-medium disabled:opacity-50"
              disabled={syncSchema.isPending}
              onClick={() => {
                if (confirm('Sync schema to remote? This applies ensure_all_tables.sql (new tables, columns, indexes) to the remote database.'))
                  syncSchema.mutate()
              }}
            >
              {syncSchema.isPending ? 'Syncing Schema...' : 'Sync Schema to Remote'}
            </button>
            {pushToRemote.isSuccess && pushToRemote.data && (
              <span className={`text-sm self-center ${pushToRemote.data.ok ? 'text-green-400' : 'text-red-400'}`}>
                {pushToRemote.data.ok ? pushToRemote.data.message : pushToRemote.data.error}
              </span>
            )}
            {resetWatermark.isSuccess && resetWatermark.data && (
              <span className={`text-sm self-center ${resetWatermark.data.ok ? 'text-green-400' : 'text-red-400'}`}>
                {resetWatermark.data.message || resetWatermark.data.error}
              </span>
            )}
            {syncSchema.isSuccess && syncSchema.data && (
              <span className={`text-sm self-center ${syncSchema.data.ok ? 'text-green-400' : 'text-red-400'}`}>
                {syncSchema.data.ok ? syncSchema.data.message : syncSchema.data.error}
              </span>
            )}
          </div>

          {status.changes_by_table.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-2">Changes by Table</h3>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-700">
                    <th className="pb-2">Table</th>
                    <th className="pb-2">Operation</th>
                    <th className="pb-2">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {status.changes_by_table.map((c, i) => (
                    <tr key={i} className="border-b border-gray-800">
                      <td className="py-1.5">{c.table_name}</td>
                      <td className="py-1.5">
                        <span className={c.operation === 'INSERT' ? 'text-green-400' : c.operation === 'DELETE' ? 'text-red-400' : 'text-yellow-400'}>
                          {c.operation}
                        </span>
                      </td>
                      <td className="py-1.5">{c.cnt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Conflicts Tab */}
      {tab === 'conflicts' && (
        <div>
          {conflicts.length === 0 ? (
            <p className="text-gray-500 text-center py-8">No pending conflicts</p>
          ) : (
            conflicts.map((c) => (
              <ConflictRow
                key={c.id}
                c={c}
                onResolve={(id, res) => resolveConflict.mutate({ conflictId: id, resolution: res })}
              />
            ))
          )}
        </div>
      )}

      {/* Log Tab */}
      {tab === 'log' && (
        <div>
          <p className="text-gray-400 text-sm mb-3">
            Pending changes since last push ({changes.length} entries, from LSN {lastPushLsn})
          </p>
          {changes.length === 0 ? (
            <p className="text-gray-500 text-center py-8">No pending changes — all synced</p>
          ) : (
            <ChangeLog changes={changes} />
          )}
        </div>
      )}

      {/* Nodes Tab */}
      {tab === 'nodes' && (
        <div>
          <div className="mb-6">
            <h3 className="text-sm font-medium text-gray-400 mb-3">Registered Nodes</h3>
            {nodes.length === 0 ? (
              <p className="text-gray-500 text-sm">No nodes registered. Register one below.</p>
            ) : (
              <div className="space-y-2">
                {nodes.map((n) => (
                  <div key={n.node_id} className="bg-gray-800 rounded p-3 flex items-center justify-between">
                    <div>
                      <span className="font-medium">{n.node_name}</span>
                      <span className="text-gray-500 text-sm ml-2">({n.node_id})</span>
                      {n.owner && <span className="text-gray-400 text-sm ml-2">— {n.owner}</span>}
                    </div>
                    <div className="text-xs text-gray-500">
                      {n.last_sync ? `Last sync: ${new Date(n.last_sync).toLocaleString()}` : 'Never synced'}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="border border-gray-700 rounded p-4">
            <h3 className="text-sm font-medium text-gray-400 mb-3">Register New Node</h3>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <input
                className="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm"
                placeholder="Node ID (e.g., laptop-alice)"
                value={newNodeId}
                onChange={(e) => setNewNodeId(e.target.value)}
              />
              <input
                className="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm"
                placeholder="Display name"
                value={newNodeName}
                onChange={(e) => setNewNodeName(e.target.value)}
              />
              <input
                className="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm"
                placeholder="Owner (optional)"
                value={newNodeOwner}
                onChange={(e) => setNewNodeOwner(e.target.value)}
              />
            </div>
            <button
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm disabled:opacity-50"
              disabled={!newNodeId || !newNodeName || registerNode.isPending}
              onClick={() => {
                registerNode.mutate(
                  { node_id: newNodeId, node_name: newNodeName, owner: newNodeOwner || undefined },
                  { onSuccess: () => { setNewNodeId(''); setNewNodeName(''); setNewNodeOwner('') } }
                )
              }}
            >
              Register Node
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
