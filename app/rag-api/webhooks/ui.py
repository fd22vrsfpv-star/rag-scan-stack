"""
Webhook monitoring dashboard UI HTML template.
"""

WEBHOOKS_UI_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webhooks Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { color: white; font-size: 28px; margin-bottom: 10px; }
        .subtitle { color: rgba(255,255,255,0.9); font-size: 14px; }
        h2 { color: #9b59b6; font-size: 18px; margin-bottom: 15px; }

        /* Stats Panel */
        .stats { background: #2a2a2a; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; }
        .stat-item { display: flex; flex-direction: column; align-items: center; padding: 15px; background: #1a1a1a; border-radius: 8px; }
        .stat-value { font-size: 32px; font-weight: bold; color: #9b59b6; }
        .stat-value.success { color: #28a745; }
        .stat-value.warning { color: #ffc107; }
        .stat-value.error { color: #dc3545; }
        .stat-label { font-size: 12px; color: #888; text-transform: uppercase; margin-top: 5px; }

        /* Controls */
        .controls { background: #2a2a2a; padding: 15px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
        .control-group { display: flex; flex-direction: column; }
        .control-group.inline { flex-direction: row; align-items: center; gap: 8px; }
        label { font-size: 12px; color: #aaa; margin-bottom: 5px; text-transform: uppercase; }
        input, select { background: #1a1a1a; border: 1px solid #444; color: #e0e0e0; padding: 8px 12px; border-radius: 5px; font-size: 14px; }
        input:focus, select:focus { outline: none; border-color: #9b59b6; }
        button { background: #9b59b6; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; font-size: 14px; transition: background 0.2s; }
        button:hover { background: #8e44ad; }
        button.secondary { background: #6c757d; }
        button.secondary:hover { background: #5a6268; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        button.success { background: #28a745; }
        button.success:hover { background: #218838; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Tables */
        .section { background: #2a2a2a; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #3a3a3a; }
        th { color: #aaa; font-size: 12px; text-transform: uppercase; font-weight: 600; }
        tr:hover { background: rgba(155, 89, 182, 0.1); }
        .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        /* Status badges */
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .badge.delivered { background: #28a745; color: white; }
        .badge.failed { background: #dc3545; color: white; }
        .badge.retrying { background: #ffc107; color: black; }
        .badge.pending { background: #6c757d; color: white; }
        .badge.enabled { background: #28a745; color: white; }
        .badge.disabled { background: #6c757d; color: white; }

        /* Event types pills */
        .event-types { display: flex; flex-wrap: wrap; gap: 4px; }
        .event-pill { background: #3a3a3a; padding: 2px 6px; border-radius: 3px; font-size: 11px; color: #aaa; }

        /* Actions */
        .actions { display: flex; gap: 8px; }
        .actions button { padding: 4px 8px; font-size: 12px; }

        /* Failure count warning */
        .failure-count { font-weight: bold; }
        .failure-count.warning { color: #ffc107; }
        .failure-count.danger { color: #dc3545; }

        /* Auto-refresh indicator */
        .refresh-indicator { display: flex; align-items: center; gap: 8px; }
        .refresh-indicator input[type="checkbox"] { width: 18px; height: 18px; accent-color: #9b59b6; }
        .refresh-spinner { width: 16px; height: 16px; border: 2px solid #3a3a3a; border-top-color: #9b59b6; border-radius: 50%; animation: spin 1s linear infinite; display: none; }
        .refresh-spinner.active { display: inline-block; }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Error message in events */
        .error-msg { color: #dc3545; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        /* Loading state */
        .loading { text-align: center; padding: 40px; color: #888; }

        /* Empty state */
        .empty { text-align: center; padding: 40px; color: #666; }

        /* Checkbox styling */
        input[type="checkbox"] { width: 16px; height: 16px; accent-color: #9b59b6; cursor: pointer; }
        .select-all-row { background: #1a1a1a !important; }
        .select-all-row:hover { background: #1a1a1a !important; }
        tr.selected { background: rgba(155, 89, 182, 0.2) !important; }

        /* Delete controls */
        .delete-controls { display: flex; gap: 10px; align-items: center; margin-left: auto; }
        .selected-count { font-size: 13px; color: #9b59b6; font-weight: 500; }

        /* Toast notifications */
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 1000; }
        .toast { background: #2a2a2a; border-left: 4px solid #9b59b6; padding: 15px 20px; border-radius: 5px; margin-bottom: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: slideIn 0.3s ease; }
        .toast.success { border-left-color: #28a745; }
        .toast.error { border-left-color: #dc3545; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Webhooks Dashboard</h1>
            <p class="subtitle">Monitor webhook configurations and delivery status</p>
        </header>

        <!-- Statistics Panel -->
        <div class="stats" id="stats-panel">
            <div class="stat-item">
                <span class="stat-value" id="stat-total">-</span>
                <span class="stat-label">Total Webhooks</span>
            </div>
            <div class="stat-item">
                <span class="stat-value success" id="stat-enabled">-</span>
                <span class="stat-label">Enabled</span>
            </div>
            <div class="stat-item">
                <span class="stat-value" id="stat-disabled">-</span>
                <span class="stat-label">Disabled</span>
            </div>
            <div class="stat-item">
                <span class="stat-value success" id="stat-delivered">-</span>
                <span class="stat-label">Delivered</span>
            </div>
            <div class="stat-item">
                <span class="stat-value error" id="stat-failed">-</span>
                <span class="stat-label">Failed</span>
            </div>
            <div class="stat-item">
                <span class="stat-value warning" id="stat-retrying">-</span>
                <span class="stat-label">Retrying</span>
            </div>
            <div class="stat-item">
                <span class="stat-value success" id="stat-success-rate">-</span>
                <span class="stat-label">Success Rate</span>
            </div>
        </div>

        <!-- Webhooks Table -->
        <div class="section">
            <h2>Webhook Configurations</h2>
            <div id="webhooks-table">
                <div class="loading">Loading webhooks...</div>
            </div>
        </div>

        <!-- Events Controls -->
        <div class="controls">
            <div class="control-group">
                <label>Status Filter</label>
                <select id="status-filter">
                    <option value="">All</option>
                    <option value="delivered">Delivered</option>
                    <option value="failed">Failed</option>
                    <option value="retrying">Retrying</option>
                    <option value="pending">Pending</option>
                </select>
            </div>
            <div class="control-group">
                <label>Search</label>
                <input type="text" id="search-input" placeholder="Webhook name or event type...">
            </div>
            <div class="control-group">
                <label>Limit</label>
                <select id="limit-select">
                    <option value="25">25</option>
                    <option value="50" selected>50</option>
                    <option value="100">100</option>
                </select>
            </div>
            <div class="control-group">
                <label>&nbsp;</label>
                <button onclick="loadEvents()">Refresh</button>
            </div>
            <div class="control-group refresh-indicator">
                <label>Auto-Refresh</label>
                <input type="checkbox" id="auto-refresh" checked>
                <span class="refresh-spinner" id="refresh-spinner"></span>
                <span style="font-size: 12px; color: #888;">5s</span>
            </div>
            <div class="delete-controls">
                <span class="selected-count" id="selected-count"></span>
                <button onclick="deleteSelectedEvents()" class="danger" id="delete-selected-btn" disabled>Delete Selected</button>
                <button onclick="clearAllEvents()" class="secondary">Clear All</button>
            </div>
        </div>

        <!-- Recent Events Table -->
        <div class="section">
            <h2>Recent Delivery Events</h2>
            <div id="events-table">
                <div class="loading">Loading events...</div>
            </div>
        </div>
    </div>

    <!-- Toast Container -->
    <div class="toast-container" id="toast-container"></div>

    <script>
        const API_KEY = 'changeme'; // Will be replaced by actual key from localStorage or prompt
        let autoRefreshInterval = null;
        let webhooksCache = {};

        // Get API key from localStorage or use default
        function getApiKey() {
            return localStorage.getItem('webhooks_api_key') || API_KEY;
        }

        // Show toast notification
        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        // Fetch with API key header
        async function apiFetch(url, options = {}) {
            const headers = { 'x-api-key': getApiKey(), ...options.headers };
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401) {
                const newKey = prompt('API Key required:', getApiKey());
                if (newKey) {
                    localStorage.setItem('webhooks_api_key', newKey);
                    return apiFetch(url, options);
                }
            }
            return response;
        }

        // Load statistics
        async function loadStats() {
            try {
                const response = await apiFetch('/webhooks/stats');
                if (!response.ok) throw new Error('Failed to load stats');
                const data = await response.json();

                document.getElementById('stat-total').textContent = data.webhooks.total;
                document.getElementById('stat-enabled').textContent = data.webhooks.enabled;
                document.getElementById('stat-disabled').textContent = data.webhooks.disabled;
                document.getElementById('stat-delivered').textContent = data.events.delivered;
                document.getElementById('stat-failed').textContent = data.events.failed;
                document.getElementById('stat-retrying').textContent = data.events.retrying;
                document.getElementById('stat-success-rate').textContent = data.success_rate.toFixed(1) + '%';
            } catch (e) {
                console.error('Error loading stats:', e);
            }
        }

        // Load webhooks
        async function loadWebhooks() {
            try {
                const response = await apiFetch('/webhooks?limit=100');
                if (!response.ok) throw new Error('Failed to load webhooks');
                const data = await response.json();

                // Cache webhooks for lookup
                data.webhooks.forEach(w => webhooksCache[w.id] = w);

                if (data.webhooks.length === 0) {
                    document.getElementById('webhooks-table').innerHTML = '<div class="empty">No webhooks configured</div>';
                    return;
                }

                const html = `
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>URL</th>
                                <th>Status</th>
                                <th>Event Types</th>
                                <th>Last Success</th>
                                <th>Failures</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.webhooks.map(w => `
                                <tr>
                                    <td>${escapeHtml(w.name)}</td>
                                    <td class="truncate" title="${escapeHtml(w.url)}">${escapeHtml(w.url)}</td>
                                    <td><span class="badge ${w.enabled ? 'enabled' : 'disabled'}">${w.enabled ? 'Enabled' : 'Disabled'}</span></td>
                                    <td>
                                        <div class="event-types">
                                            ${(w.event_types || []).map(t => `<span class="event-pill">${t}</span>`).join('')}
                                        </div>
                                    </td>
                                    <td>${w.last_success ? new Date(w.last_success).toLocaleString() : '-'}</td>
                                    <td><span class="failure-count ${w.failure_count > 5 ? 'danger' : w.failure_count > 0 ? 'warning' : ''}">${w.failure_count}</span></td>
                                    <td class="actions">
                                        <button onclick="testWebhook('${w.id}')" class="success" title="Send test webhook">Test</button>
                                        <button onclick="window.open('/docs#/Webhooks/update_webhook_webhooks__webhook_id__put', '_blank')" class="secondary" title="Edit via API docs">Edit</button>
                                        <button onclick="deleteWebhook('${w.id}')" class="danger" title="Delete webhook">Delete</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
                document.getElementById('webhooks-table').innerHTML = html;
            } catch (e) {
                document.getElementById('webhooks-table').innerHTML = `<div class="empty" style="color: #dc3545;">Error loading webhooks: ${e.message}</div>`;
            }
        }

        // Load events
        async function loadEvents() {
            const spinner = document.getElementById('refresh-spinner');
            spinner.classList.add('active');

            try {
                const status = document.getElementById('status-filter').value;
                const search = document.getElementById('search-input').value;
                const limit = document.getElementById('limit-select').value;

                let url = `/webhooks/events?limit=${limit}`;
                if (status) url += `&status=${status}`;

                const response = await apiFetch(url);
                if (!response.ok) throw new Error('Failed to load events');
                const data = await response.json();

                // Filter by search term (webhook name or event type)
                let events = data.events;
                if (search) {
                    const term = search.toLowerCase();
                    events = events.filter(e => {
                        const webhook = webhooksCache[e.webhook_id];
                        const webhookName = webhook ? webhook.name.toLowerCase() : '';
                        return webhookName.includes(term) || e.event_type.toLowerCase().includes(term);
                    });
                }

                if (events.length === 0) {
                    document.getElementById('events-table').innerHTML = '<div class="empty">No events found</div>';
                    return;
                }

                const html = `
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 40px;"><input type="checkbox" id="select-all" onchange="toggleSelectAll(this)"></th>
                                <th>Event Type</th>
                                <th>Webhook</th>
                                <th>Status</th>
                                <th>Response</th>
                                <th>Attempts</th>
                                <th>Timestamp</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${events.map(e => {
                                const webhook = webhooksCache[e.webhook_id];
                                const webhookName = webhook ? webhook.name : e.webhook_id;
                                return `
                                <tr data-event-id="${e.id}">
                                    <td><input type="checkbox" class="event-checkbox" value="${e.id}" onchange="updateSelectedCount()"></td>
                                    <td><span class="event-pill">${e.event_type}</span></td>
                                    <td>${escapeHtml(webhookName)}</td>
                                    <td><span class="badge ${e.status}">${e.status}</span></td>
                                    <td>${e.response_code || '-'}</td>
                                    <td>${e.attempt}</td>
                                    <td>${new Date(e.created_at).toLocaleString()}</td>
                                    <td class="error-msg" title="${escapeHtml(e.error_message || '')}">${escapeHtml(e.error_message || '-')}</td>
                                </tr>
                            `}).join('')}
                        </tbody>
                    </table>
                `;
                document.getElementById('events-table').innerHTML = html;
                updateSelectedCount();
            } catch (e) {
                document.getElementById('events-table').innerHTML = `<div class="empty" style="color: #dc3545;">Error loading events: ${e.message}</div>`;
            } finally {
                spinner.classList.remove('active');
            }
        }

        // Test webhook
        async function testWebhook(id) {
            try {
                const response = await apiFetch(`/webhooks/${id}/test`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await response.json();

                if (data.success) {
                    showToast(`Test successful! Response: ${data.response_code} (${data.response_time_ms}ms)`, 'success');
                } else {
                    showToast(`Test failed: ${data.error || 'Unknown error'}`, 'error');
                }

                // Reload events to show the test event
                setTimeout(loadEvents, 500);
            } catch (e) {
                showToast(`Error: ${e.message}`, 'error');
            }
        }

        // Delete webhook
        async function deleteWebhook(id) {
            const webhook = webhooksCache[id];
            if (!confirm(`Delete webhook "${webhook ? webhook.name : id}"?`)) return;

            try {
                const response = await apiFetch(`/webhooks/${id}`, { method: 'DELETE' });
                if (response.ok || response.status === 204) {
                    showToast('Webhook deleted', 'success');
                    delete webhooksCache[id];
                    loadWebhooks();
                    loadStats();
                } else {
                    throw new Error('Failed to delete');
                }
            } catch (e) {
                showToast(`Error: ${e.message}`, 'error');
            }
        }

        // Escape HTML
        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Toggle select all checkboxes
        function toggleSelectAll(checkbox) {
            const checkboxes = document.querySelectorAll('.event-checkbox');
            checkboxes.forEach(cb => {
                cb.checked = checkbox.checked;
                const row = cb.closest('tr');
                if (checkbox.checked) {
                    row.classList.add('selected');
                } else {
                    row.classList.remove('selected');
                }
            });
            updateSelectedCount();
        }

        // Update selected count display
        function updateSelectedCount() {
            const checkboxes = document.querySelectorAll('.event-checkbox:checked');
            const count = checkboxes.length;
            const countEl = document.getElementById('selected-count');
            const deleteBtn = document.getElementById('delete-selected-btn');

            if (count > 0) {
                countEl.textContent = `${count} selected`;
                deleteBtn.disabled = false;
            } else {
                countEl.textContent = '';
                deleteBtn.disabled = true;
            }

            // Update row highlighting
            document.querySelectorAll('.event-checkbox').forEach(cb => {
                const row = cb.closest('tr');
                if (cb.checked) {
                    row.classList.add('selected');
                } else {
                    row.classList.remove('selected');
                }
            });

            // Update select-all checkbox state
            const selectAll = document.getElementById('select-all');
            const allCheckboxes = document.querySelectorAll('.event-checkbox');
            if (selectAll && allCheckboxes.length > 0) {
                selectAll.checked = count === allCheckboxes.length;
                selectAll.indeterminate = count > 0 && count < allCheckboxes.length;
            }
        }

        // Delete selected events
        async function deleteSelectedEvents() {
            const checkboxes = document.querySelectorAll('.event-checkbox:checked');
            const eventIds = Array.from(checkboxes).map(cb => cb.value);

            if (eventIds.length === 0) return;

            if (!confirm(`Delete ${eventIds.length} selected event(s)?`)) return;

            try {
                const params = eventIds.map(id => `event_ids=${id}`).join('&');
                const response = await apiFetch(`/webhooks/events?${params}`, { method: 'DELETE' });
                if (response.ok) {
                    const data = await response.json();
                    showToast(`Deleted ${data.deleted} event(s)`, 'success');
                    loadEvents();
                    loadStats();
                } else {
                    throw new Error('Failed to delete events');
                }
            } catch (e) {
                showToast(`Error: ${e.message}`, 'error');
            }
        }

        // Clear all events
        async function clearAllEvents() {
            if (!confirm('Delete ALL webhook events? This cannot be undone.')) return;

            try {
                const response = await apiFetch('/webhooks/events', { method: 'DELETE' });
                if (response.ok) {
                    const data = await response.json();
                    showToast(`Cleared ${data.deleted} event(s)`, 'success');
                    loadEvents();
                    loadStats();
                } else {
                    throw new Error('Failed to clear events');
                }
            } catch (e) {
                showToast(`Error: ${e.message}`, 'error');
            }
        }

        // Auto-refresh toggle
        document.getElementById('auto-refresh').addEventListener('change', function(e) {
            if (e.target.checked) {
                autoRefreshInterval = setInterval(() => {
                    loadStats();
                    loadEvents();
                }, 5000);
            } else {
                clearInterval(autoRefreshInterval);
            }
        });

        // Initialize
        async function init() {
            await loadStats();
            await loadWebhooks();
            await loadEvents();

            // Start auto-refresh if checked
            if (document.getElementById('auto-refresh').checked) {
                autoRefreshInterval = setInterval(() => {
                    loadStats();
                    loadEvents();
                }, 5000);
            }
        }

        init();
    </script>
</body>
</html>'''
