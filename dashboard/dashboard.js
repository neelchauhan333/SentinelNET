// dashboard/dashboard.js
/**
 * SentinelNet Dashboard - Upgraded
 * ✅ Device Details Modal
 * ✅ Simulate Attack button
 * ✅ Search bar filtering
 * ✅ Toast notifications
 * ✅ Auto-refresh every 10 seconds
 */

const API_URL = "http://127.0.0.1:8000";
const API_KEY = "sentinel123";

let fullDB = null;
let riskReport = null;
let chart = null;
let autoRefreshInterval = null;
let currentSearchQuery = "";

// ============ TOAST NOTIFICATIONS ============

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');

    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ'
    };

    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => toast.classList.add('toast-show'), 10);
    setTimeout(() => {
        toast.classList.remove('toast-show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ============ INITIALIZATION ============

document.addEventListener('DOMContentLoaded', function () {
    console.log('[Dashboard] Starting...');
    fetchAll();
    startAutoRefresh();
    initModal();
    initSearch();
});

function startAutoRefresh() {
    autoRefreshInterval = setInterval(() => {
        console.log('[Dashboard] Auto-refreshing...');
        fetchAll();
    }, 10000);
}

// ============ FETCH DATA ============

async function fetchAll() {
    try {
        updateStatus('Fetching data...', 'loading');

        const [dbRes, riskRes] = await Promise.all([
            fetch(`${API_URL}/database`),
            fetch(`${API_URL}/risk_report`)
        ]);

        if (!dbRes.ok || !riskRes.ok) throw new Error('Backend not responding');

        fullDB = await dbRes.json();
        riskReport = await riskRes.json();

        updateAllSections();
        updateStatus('System Active', 'active');

        // Alert banner for high risk devices
        if (riskReport.summary?.high > 0) {
            updateAlertBanner(riskReport.summary.high);
        } else {
            clearAlertBanner();
        }

    } catch (err) {
        console.error('[Dashboard] Error:', err);
        updateStatus('Backend Offline', 'error');
        showToast("Cannot connect to backend. Make sure it's running.", 'error');
    }
}

function updateStatus(text, state) {
    const statusText = document.getElementById('statusText');
    const statusDot = document.querySelector('.status-dot');
    if (statusText) statusText.textContent = text;
    if (statusDot) {
        statusDot.style.background =
            state === 'active' ? 'var(--success)' :
            state === 'loading' ? 'var(--warning)' :
            'var(--danger)';
    }
}

// ============ ALERT BANNER ============

function updateAlertBanner(count) {
    let banner = document.getElementById('alertBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'alertBanner';
        banner.className = 'alert-banner';
        document.querySelector('.container').prepend(banner);
    }
    banner.innerHTML = `
        <span class="alert-banner-icon">🚨</span>
        <span><strong>${count} HIGH RISK DEVICE${count > 1 ? 'S' : ''} DETECTED</strong> — Immediate attention required</span>
        <button class="alert-banner-close" onclick="clearAlertBanner()">✕</button>
    `;
    banner.classList.add('alert-banner-visible');
}

function clearAlertBanner() {
    const banner = document.getElementById('alertBanner');
    if (banner) banner.classList.remove('alert-banner-visible');
}

// ============ UPDATE SECTIONS ============

function updateAllSections() {
    const devices = fullDB.devices || [];
    const events = fullDB.events || [];

    // Apply search filter if active
    const filtered = currentSearchQuery
        ? devices.filter(d =>
            (d.ip_address || '').toLowerCase().includes(currentSearchQuery) ||
            (d.hostname || '').toLowerCase().includes(currentSearchQuery) ||
            (d.device_type || '').toLowerCase().includes(currentSearchQuery)
          )
        : devices;

    updateDeviceTable(filtered);
    updateEventTable(events);
    updateRiskSummary(riskReport);
    updateRiskList(riskReport.top_devices || []);
    populateDeviceSelect(devices);

    document.getElementById('device-count').textContent = filtered.length;
    document.getElementById('event-count').textContent = events.length;
    document.getElementById('total-count').textContent = riskReport.summary?.total || 0;
}

// ============ SEARCH ============

function initSearch() {
    const input = document.getElementById('searchInput');
    if (!input) return;
    input.addEventListener('input', () => {
        currentSearchQuery = input.value.trim().toLowerCase();
        if (fullDB) {
            const devices = fullDB.devices || [];
            const filtered = currentSearchQuery
                ? devices.filter(d =>
                    (d.ip_address || '').toLowerCase().includes(currentSearchQuery) ||
                    (d.hostname || '').toLowerCase().includes(currentSearchQuery) ||
                    (d.device_type || '').toLowerCase().includes(currentSearchQuery)
                  )
                : devices;
            updateDeviceTable(filtered);
            document.getElementById('device-count').textContent = filtered.length;
        }
    });
}

// ============ SIMULATE ATTACK ============

async function simulateAttack() {
    if (!fullDB || !fullDB.devices || fullDB.devices.length === 0) {
        showToast('No devices available to target', 'warning');
        return;
    }

    // Pick first non-protected device, fallback to first device
    const target = fullDB.devices.find(d => !d.is_protected) || fullDB.devices[0];

    const btn = document.getElementById('simulateBtn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Simulating...';
    }

    try {
        const res = await fetch(`${API_URL}/log_event`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': API_KEY
            },
            body: JSON.stringify({
                event_id: 'demo-' + Date.now(),
                device_id: target.device_id,
                event_type: 'MALWARE_DETECTED',
                event_time: new Date().toISOString(),
                event_data: {
                    filename: 'ransomware.exe',
                    reason: 'Simulated attack for demo',
                    hostname: target.hostname
                },
                severity: 'HIGH'
            })
        });

        if (res.ok) {
            showToast(`🚨 Attack simulated on ${target.hostname || target.ip_address}!`, 'warning');
            setTimeout(fetchAll, 1000);
        } else {
            const err = await res.json();
            showToast(err.detail || 'Simulation failed', 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        if (btn) {
            setTimeout(() => {
                btn.disabled = false;
                btn.innerHTML = '🚨 Simulate Attack';
            }, 2000);
        }
    }
}

// ============ DEVICE TABLE ============

function updateDeviceTable(devices) {
    const tbody = document.querySelector('#deviceTable tbody');

    if (!devices || devices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="no-data">${
            currentSearchQuery ? 'No devices match your search.' : 'No devices detected. Run network scanner.'
        }</td></tr>`;
        return;
    }

    tbody.innerHTML = '';

    devices.forEach(device => {
        const riskClass =
            device.risk_score >= 70 ? 'risk-high' :
            device.risk_score >= 40 ? 'risk-medium' : 'risk-low';

        const riskLabel =
            device.risk_score >= 70 ? 'HIGH' :
            device.risk_score >= 40 ? 'MEDIUM' : 'LOW';

        const statusClass = device.blocked_status ? 'status-blocked' : 'status-active';
        const statusLabel = device.blocked_status ? 'BLOCKED' : 'Active';
        const deviceIcon = getDeviceIcon(device.device_type);
        const isProtected = device.is_protected || false;

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><strong>${device.ip_address}</strong></td>
            <td>
                <div style="display:flex;align-items:center;gap:0.5rem;">
                    <span style="font-size:1.2rem;">${deviceIcon}</span>
                    <span>${device.hostname || 'Unknown'}</span>
                    ${isProtected ? '<span class="protected-badge">🛡️ Protected</span>' : ''}
                </div>
            </td>
            <td><span style="color:var(--text-muted);">${device.device_type || 'Unknown'}</span></td>
            <td>
                <span class="risk-badge ${riskClass}">
                    ${device.risk_score} — ${riskLabel}
                </span>
            </td>
            <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
            <td>
                ${device.blocked_status
                    ? `<button class="action-btn unblock" onclick="unblockDevice('${device.device_id}')">Unblock</button>`
                    : `<button class="action-btn block" onclick="blockDevice('${device.device_id}')">Block</button>`
                }
            </td>
        `;

        row.style.cursor = 'pointer';
        row.onclick = (e) => {
            if (e.target.tagName !== 'BUTTON') showDeviceDetails(device);
        };

        tbody.appendChild(row);
    });
}

function getDeviceIcon(deviceType) {
    const type = (deviceType || '').toLowerCase();
    if (type.includes('phone') || type.includes('mobile')) return '📱';
    if (type.includes('computer') || type.includes('laptop')) return '💻';
    if (type.includes('router') || type.includes('gateway')) return '🌐';
    if (type.includes('apple') || type.includes('iphone')) return '🍎';
    if (type.includes('raspberry')) return '🥧';
    if (type.includes('printer')) return '🖨️';
    if (type.includes('tv')) return '📺';
    return '🖥️';
}

// ============ EVENT TABLE ============

function updateEventTable(events) {
    const tbody = document.querySelector('#eventTable tbody');

    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="no-data">No events logged yet.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    events.slice(0, 50).forEach(event => {
        const eventIcon = getEventIcon(event.event_type);
        const eventColor = getEventColor(event.event_type);
        const timeAgo = getTimeAgo(event.event_time);

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><div style="font-size:0.85rem;color:var(--text-muted);">${timeAgo}</div></td>
            <td><code style="font-size:0.85rem;">${event.device_id}</code></td>
            <td><span style="color:${eventColor};">${eventIcon} ${event.event_type}</span></td>
            <td style="font-size:0.85rem;color:var(--text-muted);">${formatEventData(event.event_data)}</td>
        `;
        tbody.appendChild(row);
    });
}

function getEventIcon(eventType) {
    const type = (eventType || '').toUpperCase();
    if (type.includes('USB')) return '🔌';
    if (type.includes('BLOCK')) return '🚫';
    if (type.includes('PROCESS')) return '⚙️';
    if (type.includes('FILE') || type.includes('EXECUTABLE')) return '📄';
    if (type.includes('AGENT')) return '🤖';
    if (type.includes('MALWARE')) return '⚠️';
    return '📌';
}

function getEventColor(eventType) {
    const type = (eventType || '').toUpperCase();
    if (type.includes('BLOCK') || type.includes('MALWARE')) return 'var(--danger)';
    if (type.includes('SUSPICIOUS') || type.includes('USB')) return 'var(--warning)';
    return 'var(--text)';
}

function formatEventData(data) {
    if (!data || typeof data !== 'object') return 'N/A';
    const parts = [];
    if (data.filename) parts.push(`File: ${data.filename}`);
    if (data.device) parts.push(`Device: ${data.device}`);
    if (data.hostname) parts.push(`Host: ${data.hostname}`);
    if (data.process_name) parts.push(`Process: ${data.process_name}`);
    if (data.reason) parts.push(`Reason: ${data.reason}`);
    return parts.join(' | ') || JSON.stringify(data).substring(0, 50) + '...';
}

function getTimeAgo(timeStr) {
    try {
        const diff = new Date() - new Date(timeStr);
        const s = Math.floor(diff / 1000);
        const m = Math.floor(s / 60);
        const h = Math.floor(m / 60);
        if (s < 60) return `${s}s ago`;
        if (m < 60) return `${m}m ago`;
        if (h < 24) return `${h}h ago`;
        return new Date(timeStr).toLocaleDateString();
    } catch {
        return timeStr;
    }
}

// ============ RISK SUMMARY ============

function updateRiskSummary(report) {
    if (!report || !report.summary) return;
    document.getElementById('safe-count').textContent = report.summary.safe || 0;
    document.getElementById('susp-count').textContent = report.summary.suspicious || 0;
    document.getElementById('high-count').textContent = report.summary.high || 0;
}

// ============ RISK LIST ============

function updateRiskList(devices) {
    const container = document.getElementById('riskList');
    const highRisk = devices.filter(d => d.risk_score >= 40);

    if (!highRisk.length) {
        container.innerHTML = '<div class="no-data">All devices secure ✓</div>';
        return;
    }

    container.innerHTML = '';
    highRisk.slice(0, 5).forEach(device => {
        const reasons = (device.risk_reasons || []).join(', ') || 'No specific reason';
        const div = document.createElement('div');
        div.className = 'risk-item';
        div.innerHTML = `
            <div class="risk-item-header">
                <div class="risk-item-title">${device.hostname || device.ip_address}</div>
                <div class="risk-item-score">${device.risk_score}</div>
            </div>
            <div class="risk-item-reasons">${reasons}</div>
        `;
        div.onclick = () => showDeviceDetails(device);
        div.style.cursor = 'pointer';
        container.appendChild(div);
    });
}

// ============ DEVICE DETAILS MODAL ============

function initModal() {
    // Close modal when clicking backdrop
    const modal = document.getElementById('deviceModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });
}

function showDeviceDetails(device) {
    const modal = document.getElementById('deviceModal');
    const content = document.getElementById('modalContent');

    if (!modal || !content) return;

    const riskClass =
        device.risk_score >= 70 ? 'risk-high' :
        device.risk_score >= 40 ? 'risk-medium' : 'risk-low';

    const riskLabel =
        device.risk_score >= 70 ? 'HIGH' :
        device.risk_score >= 40 ? 'MEDIUM' : 'LOW';

    const reasons = device.risk_reasons || [];
    const isProtected = device.is_protected || false;
    const isBlocked = device.blocked_status || false;

    // Build risk bar percentage
    const riskPct = Math.min(device.risk_score, 100);
    const riskBarColor =
        riskPct >= 70 ? 'var(--danger)' :
        riskPct >= 40 ? 'var(--warning)' : 'var(--success)';

    content.innerHTML = `
        <div class="modal-device-header">
            <span class="modal-device-icon">${getDeviceIcon(device.device_type)}</span>
            <div>
                <h2 class="modal-device-name">${device.hostname || 'Unknown Device'}</h2>
                <p class="modal-device-ip">${device.ip_address}</p>
            </div>
            ${isProtected ? '<span class="modal-protected-tag">🛡️ Protected</span>' : ''}
        </div>

        <div class="modal-risk-bar-wrap">
            <div class="modal-risk-bar-label">
                <span>Risk Score</span>
                <span class="risk-badge ${riskClass}">${device.risk_score} — ${riskLabel}</span>
            </div>
            <div class="modal-risk-bar-track">
                <div class="modal-risk-bar-fill" style="width:${riskPct}%;background:${riskBarColor};"></div>
            </div>
        </div>

        <div class="modal-info-grid">
            <div class="modal-info-item">
                <span class="modal-info-label">MAC Address</span>
                <span class="modal-info-value">${device.mac_address || 'Unknown'}</span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Device Type</span>
                <span class="modal-info-value">${device.device_type || 'Unknown'}</span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Vendor</span>
                <span class="modal-info-value">${device.vendor || 'Unknown'}</span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Status</span>
                <span class="modal-info-value ${isBlocked ? 'status-blocked-text' : 'status-active-text'}">
                    ${isBlocked ? '🚫 BLOCKED' : '✓ Active'}
                </span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Last Seen</span>
                <span class="modal-info-value">${getTimeAgo(device.last_seen)}</span>
            </div>
            <div class="modal-info-item">
                <span class="modal-info-label">Device ID</span>
                <span class="modal-info-value modal-device-id">${device.device_id}</span>
            </div>
        </div>

        ${reasons.length > 0 ? `
        <div class="modal-reasons">
            <h3 class="modal-reasons-title">⚠ Risk Reasons</h3>
            <ul class="modal-reasons-list">
                ${reasons.map(r => `<li>${r}</li>`).join('')}
            </ul>
        </div>
        ` : `
        <div class="modal-reasons modal-reasons-safe">
            <span>✓ No risk factors detected for this device</span>
        </div>
        `}

        <div class="modal-actions">
            ${isBlocked
                ? `<button class="action-btn unblock modal-action-btn" onclick="unblockDevice('${device.device_id}'); closeModal();">
                        ✓ Unblock Device
                   </button>`
                : `<button class="action-btn block modal-action-btn" ${isProtected ? 'disabled title="Protected device cannot be blocked"' : ''} onclick="blockDevice('${device.device_id}'); closeModal();">
                        🚫 Block Device
                   </button>`
            }
            <button class="action-btn modal-action-btn modal-close-btn" onclick="closeModal()">Close</button>
        </div>
    `;

    modal.classList.add('modal-visible');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    const modal = document.getElementById('deviceModal');
    if (modal) modal.classList.remove('modal-visible');
    document.body.style.overflow = '';
}

// ============ CHART ============

function populateDeviceSelect(devices) {
    const sel = document.getElementById('deviceSelect');
    const current = sel.value;

    sel.innerHTML = '<option value="">Select device...</option>';
    devices.forEach(d => {
        const option = document.createElement('option');
        option.value = d.device_id;
        option.textContent = `${d.hostname || d.ip_address} (${d.ip_address})`;
        sel.appendChild(option);
    });

    if (current) sel.value = current;
    drawSelectedDeviceChart();
}

async function drawSelectedDeviceChart() {
    const sel = document.getElementById('deviceSelect');
    const deviceId = sel.value;

    if (!deviceId) {
        if (chart) { chart.destroy(); chart = null; }
        return;
    }

    try {
        const res = await fetch(`${API_URL}/device/${deviceId}/history`);
        const data = await res.json();
        const history = data.history || [];

        const labels = history.map(h => new Date(h.time).toLocaleTimeString());
        const scores = history.map(h => h.score);

        const ctx = document.getElementById('riskChart').getContext('2d');
        if (chart) chart.destroy();

        chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Risk Score',
                    data: scores,
                    fill: true,
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    borderColor: 'rgb(37, 99, 235)',
                    borderWidth: 2,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        min: 0, max: 100,
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { color: 'rgba(255,255,255,0.1)' },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });

    } catch (err) {
        console.error('[Chart] Error:', err);
    }
}

// ============ ACTIONS ============

async function blockDevice(deviceId) {
    if (!confirm('Block this device?\n\nThis will prevent network access.')) return;

    try {
        const res = await fetch(`${API_URL}/block_device/${deviceId}`, {
            method: 'POST',
            headers: { 'x-api-key': API_KEY }
        });

        if (res.ok) {
            showToast('Device blocked successfully!', 'success');
            setTimeout(fetchAll, 500);
        } else {
            const err = await res.json();
            showToast(err.detail || 'Failed to block device', 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    }
}

async function unblockDevice(deviceId) {
    if (!confirm('Unblock this device?\n\nDevice will regain network access.')) return;

    try {
        const res = await fetch(`${API_URL}/unblock_device/${deviceId}`, {
            method: 'POST',
            headers: { 'x-api-key': API_KEY }
        });

        if (res.ok) {
            showToast('Device unblocked successfully!', 'success');
            setTimeout(fetchAll, 500);
        } else {
            const err = await res.json();
            showToast(err.detail || 'Failed to unblock device', 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    }
}

// ============ EXPORT ============

function exportData() {
    if (!fullDB) {
        showToast('No data to export', 'warning');
        return;
    }
    const payload = {
        exported_at: new Date().toISOString(),
        summary: riskReport?.summary || {},
        devices: fullDB.devices || [],
        events: fullDB.events || []
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinelnet_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    showToast('Report exported!', 'success');
}

// ============ CLEANUP ============

window.addEventListener('beforeunload', () => {
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
});