// dashboard/dashboard.js
const API_URL = "http://127.0.0.1:8000";

let fullDB = null;
let riskReport = null;
let chart = null;

async function fetchAll() {
    try {
        const [dbRes, riskRes] = await Promise.all([
            fetch(`${API_URL}/database`),
            fetch(`${API_URL}/risk_report`)
        ]);
        fullDB = await dbRes.json();
        riskReport = await riskRes.json();

        updateDeviceTable(fullDB.devices || []);
        updateEventTable(fullDB.events || []);
        updateRiskSummary(riskReport);
        populateRiskTable(riskReport.top_devices || []);
        populateDeviceSelect(fullDB.devices || []);
        drawSelectedDeviceChart();
    } catch (err) {
        console.error("Fetch error:", err);
    }
}

function updateDeviceTable(devices) {
    const tbody = document.querySelector("#deviceTable tbody");
    tbody.innerHTML = "";

    devices.forEach(d => {
        const status = d.blocked_status ? "Blocked" : "Active";
        const risk = d.risk_score || 0;
        tbody.innerHTML += `
        <tr>
            <td>${d.device_id}</td>
            <td>${d.ip_address}</td>
            <td>${d.mac_address}</td>
            <td>${d.hostname}</td>
            <td>${d.last_seen}</td>
            <td>${status}</td>
            <td>${risk}</td>
            <td>
              ${d.blocked_status ? `<button class="action-btn unblock" onclick="manualUnblock('${d.device_id}')">Unblock</button>` :
              `<button class="action-btn block" onclick="manualBlock('${d.device_id}')">Block</button>`}
            </td>
        </tr>`;
    });
}

function updateEventTable(events) {
    const tbody = document.querySelector("#eventTable tbody");
    tbody.innerHTML = "";
    events.slice(-200).reverse().forEach(ev => {
        tbody.innerHTML += `
        <tr>
            <td>${ev.event_id}</td>
            <td>${ev.device_id}</td>
            <td>${ev.event_type}</td>
            <td>${ev.event_time}</td>
            <td>${JSON.stringify(ev.event_data)}</td>
        </tr>`;
    });
}

function updateRiskSummary(report) {
    document.getElementById("safe-count").innerText = report.summary.safe;
    document.getElementById("susp-count").innerText = report.summary.suspicious;
    document.getElementById("high-count").innerText = report.summary.high;
}

function populateRiskTable(devs) {
    const tbody = document.querySelector("#riskTable tbody");
    tbody.innerHTML = "";
    devs.forEach(d => {
        const reason = (d.risk_reasons && d.risk_reasons.join(", ")) || "";
        tbody.innerHTML += `<tr><td>${d.device_id} (${d.hostname || ""})</td><td>${d.risk_score}</td><td>${reason}</td></tr>`;
    });
}

function populateDeviceSelect(devices) {
    const sel = document.getElementById("deviceSelect");
    const current = sel.value;
    sel.innerHTML = "<option value=''>-- Choose device for timeline --</option>";
    devices.forEach(d => {
        sel.innerHTML += `<option value="${d.device_id}">${d.device_id} - ${d.hostname || d.ip_address}</option>`;
    });
    if (current) sel.value = current;
}

// draw chart for selected device or top device
function drawSelectedDeviceChart() {
    const sel = document.getElementById("deviceSelect");
    const selectedId = sel.value || (riskReport.top_devices && riskReport.top_devices[0] && riskReport.top_devices[0].device_id);
    let device = null;
    if (fullDB && fullDB.devices) {
        device = fullDB.devices.find(d => d.device_id == selectedId);
    }
    // fallback: no device
    if (!device) {
        // clear chart
        if (chart) {
            chart.destroy();
            chart = null;
        }
        const ctx = document.getElementById("riskChart").getContext("2d");
        ctx.clearRect(0,0,400,250);
        return;
    }

    const history = device.risk_history || [];
    const labels = history.map(h => new Date(h.time).toLocaleString());
    const data = history.map(h => h.score);

    const ctx = document.getElementById("riskChart").getContext("2d");
    if (chart) chart.destroy();

    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: `${device.device_id} Risk Score`,
                data: data,
                fill: false,
                tension: 0.25,
                borderColor: 'rgba(37,99,235,1)',
                backgroundColor: 'rgba(37,99,235,0.2)'
            }]
        },
        options: {
            scales: {
                y: { min: 0, max: 100 }
            }
        }
    });
}

// manual block
async function manualBlock(device_id) {
    if (!confirm(`Block device ${device_id} ?`)) return;
    try {
        const res = await fetch(`${API_URL}/block_device/${device_id}`, { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            alert("Error: " + (err.detail || JSON.stringify(err)));
        } else {
            alert("Device blocked");
            fetchAll();
        }
    } catch (e) {
        console.error(e);
        alert("Network error");
    }
}

// manual unblock (simple client-side only: we'll flip blocked_status in DB by sending a manual event "UNBLOCK" and edit DB locally)
async function manualUnblock(device_id) {
    // Unblock functionality: we'll directly update DB via a small manual endpoint not implemented yet.
    alert("Unblock currently not implemented server-side. You can re-run a /pi_scan for the device to restore status or we can add an unblock endpoint. Ask me to add it if you want.");
}

fetchAll();
