// Pulse Network Monitor — Section 5: Troubleshooting Toolkit, Modals & Wizards

function switchToolkitTab(tabId) {
  ['tracerouteTab', 'dnsTab', 'portTab'].forEach(id => {
    const pane = document.getElementById(id);
    if (pane) pane.style.display = id === tabId ? 'block' : 'none';
  });
  document.querySelectorAll('#toolkitNavTabs .toolkit-tab').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });
}

function setTracePreset(host) {
  const input = document.getElementById('traceTargetInput');
  if (input) input.value = host;
  runTracerouteTool();
}

async function runTracerouteTool() {
  const host = document.getElementById('traceTargetInput').value.trim();
  const maxHops =
    parseInt(document.getElementById('traceHopsInput').value, 10) || 15;
  const area = document.getElementById('traceResultsArea');
  area.innerHTML =
    '<div class="tool-empty-state"><div class="spinner-ring"></div><p>Tracing route hops...</p></div>';
  try {
    const res = await apiJson('/api/tools/traceroute', {
      method: 'POST',
      body: JSON.stringify({ host, maxHops })
    });
    if (!res.hops || res.hops.length === 0) {
      area.innerHTML = `<div class="tool-empty-state"><p>${esc(
        res.error || 'No hops returned.'
      )}</p></div>`;
      return;
    }
    area.innerHTML = `
      <div class="device-list-table-wrap">
        <table class="device-list-table">
          <thead>
            <tr>
              <th style="width: 10%;">Hop</th>
              <th style="width: 24%;">Router / Node IP</th>
              <th style="width: 30%;">Role</th>
              <th style="width: 18%;">Avg Latency</th>
              <th style="width: 18%;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${res.hops
              .map(
                h => `
              <tr>
                <td class="mono">#${h.hop}</td>
                <td class="mono" style="color:var(--accent-cyan);">${esc(
                  h.ip
                )}</td>
                <td>${esc((h.role && h.role.label) || 'Transit Node')}</td>
                <td class="mono">${
                  h.latencyMs != null ? `${h.latencyMs} ms` : '*'
                }</td>
                <td><span class="status-pill ${
                  h.status === 'success' ? 'online' : 'warning'
                }">${esc(h.status.toUpperCase())}</span></td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    area.innerHTML = `<div class="tool-empty-state"><p style="color:var(--accent-red);">${esc(
      err.message
    )}</p></div>`;
  }
}

async function runDnsBenchmarkTool() {
  const domain = document.getElementById('dnsDomainInput').value.trim();
  const area = document.getElementById('dnsResultsArea');
  area.innerHTML =
    '<div class="tool-empty-state"><div class="spinner-ring"></div><p>Benchmarking DNS resolvers...</p></div>';
  try {
    const res = await apiJson('/api/tools/dns-benchmark', {
      method: 'POST',
      body: JSON.stringify({ domain })
    });
    area.innerHTML = `
      <div class="device-list-table-wrap">
        <table class="device-list-table">
          <thead>
            <tr>
              <th style="width: 24%;">DNS Provider</th>
              <th style="width: 14%;">Server</th>
              <th style="width: 16%;">Response Time</th>
              <th style="width: 32%;">Resolved IPs</th>
              <th style="width: 14%;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${(res.results || [])
              .map(
                r => `
              <tr>
                <td><strong>${esc(r.name)}</strong></td>
                <td class="mono">${esc(r.ip)}</td>
                <td class="mono">${
                  r.latencyMs != null ? `${r.latencyMs} ms` : '—'
                }</td>
                <td class="mono" style="font-size:0.78rem;">${esc(
                  (r.addresses || []).join(', ') || r.error || '—'
                )}</td>
                <td><span class="status-pill ${
                  r.status === 'success' ? 'online' : 'offline'
                }">${esc(r.status.toUpperCase())}</span></td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    area.innerHTML = `<div class="tool-empty-state"><p style="color:var(--accent-red);">${esc(
      err.message
    )}</p></div>`;
  }
}

function setPortPreset(host, port) {
  document.getElementById('portHostInput').value = host;
  document.getElementById('portNumberInput').value = port;
  runPortCheckTool();
}

async function runPortCheckTool() {
  const host = document.getElementById('portHostInput').value.trim();
  const port =
    parseInt(document.getElementById('portNumberInput').value, 10) || 80;
  const area = document.getElementById('portResultsArea');
  area.innerHTML =
    '<div class="tool-empty-state"><div class="spinner-ring"></div><p>Testing TCP socket...</p></div>';
  try {
    const res = await apiJson('/api/tools/port-check', {
      method: 'POST',
      body: JSON.stringify({ host, port })
    });
    area.innerHTML = `
      <div class="tool-empty-state" style="border-style:solid;">
        <span style="font-size:2rem;">${res.open ? '✅' : '🚫'}</span>
        <div>
          <h4>${esc(res.host)}:${res.port} is ${
      res.open ? 'OPEN & RESPONDING' : 'CLOSED / FILTERED'
    }</h4>
          <p style="color:var(--text-muted); font-size:0.86rem;">
            ${
              res.open
                ? `TCP handshake succeeded in ${res.latencyMs} ms.`
                : esc(res.error || 'Connection timed out.')
            }
          </p>
        </div>
      </div>
    `;
  } catch (err) {
    area.innerHTML = `<div class="tool-empty-state"><p style="color:var(--accent-red);">${esc(
      err.message
    )}</p></div>`;
  }
}

// Modals & Wizards
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add('open');
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('open');
}

async function submitAddDevice(event) {
  event.preventDefault();
  const payload = {
    name: document.getElementById('devNameInput').value.trim(),
    ip: document.getElementById('devIpInput').value.trim(),
    type: document.getElementById('devTypeSelect').value,
    port: parseInt(document.getElementById('devPortInput').value, 10) || 80,
    location: document.getElementById('devLocInput').value.trim() || 'Office',
    critical: document.getElementById('devCritCheckbox').checked
  };
  try {
    await apiJson('/api/devices', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    closeModal('addDeviceModal');
    document.getElementById('addDeviceForm').reset();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

function openRouterConfigForIp(ip) {
  const fleet = Array.isArray(appState.routers) ? appState.routers : [];
  const target = fleet.find(r => r.ip === ip) || (appState.router && appState.router.ip === ip ? appState.router : null);
  const ipEl = document.getElementById('routerIpInput');
  const portEl = document.getElementById('routerPortInput');
  const snmpEl = document.getElementById('routerSnmpInput');
  const stokEl = document.getElementById('routerStokInput');
  const passEl = document.getElementById('routerPasswordInput');
  if (ipEl) ipEl.value = ip || (target && target.ip) || '192.168.0.1';
  if (portEl) portEl.value = (target && target.port) || 80;
  if (snmpEl) snmpEl.value = (target && target.snmpCommunity) || 'public';
  if (stokEl) stokEl.value = '';
  if (passEl) passEl.value = '';
  openModal('routerConfigModal');
}

function openRouterConfigForSelected() {
  const ip = appState.selectedRouterIp || (appState.router && appState.router.ip) || '192.168.0.1';
  openRouterConfigForIp(ip);
}

async function submitRouterConfig(event) {
  event.preventDefault();
  const payload = {
    ip: document.getElementById('routerIpInput').value.trim(),
    port: parseInt((document.getElementById('routerPortInput') || {}).value, 10) || 80,
    stok: document.getElementById('routerStokInput').value.trim(),
    password: document.getElementById('routerPasswordInput').value,
    snmpCommunity: ((document.getElementById('routerSnmpInput') || {}).value || 'public').trim()
  };
  try {
    const res = await apiJson('/api/routers/config', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (res && res.routers) appState.routers = res.routers;
    appState.selectedRouterIp = payload.ip;
    closeModal('routerConfigModal');
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function runDiagnosticWizard() {
  openModal('diagnosticWizardModal');
  const content = document.getElementById('wizardContent');
  content.innerHTML =
    '<div class="tool-empty-state"><div class="spinner-ring"></div><p>Running full network health diagnosis...</p></div>';
  try {
    const res = await apiJson('/api/diagnostics/run', {
      method: 'POST',
      body: JSON.stringify({})
    });
    content.innerHTML = `
      <div class="friendly-tip-box" style="margin-bottom:10px;">
        <span style="font-size:1.5rem;">${
          res.overallVerdict === 'HEALTHY'
            ? '✅'
            : res.overallVerdict === 'DEGRADED'
            ? '⚠️'
            : '🚨'
        }</span>
        <div>
          <strong>${esc(res.summaryHeadline)}</strong>
          <div style="font-size:0.8rem; color:var(--text-dim);">Scan completed in ${
            res.durationMs
          } ms</div>
        </div>
      </div>
      ${(res.findings || [])
        .map(
          f => `
        <div class="incident-row">
          <div>
            <span class="status-pill ${
              f.status === 'OPTIMAL'
                ? 'online'
                : f.status === 'WARNING'
                ? 'warning'
                : 'offline'
            }">${esc(f.status)}</span>
            <strong style="margin-left:8px;">${esc(f.title)}</strong>
            <p style="font-size:0.82rem; color:var(--text-muted); margin-top:4px;">${esc(
              f.detail
            )}</p>
          </div>
        </div>
      `
        )
        .join('')}
      <div style="margin-top:8px;">
        <h4 style="font-size:0.9rem; margin-bottom:6px;">Recommended Actions:</h4>
        <ul style="padding-left:20px; font-size:0.85rem; color:var(--text-muted);">
          ${(res.recommendations || []).map(r => `<li>${esc(r)}</li>`).join('')}
        </ul>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="tool-empty-state"><p style="color:var(--accent-red);">${esc(
      err.message
    )}</p></div>`;
  }
}

async function runNetworkDiscovery() {
  const content = document.getElementById('discoverModalContent');
  content.innerHTML =
    '<div class="tool-empty-state"><div class="spinner-ring"></div><p>Scanning local wired &amp; Wi-Fi LAN subnets...</p></div>';
  try {
    const res = await apiJson('/api/network/discover', {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
    const list = res.inventory || res.devices || [];
    content.innerHTML = `
      <div style="margin-bottom:10px; font-size:0.85rem; color:var(--text-muted);">
        Found <strong>${
          res.totalDiscovered ?? list.length
        }</strong> active hosts across <code>${esc(
      (res.networks || []).join(', ')
    )}</code>.
      </div>
      <div class="device-list-table-wrap" style="max-height:360px; overflow-y:auto;">
        <table class="device-list-table">
          <thead>
            <tr>
              <th style="width: 22%;">IP Address</th>
              <th style="width: 24%;">MAC Address</th>
              <th style="width: 38%;">Vendor / Name</th>
              <th style="width: 16%;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${list
              .map(
                d => `
              <tr>
                <td class="mono" style="color:var(--accent-cyan);">${esc(
                  d.ip
                )}</td>
                <td class="mono">${esc(d.mac || '—')}</td>
                <td>${esc(d.suggestedName || d.name || d.vendor)}</td>
                <td><span class="status-pill ${
                  d.isOnline !== false ? 'online' : 'offline'
                }">${d.isOnline !== false ? 'ONLINE' : 'OFFLINE'}</span></td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<div class="tool-empty-state"><p style="color:var(--accent-red);">${esc(
      err.message
    )}</p></div>`;
  }
}

function scrollToAlerts() {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('alerts');
    return;
  }
  const el = document.getElementById('notificationsCard');
  if (el) {
    el.style.display = '';
    el.scrollIntoView({ behavior: 'smooth' });
  }
}

function scrollToLanAssets() {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('devices');
    return;
  }
  const el = document.getElementById('lanAssetsSection');
  if (el) {
    el.style.display = '';
    el.scrollIntoView({ behavior: 'smooth' });
  }
}

function scrollToToolkit() {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('toolkit');
    return;
  }
  const el = document.getElementById('toolkitSection');
  if (el) {
    el.style.display = '';
    el.scrollIntoView({ behavior: 'smooth' });
  }
}

function openTracerouteGoogle() {
  scrollToToolkit();
  switchToolkitTab('tracerouteTab');
  setTracePreset('google.com');
}

