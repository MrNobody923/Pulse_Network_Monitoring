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

let tracerouteRequest = 0;

async function runTracerouteTool() {
  const request = ++tracerouteRequest;
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
    if (request !== tracerouteRequest) return;
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
                  esc(h.latencyDisplay || (h.latencyMs != null ? `${h.latencyMs} ms` : '*'))
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
    if (request !== tracerouteRequest) return;
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
      esc(String(res.state || 'unconfirmed').toUpperCase())
    }</h4>
          <p style="color:var(--text-muted); font-size:0.86rem;">
            ${
              res.open
                ? (res.latencyMs == null ? 'Nmap confirmed the port is open.' : `TCP handshake succeeded in ${res.latencyMs} ms.`)
                : esc(res.error || 'The monitor could not confirm the port state.')
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
const modalOpeners = new WeakMap();

function openModal(id) {
  const modal = document.getElementById(id);
  if (!modal || modal.classList.contains('open')) return;
  modalOpeners.set(modal, document.activeElement);
  modal.classList.add('open');
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  const title = modal.querySelector('.modal-header h2, .modal-header h3');
  if (title) {
    if (!title.id) title.id = `${id}Title`;
    modal.setAttribute('aria-labelledby', title.id);
  }
  modal.querySelector('.modal-close-btn')?.focus();
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (!modal?.classList.contains('open')) return;
  modal.classList.remove('open');
  const opener = modalOpeners.get(modal);
  const focusTarget = opener?.getClientRects().length ? opener : opener?.closest('details')?.querySelector('summary');
  focusTarget?.focus({preventScroll: true});
  modalOpeners.delete(modal);
}

document.addEventListener('keydown', event => {
  const modal = [...document.querySelectorAll('.modal-overlay.open')].at(-1);
  if (!modal || event.defaultPrevented || document.querySelector('dialog[open]')) return;
  if (event.key === 'Escape') {
    event.preventDefault();
    closeModal(modal.id);
  } else if (event.key === 'Tab') {
    const items = [...modal.querySelectorAll('button, input, select, textarea, a[href]')].filter(
      el => !el.matches(':disabled') && el.tabIndex >= 0 && el.getClientRects().length
    );
    const first = items[0];
    const last = items.at(-1);
    if (!modal.contains(document.activeElement) || document.activeElement === (event.shiftKey ? first : last)) {
      event.preventDefault();
      (event.shiftKey ? last : first)?.focus();
    }
  }
});

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
  const wanIndexEl = document.getElementById('routerWanIndexInput');
  const stokEl = document.getElementById('routerStokInput');
  const passEl = document.getElementById('routerPasswordInput');
  if (ipEl) ipEl.value = ip || (target && target.ip) || '192.168.0.1';
  if (portEl) portEl.value = (target && target.port) || 80;
  if (snmpEl) snmpEl.value = '';
  if (wanIndexEl) wanIndexEl.value = target?.wanInterfaceIndex ?? '';
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
  const tokenInput = document.getElementById('routerStokInput');
  const passwordInput = document.getElementById('routerPasswordInput');
  const payload = {
    ip: document.getElementById('routerIpInput').value.trim(),
    port: parseInt((document.getElementById('routerPortInput') || {}).value, 10) || 80,
    wanInterfaceIndex: document.getElementById('routerWanIndexInput').value
  };
  const snmpCommunity = document.getElementById('routerSnmpInput').value.trim();
  if (snmpCommunity) payload.snmpCommunity = snmpCommunity;
  if (tokenInput.value.trim()) payload.stok = tokenInput.value.trim();
  if (passwordInput.value) payload.password = passwordInput.value;
  try {
    const res = await apiJson('/api/routers/config', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (res && res.routers) appState.routers = res.routers;
    appState.selectedRouterIp = payload.ip;
    tokenInput.value = '';
    passwordInput.value = '';
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
                : f.status === 'UNAVAILABLE'
                ? 'new'
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

function openNetworkDiscovery() {
  const dialog = document.getElementById('discoverDevicesModal');
  if (!dialog.open) dialog.showModal();
  document.getElementById('discoverDeviceSearch').value = '';
  document.getElementById('discoverFavouriteStatus').textContent = '';
  const scan = document.getElementById('btnRunLanDiscovery');
  if (!scan.disabled) {
    document.getElementById('discoverScanStatus').textContent = appState.lastDiscoveryAt
      ? `Last LAN scan ${fmtTime(appState.lastDiscoveryAt)}`
      : 'Run a LAN scan to look for devices.';
  }
  renderDiscoveryResults();
}

function renderDiscoveryResults() {
  const content = document.getElementById('discoverModalContent');
  const query = document.getElementById('discoverDeviceSearch').value.trim().toLowerCase();
  const devices = appState.networkInventory.filter(device => !device.archived);
  const filtered = devices.filter(device =>
    [device.name, device.suggestedName, device.ip, device.observedMac, device.vendor]
      .some(value => String(value ?? '').toLowerCase().includes(query))
  ).sort((a, b) => Number(b.isOnline) - Number(a.isOnline));
  if (!filtered.length) {
    content.innerHTML = `<p class="discovery-status">${query ? 'No devices match your search.' : 'No discovered devices to show.'}</p>`;
    return;
  }
  const sources = {icmp: 'ICMP echo', dynamic: 'ARP cache', static: 'ARP cache', dhcp: 'Router DHCP'};
  content.innerHTML = `
    <p class="discovery-status">${filtered.length} of ${devices.length} discovered devices</p>
    <div class="device-list-table-wrap discovery-results">
      <table class="device-list-table">
        <thead><tr><th scope="col">Device</th><th scope="col">Address</th><th scope="col">Favourite</th></tr></thead>
        <tbody>${filtered.map(device => {
          const name = device.suggestedName || device.name || device.ip;
          const key = device.favoriteKey || (device.mac ? `mac:${device.mac.toLowerCase()}` : `ip:${device.ip}`);
          return `<tr>
            <td>${esc(name)}<small>${esc(sources[device.arpType] || 'LAN observation')} · ${esc(fmtTime(device.lastSeen))}</small></td>
            <td class="mono">${esc(device.ip)}<small>${esc(device.observedMac || 'MAC unknown')}</small></td>
            <td><button type="button" class="star-btn ${device.favorite ? 'active' : ''}"
              data-favorite-key="${esc(key)}" data-inventory-mac="${esc(device.mac)}"
              aria-label="Favourite ${esc(name)}" aria-pressed="${Boolean(device.favorite)}"
              onclick="saveDiscoveryFavorite(this)" ${pendingDeviceFavorites.has(key) ? 'disabled' : ''}>${device.favorite ? '★' : '☆'}</button></td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>`;
}

async function saveDiscoveryFavorite(button) {
  const feedback = document.getElementById('discoverFavouriteStatus');
  const key = button.dataset.favoriteKey;
  button.disabled = true;
  try {
    const favorite = await saveDeviceFavorite(key);
    if (favorite == null) return;
    feedback.textContent = favorite ? 'Added to Favourites.' : 'Removed from Favourites.';
    if (button.isConnected) {
      const updated = appState.networkInventory.find(device => device.mac === button.dataset.inventoryMac);
      if (updated) button.dataset.favoriteKey = updated.favoriteKey || key;
      button.setAttribute('aria-pressed', String(favorite));
      button.classList.toggle('active', favorite);
      button.textContent = favorite ? '★' : '☆';
    } else {
      renderDiscoveryResults();
    }
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function runNetworkDiscovery() {
  const button = document.getElementById('btnRunLanDiscovery');
  const status = document.getElementById('discoverScanStatus');
  button.disabled = true;
  status.textContent = 'Scanning the configured local subnets…';
  try {
    const scan = await apiJson('/api/network/discover', {method: 'POST', body: '{}'});
    appState.lastDiscoveryAt = scan.timestamp;
    appState.networkInventory = scan.inventory;
    appState.devices = scan.monitoredDevices;
    renderOverviewAndLanCardsAndList();
    status.textContent = `Observed ${scan.totalDiscovered} addresses at ${fmtTime(scan.timestamp)}.`;
    const coverage = document.getElementById('discoverCoverage');
    coverage.querySelector('ul').innerHTML = (scan.coverage || []).map(item =>
      `<li><code>${esc(item.subnet)}</code> · ${esc(item.addressesObserved)} observed · ${esc(item.icmpReplies)} ICMP replies across ${esc(item.addressesProbed)} probed</li>`
    ).join('');
    coverage.hidden = !scan.coverage?.length;
    renderDiscoveryResults();
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
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

