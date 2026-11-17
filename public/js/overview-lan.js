// Pulse Network Monitor — Overview KPI Cards, LAN Asset Summary Cards, and Vertical List View

function renderExecutiveBanner() {
  const card = document.getElementById('overviewHeadlineCard');
  const icon = document.getElementById('overviewIcon');
  const title = document.getElementById('overviewTitle');
  const desc = document.getElementById('overviewDesc');

  const rows = buildUnifiedDeviceRows();
  const activeRows = rows.filter(r => !r.archived);
  const downMonitored = activeRows.filter(r => r.monitored && r.status === 'offline');
  const ports = (appState.router && appState.router.ports) || [];
  const optimalPorts = ports.filter(p => p.status === 'optimal').length;
  const warnPorts = ports.filter(
    p => p.status === 'warning' || (p.isWan && p.linkStatus === 'disconnected')
  ).length;
  const isp = appState.isp || {};
  const pingMs = isp.tier1LatencyMs;

  card.classList.remove('warning', 'critical');
  if (downMonitored.length > 0 || isp.overallHealth === 'OUTAGE') {
    card.classList.add('critical');
    icon.textContent = 'CRIT';
    title.textContent = `Alert: ${downMonitored.length} Important Device(s) Offline`;
    desc.textContent = downMonitored.length
      ? `Not responding right now: ${downMonitored.map(d => `${d.name} (${d.ip})`).join(', ')}.`
      : 'Internet connection appears to be offline.';
  } else if (warnPorts > 0 || isp.overallHealth === 'DEGRADED') {
    card.classList.add('warning');
    icon.textContent = 'WARN';
    title.textContent = 'Notice: Slow Cable Speed or High Internet Ping';
    desc.textContent =
      'One or more router cable ports are running slow, or internet ping is higher than normal.';
  } else {
    icon.textContent = 'OK';
    title.textContent = 'Network Healthy — All Devices & Internet Working Normally';
    desc.textContent = `Tracking ${activeRows.length} active devices on your network (${
      activeRows.filter(r => r.online).length
    } online right now) with automatic daily checks.`;
  }

  const internetBadge = document.getElementById('overviewInternetBadge');
  const cablesBadge = document.getElementById('overviewCablesBadge');
  const apsBadge = document.getElementById('overviewApsBadge');
  const pingBadge = document.getElementById('overviewPingBadge');

  if (internetBadge) {
    const health =
      isp.overallHealth && isp.overallHealth !== 'UNKNOWN'
        ? isp.overallHealth
        : 'GOOD';
    internetBadge.innerHTML = `<span>Internet Line:</span> <strong>${esc(health)}</strong>`;
  }
  if (cablesBadge) {
    const portSummary =
      warnPorts > 0
        ? `${warnPorts} Slow Cable`
        : optimalPorts > 0
        ? `${optimalPorts}/${ports.length} Full Speed`
        : appState.router && appState.router.reachable
        ? 'Connected'
        : `${ports.length} Ports Ready`;
    cablesBadge.innerHTML = `<span>Router Ports:</span> <strong>${esc(portSummary)}</strong>`;
  }
  if (apsBadge) {
    const monCount = activeRows.filter(r => r.monitored).length;
    apsBadge.innerHTML = `<span>Monitored Gear:</span> <strong>${monCount} Key · ${activeRows.length} Total</strong>`;
  }
  if (pingBadge) {
    pingBadge.innerHTML = `<span>Average Ping:</span> <strong>${
      pingMs != null ? `${pingMs} ms` : 'Probing...'
    }</strong>`;
  }
}

function selectDeviceFilter(filter, scrollToList = false) {
  currentDeviceFilter = filter;
  renderOverviewAndLanCardsAndList();
  if (scrollToList) {
    scrollToLanAssets();
  }
}

function handleDeviceSearch(value) {
  currentDeviceSearch = String(value || '').trim().toLowerCase();
  renderOverviewAndLanCardsAndList();
}

function renderOverviewAndLanCardsAndList() {
  const rows = buildUnifiedDeviceRows();
  const activeRows = rows.filter(r => !r.archived);
  const archivedRows = rows.filter(r => r.archived);
  const connectedRows = activeRows.filter(r => r.online);
  const favRows = activeRows.filter(r => r.favorite);
  const newRows = activeRows.filter(r => r.isNew);
  const downRows = activeRows.filter(r => r.monitored && r.status === 'offline');
  const disconnectedRows = activeRows.filter(r => !r.monitored && !r.online);
  const offlineRows = activeRows.filter(r => !r.online);
  const monitoredRows = activeRows.filter(r => r.monitored);

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  // Update 7 Overview Cards
  setTxt('ovCardAll', activeRows.length);
  setTxt('ovCardConnected', connectedRows.length);
  setTxt('ovCardFavorites', favRows.length);
  setTxt('ovCardNew', newRows.length);
  setTxt('ovCardDown', downRows.length);
  setTxt('ovCardDisconnected', disconnectedRows.length);
  setTxt('ovCardArchived', archivedRows.length);

  // Update Left Sidebar Badges & Quick Filter Counts
  setTxt('sideBadgeDevices', activeRows.length);
  setTxt('sideFiltAll', activeRows.length);
  setTxt('sideFiltConnected', connectedRows.length);
  setTxt('sideFiltFavorites', favRows.length);
  setTxt('sideFiltNew', newRows.length);
  setTxt('sideFiltDown', downRows.length);
  setTxt('sideFiltDisconnected', disconnectedRows.length);
  setTxt('sideFiltArchived', archivedRows.length);

  const sideAlertsEl = document.getElementById('sideBadgeAlerts');
  if (sideAlertsEl) {
    const activeAlertsCount = (appState.activeAlerts || []).length;
    sideAlertsEl.textContent = activeAlertsCount;
    sideAlertsEl.className = `side-badge ${activeAlertsCount > 0 ? 'red' : 'green'}`;
  }

  const sideIspEl = document.getElementById('sideBadgeInternet');
  if (sideIspEl && appState.isp) {
    const st = appState.isp.lastSpeedTest;
    sideIspEl.textContent = st && st.downloadMbps ? `${Math.round(st.downloadMbps)}M` : (appState.isp.overallHealth || 'ISP');
  }

  // Update 5 LAN Asset Summary Cards
  setTxt('lanCardOverall', activeRows.length);
  setTxt(
    'lanCardOverallSub',
    `${connectedRows.length} connected · ${monitoredRows.length} office equipment`
  );
  setTxt('lanCardDown', downRows.length);
  setTxt('lanCardOffline', offlineRows.length);
  setTxt(
    'lanCardOfflineSub',
    `${downRows.length} down · ${disconnectedRows.length} disconnected`
  );
  setTxt('lanCardNew', newRows.length);
  setTxt('lanCardFavorites', favRows.length);

  // Update filter tab counts
  setTxt('devTabAll', activeRows.length);
  setTxt('devTabConnected', connectedRows.length);
  setTxt('devTabFavorites', favRows.length);
  setTxt('devTabNew', newRows.length);
  setTxt('devTabDown', downRows.length);
  setTxt('devTabOffline', offlineRows.length);
  setTxt('devTabDisconnected', disconnectedRows.length);
  setTxt('devTabArchived', archivedRows.length);
  setTxt('devTabMonitored', monitoredRows.length);

  const badge = document.getElementById('deviceCountBadge');
  if (badge) {
    badge.textContent = `${connectedRows.length} Connected / ${activeRows.length} Total`;
    badge.className = `status-pill ${downRows.length > 0 ? 'offline' : 'online'}`;
  }

  const lastScanEl = document.getElementById('lastScanTimeLabel');
  if (lastScanEl) {
    lastScanEl.textContent = `Last completed scan: ${
      appState.lastDiscoveryAt
        ? fmtTime(appState.lastDiscoveryAt)
        : 'Scheduled (runs automatically)'
    }`;
  }

  // Render the Deployed Access Points & Switches Downed/No-Internet Triage Board
  renderDownedDevicesTriageBoard(monitoredRows);

  // Highlight active cards and tabs
  document.querySelectorAll('[data-overview-filter]').forEach(btn => {
    btn.classList.toggle(
      'active',
      btn.getAttribute('data-overview-filter') === currentDeviceFilter
    );
  });
  document.querySelectorAll('[data-lan-filter]').forEach(btn => {
    btn.classList.toggle(
      'active',
      btn.getAttribute('data-lan-filter') === currentDeviceFilter
    );
  });
  document.querySelectorAll('[data-dev-filter]').forEach(btn => {
    btn.classList.toggle(
      'active',
      btn.getAttribute('data-dev-filter') === currentDeviceFilter
    );
  });
  document.querySelectorAll('[data-side-filter]').forEach(link => {
    link.classList.toggle(
      'active',
      link.getAttribute('data-side-filter') === currentDeviceFilter
    );
  });

  // Filter rows for the vertical list
  let filtered = rows;
  if (currentDeviceFilter === 'all') filtered = activeRows;
  else if (currentDeviceFilter === 'connected') filtered = connectedRows;
  else if (currentDeviceFilter === 'favorites') filtered = favRows;
  else if (currentDeviceFilter === 'new') filtered = newRows;
  else if (currentDeviceFilter === 'down') filtered = downRows;
  else if (currentDeviceFilter === 'offline') filtered = offlineRows;
  else if (currentDeviceFilter === 'disconnected') filtered = disconnectedRows;
  else if (currentDeviceFilter === 'archived') filtered = archivedRows;
  else if (currentDeviceFilter === 'monitored') filtered = monitoredRows;

  if (currentDeviceSearch) {
    filtered = filtered.filter(
      r =>
        r.name.toLowerCase().includes(currentDeviceSearch) ||
        r.ip.toLowerCase().includes(currentDeviceSearch) ||
        (r.mac && r.mac.toLowerCase().includes(currentDeviceSearch)) ||
        (r.vendor && r.vendor.toLowerCase().includes(currentDeviceSearch)) ||
        (r.location && r.location.toLowerCase().includes(currentDeviceSearch))
    );
  }

  const tbody = document.getElementById('devicesListBody');
  if (!tbody) return;

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 28px; color: var(--text-dim);">
          No devices match the current filter (<strong>${esc(
            currentDeviceFilter.toUpperCase()
          )}</strong>).
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .map((row, idx) => {
      let statusClass = 'online';
      let statusLabel = 'ONLINE';
      if (row.status === 'offline') {
        statusClass = 'offline';
        statusLabel = row.monitored ? 'DEVICE DOWN' : 'OFFLINE';
      } else if (row.connectivityState === 'ONLINE_NO_INTERNET') {
        statusClass = 'warning';
        statusLabel = 'NO INTERNET';
      } else if (row.status === 'warning') {
        statusClass = 'warning';
        statusLabel = 'DEGRADED';
      } else if (row.status === 'unknown') {
        statusClass = 'warning';
        statusLabel = 'PROBING';
      }

      const badges = [
        `<span class="status-pill ${statusClass}" style="font-size:0.66rem; padding:3px 8px;">${esc(statusLabel)}</span>`,
        row.isNew ? '<span class="status-pill new" style="font-size:0.64rem; padding:2px 6px;">NEW</span>' : '',
        row.archived ? '<span class="status-pill warning" style="font-size:0.64rem; padding:2px 6px;">ARCHIVED</span>' : ''
      ]
        .filter(Boolean)
        .join(' ');

      const portsHint =
        row.monitored && row.openPorts && row.openPorts.length
          ? `<div style="font-size:0.68rem;color:var(--accent-cyan);">Open Ports: ${esc(
              row.openPorts.join(', ')
            )}</div>`
          : '';

      const telemetry = row.monitored
        ? `<div class="mono" style="font-weight:700;">${
            row.latencyMs != null ? `${row.latencyMs} ms` : '—'
          } <small style="color:var(--text-dim); font-weight:500;">(${
            row.packetLossPct ?? 0
          }% loss)</small></div>${portsHint}`
        : `<div style="color:var(--text-muted); font-size:0.76rem; font-weight:600;">${
            row.online ? 'Connected on Network' : 'Not seen recently'
          }</div>`;

      let roleBadgeText = 'Office Equipment';
      if (row.monitored) {
        const t = String(row.type || '').toLowerCase();
        if (t === 'switch') roleBadgeText = 'Managed Switch';
        else if (t === 'gateway') roleBadgeText = 'Core Gateway';
        else if (t === 'router') roleBadgeText = 'Secondary Router';
        else if (t === 'ap') roleBadgeText = 'Access Point';
        else if (t === 'server') roleBadgeText = 'Server / Host';
      }

      const roleLabel = row.monitored
        ? `<span class="status-pill new" style="font-size:0.65rem; padding:2px 7px;">${roleBadgeText}</span>`
        : `<span style="color:var(--text-main); font-size:0.76rem; font-weight:700;">LAN / Wi-Fi Asset</span>`;
      const vendorText = row.hardwareModel && row.hardwareModel !== row.vendor
        ? `${row.vendor || '—'} · ${row.hardwareModel}`
        : (row.vendor || '—');

      const diagSubtext =
        row.monitored &&
        (row.status === 'offline' ||
          row.connectivityState === 'ONLINE_NO_INTERNET' ||
          row.status === 'warning') &&
        row.diagnosisSummary
          ? `<div style="margin-top:3px;font-size:0.71rem;color:${
              row.status === 'offline' ? 'var(--accent-red)' : 'var(--accent-amber)'
            };font-weight:700;">⚠️ ${esc(row.diagnosisSummary)}</div>`
          : '';

      return `
        <tr>
          <td class="mono" style="color: var(--text-dim); font-size: 0.76rem;">${idx + 1}</td>
          <td>
            <span class="dev-row-title">${esc(row.name)}</span>
            <span class="dev-row-sub">${esc(row.location)}</span>
            ${diagSubtext}
          </td>
          <td>
            <div>${roleLabel}</div>
            <span class="dev-row-sub" style="margin-top:2px;">${esc(vendorText)}</span>
          </td>
          <td>
            <div class="mono" style="color: var(--accent-cyan); font-weight: 700; font-size: 0.8rem;">${esc(
              row.ip
            )}</div>
            <div class="mono" style="font-size: 0.71rem; color: var(--text-dim); margin-top: 1px;">${esc(
              row.mac || '—'
            )}</div>
          </td>
          <td>
            ${telemetry}
            <div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 2px;">${esc(
              fmtTime(row.lastSeen)
            )}</div>
          </td>
          <td>
            <div style="display:flex; flex-wrap:wrap; gap:4px; align-items:center;">${badges}</div>
          </td>
          <td style="text-align: right;">
            <div class="row-actions-group">
              <button type="button" class="star-btn ${
                row.favorite ? 'active' : ''
              }" onclick="toggleDeviceFavorite('${esc(
        row.favoriteKey
      )}')" title="Toggle Favourite">
                ${row.favorite ? '★' : '☆'}
              </button>
              <button type="button" class="btn btn-secondary btn-xs" onclick="scanDevicePorts('${esc(
                row.ip
              )}', '${esc(row.name)}')" title="Run Nmap Port &amp; Risk Audit on ${esc(
        row.ip
      )}">Ports</button>
              ${
                row.monitored && row.id
                  ? `<button type="button" class="btn btn-secondary btn-xs" onclick="probeMonitoredDevice('${esc(
                      row.id
                    )}')">Probe</button>${
                      !(typeof appState !== 'undefined' && appState.router && row.ip === appState.router.ip)
                        ? `<button type="button" class="btn btn-secondary btn-xs" style="color:var(--danger,#ef4444);border-color:rgba(239,68,68,0.35);" onclick="deleteMonitoredDevice('${esc(
                            row.id
                          )}', '${esc(
                            encodeURIComponent(row.name || row.ip)
                          )}', '${esc(
                            row.ip
                          )}')" title="Remove from Monitored Infrastructure">Remove</button>`
                        : ''
                    }`
                  : `<button type="button" class="btn btn-secondary btn-xs" onclick="promoteLanDeviceAsInfra('${esc(
                      row.ip
                    )}', '${esc(row.mac || '')}', '${esc(
                      encodeURIComponent(row.name || row.ip)
                    )}')" title="Promote this LAN device to Monitored Access Point / Router">+ Track AP</button>`
              }
              ${
                !row.authorized && row.mac
                  ? `<button type="button" class="btn btn-primary btn-xs" onclick="authorizeLanDevice('${esc(
                      row.mac
                    )}')">Review</button>`
                  : ''
              }
              <button type="button" class="btn btn-secondary btn-xs" onclick="toggleDeviceArchive('${esc(
                row.favoriteKey
              )}')">
                ${row.archived ? 'Restore' : 'Archive'}
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

async function toggleDeviceFavorite(assetKey) {
  try {
    await apiJson('/api/network/inventory/favorite', {
      method: 'POST',
      body: JSON.stringify({ asset_key: assetKey })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function toggleDeviceArchive(assetKey) {
  try {
    await apiJson('/api/network/inventory/archive', {
      method: 'POST',
      body: JSON.stringify({ asset_key: assetKey })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function authorizeLanDevice(mac) {
  try {
    await apiJson('/api/network/inventory/authorize', {
      method: 'POST',
      body: JSON.stringify({ mac })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function probeMonitoredDevice(deviceId) {
  try {
    await apiJson(`/api/devices/${encodeURIComponent(deviceId)}/probe`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

function scanDevicePorts(ip, name) {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('nmap');
  }
  if (typeof selectNmapTargetPreset === 'function') {
    selectNmapTargetPreset(ip, name);
  }
  if (typeof runNmapPortScan === 'function') {
    runNmapPortScan();
  }
}

async function triggerInlineLanScan() {
  const btn = document.getElementById('btnScanLanInline');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Scanning LAN...';
  }
  try {
    await apiJson('/api/network/discover', {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(`LAN scan error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔍 Scan Local LAN Now';
    }
  }
}

let currentTriageMatrixFilter = 'all';

function setTriageMatrixFilter(filter) {
  currentTriageMatrixFilter = filter || 'all';
  document.querySelectorAll('#triageFilterPills [data-triage-filter]').forEach(btn => {
    btn.classList.toggle(
      'active',
      btn.getAttribute('data-triage-filter') === currentTriageMatrixFilter
    );
  });
  const rows = buildUnifiedDeviceRows().filter(r => !r.archived && r.monitored);
  renderDownedDevicesTriageBoard(rows);
}

function quickTraceDevice(ip) {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('toolkit');
  } else {
    scrollToToolkit();
  }
  const traceInput = document.getElementById('traceTargetInput');
  if (traceInput) {
    traceInput.value = ip;
  }
  if (typeof runTracerouteTool === 'function') {
    runTracerouteTool();
  }
}

async function probeAllInfrastructureNow() {
  const btn = document.getElementById('btnProbeAllInfra');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Probing All APs & Switches...';
  }
  try {
    const res = await apiJson('/api/devices/probe-all', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.devices) appState.devices = res.devices;
    if (res.inventory) appState.networkInventory = res.inventory;
    if (res.activeAlerts) appState.activeAlerts = res.activeAlerts;
    await loadInitialState();
  } catch (err) {
    alert(`Probe error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Probe All APs & Switches Now';
    }
  }
}

async function syncInfrastructureDevicesNow() {
  const btn = document.getElementById('btnSyncInfra');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Syncing APs & Switches...';
  }
  try {
    const res = await apiJson('/api/network/sync-infrastructure', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.devices) appState.devices = res.devices;
    if (res.inventory) appState.networkInventory = res.inventory;
    if (res.activeAlerts) appState.activeAlerts = res.activeAlerts;
    await loadInitialState();
  } catch (err) {
    alert(`Infrastructure sync error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔄 Sync Deployed APs & Switches';
    }
  }
}

function renderDownedDevicesTriageBoard(monitoredRows) {
  const card = document.getElementById('downedDevicesTriageCard');
  if (!card) return;

  const list = Array.isArray(monitoredRows) ? monitoredRows : [];
  const totalInfra = list.length;
  const downDevices = list.filter(
    d => d.status === 'offline' || d.connectivityState === 'DEVICE_DOWN'
  );
  const noInternetDevices = list.filter(
    d => d.status !== 'offline' && d.connectivityState === 'ONLINE_NO_INTERNET'
  );
  const degradedDevices = list.filter(
    d =>
      d.status !== 'offline' &&
      d.connectivityState !== 'ONLINE_NO_INTERNET' &&
      (d.status === 'warning' || d.connectivityState === 'DEGRADED_LINK')
  );
  const onlineWithInternet = list.filter(
    d => d.online && d.hasInternet && d.status === 'online'
  );

  const apCount = list.filter(d => String(d.type).toLowerCase() === 'ap').length;
  const swCount = list.filter(d => String(d.type).toLowerCase() === 'switch').length;
  const gwCount = list.filter(d => ['gateway', 'router'].includes(String(d.type).toLowerCase())).length;

  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setEl('triageTotalInfra', totalInfra);
  setEl(
    'triageTotalFoot',
    `${gwCount} Routers/Gateways · ${swCount} Switches · ${apCount} Access Points`
  );
  setEl('triageOnlineInternet', onlineWithInternet.length);
  setEl('triageDownCount', downDevices.length);
  setEl('triageNoInternetCount', noInternetDevices.length);
  setEl('triageDegradedCount', degradedDevices.length);

  const statusBadge = document.getElementById('triageStatusBadge');
  const headerIcon = document.getElementById('triageHeaderIcon');
  const sideBadgeTriage = document.getElementById('sideBadgeTriage');
  if (downDevices.length > 0) {
    card.style.borderColor = 'var(--status-down-border)';
    if (statusBadge) {
      statusBadge.className = 'status-pill offline';
      statusBadge.textContent = `🚨 ${downDevices.length} DEVICE(S) DOWN — FIX REQUIRED`;
    }
    if (headerIcon) {
      headerIcon.style.background = 'var(--status-down-bg)';
      headerIcon.style.color = 'var(--status-down-text)';
    }
    if (sideBadgeTriage) {
      sideBadgeTriage.className = 'side-badge red';
      sideBadgeTriage.textContent = `${downDevices.length} Down`;
    }
  } else if (noInternetDevices.length > 0 || degradedDevices.length > 0) {
    card.style.borderColor = 'var(--status-warn-border)';
    if (statusBadge) {
      statusBadge.className = 'status-pill warning';
      statusBadge.textContent =
        noInternetDevices.length > 0
          ? `🟠 ${noInternetDevices.length} ON LAN WITH NO INTERNET`
          : `🟡 ${degradedDevices.length} DEGRADED LINK`;
    }
    if (headerIcon) {
      headerIcon.style.background = 'var(--status-warn-bg)';
      headerIcon.style.color = 'var(--status-warn-text)';
    }
    if (sideBadgeTriage) {
      sideBadgeTriage.className = 'side-badge amber';
      sideBadgeTriage.textContent =
        noInternetDevices.length > 0
          ? `${noInternetDevices.length} No Net`
          : `${degradedDevices.length} Warn`;
    }
  } else {
    card.style.borderColor = 'var(--status-up-border)';
    if (statusBadge) {
      statusBadge.className = 'status-pill online';
      statusBadge.textContent = `🟢 ALL ${totalInfra} APs & SWITCHES ONLINE & INTERNET READY`;
    }
    if (headerIcon) {
      headerIcon.style.background = 'var(--status-up-bg)';
      headerIcon.style.color = 'var(--status-up-text)';
    }
    if (sideBadgeTriage) {
      sideBadgeTriage.className = 'side-badge green';
      sideBadgeTriage.textContent = `${totalInfra} OK`;
    }
  }

  const triageListEl = document.getElementById('downedTriageList');
  const impacted = [...downDevices, ...noInternetDevices, ...degradedDevices];

  if (triageListEl) {
    if (impacted.length === 0) {
      triageListEl.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:space-between; gap:14px; padding:16px 20px; border-radius:12px; background:var(--status-up-bg); border:1px solid var(--status-up-border); flex-wrap:wrap;">
          <div style="display:flex; align-items:center; gap:12px;">
            <span style="font-size:1.6rem;">✅</span>
            <div>
              <strong style="color:var(--status-up-text); font-size:0.95rem; display:block;">Zero Downed or Disconnected Infrastructure — All ${totalInfra} Deployed APs, Switches &amp; Gateways Are Communicating</strong>
              <span style="color:var(--text-muted); font-size:0.82rem;">Every monitored Wi-Fi Access Point and Network Switch is online and connected to the internet.</span>
            </div>
          </div>
        </div>
      `;
    } else {
      triageListEl.innerHTML = impacted
        .map(dev => {
          const isDown =
            dev.status === 'offline' || dev.connectivityState === 'DEVICE_DOWN';
          const isNoNet = dev.connectivityState === 'ONLINE_NO_INTERNET';
          const borderCol = isDown
            ? 'var(--status-down-border)'
            : 'var(--status-warn-border)';
          const bgCol = isDown
            ? 'var(--row-down-bg)'
            : 'var(--row-warn-bg)';
          const badgeHtml = isDown
            ? '<span class="status-pill offline" style="font-weight:800;">🔴 DEVICE DOWN / UNREACHABLE</span>'
            : isNoNet
            ? '<span class="status-pill warning" style="font-weight:800;">🟠 CONNECTED TO LAN — NO INTERNET</span>'
            : '<span class="status-pill warning" style="font-weight:800;">🟡 DEGRADED LINK / PACKET LOSS</span>';

          const devType = String(dev.type).toLowerCase();
          const roleIcon =
            devType === 'switch'
              ? '🔀 Network Switch'
              : devType === 'gateway'
              ? '🌐 Main Router'
              : devType === 'router'
              ? '🌐 Router'
              : '📡 Wi-Fi Access Point';

          const defaultFixSteps = isDown
            ? [
                `Check the PoE switch port feeding ${dev.name} (${dev.ip}, MAC ${dev.mac || 'N/A'}) — verify PoE and Link LEDs.`,
                `Inspect or reseat the RJ45 Ethernet drop at ${dev.location || 'the device mount'} and confirm the power LED is lit.`,
                `Power-cycle the PoE port for 10 seconds, then click '⚡ Re-Probe Now' to confirm recovery.`
              ]
            : isNoNet
            ? [
                `Do NOT replace or climb to ${dev.name} (${dev.ip}) — its local LAN link is online (${dev.latencyMs ?? '—'} ms).`,
                `Check the Internet cable plugged into your Main Router (192.168.0.1) and the ISP Fiber/Modem box.`,
                `Verify external DNS (1.1.1.1 / 8.8.8.8) recovery on the Internet Health tab.`
              ]
            : [
                `Check the network cable for ${dev.ip} — make sure it connects at full Gigabit speed (1000 Mbps) instead of slow 100 Mbps mode.`,
                `Inspect the RJ45 patch cable for ${dev.name} (${dev.ip}) for damaged twisted pairs or EMI.`,
                `Run '⚡ Re-Probe Now' or Traceroute to verify packet stability.`
              ];

          const steps =
            Array.isArray(dev.fixSteps) && dev.fixSteps.length
              ? dev.fixSteps
              : defaultFixSteps;

          const diagTitle =
            dev.diagnosisTitle ||
            (isDown
              ? `Isolated Outage on ${dev.subnet || 'LAN Subnet'}`
              : isNoNet
              ? 'Connected to Local LAN Without Upstream Internet'
              : 'High Packet Loss / Latency Warning');

          const likelyFault =
            dev.likelyFault ||
            (isDown
              ? 'PoE Port Power Loss / Disconnected RJ45 Cable / Hung AP'
              : isNoNet
              ? 'Upstream ISP / Gateway WAN Outage'
              : 'Cable Degradation or Duplex Mismatch');

          const diagSummary =
            dev.diagnosisSummary ||
            (isDown
              ? `${dev.name} (${dev.ip}) failed both TCP management port and ICMP echo probes while sibling devices on ${
                  dev.subnet || 'this subnet'
                } remain online.`
              : `${dev.name} (${dev.ip}) is experiencing degraded connectivity.`);

          return `
            <div style="border:1.5px solid ${borderCol}; background:${bgCol}; border-radius:14px; padding:16px 18px;">
              <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:10px;">
                <div>
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                    ${badgeHtml}
                    <span class="status-pill new" style="font-size:0.72rem;">${esc(roleIcon)}</span>
                    <span class="mono-chip" style="color:var(--accent-cyan);">IP: ${esc(
                      dev.ip
                    )}</span>
                    <span class="mono-chip" style="color:var(--text-muted);">MAC: ${esc(
                      dev.mac || '—'
                    )}</span>
                    <span style="font-size:0.76rem; color:var(--text-muted); font-weight:600;">📍 ${esc(
                      dev.location || dev.subnet || 'Office LAN'
                    )}</span>
                  </div>
                  <h3 style="margin:4px 0 2px 0; font-size:1.05rem; font-weight:800; color:var(--text-main);">
                    ${esc(dev.name)} — <span style="color:${
            isDown ? 'var(--accent-red)' : 'var(--accent-amber)'
          };">${esc(diagTitle)}</span>
                  </h3>
                </div>
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                  ${
                    dev.id
                      ? `<button type="button" class="btn btn-primary btn-xs" onclick="probeMonitoredDevice('${esc(
                          dev.id
                        )}')">⚡ Re-Probe Now</button>`
                      : ''
                  }
                  <button type="button" class="btn btn-secondary btn-xs" onclick="scanDevicePorts('${esc(
                    dev.ip
                  )}', '${esc(dev.name)}')">🛡️ Nmap Port Audit</button>
                  <button type="button" class="btn btn-secondary btn-xs" onclick="quickTraceDevice('${esc(
                    dev.ip
                  )}')">🚀 Traceroute</button>
                </div>
              </div>

              <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:12px; margin-top:8px;">
                <div style="background:var(--bg-card); border:1px solid var(--border-subtle); border-radius:10px; padding:11px 14px;">
                  <div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--text-dim); font-weight:800; margin-bottom:4px;">
                    🔍 What Went Wrong
                  </div>
                  <div style="font-size:0.84rem; font-weight:800; color:${
                    isDown ? 'var(--accent-red)' : 'var(--accent-amber)'
                  }; margin-bottom:4px;">
                    Main Cause: ${esc(likelyFault)}
                  </div>
                  <p style="font-size:0.81rem; color:var(--text-main); margin:0; line-height:1.45;">
                    ${esc(diagSummary)}
                  </p>
                  <div style="margin-top:8px; font-size:0.75rem; color:var(--text-muted); display:flex; gap:12px; flex-wrap:wrap;">
                    <span><strong>Check Method:</strong> ${esc(
                      dev.probeMethod || 'Network + Ping Check'
                    )}</span>
                    <span><strong>Dropped Data:</strong> ${
                      dev.packetLossPct ?? 100
                    }%</span>
                    <span><strong>Last Checked:</strong> ${esc(
                      fmtTime(dev.lastSeen)
                    )}</span>
                  </div>
                </div>

                <div style="background:var(--bg-card); border:1px solid var(--border-subtle); border-radius:10px; padding:11px 14px;">
                  <div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--accent-cyan); font-weight:800; margin-bottom:6px;">
                    🛠️ How to Fix It
                  </div>
                  <ol style="margin:0; padding-left:18px; font-size:0.81rem; color:var(--text-main); line-height:1.5;">
                    ${steps.map(step => `<li style="margin-bottom:3px;">${esc(step)}</li>`).join('')}
                  </ol>
                </div>
              </div>
            </div>
          `;
        })
        .join('');
    }
  }

  // Render Subnet-by-Subnet Infrastructure Communication Matrix
  const matrixEl = document.getElementById('infraSubnetMatrix');
  if (!matrixEl) return;

  let matrixRows = list;
  if (currentTriageMatrixFilter === 'issues') {
    matrixRows = impacted;
  } else if (currentTriageMatrixFilter === 'switch') {
    matrixRows = list.filter(d =>
      ['switch', 'gateway', 'router'].includes(String(d.type).toLowerCase())
    );
  } else if (currentTriageMatrixFilter === 'ap') {
    matrixRows = list.filter(d => String(d.type).toLowerCase() === 'ap');
  }

  if (matrixRows.length === 0) {
    matrixEl.innerHTML = `
      <div style="padding:18px; text-align:center; color:var(--text-muted); font-size:0.84rem;">
        No devices match the selected filter.
      </div>
    `;
    return;
  }

  matrixEl.innerHTML = `
    <div class="device-list-table-wrap" style="max-height: 390px; overflow-y: auto;">
      <table class="device-list-table">
        <thead>
          <tr>
            <th>Device &amp; Area</th>
            <th>Device Type</th>
            <th>IP Address</th>
            <th>Hardware Address</th>
            <th>Connection Method</th>
            <th>Speed &amp; Stability</th>
            <th>Connection Status</th>
            <th>Status / Quick Actions</th>
          </tr>
        </thead>
        <tbody>
          ${matrixRows
            .map(dev => {
              const isDown =
                dev.status === 'offline' || dev.connectivityState === 'DEVICE_DOWN';
              const isNoNet = dev.connectivityState === 'ONLINE_NO_INTERNET';
              const t = String(dev.type || 'ap').toLowerCase();
              const roleBadge =
                t === 'gateway'
                  ? '<span class="status-pill new" style="font-size:0.7rem;">🌐 Main Router</span>'
                  : t === 'router'
                  ? '<span class="status-pill new" style="font-size:0.7rem;">🌐 Router</span>'
                  : t === 'switch'
                  ? '<span class="status-pill new" style="font-size:0.7rem;">🔀 Network Switch</span>'
                  : '<span class="status-pill new" style="font-size:0.7rem;">📡 Wi-Fi AP</span>';

              const netBadge = isDown
                ? '<span class="status-pill offline">🔴 DOWN / OFFLINE</span>'
                : isNoNet
                ? '<span class="status-pill warning">🟠 ON LAN · NO INTERNET</span>'
                : dev.status === 'warning'
                ? '<span class="status-pill warning">🟡 SLOW / UNSTABLE</span>'
                : '<span class="status-pill online">🟢 ONLINE · INTERNET OK</span>';

              const portsInfo =
                dev.openPorts && dev.openPorts.length
                  ? `Web Port ${dev.openPorts.join(', ')} + Ping`
                  : dev.probeMethod || (isDown ? 'No Response' : 'Ping Reply');

              return `
                <tr style="${
                  isDown
                    ? 'background:var(--row-down-bg);'
                    : isNoNet
                    ? 'background:var(--row-warn-bg);'
                    : ''
                }">
                  <td>
                    <span class="dev-row-title">${esc(dev.name)}</span>
                    <span class="dev-row-sub">${esc(dev.location || dev.subnet)}</span>
                  </td>
                  <td>${roleBadge}</td>
                  <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${esc(
                    dev.ip
                  )}</td>
                  <td class="mono" style="font-size:0.78rem; color:var(--text-muted);">${esc(
                    dev.mac || '—'
                  )}</td>
                  <td class="mono" style="font-size:0.76rem;">${esc(portsInfo)}</td>
                  <td class="mono">
                    ${dev.latencyMs != null ? `${dev.latencyMs} ms` : '—'}
                    <small style="color:var(--text-dim);">(${
                      dev.packetLossPct ?? (isDown ? 100 : 0)
                    }% loss)</small>
                  </td>
                  <td>${netBadge}</td>
                  <td>
                    <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                      <span style="font-size:0.76rem; font-weight:${
                        isDown || isNoNet ? '700' : '400'
                      }; color:${
                        isDown
                          ? 'var(--accent-red)'
                          : isNoNet
                          ? 'var(--accent-amber)'
                          : 'var(--text-muted)'
                      }; max-width:260px;">
                        ${esc(
                          isDown || isNoNet
                            ? dev.likelyFault || 'Check PoE & Cable'
                            : 'Communicating normally'
                        )}
                      </span>
                      <div class="row-actions-group">
                        ${
                          dev.id
                            ? `<button type="button" class="btn btn-secondary btn-xs" onclick="probeMonitoredDevice('${esc(
                                dev.id
                              )}')">⚡ Probe</button>`
                            : ''
                        }
                        <button type="button" class="btn btn-secondary btn-xs" onclick="scanDevicePorts('${esc(
                          dev.ip
                        )}', '${esc(dev.name)}')">🛡️ Ports</button>
                      </div>
                    </div>
                  </td>
                </tr>
              `;
            })
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

