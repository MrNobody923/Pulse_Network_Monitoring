// Pulse Network Monitor — Alerts Operations Center & Section 1 Router Cables/Ports

function setAlertFilter(filter) {
  currentAlertFilter = filter;
  document.querySelectorAll('#alertFilterTabs .filter-tab').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-filter') === filter);
  });
  renderAlertsCenter();
}

function handleAlertSearch(val) {
  currentAlertSearch = String(val || '').trim().toLowerCase();
  renderAlertsCenter();
}

function renderAlertsCenter() {
  const alerts = appState.activeAlerts || [];
  const stats = appState.alertStats || {};
  const critCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const warnCount = alerts.filter(a => a.severity === 'WARNING').length;
  const ackCount = alerts.filter(a => a.status === 'ACKNOWLEDGED').length;

  const setTxt = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  setTxt('opsCritVal', critCount);
  setTxt('opsWarnVal', warnCount);
  setTxt('opsAckVal', ackCount);
  setTxt('opsResVal', stats.resolvedCount ?? 0);
  setTxt('filtCountAll', alerts.length);
  setTxt('filtCountCrit', critCount);
  setTxt('filtCountWarn', warnCount);

  const badge = document.getElementById('notifCountBadge');
  if (badge) {
    badge.textContent = `${alerts.length} Active`;
    badge.className = `status-pill ${
      critCount > 0 ? 'offline' : alerts.length > 0 ? 'warning' : 'online'
    }`;
  }

  const healthEl = document.getElementById('opsHealthFeedback');
  if (healthEl) {
    if (critCount > 0) {
      healthEl.textContent = `${critCount} CRITICAL OUTAGE`;
      healthEl.style.color = 'var(--accent-red)';
    } else if (warnCount > 0) {
      healthEl.textContent = `${warnCount} DEGRADED WARNING`;
      healthEl.style.color = 'var(--accent-amber)';
    } else {
      healthEl.textContent = '100% HEALTHY';
      healthEl.style.color = 'var(--accent-green)';
    }
  }

  let filtered = alerts;
  if (currentAlertFilter === 'critical')
    filtered = alerts.filter(a => a.severity === 'CRITICAL');
  else if (currentAlertFilter === 'warning')
    filtered = alerts.filter(a => a.severity === 'WARNING');
  else if (currentAlertFilter === 'router')
    filtered = alerts.filter(a => a.category === 'router');
  else if (currentAlertFilter === 'isp')
    filtered = alerts.filter(a => a.category === 'isp');
  else if (currentAlertFilter === 'ap')
    filtered = alerts.filter(a => a.category === 'device');
  else if (currentAlertFilter === 'ack')
    filtered = alerts.filter(a => a.status === 'ACKNOWLEDGED');

  if (currentAlertSearch) {
    filtered = filtered.filter(
      a =>
        (a.title && a.title.toLowerCase().includes(currentAlertSearch)) ||
        (a.message && a.message.toLowerCase().includes(currentAlertSearch)) ||
        (a.ip && a.ip.toLowerCase().includes(currentAlertSearch)) ||
        (a.errorCode && a.errorCode.toLowerCase().includes(currentAlertSearch))
    );
  }

  const emptyEl = document.getElementById('emptyAlertsState');
  const listEl = document.getElementById('alertItemsList');
  if (!listEl || !emptyEl) return;

  if (filtered.length === 0) {
    emptyEl.style.display = 'flex';
    listEl.innerHTML = '';
    return;
  }

  emptyEl.style.display = 'none';
  listEl.innerHTML = filtered
    .map(alert => {
      const isCrit = alert.severity === 'CRITICAL';
      const isInfo = alert.severity === 'INFO';
      const catLabel =
        alert.category === 'gaming'
          ? '🎮 Mobile Game Opened'
          : alert.category === 'router'
          ? '🔌 Router Cable'
          : alert.category === 'isp'
          ? '🌐 Internet WAN'
          : alert.type === 'HIGH_LATENCY_PACKET_LOSS'
          ? '🟡 Slow / Loss'
          : '📡 Offline Device';
      const fails = alert.consecutiveFailures && alert.consecutiveFailures > 1
        ? `<span class="status-pill new">Failed ${alert.consecutiveFailures}x</span>`
        : '';
      const lastProbe = alert.lastProbeResult
        ? `<div style="margin-top:6px; font-size:0.76rem; padding:5px 9px; border-radius:6px; background:var(--box-inner-bg); border:1px solid var(--border-subtle); color:var(--text-muted);">
             <strong>Last Re-Test (${esc(alert.lastProbeResult.status || 'CHECKED')}):</strong> ${esc(alert.lastProbeResult.feedback || '')}
             <span class="mono" style="margin-left:6px; color:var(--text-dim);">${esc(fmtTime(alert.lastProbeResult.testedAt))}</span>
           </div>`
        : '';
      const notes = (alert.notes || [])
        .map(
          n =>
            `<div style="font-size:0.76rem; color:var(--text-muted); margin-top:4px;">💬 <strong>${esc(
              n.author
            )}:</strong> ${esc(n.text)}</div>`
        )
        .join('');
      return `
        <div class="alert-item-row ${isCrit ? 'critical' : ''}">
          <div style="flex: 1; min-width: 260px;">
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
              <span class="status-pill ${isCrit ? 'offline' : isInfo ? 'new' : 'warning'}">${esc(
        alert.severity
      )}</span>
              <span class="mono-chip" style="font-size:0.7rem;">${catLabel}</span>
              ${fails}
              <strong>${esc(alert.title)}</strong>
              <code style="font-size:0.75rem; color:var(--accent-cyan);">${esc(
                alert.target || alert.ip || ''
              )}</code>
              ${
                alert.status === 'ACKNOWLEDGED'
                  ? '<span class="status-pill new">ACKNOWLEDGED</span>'
                  : ''
              }
            </div>
            <p style="font-size:0.84rem; color:var(--text-muted);">${esc(
              alert.message
            )}</p>
            ${
              alert.likelyFault
                ? `<p style="font-size:0.78rem; color:var(--accent-amber); font-weight:700; margin-top:4px;">⚡ Cause: ${esc(
                    alert.likelyFault
                  )}</p>`
                : ''
            }
            ${
              Array.isArray(alert.remediation) && alert.remediation.length
                ? `<ul style="margin:4px 0 0 16px; font-size:0.77rem; color:var(--text-dim);">${alert.remediation
                    .map(step => `<li>${esc(step)}</li>`)
                    .join('')}</ul>`
                : alert.solution
                ? `<p style="font-size:0.78rem; color:var(--text-dim); margin-top:4px;">🔧 <strong>Fix:</strong> ${esc(
                    alert.solution
                  )}</p>`
                : ''
            }
            ${lastProbe}
            ${notes}
          </div>
          <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
            <button class="btn btn-secondary btn-xs" onclick="retestAlert('${esc(
              alert.key
            )}', this)">🔄 Re-Test</button>
            <button class="btn btn-secondary btn-xs" onclick="acknowledgeAlert('${esc(
              alert.key
            )}')">👁️ Acknowledge</button>
            <button class="btn btn-secondary btn-xs" onclick="promptAlertNote('${esc(
              alert.key
            )}')">💬 Note</button>
            <button class="btn btn-secondary btn-xs" onclick="dismissAlert('${esc(
              alert.key
            )}')">✕ Dismiss</button>
          </div>
        </div>
      `;
    })
    .join('');
}

async function triggerLiveAlertDrill() {
  try {
    await apiJson('/api/alerts/test-drill', {
      method: 'POST',
      body: JSON.stringify({ type: 'DUPLEX_COLLISION' })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function acknowledgeAllAlerts() {
  try {
    await apiJson('/api/alerts/acknowledge-all', {
      method: 'POST',
      body: JSON.stringify({ technician: 'Network Admin' })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function retestAlert(key, btnEl) {
  const prevText = btnEl ? btnEl.textContent : '';
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.textContent = 'Testing...';
  }
  try {
    await apiJson(`/api/alerts/${encodeURIComponent(key)}/retest`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.textContent = prevText || '🔄 Re-Test';
    }
  }
}

async function acknowledgeAlert(key) {
  try {
    await apiJson(`/api/alerts/${encodeURIComponent(key)}/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ technician: 'Network Admin' })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function promptAlertNote(key) {
  const note = window.prompt('Enter technician diagnostic note:');
  if (!note) return;
  try {
    await apiJson(`/api/alerts/${encodeURIComponent(key)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ author: 'Technician', note })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function dismissAlert(key) {
  try {
    await apiJson(`/api/alerts/${encodeURIComponent(key)}/dismiss`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

// Section 1: Multi-Router Fleet & Cables / Ports
function selectRouterForInspection(ip) {
  appState.selectedRouterIp = ip;
  renderRouterSection();
}

function renderRouterSection() {
  const fleet =
    Array.isArray(appState.routers) && appState.routers.length
      ? appState.routers
      : appState.router
      ? [appState.router]
      : [];
  const router =
    fleet.find(r => r.ip === appState.selectedRouterIp) ||
    appState.router ||
    fleet[0] ||
    {};

  const fleetContainer = document.getElementById('routerFleetContainer');
  if (fleetContainer) {
    if (fleet.length > 0) {
      fleetContainer.innerHTML = `
        <div class="device-list-table-wrap">
          <table class="device-list-table">
            <thead>
              <tr>
                <th style="width: 14%;">Router IP</th>
                <th style="width: 24%;">Router Model &amp; Role</th>
                <th style="width: 12%;">Status</th>
                <th style="width: 11%;">Ping</th>
                <th style="width: 15%;">Open Admin Ports</th>
                <th style="width: 12%;">Details Available</th>
                <th style="width: 12%; text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${fleet
                .map(r => {
                  const isSel = r.ip === router.ip;
                  const online = Boolean(r.reachable);
                  const openPortsStr =
                    Array.isArray(r.openPorts) && r.openPorts.length
                      ? `Web Port ${r.openPorts.join(', ')}`
                      : 'Ping Only';
                  const telLabel = r.telemetryAvailable
                    ? r.snmp && r.snmp.sysDescr
                      ? 'Switch/SNMP Stats'
                      : 'Port & CPU Details'
                    : r.hasToken
                    ? 'Login Expired'
                    : 'Model & Ping OK';
                  const telCls = r.telemetryAvailable ? 'online' : 'new';
                  return `
                    <tr style="${isSel ? 'background: rgba(56, 189, 248, 0.08);' : ''}">
                      <td class="mono" style="color:var(--accent-cyan); font-weight:700;">
                        ${esc(r.ip)}
                        ${isSel ? '<div style="font-size:0.65rem;color:var(--accent-green);">● VIEWING</div>' : ''}
                      </td>
                      <td>
                        <strong>${esc(r.model || `Router (${r.ip})`)}</strong>
                        <div style="font-size:0.72rem; color:var(--text-dim);">${esc(r.role || (r.isPrimary ? 'Main Gateway' : 'Secondary Router'))} · ${esc(String(r.protocol || 'http').toUpperCase())}</div>
                      </td>
                      <td>
                        <span class="status-pill ${online ? 'online' : 'offline'}">${online ? 'ONLINE' : 'OFFLINE'}</span>
                      </td>
                      <td class="mono">${r.latencyMs != null ? `${r.latencyMs} ms` : '—'}</td>
                      <td class="mono" style="font-size:0.76rem;">${esc(openPortsStr)}</td>
                      <td><span class="status-pill ${telCls}" style="font-size:0.66rem;">${esc(telLabel)}</span></td>
                      <td style="text-align: right;">
                        <div class="row-actions-group">
                          <button type="button" class="btn btn-secondary btn-xs" onclick="selectRouterForInspection('${esc(r.ip)}')">Inspect</button>
                          <button type="button" class="btn btn-secondary btn-xs" onclick="openRouterConfigForIp('${esc(r.ip)}')">Settings</button>
                          ${
                            !(typeof appState !== 'undefined' && appState.router && r.ip === appState.router.ip) &&
                            typeof appState !== 'undefined' &&
                            (appState.devices || []).some(d => d.ip === r.ip)
                              ? `<button type="button" class="btn btn-secondary btn-xs" style="color:var(--danger,#ef4444);border-color:rgba(239,68,68,0.35);" onclick="removeRouterFromFleet('${esc(r.ip)}')" title="Remove pulled-out or decommissioned router/AP from fleet">Remove</button>`
                              : ''
                          }
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
    } else {
      fleetContainer.innerHTML = '';
    }
  }

  const modelEl = document.getElementById('routerModelBadge');
  const ipEl = document.getElementById('routerIpText');
  const uptimeEl = document.getElementById('routerUptimeText');

  if (modelEl)
    modelEl.textContent = router.model || 'TP-Link BE3600 (Archer BE230)';
  if (ipEl) ipEl.textContent = router.ip || '192.168.0.1';
  if (uptimeEl) {
    uptimeEl.textContent = router.reachable
      ? `Online & Reachable${router.latencyMs != null ? ` (${router.latencyMs} ms)` : ''}`
      : 'Probing Gateway...';
    uptimeEl.style.color = router.reachable
      ? 'var(--accent-green)'
      : 'var(--accent-amber)';
  }

  const bay = document.getElementById('duplexPortBay');
  if (bay) {
    const ports = router.ports || [];
    bay.innerHTML = ports
      .map((port, idx) => {
        const isUnknown =
          port.status === 'unknown' ||
          (!port.simulation && !router.telemetryAvailable && port.linkStatus === 'unknown');
        const st =
          port.status === 'warning'
            ? 'warning'
            : port.linkStatus === 'disconnected'
            ? 'disconnected'
            : isUnknown
            ? 'unknown'
            : 'optimal';
        const ifName = port.isWan || idx === 0 ? 'Internet Port' : `LAN Port ${idx}`;
        const wanUpOnlyL3 =
          isUnknown && (port.isWan || idx === 0) && router.wanInternetStatus === 'CONNECTED';
        const speedLabel = port.speed
          ? `${port.speed} Mbps`
          : port.linkStatus === 'disconnected'
          ? 'Unplugged'
          : wanUpOnlyL3
          ? 'Internet Active'
          : isUnknown
          ? 'Waiting for login'
          : '1000 Mbps';
        const duplexLabel =
          port.duplex && port.duplex !== 'Unknown'
            ? port.duplex
            : port.linkStatus === 'disconnected'
            ? 'Disconnected'
            : isUnknown
            ? 'Add router login in Settings to see port speed'
            : '1000 Mbps Full Speed';
        const ledClass =
          st === 'optimal'
            ? 'green'
            : st === 'warning'
            ? 'amber'
            : st === 'disconnected'
            ? 'red'
            : wanUpOnlyL3
            ? 'cyan'
            : 'muted';
        const pillCls =
          st === 'optimal'
            ? 'online'
            : st === 'warning'
            ? 'warning'
            : st === 'disconnected'
            ? 'offline'
            : 'new';
        const pillText =
          st === 'optimal'
            ? 'FULL SPEED'
            : st === 'warning'
            ? 'SLOW CABLE'
            : st === 'disconnected'
            ? 'UNPLUGGED'
            : wanUpOnlyL3
            ? 'INTERNET OK'
            : 'CONNECTED';
        return `
          <div class="port-slot-card ${st}">
            <div class="port-slot-top">
              <span style="display:inline-flex; align-items:center; gap:6px;">
                <span class="nav-led ${ledClass}"></span>
                ${esc(ifName)}
              </span>
              <span class="status-pill ${pillCls}">${pillText}</span>
            </div>
            <div class="port-speed-val">${esc(speedLabel)}</div>
            <div class="port-duplex-val">${esc(duplexLabel)}</div>
            <div class="port-desc-val">${esc(port.label || port.name)} · ${esc(port.description || '')}</div>
          </div>
        `;
      })
      .join('');
  }

  const cpuPct = router.cpu && router.cpu.loadPct != null ? router.cpu.loadPct : null;
  const memPct = router.memory && router.memory.usagePct != null ? router.memory.usagePct : null;
  const cpuText = document.getElementById('cpuValText');
  const cpuFill = document.getElementById('cpuMeterFill');
  const memText = document.getElementById('memValText');
  const memFill = document.getElementById('memMeterFill');

  if (cpuText) {
    cpuText.textContent = cpuPct != null ? `${cpuPct}% (Normal)` : '— (Add router login token in Settings)';
  }
  if (cpuFill) cpuFill.style.width = `${cpuPct != null ? cpuPct : 0}%`;
  if (memText) {
    memText.textContent = memPct != null ? `${memPct}% (Stable)` : '— (Add router login token in Settings)';
  }
  if (memFill) memFill.style.width = `${memPct != null ? memPct : 0}%`;
}

async function simulatePort(portIndex, speed, duplex, linkStatus) {
  try {
    const fleet = Array.isArray(appState.routers) ? appState.routers : [];
    const activeRouter = fleet.find(r => r.ip === appState.selectedRouterIp) || appState.router || {};
    await apiJson('/api/router/simulate', {
      method: 'POST',
      body: JSON.stringify({
        ip: activeRouter.ip || undefined,
        portIndex,
        speed,
        duplex,
        linkStatus
      })
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

