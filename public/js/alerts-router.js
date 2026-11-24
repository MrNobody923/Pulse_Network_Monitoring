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
  const liveAlerts = alerts.filter(a => !a.isDrill);

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
    const liveCritical = liveAlerts.filter(a => a.severity === 'CRITICAL').length;
    const liveWarnings = liveAlerts.filter(a => a.severity === 'WARNING').length;
    if (liveCritical > 0) {
      healthEl.textContent = `${liveCritical} CRITICAL`;
      healthEl.style.color = 'var(--accent-red)';
    } else if (liveWarnings > 0) {
      healthEl.textContent = `${liveWarnings} WARNING${liveWarnings === 1 ? '' : 'S'}`;
      healthEl.style.color = 'var(--accent-amber)';
    } else {
      healthEl.textContent = liveAlerts.length ? 'NO CRITICAL OR WARNING ALERTS' : 'NO ACTIVE NETWORK ALERTS';
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
    emptyEl.querySelector('h4').textContent = alerts.length ? 'No alerts match this view' : 'No active alerts';
    renderDashboardControls(listEl, '');
    return;
  }

  emptyEl.style.display = 'none';
  const renderAlert = alert => {
      const isCrit = alert.severity === 'CRITICAL';
      const isInfo = alert.severity === 'INFO';
      const catLabel = alert.isDrill ? 'Simulation'
          : alert.verificationUnavailable
          ? 'Unconfirmed'
          : alert.category === 'gaming'
          ? '🎮 Mobile Game Opened'
          : alert.category === 'router'
          ? '🔌 Router Cable'
          : alert.category === 'isp'
          ? '🌐 Internet WAN'
          : alert.type === 'HIGH_LATENCY_PACKET_LOSS'
          ? '🟡 Slow / Loss'
          : 'No probe reply';
      const fails = !alert.verificationUnavailable && alert.consecutiveFailures && alert.consecutiveFailures > 1
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
            ${alert.lastChecked ? `<p class="gateway-note">Last checked ${esc(fmtTime(alert.lastChecked))}</p>` : ''}
            ${
              alert.likelyFault
                ? `<p style="font-size:0.78rem; color:var(--accent-amber); font-weight:700; margin-top:4px;">Possible cause: ${esc(
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
            <button type="button" class="btn btn-secondary btn-xs" onclick="openIncident(${inlineString(alert.key)})">Incident details</button>
            ${alert.isDrill ? '' : `<button class="btn btn-secondary btn-xs" onclick="retestAlert(${inlineString(
              alert.key
            )}, this)">🔄 Re-Test</button>`}
            <button class="btn btn-secondary btn-xs" onclick="acknowledgeAlert(${inlineString(
              alert.key
            )})">👁️ Acknowledge</button>
            <button class="btn btn-secondary btn-xs" onclick="promptAlertNote(${inlineString(
              alert.key
            )})">💬 Note</button>
            <button class="btn btn-secondary btn-xs" onclick="dismissAlert(${inlineString(
              alert.key
            )}, this)">✕ Dismiss</button>
          </div>
        </div>
      `;
  };
  const groups = new Map();
  for (const alert of filtered) {
    const upstream = alert.upstreamIncident;
    if (!upstream) continue;
    if (!groups.has(upstream.key)) groups.set(upstream.key, {upstream, children: []});
    groups.get(upstream.key).children.push(alert);
  }
  const visibleByKey = new Map(filtered.map(alert => [alert.key, alert]));
  const renderedGroups = new Set();
  const markup = filtered.map(alert => {
    const groupKey = alert.upstreamIncident?.key || alert.key;
    const group = groups.get(groupKey);
    if (!group) return renderAlert(alert);
    if (renderedGroups.has(groupKey)) return '';
    renderedGroups.add(groupKey);
    const root = visibleByKey.get(groupKey);
    const count = group.children.length;
    return `<section class="upstream-incident" aria-label="Upstream outage group">
      <h3>Possible upstream cause · ${esc(group.upstream.name)} (${esc(group.upstream.ip)})</h3>
      ${root ? renderAlert(root) : '<p class="gateway-note">The upstream alert is outside this filter.</p>'}
      <p class="gateway-note">${count} downstream ${count === 1 ? 'alert' : 'alerts'} linked by confirmed dependencies</p>
      ${group.children.map(renderAlert).join('')}
    </section>`;
  }).join('');
  renderDashboardControls(listEl, markup);
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

async function acknowledgeAllAlerts(btnEl) {
  const btn = btnEl || document.getElementById('btnDismissAll');
  const prevText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Acknowledging...';
  }
  try {
    const res = await apiJson('/api/alerts/acknowledge-all', {
      method: 'POST',
      body: JSON.stringify({ technician: 'Network Admin' })
    });
    if (res && Array.isArray(res.active)) {
      appState.activeAlerts = res.active;
      renderAlertsCenter();
    }
    await loadInitialState();
    if (btn) {
      btn.textContent = '✓ All Acknowledged';
      setTimeout(() => {
        btn.textContent = prevText || '👁️ Acknowledge All';
      }, 2000);
    }
  } catch (err) {
    if (btn) btn.textContent = prevText || '👁️ Acknowledge All';
    alert(err.message);
  } finally {
    if (btn) btn.disabled = false;
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

async function dismissAlert(key, btnEl) {
  if (btnEl) btnEl.disabled = true;
  try {
    await apiJson(`/api/alerts/${encodeURIComponent(key)}/dismiss`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    appState.activeAlerts = (appState.activeAlerts || []).filter(a => a.key !== key);
    renderAlertsCenter();
    await loadInitialState();
  } catch (err) {
    if (btnEl) btnEl.disabled = false;
    alert(err.message);
  }
}

function renderGatewayHealth() {
  const isp = appState.isp || {};
  const gateway = appState.router || {};
  const wan = isp.routerWanThroughput;
  const pc = isp.liveThroughput;
  const fresh = (sample, maxAge) => sample && Date.now() - Date.parse(sample) < maxAge;
  const probeFresh = fresh(isp.probeTimestamp, 30000);
  const wanFresh = wan?.status === 'live' && wan.routerIp === gateway.ip && fresh(wan.timestamp, 8000);
  const pcFresh = fresh(pc?.timestamp, 6000);
  const measures = (fields) => fields.filter(([value]) => Number.isFinite(value))
    .map(([value, suffix]) => `${value}${suffix}`).join(' · ');
  const set = (id, text) => { document.getElementById(id).textContent = text || 'Unavailable'; };
  const external = probeFresh ? (isp.probes || []).filter(probe => probe.id !== 'gateway') : [];
  const replies = external.filter(probe => probe.alive === true).length;
  const pingMatches = probeFresh && gateway.ip && isp.wanGatewayIp === gateway.ip;
  const signal = pcFresh ? pc.wifiSignal : null;
  const ports = fresh(gateway.lastChecked, 90000) ? (gateway.ports || []).filter(port => !port.simulation) : [];
  const wanPort = ports.find(port => port.isWan);
  const link = wan?.routerIp === gateway.ip && fresh(wan?.physicalLink?.timestamp, 25000) ? wan.physicalLink : null;
  const lanPorts = ports.filter(port => !port.isWan);
  const lanUp = lanPorts.filter(port => port.linkStatus === 'connected').length;
  const lanDown = lanPorts.filter(port => port.linkStatus === 'disconnected').length;
  set('gatewayConnectionStatus', !gateway.lastChecked ? 'Waiting for the first gateway check.'
    : !gateway.reachable ? 'The gateway did not respond to the latest check.'
    : gateway.authenticated ? 'Gateway reachable. Router admin connected.'
    : gateway.hasToken || gateway.hasPassword
      ? 'Gateway reachable. Router admin session unavailable. Check the connection in router settings.'
      : 'Gateway reachable. Connect the router in Settings for supported client and port readings.');
  set('gatewayWanStatus', external.length
    ? `${replies ? 'Reachable' : 'No replies'} · ${replies}/${external.length} internet probes` : null);
  set('gatewayWanTraffic', wanFresh ? `↓ ${fmtMbps(wan.rxMbps)} · ↑ ${fmtMbps(wan.txMbps)}` : null);
  set('gatewayWanQuality', external.length ? measures([
    [isp.tier1LatencyMs, ' ms latency'], [isp.packetLossPct, '% loss'], [isp.jitterMs, ' ms jitter'],
  ]) : null);
  set('gatewayWanLink', wanPort?.linkStatus === 'connected'
    ? (wanPort.speed ? `Up · ${wanPort.speed} Mbps` : 'Up')
    : wanPort?.linkStatus === 'disconnected' ? 'Down'
    : link ? `${{up: 'Up', down: 'Down', initializing: 'Initializing'}[link.status]} · Router UPnP` : null);
  set('gatewayLanStatus', pingMatches && typeof isp.wanGatewayReachable === 'boolean'
    ? isp.wanGatewayReachable ? ['Reachable', measures([[isp.wanGatewayLatencyMs, ' ms']])].filter(Boolean).join(' · ') : 'No reply'
    : null);
  set('gatewayLanLink', pcFresh && Number.isFinite(pc.linkSpeedMbps) ? `${pc.linkSpeedMbps} Mbps · ${pc.source}` : null);
  set('gatewayLanSignal', signal && measures([[signal.signalPercent, '%'], [signal.rssiDbm, ' dBm']]));
  set('gatewayLanPorts', lanUp || lanDown
    ? `${lanUp} up · ${lanDown} down${lanPorts.length > lanUp + lanDown ? ` · ${lanPorts.length - lanUp - lanDown} unknown` : ''}`
    : null);
}

function renderGatewayClients() {
  const gateway = appState.router || {};
  const input = document.getElementById('gatewayClientSearch');
  const query = input.value.trim().toLowerCase();
  const source = gateway.routerClientSource;
  const reported = Array.isArray(gateway.routerClients) && Date.now() - Date.parse(gateway.lastChecked) < 90000;
  const clients = reported ? gateway.routerClients : (appState.networkInventory || []).filter(row => row.isOnline && !row.archived);
  const rules = (appState.gameActivity?.blocks || []).filter(rule =>
    rule.active && rule.scope === 'device_wifi_cut' && rule.controlStatus);
  const enabled = reported && source === 'router' && gateway.denyListEnabled === true;
  const visible = clients.filter(row => [row.name, row.ip, row.observedMac ?? row.mac].some(value =>
    String(value ?? '').toLowerCase().includes(query)));
  document.getElementById('gatewayClientSource').textContent = reported
    ? `${clients.length} ${source === 'dhcp' ? 'router DHCP leases' : 'router-reported clients'} · ${fmtTime(gateway.lastChecked)}`
    : `${clients.length} previously observed in LAN inventory. Connect the router admin session for its client list.`;
  document.getElementById('gatewayAccessStatus').textContent = enabled
    ? 'Device blocks use the router’s deny list.'
    : !reported ? 'Access control requires the router admin session.'
    : gateway.denyListEnabled === false ? 'Enable deny-list mode in the router to use device blocks here.'
    : 'The router did not confirm deny-list access.';
  const results = document.getElementById('gatewayClients');
  const table = visible.length ? `<div class="device-list-table-wrap gateway-client-table">
    <table class="device-list-table">
      <thead><tr><th scope="col">Device</th><th scope="col">Address</th>${enabled ? '<th scope="col">Access</th>' : ''}</tr></thead>
      <tbody>${visible.map(row => {
        const mac = row.observedMac ?? row.mac;
        const restricted = rules.some(rule => rule.mac === row.mac || rule.ip === row.ip);
        return `<tr><td><strong>${esc(row.name || row.ip)}</strong>${!reported ? `<small>${esc(fmtTime(row.lastSeen))}</small>` : ''}</td>
          <td class="mono">${esc(row.ip)}<small>${esc(mac || 'MAC unknown')}</small></td>
          ${enabled ? `<td>${restricted ? 'Restriction recorded' : `<button type="button" class="btn btn-secondary btn-xs"
            onclick="openGatewayBlock(${inlineString(row.ip)}, ${inlineString(row.mac)})">Block access</button>`}</td>` : ''}</tr>`;
      }).join('')}</tbody>
    </table></div>` : `<p class="gateway-note">${query ? 'No matching devices.' : 'No clients reported.'}</p>`;
  if (results.dataset.content !== table) {
    const scrollTop = results.querySelector('.gateway-client-table')?.scrollTop;
    results.innerHTML = table;
    results.dataset.content = table;
    if (scrollTop && !query) results.querySelector('.gateway-client-table')?.scrollTo(0, scrollTop);
  }
  const rulesEl = document.getElementById('gatewayAccessRules');
  const active = rules.length ? `<h4>Device access rules</h4>${rules.map(rule => `<div class="gateway-rule">
    <div><strong>${esc(rule.deviceName || rule.ip)}</strong><small>${esc(rule.ip)} · ${rule.controlStatus === 'active'
      ? `Blocked until ${esc(fmtTime(rule.expiresAt))}` : 'Restoration pending verification'}</small></div>
    <button type="button" class="btn btn-secondary btn-xs" onclick="restoreGatewayAccess(${inlineString(rule.id)}, this)">Restore access</button>
  </div>`).join('')}` : '';
  if (rulesEl.dataset.content !== active) {
    rulesEl.innerHTML = active;
    rulesEl.dataset.content = active;
  }
}

let gatewayBlockTarget;

function openGatewayBlock(ip, mac) {
  const dialog = document.getElementById('gatewayAccessDialog');
  if (dialog.open || document.getElementById('btnSubmitGatewayBlock').disabled) return;
  const gateway = appState.router || {};
  const client = gateway.routerClients?.find(row => row.ip === ip && row.mac === mac);
  if (gateway.routerClientSource !== 'router' || gateway.denyListEnabled !== true || !client) return;
  gatewayBlockTarget = {ip, mac};
  document.getElementById('gatewayAccessTarget').textContent = `${client.name} · ${ip} · ${mac}`;
  document.getElementById('gatewayBlockFeedback').textContent = '';
  document.getElementById('gatewayAccessDuration').value = '15';
  dialog.showModal();
}

async function submitGatewayBlock(event) {
  event.preventDefault();
  const dialog = document.getElementById('gatewayAccessDialog');
  const feedback = document.getElementById('gatewayBlockFeedback');
  const button = document.getElementById('btnSubmitGatewayBlock');
  if (!gatewayBlockTarget || button.disabled) return;
  button.disabled = true;
  feedback.textContent = 'Verifying the router rule…';
  try {
    const durationMinutes = Number(document.getElementById('gatewayAccessDuration').value);
    const result = await apiJson('/api/router/access/block', {
      method: 'POST', body: JSON.stringify({...gatewayBlockTarget, durationMinutes}),
    });
    applyGameActivitySnapshot(result.gameActivity);
    renderGatewayClients();
    if (result.success) {
      dialog.close();
      document.getElementById('gatewayRestoreFeedback').textContent = `Router confirmed the block until ${fmtTime(result.expiresAt)}.`;
    } else {
      feedback.textContent = result.error || result.enforcementDetails?.setupHint || 'Router did not confirm the block.';
    }
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function restoreGatewayAccess(ruleId, button) {
  button.disabled = true;
  const feedback = document.getElementById('gatewayRestoreFeedback');
  feedback.textContent = 'Verifying restoration…';
  try {
    const result = await apiJson('/api/router/access/restore', {method: 'POST', body: JSON.stringify({ruleId})});
    applyGameActivitySnapshot(result.gameActivity);
    renderGatewayClients();
    feedback.textContent = result.success ? 'Router confirmed access was restored.' : result.error;
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function refreshMainGateway() {
  const button = document.getElementById('btnRefreshGateway');
  const status = document.getElementById('gatewayRefreshStatus');
  button.disabled = true;
  status.textContent = 'Checking main gateway…';
  try {
    const data = await apiJson('/api/router/refresh', {method: 'POST', body: '{}'});
    appState.router = data.router;
    appState.routers = data.routers;
    renderRouterSection();
    status.textContent = `Checked ${fmtTime(data.router.lastChecked)}.`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

// Multi-router fleet and Ethernet ports
function selectRouterForInspection(ip) {
  appState.selectedRouterIp = ip;
  renderRouterSection();
}

function renderRouterSection() {
  renderGatewayHealth();
  renderGatewayClients();
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
      renderDashboardControls(fleetContainer, `
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
                    : !r.lastChecked ? 'Awaiting check'
                    : !online ? 'Unavailable'
                    : r.authenticated ? 'Hardware readings unavailable'
                    : 'Router admin disconnected';
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
                          <button type="button" class="btn btn-secondary btn-xs" onclick="selectRouterForInspection(${inlineString(r.ip)})">Inspect</button>
                          <button type="button" class="btn btn-secondary btn-xs" onclick="openRouterConfigForIp(${inlineString(r.ip)})">Settings</button>
                          ${
                            !(typeof appState !== 'undefined' && appState.router && r.ip === appState.router.ip) &&
                            typeof appState !== 'undefined' &&
                            (appState.devices || []).some(d => d.ip === r.ip)
                              ? `<button type="button" class="btn btn-secondary btn-xs" style="color:var(--danger,#ef4444);border-color:rgba(239,68,68,0.35);" onclick="removeRouterFromFleet(${inlineString(r.ip)})" title="Remove pulled-out or decommissioned router/AP from fleet">Remove</button>`
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
      `);
    } else {
      renderDashboardControls(fleetContainer, '');
    }
  }

  const modelEl = document.getElementById('routerModelBadge');
  const ipEl = document.getElementById('routerIpText');
  const uptimeEl = document.getElementById('routerUptimeText');

  if (modelEl)
    modelEl.textContent = router.model || 'Router model unavailable';
  if (ipEl) ipEl.textContent = router.ip || '—';
  if (uptimeEl) {
    uptimeEl.textContent = router.reachable
      ? `Online & Reachable${router.latencyMs != null ? ` (${router.latencyMs} ms)` : ''}`
      : router.lastChecked ? 'No reply from router' : 'Waiting for router check';
    uptimeEl.style.color = router.reachable
      ? 'var(--accent-green)'
      : 'var(--accent-amber)';
  }

  const bay = document.getElementById('duplexPortBay');
  if (bay) {
    const ports = router.ports || [];
    bay.innerHTML = ports
      .map((port, idx) => {
        const isUnknown = port.linkStatus !== 'connected' && port.linkStatus !== 'disconnected';
        const st =
          port.status === 'warning'
            ? 'warning'
            : port.linkStatus === 'disconnected'
            ? 'disconnected'
            : isUnknown
            ? 'unknown'
            : 'optimal';
        const ifName = port.isWan ? 'WAN' : port.name || `LAN ${idx}`;
        const speedLabel = port.linkStatus === 'connected' && port.speed
          ? `${port.speed} Mbps`
          : port.linkStatus === 'disconnected'
          ? 'Link down'
          : 'Speed unavailable';
        const duplexLabel = isUnknown
          ? router.authenticated ? 'Port readings unavailable' : 'Router admin session required'
          : port.linkStatus === 'connected' && port.duplex && port.duplex !== 'Unknown' ? port.duplex : '';
        const ledClass =
          st === 'optimal'
            ? 'green'
            : st === 'warning'
            ? 'amber'
            : st === 'disconnected'
            ? 'red'
            : 'muted';
        const pillCls =
          st === 'optimal'
            ? 'online'
            : st === 'warning'
            ? 'warning'
            : st === 'disconnected'
            ? 'offline'
            : 'new';
        const pillText = port.simulation ? 'SIMULATED' : isUnknown ? 'UNKNOWN'
          : port.linkStatus === 'connected' ? 'LINK UP' : 'LINK DOWN';
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
    cpuText.textContent = cpuPct != null ? `${cpuPct}%` : 'Unavailable';
  }
  if (cpuFill) cpuFill.style.width = `${cpuPct != null ? cpuPct : 0}%`;
  if (memText) {
    memText.textContent = memPct != null ? `${memPct}%` : 'Unavailable';
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

