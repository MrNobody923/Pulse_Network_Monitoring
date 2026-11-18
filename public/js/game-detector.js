// Pulse Network Monitor — Mobile & Online Game Detector + Real-Time Toast Notifications

let gameActivityFilter = 'active';
let gameActivitySearch = '';
const gameToastTimers = new Map();
const shownGameNotificationIds = new Set();
const seenActiveSessionIds = new Set();
const displayedToastSessionIds = new Set();
let gameBaselineSeeded = false;
let gameAutoPollInFlight = false;
let gameTerminalUserScrolledUp = false;
let gameTerminalHasVisibleRender = false;
let lastGameTerminalSignature = '';

function getGameActivityData() {
  return (
    appState.gameActivity || {
      logs: [],
      blocks: [],
      onlineDevices: [],
      autoScanActive: true,
      summary: {
        activeCount: 0,
        blockedCount: 0,
        totalCount: 0,
        onlineDevicesCount: 0,
        topGame: 'None yet',
        topZone: 'No traffic yet',
        hostDnsServerIp: '192.168.0.224',
        hostDnsPort: 53,
        hostSyslogPort: 514,
        dnsListenerPort: 5354,
        syslogListenerPort: 5140
      },
      catalog: []
    }
  );
}

function setGameActivityFilter(filter) {
  gameActivityFilter = filter || 'all';
  document.querySelectorAll('#gameFilterTabs [data-game-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-game-filter') === gameActivityFilter);
  });
  lastGameTerminalSignature = '';
  renderGamingSection();
}

function handleGameActivitySearch(value) {
  gameActivitySearch = String(value || '').trim().toLowerCase();
  lastGameTerminalSignature = '';
  renderGamingSection();
}

function updateGameNotifyButton() {
  const btn = document.getElementById('btnGameNotify');
  if (!btn) return;
  if (typeof Notification === 'undefined') {
    btn.textContent = 'In-App Alerts: ON';
    btn.disabled = true;
    return;
  }
  if (Notification.permission === 'granted') {
    btn.textContent = 'Desktop Alerts: ON';
  } else if (Notification.permission === 'denied') {
    btn.textContent = 'In-App Alerts: ON';
  } else {
    btn.textContent = 'Enable Desktop Alerts';
  }
}

async function requestGameNotificationPermission() {
  if (typeof Notification === 'undefined') return;
  try {
    await Notification.requestPermission();
  } catch (_) {}
  updateGameNotifyButton();
}

function formatGameTerminalTime(isoStr) {
  if (!isoStr) return '--:--:--';
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return String(isoStr).slice(0, 8);
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function ensureGameTerminalScrollListener(el) {
  if (!el || el.dataset.scrollBound === '1') return;
  el.dataset.scrollBound = '1';
  el.addEventListener('scroll', () => {
    const dist = el.scrollHeight - el.scrollTop - el.clientHeight;
    gameTerminalUserScrolledUp = dist > 40;
  });
}

function scrollGameTerminalToBottom(force = false) {
  const el = document.getElementById('gamingTerminalContainer');
  if (!el) return;
  if (force) gameTerminalUserScrolledUp = false;
  if (!gameTerminalUserScrolledUp) {
    el.scrollTop = el.scrollHeight;
  }
}

function renderActiveGamesLivePanel(activeLogs) {
  const panel = document.getElementById('activeGamesLivePanel');
  if (!panel) return;
  if (!Array.isArray(activeLogs) || !activeLogs.length) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }
  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="game-section-panel amber">
      <div class="game-panel-head">
        <span class="game-panel-title">Active Open Sessions (${activeLogs.length})</span>
        <span class="game-panel-sub">Manual enforcement — choose Throttle Speed to degrade a user's connection or Cut Wi-Fi to disconnect</span>
      </div>
      <div class="game-panel-rows">
        ${activeLogs
          .map(
            item => `
          <div class="game-panel-row">
            <div class="game-row-info">
              <div class="game-row-title">
                <span>${esc(item.gameName)}</span>
                <span class="status-pill warning">Playing</span>
              </div>
              <div class="game-row-sub">
                <strong>${esc(item.deviceName)}</strong> (<span class="mono">${esc(item.ip)}</span>${item.deviceType ? ` · ${esc(item.deviceType)}` : ''}) · Via <strong>${esc(item.connectedTo || 'Main Gateway Router')}</strong>
              </div>
              <div class="game-row-indicator">
                Signal: <span class="mono">${esc(item.matchedIndicator || '—')}</span> · ${esc(item.detectionMethod || 'Network Detection')}
              </div>
            </div>
            <div class="game-row-actions">
              <button type="button" class="btn btn-secondary btn-sm game-btn-danger" onclick="shutOffGameSession('${esc(item.id)}', '${esc(item.ip)}', '${esc(item.gameId)}', 'device_throttle', false)" title="Drop user's internet rate to an unplayable speed">Throttle Speed</button>
              <button type="button" class="btn btn-secondary btn-sm game-btn-warn" onclick="shutOffGameSession('${esc(item.id)}', '${esc(item.ip)}', '${esc(item.gameId)}', 'device_wifi_cut', true)" title="Disconnect device from Wi-Fi / LAN">Cut Wi-Fi</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="dismissGameSession('${esc(item.id)}')">Dismiss</button>
            </div>
          </div>
        `
          )
          .join('')}
      </div>
    </div>
  `;
}

function renderGamingSection() {
  const data = getGameActivityData();
  const logs = data.logs || [];
  const blocks = data.blocks || [];
  const summary = data.summary || {};

  const findRule = item =>
    blocks.find(
      b => (b.ip === item.ip || b.ip === '*') && (b.gameId === item.gameId || b.gameId === '*')
    ) || null;
  const isBlockedLog = item => Boolean(item.isBlocked || findRule(item));

  const seenIds = new Set();
  const deduped = [];
  for (const item of logs) {
    if (!item) continue;
    const key = item.id || `${item.ip}:${item.gameId}:${item.timestamp}`;
    if (seenIds.has(key)) continue;
    seenIds.add(key);
    deduped.push(item);
  }

  const activeUnblockedLogs = deduped.filter(x => x.isActive && !isBlockedLog(x));
  const activeCount = activeUnblockedLogs.length;
  const blockedLogs = deduped.filter(isBlockedLog);
  const blockedRuleRows = [];
  for (const rule of blocks) {
    const hasLog = blockedLogs.some(
      x => (rule.ip === x.ip || rule.ip === '*') && (rule.gameId === x.gameId || rule.gameId === '*')
    );
    if (!hasLog) {
      blockedRuleRows.push({
        id: `rule-${rule.id}`,
        timestamp: rule.createdAt || new Date().toISOString(),
        ip: rule.ip || '*',
        deviceName: rule.deviceName || rule.ip || 'Network Device',
        deviceType: rule.mac ? `MAC ${rule.mac}` : '',
        gameId: rule.gameId || '*',
        gameName: rule.gameName || 'Blocked Access',
        connectedTo: 'Active Restriction Rule',
        matchedIndicator: rule.scope === 'device_wifi_cut' ? 'Wi-Fi Cut Off' : rule.scope === 'device_throttle' ? '1 KB/s Throttle + Lag' : 'Game Block',
        detectionMethod: 'Manual Restriction Rule',
        isActive: false,
        isBlocked: true,
        _ruleRef: rule
      });
    }
  }
  const blockedTabEntries = [...blockedLogs, ...blockedRuleRows];
  const blockedEntryCount = blockedTabEntries.length;
  const totalCount = summary.totalCount ?? deduped.length;
  const onlineCount =
    summary.onlineDevicesCount ??
    (Array.isArray(data.onlineDevices) ? data.onlineDevices.length : 0);

  const setTxt = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  setTxt('gameStatActive', activeCount);
  setTxt('gameStatTotal', totalCount);
  setTxt('gameStatTopGame', summary.topGame || 'None yet');
  setTxt('gameStatTopZone', summary.topZone || 'No traffic yet');
  setTxt('gameTabAllCount', totalCount);
  setTxt('gameTabActiveCount', activeCount);
  setTxt('gameTabBlockedCount', blockedEntryCount);
  renderGameSensorBanner(data, onlineCount);
  renderWiresharkStatusBar(data.wiresharkStatus || {});
  renderGamingPolicyControls(data.policy || {});
  setTxt(
    'gameTerminalPromptText',
    activeCount > 0
      ? `${activeCount} open session(s) detected across ${onlineCount} devices — use Throttle Speed or Cut Wi-Fi to restrict access.`
      : `Watching ${onlineCount} company devices in real time — manual control only (never auto-blocks users).`
  );

  const sideBadge = document.getElementById('sideBadgeGaming');
  if (sideBadge) {
    sideBadge.textContent = activeCount > 0 ? `${activeCount} Live` : String(totalCount);
    sideBadge.className = `side-badge ${activeCount > 0 ? 'amber' : 'cyan'}`;
  }

  const headBadge = document.getElementById('gamingStatusBadge');
  if (headBadge) {
    headBadge.textContent =
      activeCount > 0 ? `${activeCount} Active Session${activeCount > 1 ? 's' : ''}` : 'Watching · Live';
    headBadge.className = `status-pill ${activeCount > 0 ? 'warning' : 'online'}`;
  }

  if (!gameBaselineSeeded) {
    for (const item of logs) {
      if (item && item.id && item.isActive) seenActiveSessionIds.add(item.id);
    }
    gameBaselineSeeded = true;
  }

  updateGameNotifyButton();
  renderActiveGamesLivePanel(activeUnblockedLogs);
  renderGameBlocksPanel(blocks);

  let filtered = deduped;
  if (gameActivityFilter === 'active') {
    filtered = activeUnblockedLogs;
  } else if (gameActivityFilter === 'blocked') {
    filtered = blockedTabEntries;
  }
  if (gameActivitySearch) {
    filtered = filtered.filter(
      x =>
        (x.gameName && x.gameName.toLowerCase().includes(gameActivitySearch)) ||
        (x.deviceName && x.deviceName.toLowerCase().includes(gameActivitySearch)) ||
        (x.ip && x.ip.toLowerCase().includes(gameActivitySearch)) ||
        (x.vendor && x.vendor.toLowerCase().includes(gameActivitySearch)) ||
        (x.connectedTo && x.connectedTo.toLowerCase().includes(gameActivitySearch)) ||
        (x.zoneLabel && x.zoneLabel.toLowerCase().includes(gameActivitySearch)) ||
        (x.matchedIndicator && x.matchedIndicator.toLowerCase().includes(gameActivitySearch)) ||
        (x.detectionMethod && x.detectionMethod.toLowerCase().includes(gameActivitySearch))
    );
  }

  // Keep only the most recent 80 entries, showing newest activity first for clean scannable review
  const capped = filtered.slice(0, 80);
  const ordered = [...capped].sort((a, b) => {
    const ta = new Date(a.timestamp || 0).getTime() || 0;
    const tb = new Date(b.timestamp || 0).getTime() || 0;
    return tb - ta;
  });

  setTxt(
    'gameTerminalShowingCount',
    `${ordered.length} ${ordered.length === 1 ? 'entry' : 'entries'}`
  );

  const container = document.getElementById('gamingTerminalContainer');
  if (!container) return;
  ensureGameTerminalScrollListener(container);

  const prevMode = (data.policy && data.policy.preventionMode) || 'alert_only';
  const ruleSig = blocks.map(b => `${b.id}:${b.ip}:${b.gameId}`).join(',');
  const signature =
    `${gameActivityFilter}|${gameActivitySearch}|${onlineCount}|${prevMode}|${ruleSig}|` +
    ordered.map(x => `${x.id}:${x.timestamp}:${x.isActive}:${x.isBlocked}`).join(',');
  if (signature === lastGameTerminalSignature) {
    return;
  }

  const prevScrollTop = container.scrollTop;
  lastGameTerminalSignature = signature;

  if (!ordered.length) {
    const filterTitle =
      gameActivityFilter === 'blocked'
        ? 'No blocked or throttled devices'
        : gameActivityFilter === 'active'
        ? 'No active game sessions right now'
        : 'No recorded game detections';
    const modeDesc =
      prevMode === 'alert_only'
        ? `Monitoring ${onlineCount} LAN device(s) in real time via DNS, TLS SNI & Wireshark DPI. Switch to All History to inspect past detections.`
        : 'Auto-prevention policy is currently active.';
    container.innerHTML = `
      <div class="game-empty-state">
        <div class="game-empty-title">${esc(filterTitle)}</div>
        <div class="game-empty-sub">${esc(modeDesc)}</div>
      </div>
    `;
    return;
  }

  container.innerHTML = ordered
    .map(item => {
      const activeRuleMatch = item._ruleRef || findRule(item);
      const isBlocked = Boolean(item.isBlocked || activeRuleMatch);
      const rowCls = isBlocked ? 'is-blocked' : item.isActive ? 'is-live' : '';
      const pillCls = isBlocked ? 'critical' : item.isActive ? 'warning' : 'online';
      const sevLabel = isBlocked ? 'Blocked' : item.isActive ? 'Playing' : 'Ended';
      const ts = formatGameTerminalTime(item.timestamp);
      const devType = item.deviceType ? ` · ${item.deviceType}` : '';
      const actionsHtml = activeRuleMatch
        ? `<button type="button" class="btn btn-secondary btn-xs game-btn-restore" onclick="unblockGameRule('${esc(
            activeRuleMatch.id
          )}')">Unblock</button>`
        : `<button type="button" class="btn btn-secondary btn-xs game-btn-danger" onclick="shutOffGameSession('${esc(
            item.id
          )}', '${esc(item.ip)}', '${esc(
            item.gameId
          )}', 'device_throttle', false)" title="Drop user's internet speed to an unplayable rate (Router QoS 1 KB/s + DNS lag + socket reset)">Throttle</button><button type="button" class="btn btn-secondary btn-xs game-btn-warn" onclick="shutOffGameSession('${esc(
            item.id
          )}', '${esc(item.ip)}', '${esc(
            item.gameId
          )}', 'device_wifi_cut', true)" title="Cut Wi-Fi connectivity completely for this device">Cut Wi-Fi</button>${
            item.isActive
              ? `<button type="button" class="btn btn-secondary btn-xs" onclick="dismissGameSession('${esc(
                  item.id
                )}')">Dismiss</button>`
              : ''
          }`;

      return `
        <div class="game-activity-row ${rowCls}">
          <div class="game-col-status">
            <span class="status-pill ${pillCls}">${esc(sevLabel)}</span>
            <span class="game-col-time">${esc(ts)}</span>
          </div>
          <div class="game-col-title">
            <div class="game-title-main" title="${esc(item.gameName)}">${esc(item.gameName)}</div>
            <div class="game-title-method">${esc(item.detectionMethod || 'Network Detection')}</div>
          </div>
          <div class="game-col-device">
            <div class="game-device-main">${esc(item.deviceName)} <span class="mono" style="font-weight:500;">(${esc(item.ip)}${esc(devType)})</span></div>
            <div class="game-device-sub">${esc(item.connectedTo || 'Main Gateway Router')} · Signal: <code>${esc(item.matchedIndicator || '—')}</code></div>
          </div>
          <div class="game-row-actions">${actionsHtml}</div>
        </div>
      `;
    })
    .join('');

  container.scrollTop = prevScrollTop;
}

function renderGameBlocksPanel(blocks) {
  const panel = document.getElementById('gameBlocksPanel');
  if (!panel) return;
  if (!Array.isArray(blocks) || !blocks.length) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }
  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="game-section-panel danger">
      <div class="game-panel-head">
        <span class="game-panel-title">Active Restrictions (${blocks.length})</span>
        <span class="game-panel-sub">Throttled or disconnected devices remain restricted until manually unblocked</span>
      </div>
      <div class="game-panel-rows">
        ${blocks
          .map(
            b => `
          <div class="game-panel-row">
            <div class="game-row-info">
              <div class="game-row-title">
                <span>${esc(b.deviceName || b.ip)}</span>
                <span class="status-pill critical">${b.scope === 'device_wifi_cut' ? 'Wi-Fi Cut Off' : b.scope === 'device_throttle' ? 'Throttled · Unplayable' : 'Blocked'}</span>
              </div>
              <div class="game-row-sub">
                IP: <span class="mono">${esc(b.ip)}</span>${b.mac ? ` · MAC: <span class="mono">${esc(b.mac)}</span>` : ''} · Rule: ${esc(b.gameName)}
              </div>
            </div>
            <div class="game-row-actions">
              ${
                b.ip && b.ip !== '*' && b.scope !== 'device_throttle' && b.scope !== 'device_wifi_cut'
                  ? `<button type="button" class="btn btn-secondary btn-xs game-btn-warn" onclick="shutOffGameSession('', '${esc(
                      b.ip
                    )}', '${esc(b.gameId || '*')}', 'device_throttle', false)">Throttle Speed</button>`
                  : ''
              }
              ${
                b.ip && b.ip !== '*' && b.scope !== 'device_wifi_cut'
                  ? `<button type="button" class="btn btn-secondary btn-xs game-btn-danger" onclick="shutOffGameSession('', '${esc(
                      b.ip
                    )}', '${esc(b.gameId || '*')}', 'device_wifi_cut', true)">Cut Wi-Fi</button>`
                  : ''
              }
              <button type="button" class="btn btn-secondary btn-xs game-btn-restore" onclick="unblockGameRule('${esc(
                b.id
              )}')">Unblock</button>
            </div>
          </div>
        `
          )
          .join('')}
      </div>
    </div>
  `;
}

function dismissGameToast(toastId) {
  const el = document.getElementById(toastId);
  if (el) el.remove();
  if (gameToastTimers.has(toastId)) {
    clearTimeout(gameToastTimers.get(toastId));
    gameToastTimers.delete(toastId);
  }
}

function jumpToGamingWorkspace(toastId) {
  dismissGameToast(toastId);
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('gaming');
  }
}

function renderGameSensorBanner(data, onlineCount) {
  const bar = document.getElementById('gameAutoStatusBar');
  const badge = document.getElementById('gameAutoPulseBadge');
  const line = document.getElementById('gameSensorTelemetryLine');
  const setupBtn = document.getElementById('btnSetupRouterDns');
  const s = data.sensorStatus || {};
  const hostIp = s.dnsHost || (data.summary && data.summary.hostDnsServerIp) || '192.168.0.224';
  const routerIp = s.routerIp || '192.168.0.1';
  const qTotal = Number(s.dnsQueriesTotal || 0);
  const bTotal = Number(s.dnsBlockedTotal || 0);
  const cCount = Number(s.dnsClientsCount || 0);
  const bypass = Array.isArray(s.bypassingExternalDns) ? s.bypassingExternalDns : [];

  if (!s.sensorOnline) {
    if (bar) bar.classList.add('warn');
    if (badge) {
      badge.className = 'status-pill warning';
      badge.textContent = `Sensor Standby · ${onlineCount} Devices`;
    }
    if (line) {
      line.innerHTML = `Host DNS sensor offline — run <code>host_game_sensor.py</code> for live UDP/TCP 53 capture on <code>${esc(hostIp)}</code>.`;
    }
    if (setupBtn) setupBtn.style.display = 'inline-flex';
    return;
  }

  if (s.dnsInterceptReady || cCount > 0) {
    if (bar) bar.classList.remove('warn');
    if (badge) {
      badge.className = 'status-pill online';
      badge.textContent = `Sensor Live · ${cCount} DNS Clients`;
    }
    if (line) {
      const lastDom = s.lastDnsDomain
        ? ` · Latest: <code>${esc(s.lastDnsClientIp || '')}</code> → <code>${esc(s.lastDnsDomain)}</code>`
        : '';
      line.innerHTML = `Host <code>${esc(hostIp)}:53</code>${s.hotspotIp ? ` + <code>${esc(s.hotspotIp)}:53</code>` : ''} · Syslog <code>514</code> · ${qTotal.toLocaleString()} queries · ${bTotal} blocked${lastDom}`;
    }
    if (setupBtn) setupBtn.style.display = 'none';
  } else {
    if (bar) bar.classList.add('warn');
    if (badge) {
      badge.className = 'status-pill warning';
      badge.textContent = `Phone DNS Setup Needed · 0 Phones Routed`;
    }
    if (line) {
      line.innerHTML = bypass.length
        ? `Router (<code>${esc(routerIp)}</code>) DHCP assigns <code>${esc(bypass.join(', '))}</code> so Wi-Fi phones bypass this PC. Set Router DHCP Primary DNS (or your Phone Wi-Fi DNS, with Android Private DNS Off) to <code>${esc(hostIp)}</code> for instant mobile game alerts.`
        : `Set Router DHCP Primary DNS (or your Phone Wi-Fi DNS, with Android Private DNS Off) to <code>${esc(hostIp)}</code> for instant mobile game alerts.`;
    }
    if (setupBtn) setupBtn.style.display = 'inline-flex';
  }
}

function renderGamingPolicyControls(policy) {
  const mode = (policy && policy.preventionMode) || 'alert_only';
  const badge = document.getElementById('gameManualModeBadge');
  const resetBtn = document.getElementById('btnForceManualMode');
  const hint = document.getElementById('gamePolicyHint');
  const isManual = mode === 'alert_only';
  if (badge) {
    badge.className = `status-pill ${isManual ? 'online' : 'warning'}`;
    badge.textContent = isManual ? 'Manual Block Only' : 'Auto-Block Active';
  }
  if (resetBtn) {
    resetBtn.style.display = isManual ? 'none' : 'inline-flex';
  }
  if (!hint) return;
  hint.innerHTML = isManual
    ? 'Manual enforcement mode — scans never auto-block users.'
    : '<strong style="color:var(--accent-amber);">Auto-block is active via policy config.</strong> Click Revert to Manual to restore prompt-only enforcement.';
}

function showGameDetectedToast(detection) {
  if (!detection || !detection.gameName) return;
  if (detection.id) {
    seenActiveSessionIds.add(detection.id);
    if (displayedToastSessionIds.has(detection.id)) return;
    displayedToastSessionIds.add(detection.id);
  }
  const isAuto = Boolean(detection.autoPrevented);
  const container = document.getElementById('gameToastContainer');
  const toastId = `game-toast-${detection.id || Date.now()}`;
  if (container) {
    const existing = document.getElementById(toastId);
    if (existing) existing.remove();
    const card = document.createElement('div');
    card.id = toastId;
    card.className = 'game-toast-card';
    card.innerHTML = `
      <div class="game-toast-head">
        <span class="game-toast-badge">${isAuto ? 'Auto-Prevented' : 'Game Detected'}</span>
        <button type="button" class="game-toast-close" onclick="dismissGameToast('${esc(toastId)}')" aria-label="Close">✕</button>
      </div>
      <div class="game-toast-title">${esc(detection.gameName)}</div>
      <div class="game-toast-meta">
        <div><strong>Device:</strong> ${esc(detection.deviceName)} <span class="mono">(${esc(detection.ip)})</span></div>
        <div><strong>Via:</strong> ${esc(detection.connectedTo)}</div>
        <div class="dev-row-sub">${esc(detection.matchedIndicator || '')} · ${esc(detection.detectionMethod || '')}</div>
      </div>
      <div class="game-toast-actions">
        ${
          isAuto
            ? ''
            : `<button type="button" class="btn btn-secondary btn-xs game-btn-danger" onclick="shutOffGameFromToast('${esc(toastId)}', '${esc(detection.id || '')}', '${esc(detection.ip || '')}', '${esc(detection.gameId || '')}')">Throttle Speed</button>`
        }
        <button type="button" class="btn btn-primary btn-xs" onclick="jumpToGamingWorkspace('${esc(toastId)}')">Inspect</button>
        <button type="button" class="btn btn-secondary btn-xs" onclick="dismissGameToast('${esc(toastId)}')">Dismiss</button>
      </div>
    `;
    container.prepend(card);
    while (container.children.length > 4) {
      container.lastElementChild.remove();
    }
    const timer = setTimeout(() => dismissGameToast(toastId), 12000);
    gameToastTimers.set(toastId, timer);
  }

  const notifKey = `${detection.id || detection.gameId}:${detection.timestamp || ''}`;
  if (
    !shownGameNotificationIds.has(notifKey) &&
    typeof Notification !== 'undefined' &&
    Notification.permission === 'granted'
  ) {
    shownGameNotificationIds.add(notifKey);
    try {
      new Notification(`${detection.gameIcon || '🎮'} ${detection.gameName} opened`, {
        body: `Device: ${detection.deviceName} (${detection.ip})\nConnected To: ${detection.connectedTo}`
      });
    } catch (_) {}
  }
}

async function runLanGameScan() {
  const btn = document.getElementById('btnScanGames');
  const banner = document.getElementById('gameScanResultBanner');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Scanning Network...';
  }
  if (banner) {
    banner.style.display = 'block';
    banner.innerHTML = `<div class="game-scan-banner"><div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;"><span class="status-pill warning">Scanning Topology</span><span style="font-size:0.78rem; color:var(--text-muted);">Polling routers, APs, ARP neighbors, DNS cache &amp; game ports across subnets...</span></div></div>`;
  }
  try {
    const res = await apiJson('/api/gaming/scan', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    const dets = Array.isArray(res.detections) ? res.detections : [];
    if (dets.length) {
      showGameDetectedToast(dets[0]);
      if (dets.some(d => d.isBlocked) && gameActivityFilter === 'active') {
        setGameActivityFilter('blocked');
      }
    }
    if (banner) {
      const nodesCnt = Number(res.topologyNodesScanned || 0);
      const hubsCnt = Number(res.topologyHubsScanned || 0);
      const devCnt = Number(res.scannedDevices || 0);
      const foundCnt = Number(res.confirmedHits ?? res.detectedCount ?? 0);
      const activeCnt = Number(res.activeCount || 0);
      const blockedCnt = Number(res.blockedCount || 0);
      const act = res.gameActivity || getGameActivityData();
      const bypass = (act.sensorStatus && act.sensorStatus.bypassingExternalDns) || [];
      const noteHtml =
        foundCnt > 0 || activeCnt > 0 || blockedCnt > 0
          ? `Scanned ${hubsCnt} router/AP hub(s)${nodesCnt ? ` (${nodesCnt} map nodes)` : ''} &amp; ${devCnt} device(s) — <strong>${foundCnt}</strong> live hit(s) (${activeCnt} active, ${blockedCnt} blocked).`
          : bypass.length && !(act.sensorStatus && act.sensorStatus.dnsInterceptReady)
          ? `Scanned ${hubsCnt} router/AP hub(s) &amp; ${devCnt} device(s). 0 open game ports/processes. External DHCP DNS detected (<code>${esc(bypass.join(', '))}</code>) — configure Wi-Fi DNS interception to capture phone lookups.`
          : `Scanned ${hubsCnt} router/AP hub(s) &amp; ${devCnt} device(s) across the topology — no active games detected.`;
      banner.style.display = 'block';
      banner.innerHTML = `
        <div class="game-scan-banner">
          <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; flex:1;">
            <span class="status-pill ${foundCnt > 0 || activeCnt > 0 ? 'warning' : 'online'}">${foundCnt > 0 ? `Found ${foundCnt} Match(es)` : 'Scan Complete'}</span>
            <span style="font-size:0.78rem; color:var(--text-muted);">${noteHtml}</span>
          </div>
          <button type="button" class="btn btn-secondary btn-xs" onclick="document.getElementById('gameScanResultBanner').style.display='none'">Dismiss</button>
        </div>
      `;
    }
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    if (banner) banner.style.display = 'none';
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Scan Connected Devices Now';
    }
  }
}

async function dismissGameSession(id) {
  try {
    const res = await apiJson('/api/gaming/dismiss', {
      method: 'POST',
      body: JSON.stringify({ id })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function clearGameActivity() {
  if (!window.confirm('Clear all detected mobile/online game history?')) return;
  try {
    const res = await apiJson('/api/gaming/clear', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function shutOffGameSession(
  sessionId,
  ip,
  gameId,
  scope = 'device_throttle',
  cutWifi = false
) {
  const banner = document.getElementById('gameScanResultBanner');
  try {
    const res = await apiJson('/api/gaming/block', {
      method: 'POST',
      body: JSON.stringify({
        sessionId: sessionId || '',
        ip: ip || '',
        gameId: gameId || '',
        scope: scope || 'device_throttle',
        cutWifi: Boolean(cutWifi)
      })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    const det = res.enforcementDetails || null;
    if (banner && det) {
      const hasSetupGap = Boolean(det.requiresSetup && det.setupHint);
      const layerText = Array.isArray(det.layers) && det.layers.length
        ? det.layers.join(' + ')
        : 'Rule Saved';
      banner.style.display = 'block';
      banner.innerHTML = `
        <div class="game-scan-banner">
          <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; flex:1;">
            <span class="status-pill ${hasSetupGap ? 'warning' : 'online'}">${hasSetupGap ? 'Router Setup Needed' : (scope === 'device_throttle' ? 'Connection Throttled' : 'Restriction Applied')}</span>
            <span style="font-size:0.78rem; color:var(--text-muted);">${hasSetupGap ? esc(det.setupHint) : `Active layers for ${esc(ip || 'device')}: <strong>${esc(layerText)}</strong>.`}</span>
          </div>
          ${hasSetupGap && typeof openModal === 'function' ? `<button type="button" class="btn btn-primary btn-xs" onclick="openModal('routerConfigModal')">Router Settings</button>` : ''}
          <button type="button" class="btn btn-secondary btn-xs" onclick="document.getElementById('gameScanResultBanner').style.display='none'">Dismiss</button>
        </div>
      `;
    }
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function shutOffGameFromToast(toastId, sessionId, ip, gameId) {
  dismissGameToast(toastId);
  await shutOffGameSession(sessionId, ip, gameId, 'device_throttle', false);
}

async function unblockGameRule(ruleId) {
  try {
    const res = await apiJson('/api/gaming/unblock', {
      method: 'POST',
      body: JSON.stringify({ ruleId })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function setGamingPolicyMode(preventionMode) {
  try {
    const res = await apiJson('/api/gaming/policy', {
      method: 'POST',
      body: JSON.stringify({ preventionMode })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    renderGamingSection();
  } catch (err) {
    alert(err.message);
  }
}

async function configureRouterGameDns() {
  const btn = document.getElementById('btnSetupRouterDns');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Configuring...';
  }
  try {
    const res = await apiJson('/api/gaming/setup-router-dns', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res && res.requiresRouterLogin && typeof openModal === 'function') {
      alert(res.message);
      openModal('routerConfigModal');
    } else if (res && res.message) {
      alert(res.message);
    }
    await refreshGameActivityAuto();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Setup Wi-Fi DNS';
    }
  }
}

function renderWiresharkStatusBar(ws) {
  const bar = document.getElementById('gameWiresharkBar');
  const badge = document.getElementById('gameWiresharkBadge');
  const sum = document.getElementById('gameWiresharkSummary');
  const strip = document.getElementById('gameWiresharkHitsStrip');
  const toggleBtn = document.getElementById('btnToggleWireshark');
  if (!bar && !badge && !sum) return;

  const s = ws && typeof ws === 'object' ? ws : {};
  const enabled = s.enabled !== false;
  const active = Boolean(s.active && enabled);
  const tsharkOn = Boolean(s.tsharkInstalled);
  const npcapOn = Boolean(s.npcapAvailable);
  const pkts = Number(s.packetsCaptured || 0);
  const matched = Number(s.packetsMatched || 0);
  const tlsCnt = Number(s.tlsSniMatches || 0);
  const dnsCnt = Number(s.dnsMatches || 0);
  const flowCnt = Number(s.portMatches || 0);
  const pcapKB = ((Number(s.pcapBytes || 0)) / 1024).toFixed(1);
  const ifaceCount = Array.isArray(s.selectedInterfaces) ? s.selectedInterfaces.length : 0;

  if (badge) {
    if (!enabled) {
      badge.className = 'status-pill';
      badge.textContent = 'Wireshark · Paused';
    } else if (active) {
      badge.className = 'status-pill online';
      badge.textContent = `Wireshark · ${tsharkOn ? 'TShark Live' : 'Npcap Live'} (${pkts.toLocaleString()} pkts)`;
    } else if (npcapOn || tsharkOn) {
      badge.className = 'status-pill warning';
      badge.textContent = 'Wireshark · Standby';
    } else {
      badge.className = 'status-pill';
      badge.textContent = 'Wireshark · Offline .pcap Mode';
    }
  }
  if (bar) {
    bar.classList.toggle('warn', Boolean(enabled && !active && (npcapOn || tsharkOn)));
  }
  if (toggleBtn) {
    toggleBtn.textContent = enabled ? 'Pause' : 'Resume';
  }
  if (sum) {
    const engineLabel = tsharkOn ? 'TShark' : npcapOn ? 'Npcap (wpcap)' : 'Offline Parser';
    const tzspText = s.tzspActive ? ` · TZSP :${s.tzspPort || 37008}` : '';
    const nicText = ifaceCount > 0 ? ` · ${ifaceCount} NIC(s)` : '';
    sum.innerHTML =
      `${esc(engineLabel)}${esc(nicText)}${esc(tzspText)} · ` +
      `Matched: <strong>${matched}</strong> (SNI ${tlsCnt} · DNS ${dnsCnt} · Flows ${flowCnt}) · ` +
      `<code>${esc(pcapKB)} KB</code>`;
  }
  if (strip) {
    const hits = Array.isArray(s.recentHits) ? s.recentHits.slice(0, 2) : [];
    const lastA = s.lastAnalyze;
    const parts = [];
    if (hits.length) {
      parts.push(
        `<strong>Recent DPI Hits:</strong> ` +
          hits
            .map(
              h =>
                `<span class="mono">[${esc(h.protocol || 'DPI')}]</span> ${esc(h.ip)} → <code>${esc(
                  h.matchedIndicator || h.gameName
                )}</code>`
            )
            .join(' · ')
      );
    }
    if (lastA && lastA.filename) {
      parts.push(
        `<strong>Analyzed:</strong> <code>${esc(lastA.filename)}</code> (${Number(
          lastA.packetsParsed || 0
        )} pkts, <strong>${Number(lastA.uniqueMatches || 0)}</strong> match(es))`
      );
    }
    if (parts.length) {
      strip.style.display = 'block';
      strip.innerHTML = parts.join('<br>');
    } else {
      strip.style.display = 'none';
      strip.innerHTML = '';
    }
  }
}

async function toggleWiresharkCapture() {
  const ws = (getGameActivityData() && getGameActivityData().wiresharkStatus) || {};
  const nextEnabled = ws.enabled === false;
  try {
    const res = await apiJson('/api/gaming/wireshark/config', {
      method: 'POST',
      body: JSON.stringify({ enabled: nextEnabled })
    });
    if (res && res.wiresharkStatus && appState.gameActivity) {
      appState.gameActivity.wiresharkStatus = res.wiresharkStatus;
    }
    await refreshGameActivityAuto();
  } catch (err) {
    alert(err.message);
  }
}

async function copyWiresharkDisplayFilter() {
  const ws = (getGameActivityData() && getGameActivityData().wiresharkStatus) || {};
  const filter = String(ws.displayFilter || 'dns or tls.handshake.type == 1');
  const btn = document.getElementById('btnCopyWiresharkFilter');
  try {
    await navigator.clipboard.writeText(filter);
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => {
        btn.textContent = prev;
      }, 2000);
    }
  } catch (_) {
    window.prompt('Copy Wireshark Display Filter:', filter);
  }
}

function triggerWiresharkPcapImport() {
  const inp = document.getElementById('wiresharkPcapFileInput');
  if (inp) inp.click();
}

async function handleWiresharkPcapUpload(input) {
  const file = input && input.files && input.files[0];
  if (!file) return;
  const banner = document.getElementById('gameScanResultBanner');
  try {
    if (file.size > 11 * 1024 * 1024) {
      alert('Please upload a .pcap or .pcapng capture smaller than 11 MB.');
      return;
    }
    if (banner) {
      banner.style.display = 'block';
      banner.innerHTML = `<div class="game-scan-banner"><div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;"><span class="status-pill warning">Analyzing Capture</span><span style="font-size:0.78rem; color:var(--text-muted);">Dissecting DNS, TLS SNI, HTTP &amp; UDP/TCP game packets from <code>${esc(file.name)}</code>...</span></div></div>`;
    }
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let bin = '';
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    const dataBase64 = btoa(bin);
    const res = await apiJson('/api/gaming/wireshark/analyze', {
      method: 'POST',
      body: JSON.stringify({ filename: file.name, dataBase64, ingest: true })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    if (banner) {
      banner.style.display = 'block';
      banner.innerHTML = `
        <div class="game-scan-banner">
          <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; flex:1;">
            <span class="status-pill ${res.uniqueMatches > 0 ? 'warning' : 'online'}">${esc(file.name)}</span>
            <span style="font-size:0.78rem; color:var(--text-muted);">Parsed <strong>${Number(res.packetsParsed || 0)}</strong> packets — found <strong>${Number(res.uniqueMatches || 0)}</strong> match(es) (${Number(res.detectionsLogged || 0)} active session(s)).</span>
          </div>
          <button type="button" class="btn btn-secondary btn-xs" onclick="document.getElementById('gameScanResultBanner').style.display='none'">Dismiss</button>
        </div>
      `;
    }
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    if (banner) banner.style.display = 'none';
    alert(err.message);
  } finally {
    input.value = '';
  }
}

function notifyUnseenActiveGames(activity) {
  if (!activity || !Array.isArray(activity.logs) || !gameBaselineSeeded) return;
  const activeLogs = activity.logs.filter(x => x && x.isActive && !x.isBlocked);
  for (const item of activeLogs) {
    if (item.id && !seenActiveSessionIds.has(item.id)) {
      seenActiveSessionIds.add(item.id);
      showGameDetectedToast(item);
    }
  }
}

let gamePollCounter = 0;

async function refreshGameActivityAuto() {
  if (gameAutoPollInFlight || document.hidden) return;
  gamePollCounter += 1;
  const gSection = document.getElementById('gamingSection');
  const isViewingGaming = Boolean(gSection && gSection.style.display !== 'none');
  if (!isViewingGaming && gamePollCounter % 2 !== 0) return;

  gameAutoPollInFlight = true;
  try {
    const activity = await apiJson('/api/gaming/activity');
    if (activity && typeof activity === 'object') {
      appState.gameActivity = activity;
      notifyUnseenActiveGames(activity);
      renderGamingSection();
    }
  } catch (_) {
  } finally {
    gameAutoPollInFlight = false;
  }
}

setInterval(refreshGameActivityAuto, 2000);
