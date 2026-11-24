// Pulse Network Monitor — Mobile & Online Game Detector + Real-Time Toast Notifications

let gameActivityFilter = 'active';
let gameActivitySearch = '';
const gameToastTimers = new Map();
const shownGameNotificationIds = new Set();
let gameNotificationBusy = false;
let gameNotificationMessage = '';
const seenActiveSessionIds = new Set();
const displayedToastSessionIds = new Set();
let gameBaselineSeeded = false;
let gameAutoPollInFlight = false;
let gameEventStreamConnected = false;
let gameActivityRevision = 0;
let gameTerminalUserScrolledUp = false;
let gameTerminalHasVisibleRender = false;
let lastGameTerminalSignature = '';
const GAME_LAUNCHER_IDS = new Set(['steam_client', 'riot_client']);
const ANDROID_APP_DETECTION = 'Android foreground app';

function isWebsiteDetection(gameId) {
  return gameId?.endsWith('_website') === true;
}

function isMonitorOnlyDetection(gameId) {
  return GAME_LAUNCHER_IDS.has(gameId) || isWebsiteDetection(gameId);
}

function isGameOpen(item) {
  return item.detectionMethod === ANDROID_APP_DETECTION
    || (item.detectionMethod || '').endsWith('Windows game process');
}

function getGameActivityData() {
  return (
    appState.gameActivity || {
      logs: [],
      blocks: [],
      onlineDevices: [],
      autoScanActive: false,
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

function gameDesktopAlertPermission() {
  if (!window.isSecureContext) return 'insecure';
  return typeof Notification === 'undefined' || typeof Notification.requestPermission !== 'function'
    ? 'unsupported' : Notification.permission;
}

function updateGameNotifyButton() {
  const btn = document.getElementById('btnGameNotify');
  const status = document.getElementById('gameNotifyStatus');
  if (!btn || !status) return;
  const permission = gameDesktopAlertPermission();
  const help = {
    insecure: 'Open Vertex Sentry on localhost or through HTTPS for desktop alerts.',
    unsupported: 'This browser does not support desktop alerts here. In-app alerts are available.',
    denied: 'Allow Notifications in this site’s browser settings to receive new game alerts.',
  };
  btn.disabled = gameNotificationBusy || permission === 'granted' || Boolean(help[permission]);
  btn.textContent = gameNotificationBusy ? 'Requesting permission…'
    : permission === 'granted' ? 'Desktop alerts enabled'
    : permission === 'denied' ? 'Desktop alerts blocked'
    : help[permission] ? 'Desktop alerts unavailable' : 'Enable desktop alerts';
  const message = help[permission] || gameNotificationMessage;
  if (status.textContent !== message) status.textContent = message;
}

function sendGameDesktopNotification(title, body, tag) {
  return new Promise(resolve => {
    let notification;
    try {
      notification = new Notification(title, {body, tag, icon: '/vertex-sentry-192.png'});
    } catch (_) {
      resolve('failed');
      return;
    }
    const timer = setTimeout(() => resolve('unconfirmed'), 4500);
    notification.onshow = () => {
      clearTimeout(timer);
      resolve('shown');
    };
    notification.onerror = () => {
      clearTimeout(timer);
      resolve('failed');
    };
    notification.onclick = () => {
      window.focus();
      navigateSidebar('gaming');
      notification.close();
    };
  });
}

async function notifyGameOnDesktop(detection) {
  if (gameDesktopAlertPermission() !== 'granted' || detection.hintType || detection.portHint || detection.isDismissed
      || (detection.isActive === false && !detection.autoPrevented)) return;
  const key = detection.id || `${detection.ip}:${detection.gameId}:${detection.timestamp || ''}`;
  if (shownGameNotificationIds.has(key)) return;
  shownGameNotificationIds.add(key);
  const evidence = GAME_LAUNCHER_IDS.has(detection.gameId) ? 'running'
    : isWebsiteDetection(detection.gameId) ? 'observed'
    : isGameOpen(detection) ? 'opened' : 'activity detected';
  const who = detection.deviceName || detection.ip;
  const body = [
    who, detection.ip && detection.ip !== who ? detection.ip : '', detection.connectedTo,
    detection.timestamp ? fmtTime(detection.timestamp) : '',
  ].filter(Boolean).join(' · ');
  const delivery = await sendGameDesktopNotification(`${detection.gameName} ${evidence}`, body, `game-${key}`);
  if (delivery === 'failed') {
    shownGameNotificationIds.delete(key);
    gameNotificationMessage = 'The browser could not show a game alert. Check your browser’s Windows notification settings.';
    updateGameNotifyButton();
  }
}

async function requestGameNotificationPermission() {
  const initial = gameDesktopAlertPermission();
  if (gameNotificationBusy || initial !== 'default') return;
  gameNotificationBusy = true;
  gameNotificationMessage = '';
  updateGameNotifyButton();
  try {
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
      gameNotificationMessage = 'Keep Vertex Sentry open to receive alerts for new detections.';
    } else if (permission === 'default') {
      gameNotificationMessage = 'Notification permission was not granted. Select Enable desktop alerts to try again.';
    }
  } catch (_) {
    gameNotificationMessage = 'The browser could not request notification permission. Check this site’s browser settings.';
  } finally {
    gameNotificationBusy = false;
    updateGameNotifyButton();
  }
}

window.addEventListener('focus', updateGameNotifyButton);

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

function gameSessionStatus(item) {
  const method = item.detectionMethod || '';
  if (GAME_LAUNCHER_IDS.has(item.gameId)) return 'Client running';
  if (isWebsiteDetection(item.gameId)) return 'Website signal';
  if (isGameOpen(item)) return 'App open';
  if (method.includes('Port Scan') || method === 'Auto LAN Game Port Sensor') return 'Port open';
  return 'Network activity';
}

function renderActiveGamesLivePanel(activeLogs) {
  const panel = document.getElementById('activeGamesLivePanel');
  if (!panel) return;
  if (deferDashboardControlRender(panel, () => renderActiveGamesLivePanel(activeLogs))) return;
  if (!Array.isArray(activeLogs) || !activeLogs.length) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }
  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="game-section-panel amber">
      <div class="game-panel-head">
        <span class="game-panel-title">Current Detections (${activeLogs.length})</span>
      </div>
      <div class="game-panel-rows">
        ${activeLogs
          .map(
            item => `
          <div class="game-panel-row">
            <div class="game-row-info">
              <div class="game-row-title">
                <span>${esc(item.gameName)}</span>
                <span class="status-pill warning">${gameSessionStatus(item)}</span>
              </div>
              <div class="game-row-sub">
                <strong>${esc(item.deviceName)}</strong> (<span class="mono">${esc(item.ip)}</span>${item.deviceType ? ` · ${esc(item.deviceType)}` : ''}) · Via <strong>${esc(item.connectedTo || 'Connection unknown')}</strong>
              </div>
              ${item.player ? `<div class="game-row-sub">Windows account <strong>${esc(item.player)}</strong></div>` : ''}
              <div class="game-row-indicator">
                Signal: <span class="mono">${esc(item.matchedIndicator || '—')}</span> · ${esc(item.detectionMethod || 'Network Detection')}
              </div>
            </div>
            <div class="game-row-actions">
              ${isMonitorOnlyDetection(item.gameId) ? '' : `
                <button type="button" class="btn btn-secondary btn-sm game-btn-danger" onclick="shutOffGameSession(${inlineString(item.id)}, ${inlineString(item.ip)}, ${inlineString(item.gameId)}, 'device_throttle')">Limit Bandwidth</button>
                <button type="button" class="btn btn-secondary btn-sm game-btn-warn" onclick="shutOffGameSession(${inlineString(item.id)}, ${inlineString(item.ip)}, ${inlineString(item.gameId)}, 'device_wifi_cut')">Block Device Access</button>
              `}
              <button type="button" class="btn btn-secondary btn-sm" onclick="dismissGameSession(${inlineString(item.id)})">Dismiss</button>
            </div>
          </div>
        `
          )
          .join('')}
      </div>
    </div>
  `;
}

function renderGameCoverage() {
  const activity = getGameActivityData();
  const {subnets = [], lastScanAt, lastScan = [], endpointIps = [], recentDnsIps = [], endpointEnrollmentEnabled} = activity.coverage || {};
  const scope = document.getElementById('gameCoverageScope');
  if (!scope) return;
  scope.textContent = [
    subnets.length ? `Discovery scope: ${subnets.join(', ')}.` : 'Discovery scope is awaiting a LAN scan.',
    lastScanAt
      ? `Last LAN scan ${fmtTime(lastScanAt)}.${lastScan.length ? '' : ' Run a new scan to record per-subnet counts.'}`
      : 'No LAN scan recorded.'
  ].join(' ');
  const routerConnected = appState.router?.authenticated === true;
  document.getElementById('btnGameCoverageRouter').hidden = routerConnected || !activity.sensorStatus?.routerIp;
  const capture = activity.wiresharkStatus || {};
  document.getElementById('gameCoverageSignals').textContent = [
    routerConnected ? 'Router admin connected' : 'Router admin disconnected',
    capture.active && capture.sensorCaptureEnabled !== false ? 'Packet capture active' : 'Packet capture inactive',
    endpointEnrollmentEnabled ? `${endpointIps.length} Windows endpoint(s) reporting` : 'Windows endpoint enrollment off',
    `${recentDnsIps.length} IP(s) with recent sensor DNS queries`
  ].join(' · ');
  const catalog = document.getElementById('gameSupportedCatalog');
  if (catalog.open) {
    const titles = [...(activity.catalog || [])].sort((a, b) => a.name.localeCompare(b.name));
    document.getElementById('gameSupportedRows').innerHTML = titles.length
      ? `<div class="device-list-table-wrap"><table class="device-list-table">
          <thead><tr><th scope="col">Title</th><th scope="col">Detection signals</th></tr></thead>
          <tbody>${titles.map(title => {
            const sources = [];
            if (title.hasWindowsProcess) {
              sources.push(GAME_LAUNCHER_IDS.has(title.id) ? 'Windows client process' : 'Windows game process');
            }
            if (title.hasAndroidPackage) sources.push('Android foreground app');
            if (title.domains.length || title.ports.length) sources.push('Network activity');
            return `<tr><td>${esc(title.name)}</td><td>${esc(sources.join(' · '))}</td></tr>`;
          }).join('')}</tbody>
        </table></div>`
      : '<p class="game-deck-meta">Waiting for the game catalog…</p>';
  }
  const networks = document.getElementById('gameCoverageSubnets');
  networks.innerHTML = lastScan.length ? `
    <div class="device-list-table-wrap">
      <table class="device-list-table">
        <thead><tr><th scope="col">Subnet in last scan</th><th scope="col">Addresses probed</th><th scope="col">ICMP replies</th><th scope="col">Addresses observed</th></tr></thead>
        <tbody>${lastScan.map(row => `<tr>
          <td class="mono">${esc(row.subnet)}</td>
          <td>${esc(row.addressesProbed)}</td><td>${esc(row.icmpReplies)}</td><td>${esc(row.addressesObserved)}</td>
        </tr>`).join('')}</tbody>
      </table>
    </div>` : '';

  if (!document.getElementById('gameCoverageDevices').open) return;
  const devices = new Map();
  const add = (ip, name, evidence) => {
    if (!ip) return;
    if (!devices.has(ip)) devices.set(ip, {ip, name: name || ip, signals: new Set()});
    if (evidence) devices.get(ip).signals.add(evidence);
  };
  for (const device of appState.networkInventory || []) {
    if (device.isOnline && !device.archived) add(device.ip, device.suggestedName || device.name);
  }
  for (const device of appState.devices || []) {
    if (!device.archived && device.alive === true) add(device.ip, device.name);
  }
  for (const ip of endpointIps) add(ip, '', 'Managed Windows endpoint');
  for (const ip of recentDnsIps) add(ip, '', 'Recent DNS query');
  for (const log of activity.logs || []) {
    if (log.isActive && !log.hintType && !log.portHint) add(log.ip, log.deviceName, 'Live game signal');
  }
  const query = document.getElementById('gameCoverageSearch').value.trim().toLowerCase();
  const filtered = [...devices.values()]
    .filter(device => device.ip.includes(query) || device.name.toLowerCase().includes(query))
    .sort((a, b) => b.signals.size - a.signals.size || a.name.localeCompare(b.name));
  document.getElementById('gameCoverageDeviceRows').innerHTML = filtered.length ? `
    <div class="device-list-table-wrap">
      <table class="device-list-table">
        <thead><tr><th scope="col">Device</th><th scope="col">IP</th><th scope="col">Detection evidence</th></tr></thead>
        <tbody>${filtered.map(row => `<tr><td>${esc(row.name)}</td><td class="mono">${esc(row.ip)}</td>
          <td>${esc([...row.signals].join(' · ') || 'No recent detection evidence')}</td></tr>`).join('')}</tbody>
      </table>
    </div>` : '<p class="game-deck-meta">No matching devices.</p>';
}

function renderGamingSection() {
  const data = getGameActivityData();
  const logs = data.logs || [];
  const blocks = data.blocks || [];
  const summary = data.summary || {};

  const findRule = item =>
    isMonitorOnlyDetection(item.gameId) ? null : blocks.find(
      b => !b.controlStatus && (b.ip === item.ip || b.ip === '*') && (b.gameId === item.gameId || b.gameId === '*')
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
  const openGames = activeUnblockedLogs.filter(isGameOpen);
  const blockedLogs = deduped.filter(isBlockedLog);
  const blockedRuleRows = [];
  for (const rule of blocks) {
    const hasLog = blockedLogs.some(
      x => (rule.ip === x.ip || rule.ip === '*') && (rule.gameId === x.gameId || rule.gameId === '*')
    );
    if (rule.controlStatus || !hasLog) {
      blockedRuleRows.push({
        id: `rule-${rule.id}`,
        timestamp: rule.createdAt || new Date().toISOString(),
        ip: rule.ip || '*',
        deviceName: rule.deviceName || rule.ip || 'Network Device',
        deviceType: rule.mac ? `MAC ${rule.mac}` : '',
        gameId: rule.gameId || '*',
        gameName: rule.gameName || 'Blocked Access',
        connectedTo: 'Active Restriction Rule',
        matchedIndicator: rule.controlStatus === 'restore_pending' ? 'Restoration unverified' : rule.scope === 'device_wifi_cut' ? 'Device access block' : rule.scope === 'device_throttle' ? 'Router bandwidth limit' : 'Game Block',
        detectionMethod: 'Manual Restriction Rule',
        isActive: false,
        isBlocked: !rule.controlStatus || rule.controlStatus === 'active',
        _ruleRef: rule
      });
    }
  }
  const blockedTabEntries = [...blockedLogs, ...blockedRuleRows];
  const blockedEntryCount = blockedTabEntries.length;
  const totalCount = summary.totalCount ?? deduped.filter(item => !item.hintType && !item.portHint).length;
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
  setTxt('gameTabAllCount', deduped.length);
  setTxt('gameTabActiveCount', activeCount);
  setTxt('gameTabOpenCount', openGames.length);
  setTxt('gameTabBlockedCount', blockedEntryCount);
  renderGameSensorBanner(data, onlineCount);
  renderWiresharkStatusBar(data.wiresharkStatus || {});
  renderGameCoverage();
  renderGamingPolicyControls(data.policy || {});
  setTxt(
    'gameTerminalPromptText',
    activeCount > 0
      ? `${activeCount} live detections across ${onlineCount} visible devices.`
      : 'Waiting for recognized game traffic or a Windows game process.'
  );

  const sideBadge = document.getElementById('sideBadgeGaming');
  if (sideBadge) {
    sideBadge.textContent = activeCount > 0 ? `${activeCount} Live` : String(totalCount);
    sideBadge.className = `side-badge ${activeCount > 0 ? 'amber' : 'cyan'}`;
  }

  const headBadge = document.getElementById('gamingStatusBadge');
  if (headBadge) {
    headBadge.textContent =
      activeCount > 0 ? `${activeCount} Live Detection${activeCount > 1 ? 's' : ''}` : 'No active detections';
    headBadge.className = `status-pill ${activeCount > 0 ? 'warning' : 'online'}`;
  }

  updateGameNotifyButton();
  renderGameBlocksPanel(blocks);

  const matchesSearch = item => !gameActivitySearch || [
    item.gameName, item.player, item.deviceName, item.ip, item.vendor,
    item.connectedTo, item.zoneLabel, item.matchedIndicator, item.detectionMethod
  ].some(value => value && value.toLowerCase().includes(gameActivitySearch));
  renderActiveGamesLivePanel((gameActivityFilter === 'open' ? openGames : activeUnblockedLogs).filter(matchesSearch));

  let filtered = deduped;
  if (gameActivityFilter === 'active') {
    filtered = activeUnblockedLogs;
  } else if (gameActivityFilter === 'open') {
    filtered = openGames;
  } else if (gameActivityFilter === 'blocked') {
    filtered = blockedTabEntries;
  }
  if (gameActivitySearch) {
    filtered = filtered.filter(matchesSearch);
  }

  // Keep only the most recent 80 entries, showing newest activity first for clean scannable review
  const capped = gameActivityFilter === 'active' || gameActivityFilter === 'open' ? filtered : filtered.slice(0, 80);
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
  const ruleSig = blocks.map(b => `${b.id}:${b.ip}:${b.gameId}:${b.controlStatus}:${b.expiresAt}`).join(',');
  const signature =
    `${gameActivityFilter}|${gameActivitySearch}|${onlineCount}|${prevMode}|${ruleSig}|` +
    ordered.map(x => `${x.id}:${x.timestamp}:${x.isActive}:${x.isBlocked}:${x.isDismissed}`).join(',');
  if (signature === lastGameTerminalSignature) {
    return;
  }

  const prevScrollTop = container.scrollTop;
  lastGameTerminalSignature = signature;

  if (!ordered.length) {
    const filterTitle =
      gameActivityFilter === 'blocked'
        ? 'No blocked or throttled devices'
        : gameActivityFilter === 'open'
        ? 'No games confirmed open'
        : gameActivityFilter === 'active'
        ? 'No active detections right now'
        : 'No recorded detections';
    const modeDesc =
      gameActivityFilter === 'open'
        ? 'This view requires a Windows process or an Android foreground report.'
        : prevMode === 'alert_only'
        ? 'Switch to All History to inspect earlier detections.'
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
      const pendingRestore = activeRuleMatch?.controlStatus === 'restore_pending';
      const isBlocked = !pendingRestore && Boolean(item.isBlocked || activeRuleMatch);
      const rowCls = isBlocked ? 'is-blocked' : item.isActive ? 'is-live' : '';
      const hint = {lan_discovery: 'LAN discovery', port: 'Port hint', dns_cache: 'Cached DNS', capture_file: 'Imported capture'}[item.hintType]
        || (item.portHint ? 'Port hint' : '');
      const pillCls = isBlocked ? 'critical' : item.isActive || pendingRestore ? 'warning' : hint ? 'new' : 'online';
      const sevLabel = pendingRestore ? 'Restore Pending' : isBlocked ? 'Restricted' : hint || (item.isActive ? gameSessionStatus(item) : item.isDismissed ? 'Dismissed' : 'Ended');
      const ts = formatGameTerminalTime(item.timestamp);
      const devType = item.deviceType ? ` · ${item.deviceType}` : '';
      const actionsHtml = activeRuleMatch
        ? `<button type="button" class="btn btn-secondary btn-xs game-btn-restore" onclick="unblockGameRule(${inlineString(
            activeRuleMatch.id
          )})">Restore Access</button>`
        : item.isActive ? `${isMonitorOnlyDetection(item.gameId) ? '' : `<button type="button" class="btn btn-secondary btn-xs game-btn-danger" onclick="shutOffGameSession(${inlineString(
            item.id
          )}, ${inlineString(item.ip)}, ${inlineString(
            item.gameId
          )}, 'device_throttle')">Limit Bandwidth</button><button type="button" class="btn btn-secondary btn-xs game-btn-warn" onclick="shutOffGameSession(${inlineString(
            item.id
          )}, ${inlineString(item.ip)}, ${inlineString(
            item.gameId
          )}, 'device_wifi_cut')">Block Device Access</button>`}
          <button type="button" class="btn btn-secondary btn-xs" onclick="dismissGameSession(${inlineString(item.id)})">Dismiss</button>` : '';

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
            ${item.player ? `<div class="game-device-sub">Windows account ${esc(item.player)}</div>` : ''}
            <div class="game-device-sub">${esc(item.connectedTo || 'Connection unknown')} · Signal: <code>${esc(item.matchedIndicator || '—')}</code></div>
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
  if (deferDashboardControlRender(panel, () => renderGameBlocksPanel(blocks))) return;
  if (!Array.isArray(blocks) || !blocks.length) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }
  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="game-section-panel danger">
      <div class="game-panel-head">
        <span class="game-panel-title">Device Restrictions (${blocks.length})</span>
      </div>
      <div class="game-panel-rows">
        ${blocks
          .map(
            b => `
          <div class="game-panel-row">
            <div class="game-row-info">
              <div class="game-row-title">
                <span>${esc(b.deviceName || b.ip)}</span>
                <span class="status-pill ${b.controlStatus && b.controlStatus !== 'active' ? 'warning' : 'critical'}">${
                  b.controlStatus === 'restore_pending' ? 'Restore Pending'
                  : b.controlStatus === 'applying' ? 'Awaiting Verification'
                  : b.scope === 'device_throttle' ? 'Bandwidth Limited' : 'Access Blocked'
                }</span>
              </div>
              <div class="game-row-sub">
                IP: <span class="mono">${esc(b.ip)}</span>${b.mac ? ` · MAC: <span class="mono">${esc(b.mac)}</span>` : ''} · ${esc(b.gameName)}${b.expiresAt ? ` · Restore due ${esc(new Date(b.expiresAt).toLocaleString())}` : ''}
              </div>
            </div>
            <div class="game-row-actions">
              <button type="button" class="btn btn-secondary btn-xs game-btn-restore" onclick="unblockGameRule(${inlineString(
                b.id
              )})">Restore Access</button>
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
  const canChangeDns = data.policy?.restrictionsEnabled === true && s.dnsForwardingEnabled === true && s.sensorOnline;
  const hostIp = s.dnsHost || (data.summary && data.summary.hostDnsServerIp) || '192.168.0.224';
  const dnsPort = s.dnsPort || 53;
  const qTotal = Number(s.dnsQueriesTotal || 0);
  const bTotal = Number(s.dnsBlockedTotal || 0);
  const failed = Number(s.dnsForwardFailures || 0);
  const cCount = Number(s.dnsClientsCount || 0);
  const bypass = Array.isArray(s.bypassingExternalDns) ? s.bypassingExternalDns : [];

  if (!s.sensorOnline) {
    if (bar) bar.classList.add('warn');
    if (badge) {
      badge.className = 'status-pill warning';
      badge.textContent = `Sensor Standby · ${onlineCount} Devices`;
    }
    if (line) {
      line.textContent = 'Host capture sensor offline. Managed Windows endpoint reports can still arrive.';
    }
    if (setupBtn) setupBtn.style.display = 'none';
    return;
  }

  if (s.dnsForwardingEnabled !== true) {
    if (bar) bar.classList.remove('warn');
    if (badge) {
      badge.className = 'status-pill online';
      badge.textContent = 'Passive sensor online';
    }
    if (line) line.textContent = 'Game signals come from visible packet capture, router logs, and managed endpoints.';
    if (setupBtn) setupBtn.style.display = 'none';
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
      line.innerHTML = `DNS <code>${esc(hostIp)}:${dnsPort}</code> · ${qTotal.toLocaleString()} queries · ${bTotal} blocked · ${failed} upstream failures${lastDom}`;
    }
    if (setupBtn) setupBtn.style.display = 'none';
  } else {
    if (bar) bar.classList.add('warn');
    if (badge) {
      badge.className = 'status-pill warning';
      badge.textContent = 'No client DNS traffic';
    }
    if (line) {
      const hostDns = bypass.length ? ` Windows lists <code>${esc(bypass.join(', '))}</code> as other DNS servers.` : '';
      const dnsAddress = s.hotspotIp || hostIp;
      line.innerHTML = `Vertex Sentry has received no client DNS. On a phone connected to this Wi-Fi, set DNS to <code>${esc(dnsAddress)}</code>, load a page, then open a supported game.${hostDns}`;
    }
    if (setupBtn) setupBtn.style.display = canChangeDns ? 'inline-flex' : 'none';
  }
}

function renderGamingPolicyControls(policy) {
  const mode = (policy && policy.preventionMode) || 'alert_only';
  const badge = document.getElementById('gameManualModeBadge');
  const resetBtn = document.getElementById('btnForceManualMode');
  const hint = document.getElementById('gamePolicyHint');
  const isManual = mode === 'alert_only';
  const restrictionsEnabled = policy?.restrictionsEnabled === true;
  const deviceControlsEnabled = policy?.deviceControlsEnabled === true || restrictionsEnabled;
  document.documentElement.classList.toggle('game-restrictions-enabled', deviceControlsEnabled);
  if (badge) {
    badge.className = `status-pill ${isManual ? 'online' : 'warning'}`;
    badge.textContent = mode !== 'alert_only' ? 'Auto-Block Active' : deviceControlsEnabled ? 'Manual Device Controls' : 'Monitoring Only';
  }
  if (resetBtn) {
    resetBtn.style.display = isManual ? 'none' : 'inline-flex';
  }
  if (!hint) return;
  hint.innerHTML = !restrictionsEnabled
    ? 'Alerts monitor game activity. Manual controls require a current detection, confirmed MAC, and router verification.'
    : isManual
    ? 'Manual enforcement mode — scans never auto-block users.'
    : '<strong style="color:var(--accent-amber);">Auto-block is active via policy config.</strong> Click Revert to Manual to restore prompt-only enforcement.';
}

function showGameDetectedToast(detection) {
  if (!detection?.gameName || detection.hintType || detection.portHint || detection.isDismissed
      || (detection.isActive === false && !detection.autoPrevented)) return;
  void notifyGameOnDesktop(detection);
  if (detection.id) {
    seenActiveSessionIds.add(detection.id);
    if (displayedToastSessionIds.has(detection.id)) return;
    displayedToastSessionIds.add(detection.id);
  }
  const isAuto = Boolean(detection.autoPrevented);
  const launcher = GAME_LAUNCHER_IDS.has(detection.gameId);
  const website = isWebsiteDetection(detection.gameId);
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
        <span class="game-toast-badge">${launcher ? 'Client running' : website ? 'Website activity' : isAuto ? 'Auto-Prevented' : isGameOpen(detection) ? 'App open' : 'Network activity'}</span>
        <button type="button" class="game-toast-close" onclick="dismissGameToast(${inlineString(toastId)})" aria-label="Close">✕</button>
      </div>
      <div class="game-toast-title">${esc(detection.gameName)}</div>
      <div class="game-toast-meta">
        <div><strong>Device:</strong> ${esc(detection.deviceName)} <span class="mono">(${esc(detection.ip)})</span></div>
        ${detection.player ? `<div><strong>Windows account</strong> ${esc(detection.player)}</div>` : ''}
        <div><strong>Via:</strong> ${esc(detection.connectedTo)}</div>
        <div class="dev-row-sub">${esc(detection.matchedIndicator || '')} · ${esc(detection.detectionMethod || '')}</div>
      </div>
      <div class="game-toast-actions">
        ${
          isAuto || isMonitorOnlyDetection(detection.gameId)
            ? ''
            : `<button type="button" class="btn btn-secondary btn-xs game-btn-danger" onclick="shutOffGameFromToast(${inlineString(toastId)}, ${inlineString(detection.id || '')}, ${inlineString(detection.ip || '')}, ${inlineString(detection.gameId || '')})">Limit Bandwidth</button>`
        }
        <button type="button" class="btn btn-primary btn-xs" onclick="jumpToGamingWorkspace(${inlineString(toastId)})">Inspect</button>
        ${!isAuto && detection.id
          ? `<button type="button" class="btn btn-secondary btn-xs" onclick="dismissGameSession(${inlineString(detection.id)})">Dismiss session</button>`
          : ''}
      </div>
    `;
    container.prepend(card);
    while (container.children.length > 4) {
      container.lastElementChild.remove();
    }
    const timer = setTimeout(() => dismissGameToast(toastId), 12000);
    gameToastTimers.set(toastId, timer);
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
    banner.innerHTML = `<div class="game-scan-banner"><div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;"><span class="status-pill warning">Scanning Network</span><span class="game-deck-meta">Refreshing LAN discovery and checking game-related ports on known clients.</span></div></div>`;
  }
  try {
    const res = await apiJson('/api/gaming/scan', {
      method: 'POST',
      body: JSON.stringify({})
    });
    applyGameActivitySnapshot(res.gameActivity);
    const dets = Array.isArray(res.detections) ? res.detections : [];
    if (dets.length) {
      if (dets.some(d => d.isBlocked) && gameActivityFilter === 'active') {
        setGameActivityFilter('blocked');
      }
    }
    if (banner) {
      const routersPolled = Number(res.routersPolled || 0);
      const devCnt = Number(res.scannedDevices || 0);
      const foundCnt = Number(res.confirmedHits ?? res.detectedCount ?? 0);
      const portHints = Number(res.openPortHits || 0);
      const activeCnt = Number(res.activeCount || 0);
      const blockedCnt = Number(res.blockedCount || 0);
      const noteHtml = `Checked game-related ports on ${devCnt} candidate device(s). Attempted client-list reads on ${routersPolled} configured router(s). ${activeCnt} active game detection(s), ${blockedCnt} blocked.`;
      banner.style.display = 'block';
      banner.innerHTML = `
        <div class="game-scan-banner">
          <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; flex:1;">
            <span class="status-pill ${foundCnt > 0 || activeCnt > 0 ? 'warning' : 'online'}">${foundCnt > 0 ? `Found ${foundCnt} Match(es)` : 'Scan Complete'}</span>
            <span style="font-size:0.78rem; color:var(--text-muted);">${noteHtml}${portHints ? ` Open-port hints: ${portHints}.` : ''}</span>
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
    dismissGameToast(`game-toast-${id}`);
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

let pendingGameDeviceControl = null;

function shutOffGameSession(sessionId, ip, gameId, scope = 'device_throttle', toastId = '') {
  if (!sessionId || isMonitorOnlyDetection(gameId)) return;
  const bandwidth = scope === 'device_throttle';
  const rates = document.getElementById('gameControlRates');
  pendingGameDeviceControl = {sessionId, ip, gameId, scope, toastId};
  document.getElementById('gameControlTitle').textContent = bandwidth ? 'Limit Device Bandwidth' : 'Block Device Access';
  const device = (getGameActivityData().logs || []).find(item => item.id === sessionId);
  document.getElementById('gameControlDevice').textContent = [
    device?.deviceName, ip, device?.mac
  ].filter(Boolean).join(' ? ');
  document.getElementById('gameControlError').textContent = '';
  rates.hidden = !bandwidth;
  for (const input of rates.querySelectorAll('input')) input.disabled = !bandwidth;
  document.getElementById('gameControlSubmit').textContent = bandwidth ? 'Apply Limit' : 'Block Device Access';
  openModal('gameControlModal');
}

async function submitGameDeviceControl(event) {
  event.preventDefault();
  const control = pendingGameDeviceControl;
  if (!control) return;
  const submit = document.getElementById('gameControlSubmit');
  if (submit.disabled) return;
  const feedback = document.getElementById('gameControlError');
  const {sessionId, ip, gameId, scope, toastId} = control;
  const body = {
    sessionId, ip, gameId, scope, routerOnly: true,
    durationMinutes: document.getElementById('gameControlDuration').value
  };
  if (scope === 'device_throttle') {
    body.downloadKbps = document.getElementById('gameControlDownload').value;
    body.uploadKbps = document.getElementById('gameControlUpload').value;
  }
  submit.disabled = true;
  feedback.textContent = 'Checking the router?';
  try {
    const result = await apiJson('/api/gaming/block', {method: 'POST', body: JSON.stringify(body)});
    applyGameActivitySnapshot(result.gameActivity);
    renderGamingSection();
    if (!result.success) {
      feedback.textContent = result.enforcementDetails?.setupHint || 'The router did not verify the restriction.';
      return;
    }
    if (toastId) dismissGameToast(toastId);
    if (pendingGameDeviceControl === control) closeModal('gameControlModal');
  } catch (err) {
    feedback.textContent = err.message;
  } finally {
    submit.disabled = false;
  }
}

function shutOffGameFromToast(toastId, sessionId, ip, gameId) {
  shutOffGameSession(sessionId, ip, gameId, 'device_throttle', toastId);
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

let captureConfigPending = false;

function renderWiresharkStatusBar(ws) {
  const bar = document.getElementById('gameWiresharkBar');
  const badge = document.getElementById('gameWiresharkBadge');
  const sum = document.getElementById('gameWiresharkSummary');
  const strip = document.getElementById('gameWiresharkHitsStrip');
  const toggleBtn = document.getElementById('btnToggleWireshark');
  const download = document.getElementById('btnDownloadWiresharkPcap');
  const s = ws || {};
  const known = typeof s.enabled === 'boolean';
  const changing = s.sensorOnline && typeof s.sensorCaptureEnabled === 'boolean' && s.enabled !== s.sensorCaptureEnabled;
  const localActive = s.activeInterfaceCount == null ? s.active && !s.tzspActive : s.activeInterfaceCount > 0;
  const sources = [];
  if (localActive) sources.push(({tshark: 'TShark', 'npcap-wpcap': 'Npcap'})[s.engine] || 'Local adapters');
  if (s.tzspActive) sources.push('Router mirror listener');

  let label = 'Checking capture status…';
  let style = '';
  const details = [];
  if (known) {
    if (changing) label = s.enabled ? 'Resuming…' : 'Pausing…';
    else if (!s.enabled) label = 'Paused';
    else if (!s.sensorOnline) {
      label = 'Sensor offline';
      style = 'warning';
      details.push('Start the host sensor to capture live traffic.');
    } else if (localActive) {
      label = 'Capturing';
      style = 'online';
    } else if (s.tzspActive) {
      label = 'Router mirror ready';
      style = 'online';
    } else {
      label = 'Capture unavailable';
      style = 'warning';
      details.push('Check the capture adapter and host sensor configuration.');
    }
    if (s.enabled && sources.length) details.push(sources.join(' + '));
    if (s.sensorOnline || s.packetsCaptured) {
      details.push(`${Number(s.packetsCaptured || 0).toLocaleString()} packets seen`);
      details.push(`${Number(s.packetsMatched || 0).toLocaleString()} game matches`);
    }
    details.push(s.pcapAvailable ? 'Export contains saved game traffic' : 'No saved packets to download');
  }
  if (badge.textContent !== label) badge.textContent = label;
  badge.className = `status-pill ${style}`.trim();
  bar.classList.toggle('warn', style === 'warning');
  toggleBtn.disabled = !known || captureConfigPending || changing;
  toggleBtn.textContent = s.enabled === false ? 'Resume capture' : 'Pause capture';
  if (s.pcapAvailable) {
    download.href = s.pcapUrl;
    download.removeAttribute('aria-disabled');
  } else {
    download.removeAttribute('href');
    download.setAttribute('aria-disabled', 'true');
  }
  sum.textContent = details.join(' · ');
  if (strip) {
    const hits = Array.isArray(s.recentHits) ? s.recentHits.slice(0, 2) : [];
    const talkers = Array.isArray(s.topTalkers) ? s.topTalkers.slice(0, 4) : [];
    const encDns = Array.isArray(s.encryptedDnsClients) ? s.encryptedDnsClients.slice(0, 4) : [];
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
                )}</code>${h.frameSourceMac ? ` · Frame source MAC: <code>${esc(h.frameSourceMac)}</code>` : ''}`
            )
            .join(' · ')
      );
    }
    if (talkers.length) {
      parts.push(
        `<strong>Top Passive Talkers (60s):</strong> ` +
          talkers
            .map(
              t =>
                `<span class="mono">${esc(t.ip)}</span> (${Number(t.totalKB || 0).toLocaleString()} KB · ${Number(t.kbps || 0)} Kbps)`
            )
            .join(' · ')
      );
    }
    if (encDns.length) {
      parts.push(
        `<strong style="color:var(--accent-amber);">⚠️ Encrypted DNS Bypass:</strong> ` +
          encDns
            .map(
              c =>
                `<span class="mono">${esc(c.ip)}</span> via <code>${esc(c.protocol || 'DoH/DoT')}</code> (${esc(c.resolver || 'external')})`
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
  const button = document.getElementById('btnToggleWireshark');
  if (button.disabled) return;
  captureConfigPending = true;
  button.disabled = true;
  const feedback = document.getElementById('gameWiresharkFeedback');
  feedback.textContent = '';
  const ws = (getGameActivityData() && getGameActivityData().wiresharkStatus) || {};
  const nextEnabled = ws.enabled === false;
  try {
    const res = await apiJson('/api/gaming/wireshark/config', {
      method: 'POST',
      body: JSON.stringify({ enabled: nextEnabled })
    });
    if (res && res.wiresharkStatus && appState.gameActivity) {
      gameActivityRevision += 1;
      appState.gameActivity.wiresharkStatus = res.wiresharkStatus;
      renderGamingSection();
    }
    await refreshGameActivityAuto(true);
  } catch (err) {
    feedback.textContent = err.message;
  } finally {
    captureConfigPending = false;
    renderWiresharkStatusBar(getGameActivityData().wiresharkStatus);
  }
}

async function copyWiresharkDisplayFilter() {
  const ws = (getGameActivityData() && getGameActivityData().wiresharkStatus) || {};
  const filter = String(ws.displayFilter || 'dns or tls.handshake.type == 1');
  try {
    await navigator.clipboard.writeText(filter);
    document.getElementById('gameWiresharkFeedback').textContent = 'Wireshark filter copied.';
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
  const button = document.getElementById('btnImportWiresharkPcap');
  const feedback = document.getElementById('gameWiresharkFeedback');
  if (button.disabled) return;
  button.disabled = true;
  try {
    if (file.size > 11 * 1024 * 1024) {
      feedback.textContent = 'Choose a capture file of 11 MB or less.';
      return;
    }
    feedback.textContent = `Analyzing ${file.name}…`;
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
      body: JSON.stringify({ filename: file.name, dataBase64 })
    });
    applyGameActivitySnapshot(res.gameActivity);
    feedback.textContent = `${file.name}: ${res.packetsParsed} packets analyzed, ${res.uniqueMatches} historical game matches.`;
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    feedback.textContent = err.message;
  } finally {
    button.disabled = false;
    input.value = '';
  }
}

function notifyUnseenActiveGames(activity) {
  if (!activity || !Array.isArray(activity.logs)) return;
  const activeLogs = activity.logs.filter(x => x && x.isActive && !x.isBlocked && !x.hintType && !x.portHint);
  if (!gameBaselineSeeded) {
    for (const item of activeLogs) {
      if (item.id) seenActiveSessionIds.add(item.id);
    }
    gameBaselineSeeded = true;
    return;
  }
  for (const item of activeLogs) {
    if (item.id && !seenActiveSessionIds.has(item.id)) {
      seenActiveSessionIds.add(item.id);
      showGameDetectedToast(item);
    }
  }
}

function applyGameActivitySnapshot(activity) {
  if (!activity || !Array.isArray(activity.logs)) return;
  gameActivityRevision += 1;
  appState.gameActivity = activity;
  notifyUnseenActiveGames(activity);
}

function applyLiveGameDetection(detection, updated = false) {
  if (!detection?.id || detection.hintType || detection.portHint) return;
  gameActivityRevision += 1;
  const activity = getGameActivityData();
  const logs = activity.logs || [];
  const previous = logs.find(item => item.id === detection.id);
  if (previous && Date.parse(previous.timestamp) > Date.parse(detection.timestamp)) return;
  appState.gameActivity = {
    ...activity,
    logs: [detection, ...logs.filter(item => item.id !== detection.id)],
    summary: {
      ...activity.summary,
      totalCount: (activity.summary?.totalCount ?? logs.filter(item => !item.hintType && !item.portHint).length)
        + (!previous || previous.hintType || previous.portHint ? 1 : 0)
    }
  };
  if (!updated && !seenActiveSessionIds.has(detection.id)) showGameDetectedToast(detection);
}

function applyEndedGameSessions(sessionIds) {
  if (!Array.isArray(sessionIds) || !sessionIds.length) return;
  const activity = getGameActivityData();
  const ended = new Set(sessionIds);
  gameActivityRevision += 1;
  appState.gameActivity = {
    ...activity,
    logs: (activity.logs || []).map(item => ended.has(item.id) ? {...item, isActive: false} : item)
  };
}

async function refreshGameActivityAuto(force = false) {
  if (gameAutoPollInFlight) return;
  const gSection = document.getElementById('gamingSection');
  const isViewingGaming = Boolean(gSection && gSection.style.display !== 'none');
  if (!force && gameEventStreamConnected && (document.hidden || !isViewingGaming)) return;

  gameAutoPollInFlight = true;
  const revision = gameActivityRevision;
  try {
    const activity = await apiJson('/api/gaming/activity');
    if (revision === gameActivityRevision) {
      applyGameActivitySnapshot(activity);
      renderGamingSection();
    }
  } catch (_) {
  } finally {
    gameAutoPollInFlight = false;
  }
}

setInterval(refreshGameActivityAuto, 3000);
