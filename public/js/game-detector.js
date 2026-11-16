// Pulse Network Monitor — Mobile & Online Game Detector + Real-Time Toast Notifications

let gameActivityFilter = 'active';
let gameActivitySearch = '';
const gameToastTimers = new Map();
const shownGameNotificationIds = new Set();
const seenActiveSessionIds = new Set();
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
    btn.textContent = '🔔 In-App Popup Alerts: ON';
    btn.disabled = true;
    return;
  }
  if (Notification.permission === 'granted') {
    btn.textContent = '🔔 Browser + App Notifications: ON';
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-secondary');
  } else if (Notification.permission === 'denied') {
    btn.textContent = '🔔 In-App Alerts: ON (Desktop Blocked)';
  } else {
    btn.textContent = '🔔 Enable Desktop Popup Alerts';
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
    <div class="active-games-live-box">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:10px; flex-wrap:wrap;">
        <strong style="font-size:0.88rem; color:var(--accent-amber);">🎮 Games Currently Open &amp; Playing (${activeLogs.length})</strong>
        <span style="font-size:0.74rem; color:var(--text-muted);">Choose an action below to lag &amp; shut off the game and Wi-Fi strictly for that user.</span>
      </div>
      <div class="active-games-live-list">
        ${activeLogs
          .map(
            item => `
          <div class="active-game-card">
            <div class="active-game-meta">
              <div style="display:flex; align-items:center; gap:9px; flex-wrap:wrap;">
                <span style="font-size:1.35rem; line-height:1;">${esc(item.gameIcon || '🎮')}</span>
                <div>
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <strong style="font-size:0.9rem;">${esc(item.gameName)}</strong>
                    <span class="status-pill warning">🎮 OPEN &amp; PLAYING NOW</span>
                  </div>
                  <div style="font-size:0.76rem; color:var(--text-muted); margin-top:2px;">
                    <strong>${esc(item.deviceName)}</strong> (<span class="mono">${esc(item.ip)}</span>${item.deviceType ? ` · ${esc(item.deviceType)}` : ''}) · 📡 <strong>${esc(item.connectedTo || 'Main Gateway Router')}</strong>
                  </div>
                  <div style="font-size:0.72rem; color:var(--text-dim); margin-top:2px;">
                    Trigger: <span class="mono">${esc(item.matchedIndicator || '—')}</span> (${esc(item.detectionMethod || 'Network Detection')})
                  </div>
                </div>
              </div>
            </div>
            <div class="active-game-actions">
              <button type="button" class="btn btn-primary btn-sm game-btn-danger" onclick="shutOffGameSession('${esc(item.id)}', '${esc(item.ip)}', '${esc(item.gameId)}', 'device_wifi_cut', true)">🛑 Block Game &amp; Cut User Wi-Fi</button>
              <button type="button" class="btn btn-secondary btn-sm game-btn-warn" onclick="shutOffGameSession('${esc(item.id)}', '${esc(item.ip)}', '${esc(item.gameId)}', 'device_game', false)">🚫 Block Game Only</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="dismissGameSession('${esc(item.id)}')">✓ Dismiss</button>
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
  const blockedLogCount = deduped.filter(isBlockedLog).length;
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
  setTxt('gameTabBlockedCount', blockedLogCount);
  renderGameSensorBanner(data, onlineCount);
  renderGamingPolicyControls(data.policy || {});
  setTxt(
    'gameTerminalPromptText',
    activeCount > 0
      ? `🎮 ${activeCount} game(s) open now — use Block buttons to shut off the game & user Wi-Fi.`
      : `Watching ${onlineCount} company devices in real time — entries appear the instant a game opens.`
  );

  const sideBadge = document.getElementById('sideBadgeGaming');
  if (sideBadge) {
    sideBadge.textContent = activeCount > 0 ? `${activeCount} Live` : String(totalCount);
    sideBadge.className = `side-badge ${activeCount > 0 ? 'amber' : 'cyan'}`;
  }

  const headBadge = document.getElementById('gamingStatusBadge');
  if (headBadge) {
    headBadge.textContent =
      activeCount > 0 ? `🎮 ${activeCount} GAME(S) OPEN NOW` : 'WATCHING · NO GAMES OPEN';
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
    filtered = filtered.filter(isBlockedLog);
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

  // Keep only the most recent 80 entries so logs never over-stack, sorted oldest -> newest (tail -f)
  const capped = filtered.slice(0, 80);
  const ordered = [...capped].sort((a, b) => {
    const ta = new Date(a.timestamp || 0).getTime() || 0;
    const tb = new Date(b.timestamp || 0).getTime() || 0;
    return ta - tb;
  });

  setTxt(
    'gameTerminalShowingCount',
    `${ordered.length} ${ordered.length === 1 ? 'line' : 'lines'}`
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

  const isVisible = container.clientHeight > 0;
  const prevScrollTop = container.scrollTop;
  const distFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
  const wasNearBottom = distFromBottom <= 40;
  const shouldPinBottom =
    (!gameTerminalHasVisibleRender && isVisible) ||
    (!gameTerminalUserScrolledUp && wasNearBottom);
  if (isVisible) gameTerminalHasVisibleRender = true;
  lastGameTerminalSignature = signature;

  if (!ordered.length) {
    const modeDesc =
      prevMode === 'auto_wifi_cut'
        ? 'ZERO-TOLERANCE PREVENTION ON: any opened game is blocked & user Wi-Fi is cut immediately at packet arrival.'
        : prevMode === 'auto_block_game'
        ? 'AUTO-PREVENTION ON: any opened game is blocked in real time; blocked entries appear above & in Blocked Users.'
        : 'No game is currently open. Terminal will display live game sessions and Block buttons automatically as soon as a user opens a game.';
    container.innerHTML = `
      <div class="ps-log-line game-term-line ps-lvl-live">
        <span class="ps-ts">[${esc(formatGameTerminalTime(new Date().toISOString()))}]</span>
        <span class="ps-sev">[${prevMode === 'alert_only' ? 'WATCHING' : 'GUARDING'}]</span>
        <span class="ps-tag">[IDLE · REAL-TIME]</span>
        <span class="ps-body-col"><span class="ps-msg">${esc(modeDesc)}</span></span>
      </div>
    `;
    return;
  }

  container.innerHTML = ordered
    .map(item => {
      const matchingRule = findRule(item);
      const isBlocked = Boolean(item.isBlocked || matchingRule);
      const lvlCls = isBlocked
        ? 'ps-lvl-crit'
        : item.isActive
        ? 'ps-lvl-warn'
        : 'ps-lvl-info';
      const sevLabel = isBlocked ? 'BLOCKED' : item.isActive ? 'PLAYING' : 'ENDED';
      const ts = formatGameTerminalTime(item.timestamp);
      const devType = item.deviceType ? ` · ${item.deviceType}` : '';
      const actionsHtml = matchingRule
        ? `<button type="button" class="game-term-btn unblock" onclick="unblockGameRule('${esc(
            matchingRule.id
          )}')">🟢 Unblock User</button>`
        : `<button type="button" class="game-term-btn shutoff" onclick="shutOffGameSession('${esc(
            item.id
          )}', '${esc(item.ip)}', '${esc(
            item.gameId
          )}', 'device_wifi_cut', true)" title="Lag & shut off all games + Wi-Fi access for this device IP/MAC only">🛑 Block Game &amp; Cut Wi-Fi</button><button type="button" class="game-term-btn blockall" onclick="shutOffGameSession('${esc(
            item.id
          )}', '${esc(item.ip)}', '${esc(
            item.gameId
          )}', 'device_game', false)" title="Block only this game for this device">🚫 Block Game Only</button>${
            item.isActive
              ? `<button type="button" class="game-term-btn clear" onclick="dismissGameSession('${esc(
                  item.id
                )}')">✓ Dismiss</button>`
              : ''
          }`;

      return `
        <div class="ps-log-line game-term-line ${lvlCls}">
          <span class="ps-ts">[${esc(ts)}]</span>
          <span class="ps-sev">[${esc(sevLabel)}]</span>
          <span class="ps-tag" title="${esc(item.gameName)}">${esc(item.gameIcon || '🎮')} ${esc(item.gameName)}</span>
          <span class="ps-body-col game-term-body-col">
            <span class="game-term-msg"><span class="ps-target">${esc(item.deviceName)}</span> <span class="mono">(${esc(item.ip)}${esc(devType)})</span> via 📡 <strong>${esc(item.connectedTo || 'Main Gateway Router')}</strong> — <span class="mono">${esc(item.matchedIndicator || '—')}</span> (${esc(item.detectionMethod || 'Network Detection')})</span>
            <span class="game-term-actions">${actionsHtml}</span>
          </span>
        </div>
      `;
    })
    .join('');

  if (shouldPinBottom) {
    container.scrollTop = container.scrollHeight;
  } else {
    container.scrollTop = prevScrollTop;
  }
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
    <div class="game-blocks-box">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:8px; flex-wrap:wrap;">
        <strong style="font-size:0.84rem; color:var(--accent-red);">🛑 Active Per-User Game &amp; Wi-Fi Cut-Offs (${blocks.length})</strong>
        <span style="font-size:0.73rem; color:var(--text-muted);">Cuts DNS/Wi-Fi connectivity (<code>0.0.0.0</code>, TTL 1s) + drops open game sockets strictly for the targeted company device until unblocked.</span>
      </div>
      <div class="game-blocks-list">
        ${blocks
          .map(
            b => `
          <div class="game-block-chip">
            <div>
              <strong style="font-size:0.79rem;">${esc(b.gameName)}</strong>
              <span class="dev-row-sub">on ${esc(b.deviceName)} (${esc(b.ip)})</span>
            </div>
            <button type="button" class="btn btn-secondary btn-xs" style="border-color:var(--accent-green); color:var(--accent-green);" onclick="unblockGameRule('${esc(
              b.id
            )}')">🟢 Unblock User</button>
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
      badge.textContent = `🟠 SENSOR STANDBY · ${onlineCount} DEVICES WATCHED`;
    }
    if (line) {
      line.innerHTML = `Host DNS sensor (<code>host_game_sensor.py</code>) has not checked in yet — run <code>start-monitor.bat</code> for sub-second UDP/TCP 53 interception on <code>${esc(hostIp)}</code>.`;
    }
    if (setupBtn) setupBtn.style.display = 'inline-flex';
    return;
  }

  if (s.dnsInterceptReady || cCount > 0) {
    if (bar) bar.classList.remove('warn');
    if (badge) {
      badge.className = 'status-pill online';
      badge.textContent = `🟢 REAL-TIME LIVE · ${cCount} WIFI/DNS CLIENTS (${qTotal} QUERIES)`;
    }
    if (line) {
      const lastDom = s.lastDnsDomain
        ? ` · Last query: <code>${esc(s.lastDnsClientIp || '')}</code> → <code>${esc(s.lastDnsDomain)}</code>`
        : '';
      line.innerHTML = `Listening on <code>${esc(hostIp)}:53</code>${s.hotspotIp ? ` + Hotspot <code>${esc(s.hotspotIp)}:53</code>` : ''}, Syslog <code>514</code> &amp; LAN sweep — <strong>${bTotal}</strong> prevented.${lastDom}`;
    }
    if (setupBtn) setupBtn.style.display = 'none';
  } else {
    if (bar) bar.classList.add('warn');
    if (badge) {
      badge.className = 'status-pill warning';
      badge.textContent = `🟠 SENSOR ON · WAITING FOR ROUTER DHCP DNS`;
    }
    if (line) {
      const dnsNote = bypass.length
        ? `Router (<code>${esc(routerIp)}</code>) currently assigns DNS <code>${esc(bypass.join(', '))}</code> instead of <code>${esc(hostIp)}</code> — phones bypass the monitor until router DHCP DNS (or test phone DNS / Windows Mobile Hotspot) points to <code>${esc(hostIp)}</code>.`
        : `Set Router DHCP Primary DNS (or a phone Wi-Fi DNS) to <code>${esc(hostIp)}</code> for instant packet-0 mobile detection &amp; prevention.`;
      line.innerHTML = dnsNote;
    }
    if (setupBtn) setupBtn.style.display = 'inline-flex';
  }
}

function renderGamingPolicyControls(policy) {
  const mode = (policy && policy.preventionMode) || 'alert_only';
  document.querySelectorAll('#gamePolicyModePills [data-policy-mode]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-policy-mode') === mode);
  });
  const hint = document.getElementById('gamePolicyHint');
  if (!hint) return;
  if (mode === 'auto_wifi_cut') {
    hint.innerHTML =
      '<strong style="color:var(--accent-red);">ZERO-TOLERANCE ACTIVE:</strong> Opening any mobile/PC game immediately sinkholes DNS, drops sockets &amp; cuts Wi-Fi for that device.';
  } else if (mode === 'auto_block_game') {
    hint.innerHTML =
      '<strong style="color:var(--accent-amber);">REAL-TIME PREVENTION ACTIVE:</strong> Game servers are automatically blocked on packet arrival while normal work internet keeps working.';
  } else {
    hint.textContent =
      'Real-time alerts appear when a game opens; click Block buttons to shut off the game or user Wi-Fi.';
  }
}

function showGameDetectedToast(detection) {
  if (!detection || !detection.gameName) return;
  if (detection.id) seenActiveSessionIds.add(detection.id);
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
        <span class="game-toast-badge">${isAuto ? '🛡️ AUTO-PREVENTED IN REAL TIME' : `${esc(detection.gameIcon || '🎮')} GAME DETECTED`}</span>
        <button type="button" class="game-toast-close" onclick="dismissGameToast('${esc(toastId)}')" aria-label="Close">✕</button>
      </div>
      <div class="game-toast-title">${esc(detection.gameName)} ${isAuto ? 'blocked' : 'opened'}</div>
      <div class="game-toast-meta">
        <div><strong>Device:</strong> ${esc(detection.deviceName)} <span class="mono">(${esc(detection.ip)})</span></div>
        <div><strong>Connected To:</strong> 📡 ${esc(detection.connectedTo)}</div>
        <div class="dev-row-sub">Trigger: ${esc(detection.matchedIndicator || '')} · ${esc(detection.detectionMethod || '')}</div>
      </div>
      <div class="game-toast-actions">
        ${
          isAuto
            ? ''
            : `<button type="button" class="btn btn-secondary btn-xs" style="border-color:var(--accent-red); color:var(--accent-red); font-weight:700;" onclick="shutOffGameFromToast('${esc(toastId)}', '${esc(detection.id || '')}', '${esc(detection.ip || '')}', '${esc(detection.gameId || '')}')">🛑 Shut Off Game &amp; Wi-Fi</button>`
        }
        <button type="button" class="btn btn-primary btn-xs" onclick="jumpToGamingWorkspace('${esc(toastId)}')">View Game Log</button>
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
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Scanning LAN...';
  }
  try {
    const res = await apiJson('/api/gaming/scan', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    if (Array.isArray(res.detections) && res.detections.length) {
      showGameDetectedToast(res.detections[0]);
    }
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔍 Scan Connected Devices Now';
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
  scope = 'device_wifi_cut',
  cutWifi = true
) {
  try {
    const res = await apiJson('/api/gaming/block', {
      method: 'POST',
      body: JSON.stringify({
        sessionId: sessionId || '',
        ip: ip || '',
        gameId: gameId || '',
        scope: scope || 'device_wifi_cut',
        cutWifi: Boolean(cutWifi)
      })
    });
    if (res.gameActivity) appState.gameActivity = res.gameActivity;
    renderGamingSection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function shutOffGameFromToast(toastId, sessionId, ip, gameId) {
  dismissGameToast(toastId);
  await shutOffGameSession(sessionId, ip, gameId, 'device_wifi_cut', true);
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
    btn.textContent = '⏳ Configuring...';
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
      btn.textContent = '⚡ Setup Whole-Wi-Fi Interception';
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
      const activeLogs = (activity.logs || []).filter(x => x && x.isActive && !x.isBlocked);
      if (gameBaselineSeeded) {
        for (const item of activeLogs) {
          if (item.id && !seenActiveSessionIds.has(item.id)) {
            seenActiveSessionIds.add(item.id);
            showGameDetectedToast(item);
          }
        }
      }
      renderGamingSection();
    }
  } catch (_) {
  } finally {
    gameAutoPollInFlight = false;
  }
}

setInterval(refreshGameActivityAuto, 2000);
