// Pulse Network Monitor — Application Bootstrapper, Sidebar Navigation & Real-Time SSE Stream

const ALL_SECTION_IDS = [
  'overviewHeadlineCard',
  'overviewKpiStrip',
  'downedDevicesTriageCard',
  'topologySection',
  'notificationsCard',
  'routerSection',
  'lanAssetsSection',
  'ispSection',
  'pingGraphSection',
  'nmapSection',
  'toolkitSection',
  'eventsSection',
  'gamingSection'
];

const OVERVIEW_SECTION_IDS = [
  'overviewHeadlineCard',
  'overviewKpiStrip',
  'pingGraphSection'
];

const WORKSPACE_SECTIONS_MAP = {
  overview: OVERVIEW_SECTION_IDS,
  triage: ['downedDevicesTriageCard'],
  topology: ['topologySection'],
  devices: ['lanAssetsSection'],
  internet: ['ispSection', 'routerSection'],
  alerts: ['notificationsCard'],
  ping: ['pingGraphSection'],
  nmap: ['nmapSection'],
  toolkit: ['toolkitSection'],
  events: ['eventsSection'],
  gaming: ['gamingSection']
};

const WORKSPACE_META_MAP = {
  overview: {
    tag: 'Overview',
    sub: 'Network health, device inventory, and internet response times'
  },
  triage: {
    tag: 'Device Health',
    sub: 'Connectivity checks for routers, access points, and switches'
  },
  topology: {
    tag: 'Network Map',
    sub: 'Network links and device health'
  },
  devices: {
    tag: 'Devices',
    sub: 'Monitored and discovered devices'
  },
  internet: {
    tag: 'Internet & Routers',
    sub: 'WAN traffic, ISP tests, and router port status'
  },
  alerts: {
    tag: 'Alerts',
    sub: 'Active incidents and alert history'
  },
  ping: {
    tag: 'Ping & Uptime',
    sub: 'Response times and reachability history'
  },
  nmap: {
    tag: 'Port Checks',
    sub: 'Review exposed services on managed devices'
  },
  toolkit: {
    tag: 'Connection Tools',
    sub: 'Traceroute, DNS lookup, and TCP checks'
  },
  events: {
    tag: 'Event Log',
    sub: 'Network changes, outages, and recoveries'
  },
  gaming: {
    tag: 'Game Detector',
    sub: 'Detected game activity and device restrictions'
  }
};

const DEVICE_FILTERS = new Set(['all', 'connected', 'favorites', 'new', 'ignored', 'down', 'offline', 'disconnected', 'archived', 'monitored']);
let currentWorkspace = 'overview';
let dashboardSnapshotRequest = null;
let lastDashboardUpdate = 0;
let lastDashboardSample = 0;
let snapshotFailed = false;
let deviceLookupRows = [];

function syncMobileSidebar() {
  const sidebar = document.getElementById('appSidebar');
  const button = document.getElementById('btnMobileMenu');
  const open = sidebar.classList.contains('open');
  sidebar.inert = window.matchMedia('(max-width: 960px)').matches && !open;
  button.setAttribute('aria-expanded', String(open));
  button.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
}

function toggleMobileSidebar() {
  const side = document.getElementById('appSidebar');
  const backdrop = document.getElementById('mobileNavBackdrop');
  if (!side) return;
  const opening = !side.classList.contains('open');
  side.classList.toggle('open', opening);
  if (backdrop) backdrop.classList.toggle('open', opening);
  syncMobileSidebar();
  if (opening) side.querySelector('[aria-current="page"]')?.focus();
}

function closeMobileSidebar(restoreFocus = false) {
  const side = document.getElementById('appSidebar');
  const backdrop = document.getElementById('mobileNavBackdrop');
  const wasOpen = side?.classList.contains('open');
  if (side) side.classList.remove('open');
  if (backdrop) backdrop.classList.remove('open');
  syncMobileSidebar();
  if (wasOpen && restoreFocus) document.getElementById('btnMobileMenu').focus();
}

function navigateSidebar(target, event, updateUrl = true) {
  if (event && (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)) return;
  if (event) event.preventDefault();
  const mobileWasOpen = document.getElementById('appSidebar').classList.contains('open');
  closeMobileSidebar();
  if (target === 'router') target = 'internet';
  if (!Object.hasOwn(WORKSPACE_SECTIONS_MAP, target)) target = 'overview';
  currentWorkspace = target;
  if (updateUrl) setWorkspaceHash(target);
  if (typeof resetSlaHoverTooltips === 'function') resetSlaHoverTooltips();
  const visibleIds = WORKSPACE_SECTIONS_MAP[target] || OVERVIEW_SECTION_IDS;

  ALL_SECTION_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.style.display = visibleIds.includes(id) ? '' : 'none';
    }
  });

  document.querySelectorAll('#sidebarWorkspaceNav [data-nav]').forEach(link => {
    const active = link.getAttribute('data-nav') === target;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });

  const meta = WORKSPACE_META_MAP[target] || WORKSPACE_META_MAP.overview;
  const tagEl = document.getElementById('headerActiveBreadcrumb');
  const subEl = document.getElementById('headerActiveSub');
  if (tagEl) {
    tagEl.textContent = meta.tag;
    if (mobileWasOpen) tagEl.focus({preventScroll: true});
  }
  if (subEl) subEl.textContent = meta.sub;
  document.title = `${meta.tag} | Vertex Sentry`;

  window.scrollTo({ top: 0, behavior: 'instant' });

  if (
    (target === 'overview' || target === 'internet' || target === 'ping') &&
    appState.isp &&
    appState.isp.pingGraph
  ) {
    setTimeout(() => {
      drawPingChart(
        appState.isp.pingGraph.targets || [],
        appState.isp.pingGraph.timeseries || {}
      );
    }, 50);
  }
  if (target === 'internet' && typeof drawWanLiveChart === 'function') {
    setTimeout(drawWanLiveChart, 50);
  }
  if (target === 'nmap' && typeof loadNmapCatalog === 'function') {
    loadNmapCatalog();
  }
  if (target === 'events' && typeof scrollTerminalToBottom === 'function') {
    setTimeout(() => scrollTerminalToBottom(false), 30);
  }
  if (target === 'gaming' && typeof scrollGameTerminalToBottom === 'function') {
    setTimeout(() => scrollGameTerminalToBottom(true), 30);
  }
}

function selectSidebarDeviceFilter(filter, event) {
  if (event && (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey)) return;
  if (event) event.preventDefault();
  const search = document.getElementById('deviceSearchInput');
  if (search) search.value = '';
  currentDeviceSearch = '';
  selectDeviceFilter(filter, false, false);
  navigateSidebar('devices');
}

function setWorkspaceHash(target, replace = false) {
  let hash = `#${target}`;
  if (target === 'devices') {
    if (currentDeviceFilter !== 'all') hash += `/${currentDeviceFilter}`;
    const search = document.getElementById('deviceSearchInput')?.value.trim();
    if (search) hash += '?' + new URLSearchParams({q: search});
  }
  if (window.location.hash !== hash) {
    if (replace) window.history.replaceState(null, '', hash);
    else window.history.pushState(null, '', hash);
  }
}

function restoreWorkspace() {
  const [fragment, query] = window.location.hash.slice(1).split('?');
  const [section, filter] = fragment.split('/');
  const legacyFilter = section.startsWith('filter-') ? section.slice(7) : '';
  const path = window.location.pathname.slice(1);
  const target = legacyFilter || section === 'lan-assets' ? 'devices' : section || path || 'overview';
  if (target === 'devices') {
    const restoredFilter = legacyFilter || filter;
    const search = document.getElementById('deviceSearchInput');
    const restoredSearch = new URLSearchParams(query).get('q')?.slice(0, 160) || '';
    if (search) search.value = restoredSearch;
    currentDeviceSearch = restoredSearch.trim().toLowerCase();
    selectDeviceFilter(DEVICE_FILTERS.has(restoredFilter) ? restoredFilter : 'all', false, false);
  }
  navigateSidebar(target, null, false);
}

function renderDeviceLookup() {
  const input = document.getElementById('deviceLookupInput');
  const result = document.getElementById('deviceLookupResults');
  const query = input.value.trim().toLowerCase();
  const rows = buildUnifiedDeviceRows();
  deviceLookupRows = rows.filter(row => query
    ? [row.name, row.ip, row.mac, row.vendor].some(value => String(value || '').toLowerCase().includes(query))
    : row.monitored && !row.archived
  ).sort((a, b) => Number(b.ip === query) - Number(a.ip === query) || Number(a.archived) - Number(b.archived)).slice(0, 8);
  if (!deviceLookupRows.length) {
    result.textContent = query ? 'No matching devices.' : 'No monitored devices yet.';
    return;
  }
  result.innerHTML = deviceLookupRows.map((row, index) => `
    <button class="lookup-result" type="button" data-lookup-index="${index}">
      <span><strong>${esc(row.name)}</strong><small class="mono">${esc(row.ip || row.mac || '—')}</small></span>
      <span class="lookup-result-status">${row.archived ? 'Archived' : row.online ? 'Online' : row.status === 'unknown' ? 'Checking' : 'Offline'}</span>
    </button>
  `).join('');
}

function openDeviceLookup() {
  const dialog = document.getElementById('deviceLookupDialog');
  if (dialog.open) return;
  document.getElementById('deviceLookupInput').value = '';
  renderDeviceLookup();
  dialog.showModal();
}

function openLookupDevice(index) {
  const device = deviceLookupRows[index];
  if (!device) return;
  const search = document.getElementById('deviceSearchInput');
  search.value = device.ip || device.mac || device.name;
  currentDeviceSearch = search.value.toLowerCase();
  selectDeviceFilter(device.archived ? 'archived' : 'all', false, false);
  document.getElementById('deviceLookupDialog').close();
  navigateSidebar('devices');
  search.focus({preventScroll: true});
}

function renderTelemetryConnection() {
  const state = document.getElementById('telemetryState');
  const status = document.getElementById('liveStatusText');
  const time = document.getElementById('telemetryUpdatedAt');
  const fresh = lastDashboardUpdate > 0 && Date.now() - lastDashboardUpdate < 35000;
  const mode = fresh ? (gameEventStreamConnected ? 'live' : 'polling')
    : (!lastDashboardUpdate && !snapshotFailed ? 'connecting' : 'offline');
  if (state.dataset.state !== mode) {
    state.dataset.state = mode;
    status.textContent = {live: 'Live updates', polling: 'Polling', offline: 'Connection lost', connecting: 'Connecting'}[mode];
    document.getElementById('alertLiveTicker').textContent = status.textContent;
    renderExecutiveBanner();
  }
  if (lastDashboardSample) {
    const stamp = new Date(lastDashboardSample);
    const formatted = `${fresh ? 'Updated' : 'Last update'} ${stamp.toLocaleTimeString()}`;
    if (time.textContent !== formatted) {
      time.textContent = formatted;
      time.dateTime = stamp.toISOString();
      time.title = stamp.toLocaleString();
    }
    time.hidden = false;
  }
}

function noteDashboardUpdate(timestamp) {
  lastDashboardUpdate = Date.now();
  const sample = Date.parse(timestamp);
  if (Number.isFinite(sample)) lastDashboardSample = Math.max(lastDashboardSample, sample);
  renderTelemetryConnection();
}

function renderAll() {
  renderExecutiveBanner();
  renderOverviewAndLanCardsAndList();
  renderAlertsCenter();
  renderRouterSection();
  renderIspSection();
  renderPingGraphSection();
  if (typeof renderNmapDeviceChips === 'function') {
    renderNmapDeviceChips();
  }
  if (typeof renderTopologySection === 'function') {
    renderTopologySection();
  }
  if (typeof renderGamingSection === 'function') {
    renderGamingSection();
  }
  renderTimeline();
}

function loadInitialState() {
  if (dashboardSnapshotRequest) return dashboardSnapshotRequest;
  const revision = gameActivityRevision;
  const refreshButton = document.getElementById('btnRefreshDashboard');
  if (refreshButton) refreshButton.disabled = true;
  dashboardSnapshotRequest = apiJson('/api/status').then(data => {
    const { gameActivity, isp, ...state } = data;
    appState = { ...appState, ...state };
    applyIspSnapshot(isp);
    if (revision === gameActivityRevision) applyGameActivitySnapshot(gameActivity);
    snapshotFailed = false;
    noteDashboardUpdate(data.timestamp);
    renderAll();
    return true;
  }).catch(err => {
    snapshotFailed = true;
    renderTelemetryConnection();
    console.error('Failed to load status:', err);
    return false;
  }).finally(() => {
    dashboardSnapshotRequest = null;
    if (refreshButton) refreshButton.disabled = false;
  });
  return dashboardSnapshotRequest;
}

async function refreshDashboardManually() {
  const feedback = document.getElementById('dashboardRefreshFeedback');
  feedback.textContent = 'Refreshing…';
  feedback.textContent = await loadInitialState() ? 'Data refreshed' : 'Refresh failed. Try again.';
}

function initEventStream() {
  if (!window.EventSource) return;
  const es = new EventSource('/api/events');
  es.addEventListener('open', () => {
    gameEventStreamConnected = true;
    renderTelemetryConnection();
  });
  es.addEventListener('error', () => {
    gameEventStreamConnected = false;
    renderTelemetryConnection();
    refreshGameActivityAuto();
  });
  es.addEventListener('snapshot', e => {
    try {
      const { gameActivity, isp, ...state } = JSON.parse(e.data);
      appState = { ...appState, ...state };
      applyIspSnapshot(isp);
      applyGameActivitySnapshot(gameActivity);
      noteDashboardUpdate(state.timestamp);
      renderAll();
    } catch (_) {}
  });
  es.addEventListener('telemetry', e => {
    try {
      const { gameActivity, isp, ...d } = JSON.parse(e.data);
      appState = { ...appState, ...d };
      applyIspSnapshot(isp);
      applyGameActivitySnapshot(gameActivity);
      noteDashboardUpdate(d.timestamp);
      if (typeof pushTerminalTick === 'function' && Array.isArray(d.devices)) {
        const up = d.devices.filter(x => x.alive).length;
        const down = d.devices.filter(x => x.status === 'offline').length;
        pushTerminalTick(
          down > 0 ? 'WARNING' : 'LIVE',
          'DEVICE_CYCLE',
          '',
          `Checked ${d.devices.length} monitored device(s): ${up} online, ${down} down.`
        );
      }
      renderAll();
    } catch (_) {}
  });

  es.addEventListener('inventory_update', e => {
    try {
      const d = JSON.parse(e.data);
      if (d.inventory) appState.networkInventory = d.inventory;
      if (d.events) appState.networkEvents = d.events;
      if (d.devices) appState.devices = d.devices;
      if (d.routers) appState.routers = d.routers;
      if (d.activeAlerts) appState.activeAlerts = d.activeAlerts;
      if (d.alertStats) appState.alertStats = d.alertStats;
      if (d.lastDiscoveryAt) appState.lastDiscoveryAt = d.lastDiscoveryAt;
      renderAll();
    } catch (_) {}
  });
  es.addEventListener('router_update', e => {
    try {
      const d = JSON.parse(e.data);
      appState.router = d;
      if (Array.isArray(d.fleet)) {
        appState.routers = d.fleet;
      }
      renderExecutiveBanner();
      renderRouterSection();
    } catch (_) {}
  });
  es.addEventListener('isp_update', e => {
    try {
      const isp = JSON.parse(e.data);
      applyIspSnapshot(isp);
      noteDashboardUpdate(isp.probeTimestamp);
      if (typeof pushTerminalTick === 'function') {
        const live = isp.liveThroughput || {};
        pushTerminalTick(
          isp.overallHealth === 'OUTAGE' ? 'CRITICAL' : (isp.overallHealth === 'DEGRADED' ? 'WARNING' : 'LIVE'),
          'ISP_PING',
          '',
          `Internet response: ${isp.tier1LatencyMs ?? '--'} ms | Router: ${isp.wanGatewayLatencyMs ?? '--'} ms | DNS: ${isp.dnsResolutionMs ?? '--'} ms | Monitor traffic: ${fmtMbps(live.rxMbps)} ↓ / ${fmtMbps(live.txMbps)} ↑ | Unanswered probes: ${isp.probeFailurePct ?? '—'}%`
        );
      }
      renderExecutiveBanner();
      renderIspSection();
      renderPingGraphSection();
    } catch (_) {}
  });
  es.addEventListener('topology_update', e => {
    try {
      appState.topology = JSON.parse(e.data);
      if (typeof renderTopologySection === 'function') {
        renderTopologySection();
      }
    } catch (_) {}
  });
  es.addEventListener('game_detected', e => {
    try {
      const d = JSON.parse(e.data);
      applyGameActivitySnapshot(d.gameActivity);
      applyLiveGameDetection(d.detection, d.updated);
      applyEndedGameSessions(d.endedSessionIds);
      renderGamingSection();
      if (d.gameActivity) renderGatewayClients();
      if (d.detection && !d.updated && !d.gameActivity) refreshGameActivityAuto(true);
    } catch (_) {}
  });
  ['new_alert', 'resolved_alert', 'alert_updated', 'alert_dismissed'].forEach(evName => {
    es.addEventListener(evName, () => {
      try {
        loadInitialState();
      } catch (_) {}
    });
  });
  es.addEventListener('network_event', e => {
    try {
      const ev = JSON.parse(e.data);
      if (typeof pushLiveNetworkEvent === 'function') {
        pushLiveNetworkEvent(ev);
      }
    } catch (_) {}
  });
  es.addEventListener('events_cleared', () => {
    appState.networkEvents = [];
    if (typeof liveTerminalTicks !== 'undefined') {
      liveTerminalTicks = [];
    }
    if (typeof renderTimeline === 'function') renderTimeline();
  });
  es.addEventListener('wan_throughput', e => {
    try {
      const liveThroughput = JSON.parse(e.data);
      applyLiveIspTelemetry({liveThroughput});
      noteDashboardUpdate(liveThroughput.timestamp);
      renderLiveIspTelemetry();
    } catch (_) {}
  });
  es.addEventListener('router_wan_throughput', e => {
    try {
      applyLiveIspTelemetry({routerWanThroughput: JSON.parse(e.data)});
      renderLiveIspTelemetry();
    } catch (_) {}
  });
  es.addEventListener('speedtest_progress', e => {
    try {
      const d = JSON.parse(e.data);
      handleSpeedTestProgress(d);
    } catch (_) {}
  });
  es.addEventListener('speedtest_result', e => {
    try {
      const st = JSON.parse(e.data);
      if (!appState.isp) appState.isp = {};
      appState.isp.lastSpeedTest = st;
      handleSpeedTestProgress({
        ...st,
        phase: 'complete',
        currentMbps: st.downloadMbps,
        downloadMbps: st.downloadMbps,
        uploadMbps: st.uploadMbps,
        pingMs: st.pingMs,
        jitterMs: st.jitterMs,
        rating: st.rating,
        progressPct: 100,
        message: `Speed Test Complete — ${st.downloadMbps} Mbps Down / ${
          st.uploadMbps ?? '--'
        } Mbps Up`
      });
      renderIspSection();
    } catch (_) {}
  });
  es.addEventListener('portscan_progress', e => {
    try {
      const d = JSON.parse(e.data);
      if (typeof handlePortScanProgress === 'function') {
        handlePortScanProgress(d);
      }
    } catch (_) {}
  });
  es.addEventListener('portscan_complete', e => {
    try {
      const report = JSON.parse(e.data);
      if (typeof renderNmapScanReport === 'function') {
        renderNmapScanReport(report);
      }
    } catch (_) {}
  });
}

async function promoteLanDeviceAsInfra(ip, mac, encodedName) {
  const rawName = encodedName ? decodeURIComponent(encodedName) : ip;
  const cleanName =
    rawName && !/^unknown|^generic/i.test(rawName)
      ? rawName
      : `Deployed AP · ${ip}`;
  const defaultRole = /deco|router|gateway|mikrotik|edgerouter/i.test(cleanName)
    ? 'router'
    : 'ap';
  if (
    !window.confirm(
      `Track "${cleanName}" (${ip}) as a Monitored ${
        defaultRole === 'router' ? 'Router / Mesh Node' : 'Access Point'
      }?\n\nThis pins it for continuous real-time uptime & latency checks.`
    )
  ) {
    return;
  }
  try {
    const res = await fetch('/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: cleanName,
        ip,
        mac: mac || '',
        type: defaultRole,
        manual: true,
        critical: true,
        location: 'LAN · Promoted Infrastructure',
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      window.alert(data.error || `Failed to track ${ip} (${res.status})`);
      return;
    }
    if (data && data.id) {
      await fetch(`/api/devices/${encodeURIComponent(data.id)}/probe`, {
        method: 'POST',
      }).catch(() => {});
    }
    if (typeof loadInitialState === 'function') {
      await loadInitialState();
    } else {
      renderAll();
    }
  } catch (err) {
    window.alert(err.message || `Failed to track ${ip}`);
  }
}

async function deleteMonitoredDevice(deviceId, encodedName, ip) {
  const label =
    (encodedName ? decodeURIComponent(encodedName) : '') || ip || deviceId;
  if (
    !window.confirm(
      `Remove "${label}"${ip ? ` (${ip})` : ''} from Monitored Infrastructure?\n\nUse this for pulled-out or decommissioned APs/routers. Active alerts for this device will be cleared.`
    )
  ) {
    return;
  }
  try {
    const res = await fetch(
      `/api/devices/${encodeURIComponent(deviceId)}`,
      { method: 'DELETE' }
    );
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      window.alert(data.error || `Failed to remove ${label} (${res.status})`);
      return;
    }
    if (typeof loadInitialState === 'function') {
      await loadInitialState();
    } else {
      renderAll();
    }
  } catch (err) {
    window.alert(err.message || `Failed to remove ${label}`);
  }
}

async function removeRouterFromFleet(ip) {
  const dev = (appState.devices || []).find(d => d.ip === ip);
  if (!dev || !dev.id) {
    window.alert(
      `Router ${ip} does not have a removable monitored device entry.`
    );
    return;
  }
  await deleteMonitoredDevice(
    dev.id,
    encodeURIComponent(dev.name || ip),
    ip
  );
}

document.addEventListener('DOMContentLoaded', () => {
  const html = document.documentElement;
  const savedTheme = localStorage.getItem('pulse_theme');
  if (savedTheme === 'light' || savedTheme === 'dark') {
    html.setAttribute('data-theme', savedTheme);
  }
  const themeIconEl = document.getElementById('themeIcon');
  if (themeIconEl) {
    themeIconEl.textContent =
      html.getAttribute('data-theme') === 'light' ? '🌙' : '☀️';
  }

  const themeBtn = document.getElementById('btnThemeToggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next =
        html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      html.setAttribute('data-theme', next);
      localStorage.setItem('pulse_theme', next);
      if (themeIconEl) {
        themeIconEl.textContent = next === 'light' ? '🌙' : '☀️';
      }
      if (typeof renderPingGraphSection === 'function') {
        renderPingGraphSection();
      }
      if (typeof drawWanLiveChart === 'function') {
        drawWanLiveChart();
      }
    });
  }

  const savedCvd = localStorage.getItem('pulse_cvd') === 'true';
  const cvdLabelEl = document.getElementById('cvdModeLabel');
  if (savedCvd) {
    html.setAttribute('data-cvd', 'true');
    if (cvdLabelEl) cvdLabelEl.textContent = 'Colors: Safe';
  }
  const cvdBtn = document.getElementById('btnCvdToggle');
  if (cvdBtn) {
    cvdBtn.addEventListener('click', () => {
      const isOn = html.getAttribute('data-cvd') === 'true';
      const next = !isOn;
      if (next) {
        html.setAttribute('data-cvd', 'true');
      } else {
        html.removeAttribute('data-cvd');
      }
      localStorage.setItem('pulse_cvd', String(next));
      if (cvdLabelEl) {
        cvdLabelEl.textContent = next ? 'Colors: Safe' : 'Colors: Auto';
      }
      if (typeof renderPingGraphSection === 'function') {
        renderPingGraphSection();
      }
      if (typeof drawWanLiveChart === 'function') {
        drawWanLiveChart();
      }
    });
  }

  const sidebarMedia = window.matchMedia('(max-width: 960px)');
  sidebarMedia.addEventListener('change', () => closeMobileSidebar());
  document.getElementById('deviceLookupInput').addEventListener('input', renderDeviceLookup);
  document.getElementById('deviceLookupInput').addEventListener('keydown', event => {
    if (event.key === 'Enter' && deviceLookupRows.length) {
      event.preventDefault();
      openLookupDevice(0);
    }
  });
  document.getElementById('deviceLookupResults').addEventListener('click', event => {
    const entry = event.target.closest('[data-lookup-index]');
    if (entry) openLookupDevice(Number(entry.dataset.lookupIndex));
  });
  const settings = document.getElementById('headerSettings');
  document.addEventListener('click', event => {
    if (settings.open && (!settings.contains(event.target) || event.target.closest('#btnRouterConfig'))) settings.open = false;
  });
  document.addEventListener('keydown', event => {
    if (event.defaultPrevented) return;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openDeviceLookup();
    } else if (event.key === 'Escape' && document.getElementById('appSidebar').classList.contains('open')) {
      closeMobileSidebar(true);
    } else if (event.key === 'Escape' && settings.open) {
      settings.open = false;
      settings.querySelector('summary').focus();
    }
  });
  window.addEventListener('hashchange', restoreWorkspace);
  restoreWorkspace();
  loadInitialState();
  if (typeof loadNmapCatalog === 'function') {
    loadNmapCatalog();
  }
  initEventStream();
  setInterval(() => { if (!document.hidden) loadInitialState(); }, 15000);
  setInterval(renderTelemetryConnection, 2000);
  let livePollInProgress = false;
  setInterval(async () => {
    if (document.hidden) return;
    const hostAge = Date.now() - Date.parse(appState.isp?.liveThroughput?.timestamp);
    if (gameEventStreamConnected && hostAge < 4000) return;
    renderLiveIspTelemetry();
    if (livePollInProgress) return;
    livePollInProgress = true;
    try {
      applyLiveIspTelemetry(await apiJson('/api/isp/live'));
      renderLiveIspTelemetry();
    } catch (_) {
      // Stale readouts stay blank until telemetry resumes.
    } finally {
      livePollInProgress = false;
    }
  }, 2000);
  setInterval(() => {
    if (
      currentWorkspace === 'events' && !document.hidden && !gameEventStreamConnected &&
      typeof eventsAutoRefresh !== 'undefined' &&
      eventsAutoRefresh &&
      typeof refreshNetworkLogsNow === 'function'
    ) {
      refreshNetworkLogsNow();
    }
  }, 5000);
  window.addEventListener('resize', () => {
    if (appState.isp && appState.isp.pingGraph) {
      drawPingChart(
        appState.isp.pingGraph.targets || [],
        appState.isp.pingGraph.timeseries || {}
      );
    }
  });
});
