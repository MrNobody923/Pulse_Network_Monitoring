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
  triage: ['overviewHeadlineCard', 'downedDevicesTriageCard'],
  topology: ['overviewHeadlineCard', 'topologySection'],
  devices: ['overviewHeadlineCard', 'lanAssetsSection'],
  internet: ['overviewHeadlineCard', 'ispSection', 'routerSection'],
  // Legacy alias: Chassis & Switchports now lives on the combined WAN/ISP page
  router: ['overviewHeadlineCard', 'ispSection', 'routerSection'],
  alerts: ['overviewHeadlineCard', 'notificationsCard'],
  ping: ['overviewHeadlineCard', 'pingGraphSection'],
  nmap: ['overviewHeadlineCard', 'nmapSection'],
  toolkit: ['overviewHeadlineCard', 'toolkitSection'],
  events: ['overviewHeadlineCard', 'eventsSection'],
  gaming: ['overviewHeadlineCard', 'gamingSection']
};

const WORKSPACE_META_MAP = {
  overview: {
    tag: 'NETWORK OVERVIEW',
    sub: 'Live Network Health, Connected Devices & Connection Speed Monitoring'
  },
  triage: {
    tag: 'WI-FI & SWITCH CHECK',
    sub: 'Check Which Wi-Fi Points, Switches & Routers Are Down or Need Attention'
  },
  topology: {
    tag: 'NETWORK MAP (TOPOLOGY)',
    sub: 'Visual Map of Your Company Network, Offline Devices & Event History'
  },
  devices: {
    tag: 'ALL NETWORK DEVICES',
    sub: 'All Company Routers, Wi-Fi Points, Switches & Connected Computers'
  },
  internet: {
    tag: 'INTERNET & ROUTERS',
    sub: 'Real-Time Internet Speed, Ping, Website Lookup & Company Router Status'
  },
  alerts: {
    tag: 'PROBLEMS & ALERTS',
    sub: 'Shows What Is Down or Slow Right Now, With Plain-English Causes & Fixes'
  },
  ping: {
    tag: 'PING & UPTIME',
    sub: 'Live Internet Response Time (Ping), Uptime History & Drop Log'
  },
  nmap: {
    tag: 'PORT SECURITY CHECK',
    sub: 'Check Devices for Open Ports, Risky Services & Simple Security Fixes'
  },
  toolkit: {
    tag: 'CONNECTION TEST TOOLS',
    sub: 'Trace Internet Path, Test Website Lookup Speed & Check Specific Ports'
  },
  events: {
    tag: 'LIVE NETWORK LOGS',
    sub: 'Real-time stream of network outages, recoveries, new devices & scans'
  },
  gaming: {
    tag: 'MOBILE GAME DETECTOR',
    sub: 'Real-Time Alerts When Connected Devices Open Mobile or Online Games'
  }
};

function toggleMobileSidebar() {
  const side = document.getElementById('appSidebar');
  const backdrop = document.getElementById('mobileNavBackdrop');
  if (!side) return;
  const opening = !side.classList.contains('open');
  side.classList.toggle('open', opening);
  if (backdrop) backdrop.classList.toggle('open', opening);
}

function closeMobileSidebar() {
  const side = document.getElementById('appSidebar');
  const backdrop = document.getElementById('mobileNavBackdrop');
  if (side) side.classList.remove('open');
  if (backdrop) backdrop.classList.remove('open');
}

function navigateSidebar(target, event) {
  if (event) event.preventDefault();
  closeMobileSidebar();
  if (target === 'router') target = 'internet';
  if (typeof resetSlaHoverTooltips === 'function') resetSlaHoverTooltips();
  const visibleIds = WORKSPACE_SECTIONS_MAP[target] || OVERVIEW_SECTION_IDS;

  ALL_SECTION_IDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.style.display = visibleIds.includes(id) ? '' : 'none';
    }
  });

  document.querySelectorAll('#sidebarWorkspaceNav [data-nav]').forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-nav') === target);
  });

  const meta = WORKSPACE_META_MAP[target] || WORKSPACE_META_MAP.overview;
  const tagEl = document.getElementById('headerActiveBreadcrumb');
  const subEl = document.getElementById('headerActiveSub');
  if (tagEl) tagEl.textContent = meta.tag;
  if (subEl) subEl.textContent = meta.sub;

  window.scrollTo({ top: 0, behavior: 'smooth' });

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
  if (event) event.preventDefault();
  closeMobileSidebar();
  navigateSidebar('devices');
  selectDeviceFilter(filter, true);
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

async function loadInitialState() {
  try {
    const data = await apiJson('/api/status');
    appState = { ...appState, ...data };
    renderAll();
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

function initEventStream() {
  if (!window.EventSource) return;
  const es = new EventSource('/api/events');
  es.addEventListener('snapshot', e => {
    try {
      appState = { ...appState, ...JSON.parse(e.data) };
      renderAll();
    } catch (_) {}
  });
  es.addEventListener('telemetry', e => {
    try {
      const d = JSON.parse(e.data);
      appState = { ...appState, ...d };
      if (d.gameActivity && typeof notifyUnseenActiveGames === 'function') {
        notifyUnseenActiveGames(d.gameActivity);
      }
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
  window.promoteLanDeviceAsInfra = async function (ip, mac, encodedName) {
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
  };

  window.deleteMonitoredDevice = async function (deviceId, encodedName, ip) {
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
  };

  window.removeRouterFromFleet = async function (ip) {
    const dev = (appState.devices || []).find(d => d.ip === ip);
    if (!dev || !dev.id) {
      window.alert(
        `Router ${ip} does not have a removable monitored device entry.`
      );
      return;
    }
    await window.deleteMonitoredDevice(
      dev.id,
      encodeURIComponent(dev.name || ip),
      ip
    );
  };

  es.addEventListener('inventory_update', e => {
    try {
      const d = JSON.parse(e.data);
      if (d.inventory) appState.networkInventory = d.inventory;
      if (d.events) appState.networkEvents = d.events;
      if (d.devices) appState.devices = d.devices;
      if (d.routers) appState.routers = d.routers;
      if (d.activeAlerts) appState.activeAlerts = d.activeAlerts;
      if (d.alertStats) appState.alertStats = d.alertStats;
      appState.lastDiscoveryAt = new Date().toISOString();
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
      appState.isp = isp;
      if (typeof pushTerminalTick === 'function') {
        const live = isp.liveThroughput || {};
        const rxMB = ((Number(live.rxMbps) || 0) / 8).toFixed(2);
        const txMB = ((Number(live.txMbps) || 0) / 8).toFixed(2);
        pushTerminalTick(
          isp.overallHealth === 'OUTAGE' ? 'CRITICAL' : (isp.overallHealth === 'DEGRADED' ? 'WARNING' : 'LIVE'),
          'ISP_PING',
          '',
          `Internet Ping: ${isp.tier1LatencyMs ?? '--'} ms | Router: ${isp.wanGatewayLatencyMs ?? '--'} ms | DNS: ${isp.dnsResolutionMs ?? '--'} ms | Speed: ${rxMB} MB/s ↓ / ${txMB} MB/s ↑ | Loss: ${isp.packetLossPct ?? 0}%`
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
      if (d.gameActivity) appState.gameActivity = d.gameActivity;
      if (typeof renderGamingSection === 'function') renderGamingSection();
      if (d.detection && typeof showGameDetectedToast === 'function') {
        showGameDetectedToast(d.detection);
      } else if (d.gameActivity && typeof notifyUnseenActiveGames === 'function') {
        notifyUnseenActiveGames(d.gameActivity);
      }
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
      handleWanThroughput(JSON.parse(e.data));
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

  const hashTab = (window.location.hash || '').replace(/^#/, '');
  const initialTab =
    WORKSPACE_SECTIONS_MAP[hashTab]
      ? hashTab
      : window.location.pathname === '/triage'
      ? 'triage'
      : window.location.pathname === '/devices'
      ? 'devices'
      : window.location.pathname === '/events'
      ? 'events'
      : 'overview';
  navigateSidebar(initialTab);
  loadInitialState();
  if (typeof loadNmapCatalog === 'function') {
    loadNmapCatalog();
  }
  initEventStream();
  setInterval(loadInitialState, 15000);
  setInterval(() => {
    if (
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
