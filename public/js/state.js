// Pulse Network Monitor — Shared State, API Helper, and Unified Device Row Builder

var appState = {
  router: null,
  routers: [],
  selectedRouterIp: null,
  isp: null,
  devices: [],
  activeAlerts: [],
  alertsHistory: [],
  alertStats: {},
  networkInventory: [],
  networkEvents: [],
  topology: { nodes: [], links: [], summary: {}, logs: [] },
  gameActivity: { logs: [], blocks: [], summary: {}, catalog: [] },
  lastDiscoveryAt: null,
  config: {}
};

let currentDeviceFilter = 'all';
let currentDeviceSearch = '';
let currentAlertFilter = 'all';
let currentAlertSearch = '';
let hiddenChartSeries = new Set();

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inlineString(value) {
  return esc(JSON.stringify(String(value ?? '')));
}

let pressedDashboardControl = null;
let dashboardReleaseTimer;
const deferredControlRenders = new Map();
const renderedControlMarkup = new WeakMap();

function deferDashboardControlRender(region, render) {
  if (!pressedDashboardControl?.isConnected || !region.contains(pressedDashboardControl)) return false;
  deferredControlRenders.set(region, render);
  return true;
}

function renderDashboardControls(region, markup) {
  if (renderedControlMarkup.get(region) === markup) {
    deferredControlRenders.delete(region);
    return;
  }
  if (deferDashboardControlRender(region, () => renderDashboardControls(region, markup))) return;
  const focused = document.activeElement;
  const action = region.contains(focused) ? focused.getAttribute('onclick') : null;
  region.innerHTML = markup;
  renderedControlMarkup.set(region, markup);
  if (action) {
    const replacement = [...region.querySelectorAll('[onclick]')].find(el => el.getAttribute('onclick') === action);
    replacement?.focus({preventScroll: true});
  }
}

function releaseDashboardControl(delay) {
  clearTimeout(dashboardReleaseTimer);
  dashboardReleaseTimer = setTimeout(() => {
    pressedDashboardControl = null;
    const renders = [...deferredControlRenders.values()];
    deferredControlRenders.clear();
    renders.forEach(render => render());
  }, delay);
}

document.addEventListener('pointerdown', event => {
  if (!event.isPrimary || event.button !== 0) return;
  clearTimeout(dashboardReleaseTimer);
  pressedDashboardControl = event.target.closest?.('button, a, summary, [data-topo-node-id], .topo-link-hit');
}, true);
document.addEventListener('pointerup', event => {
  if (event.isPrimary) releaseDashboardControl(200);
}, true);
document.addEventListener('pointercancel', event => {
  if (event.isPrimary) releaseDashboardControl(0);
}, true);
document.addEventListener('click', () => releaseDashboardControl(0), true);
window.addEventListener('blur', () => releaseDashboardControl(0));

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

async function apiJson(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

// Combine monitored devices and discovered LAN inventory into unified list rows
function buildUnifiedDeviceRows() {
  const invByIp = new Map();
  const invByMac = new Map();
  for (const item of appState.networkInventory || []) {
    if (!item?.ip) continue;
    if (item.mac) invByMac.set(item.mac.toLowerCase(), item);
    const previous = invByIp.get(item.ip);
    if (!previous || (item.isOnline && !previous.isOnline)) invByIp.set(item.ip, item);
  }

  const rows = [];
  const mergedInventory = new Set();

  for (const dev of appState.devices || []) {
    const ip = dev.ip;
    const atAddress = invByIp.get(ip);
    const match = dev.mac ? invByMac.get(dev.mac.toLowerCase()) : atAddress?.isOnline ? atAddress : null;
    const asset = match?.ip === ip ? match : {};
    if (asset.mac) mergedInventory.add(asset.mac);
    const mac = dev.mac || asset.mac || '';
    const assetKey = mac ? `mac:${mac.toLowerCase()}` : `ip:${ip}`;
    const status = dev.status || 'unknown';
    const online = dev.directlyReachable ?? (status === 'online' || status === 'warning');
    rows.push({
      id: dev.id,
      name: dev.name || ip,
      ip,
      mac,
      observedMac: asset.isOnline ? (asset.observedMac ?? '') : '',
      vendor: dev.vendor || asset.vendor || (dev.type ? dev.type.toUpperCase() : 'Monitored Equipment'),
      location: dev.location || 'Office Network',
      subnet: dev.subnet || '',
      hardwareModel: dev.hardwareModel || '',
      httpProtocol: dev.httpProtocol || 'http',
      snmpSysName: dev.snmpSysName || '',
      type: dev.type || 'device',
      port: dev.port || 80,
      monitored: true,
      online,
      directlyReachable: dev.directlyReachable ?? online,
      status,
      connectivityState: dev.connectivityState || (status === 'offline' ? 'DEVICE_DOWN' : 'UNKNOWN'),
      hasInternet: dev.hasInternet ?? null,
      probeMethod: dev.probeMethod || '',
      openPorts: Array.isArray(dev.openPorts) ? dev.openPorts : [],
      diagnosisTitle: dev.diagnosisTitle || '',
      likelyFault: dev.likelyFault || '',
      diagnosisSummary: dev.diagnosisSummary || '',
      fixSteps: Array.isArray(dev.fixSteps) ? dev.fixSteps : [],
      latencyMs: dev.latencyMs ?? dev.avgLatencyMs ?? null,
      avgLatencyMs: dev.avgLatencyMs ?? dev.latencyMs ?? null,
      packetLossPct: dev.packetLossPct ?? null,
      jitterMs: dev.jitterMs ?? null,
      favorite: Boolean(dev.favorite || asset.favorite),
      archived: Boolean(dev.archived || asset.archived),
      assetKey,
      favoriteKey: (dev.favorite && dev.favoriteKey) || (asset.favorite && asset.favoriteKey) || assetKey,
      authorized: true,
      isNew: false,
      customName: asset.customName || '',
      role: asset.role || '',
      notes: asset.notes || '',
      apAssociation: asset.apAssociation || null,
      firstSeen: asset.firstSeen || '',
      lastProbeAt: dev.lastChecked || '',
      probeIntervalSec: dev.probeIntervalSec,
      lastSeen: dev.lastChecked || asset.lastSeen || ''
    });
  }

  for (const asset of appState.networkInventory || []) {
    if (!asset || !asset.ip || mergedInventory.has(asset.mac)) continue;
    const online = Boolean(asset.isOnline);
    const mac = asset.mac || '';
    const assetKey = mac ? `mac:${mac.toLowerCase()}` : `ip:${asset.ip}`;
    const vendorName =
      asset.vendor && !asset.vendor.toLowerCase().includes('unknown') ? asset.vendor : 'LAN Client';
    rows.push({
      id: null,
      name: asset.customName || asset.name || asset.suggestedName || asset.ip,
      ip: asset.ip,
      mac,
      observedMac: asset.observedMac ?? mac,
      vendor: vendorName,
      location: asset.arpType === 'icmp' ? 'ICMP echo'
        : asset.arpType === 'dhcp' ? 'Router DHCP'
        : asset.arpType ? 'ARP cache' : 'LAN discovery',
      type: 'lan-client',
      port: null,
      monitored: false,
      online,
      status: online ? 'online' : 'offline',
      latencyMs: null,
      packetLossPct: null,
      jitterMs: null,
      favorite: Boolean(asset.favorite),
      archived: Boolean(asset.archived),
      assetKey,
      favoriteKey: asset.favoriteKey || assetKey,
      authorized: Boolean(asset.authorized),
      isNew: Boolean(!asset.authorized && !asset.reviewIgnored),
      reviewIgnored: Boolean(!asset.authorized && asset.reviewIgnored),
      customName: asset.customName || '',
      role: asset.role || '',
      notes: asset.notes || '',
      apAssociation: asset.apAssociation || null,
      firstSeen: asset.firstSeen || '',
      lastSeen: asset.lastSeen || ''
    });
  }

  rows.sort((a, b) => {
    const aDown = a.monitored && a.status === 'offline' ? 0 : 1;
    const bDown = b.monitored && b.status === 'offline' ? 0 : 1;
    if (aDown !== bDown) return aDown - bDown;
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    if (a.monitored !== b.monitored) return a.monitored ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return rows;
}

