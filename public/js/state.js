// Pulse Network Monitor — Shared State, API Helper, and Unified Device Row Builder

let appState = {
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
  for (const item of appState.networkInventory || []) {
    if (item && item.ip && !invByIp.has(item.ip)) invByIp.set(item.ip, item);
  }

  const rows = [];
  const monitoredIps = new Set();

  for (const dev of appState.devices || []) {
    const ip = dev.ip;
    monitoredIps.add(ip);
    const asset = invByIp.get(ip) || {};
    const mac = dev.mac || asset.mac || '';
    const status = dev.status || 'unknown';
    const online = dev.alive === true || status === 'online' || status === 'warning';
    rows.push({
      id: dev.id,
      name: dev.name || ip,
      ip,
      mac,
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
      status,
      connectivityState: dev.connectivityState || (online ? 'ONLINE_WITH_INTERNET' : 'DEVICE_DOWN'),
      hasInternet: dev.hasInternet !== undefined ? Boolean(dev.hasInternet) : online,
      probeMethod: dev.probeMethod || '',
      openPorts: Array.isArray(dev.openPorts) ? dev.openPorts : [],
      diagnosisTitle: dev.diagnosisTitle || '',
      likelyFault: dev.likelyFault || '',
      diagnosisSummary: dev.diagnosisSummary || '',
      fixSteps: Array.isArray(dev.fixSteps) ? dev.fixSteps : [],
      latencyMs: dev.latencyMs ?? dev.avgLatencyMs ?? null,
      avgLatencyMs: dev.avgLatencyMs ?? dev.latencyMs ?? null,
      packetLossPct: dev.packetLossPct ?? 0,
      jitterMs: dev.jitterMs ?? 0,
      favorite: Boolean(dev.favorite || asset.favorite),
      archived: Boolean(dev.archived || asset.archived),
      favoriteKey: mac ? `mac:${mac.toLowerCase()}` : `ip:${ip}`,
      authorized: true,
      isNew: false,
      firstSeen: asset.firstSeen || '',
      lastSeen: dev.lastChecked || asset.lastSeen || ''
    });
  }

  for (const asset of appState.networkInventory || []) {
    if (!asset || !asset.ip || monitoredIps.has(asset.ip)) continue;
    const online = Boolean(asset.isOnline);
    const mac = asset.mac || '';
    const vendorName =
      asset.vendor && !asset.vendor.toLowerCase().includes('unknown') ? asset.vendor : 'LAN Client';
    rows.push({
      id: null,
      name: asset.name || asset.suggestedName || asset.ip,
      ip: asset.ip,
      mac,
      vendor: vendorName,
      location: asset.arpType ? `ARP (${asset.arpType})` : 'LAN / Wi-Fi',
      type: 'lan-client',
      port: null,
      monitored: false,
      online,
      status: online ? 'online' : 'offline',
      latencyMs: null,
      packetLossPct: online ? 0 : 100,
      jitterMs: null,
      favorite: Boolean(asset.favorite),
      archived: Boolean(asset.archived),
      favoriteKey: mac ? `mac:${mac.toLowerCase()}` : `ip:${asset.ip}`,
      authorized: Boolean(asset.authorized),
      isNew: Boolean(asset.isNew && !asset.authorized),
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

