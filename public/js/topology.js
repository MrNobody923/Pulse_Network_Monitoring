// Pulse Network Monitor — Interactive Company Network Map, Cables & Problem Tracker

let topoToolMode = 'select'; // 'select' | 'link' | 'pdu'
let topoSelectedNodeId = null;
let topoSelectedLinkId = null;
let topoCableSourceId = null;
let topoPduSourceId = null;
let topoProblemsOnly = false;
let topoDeviceFilter = 'problems';
let topoDeviceSearch = '';
let topoLogFilter = 'all';
let topoZoom = 1.0;
let topoModalSelectedPeers = new Set();
let topoDraggedType = '';
let topoStageListenersBound = false;

const TOPO_DEVICE_TYPES = [
  { type: 'gateway', label: 'Router' },
  { type: 'switch', label: 'Switch' },
  { type: 'ap', label: 'Wi-Fi AP' },
  { type: 'firewall', label: 'Firewall' },
  { type: 'server', label: 'Server' },
  { type: 'device', label: 'PC / Device' },
  { type: 'cloud', label: 'Internet ISP' }
];

const TOPO_CABLE_TYPES = [
  { value: 'auto', label: '⚡ Auto Cable' },
  { value: 'copper', label: '🔌 Ethernet CAT6' },
  { value: 'fiber', label: '💡 Fiber Optic' },
  { value: 'wireless', label: '📶 Wi-Fi Wireless' },
  { value: 'wan', label: '🌐 ISP WAN' }
];

// Standard Vector Icons per Network Device Type
function getTopologyDeviceSvg(nodeType, healthState) {
  const isDown = healthState === 'down' || healthState === 'disconnected';
  const isWarn = healthState === 'no_internet' || healthState === 'degraded';
  const stroke = isDown ? '#f43f5e' : isWarn ? '#f59e0b' : '#00bceb';
  const fillBg = isDown ? 'rgba(244,63,94,0.16)' : isWarn ? 'rgba(245,158,11,0.16)' : 'rgba(4,159,217,0.16)';

  if (nodeType === 'cloud') {
    return `<svg width="42" height="34" viewBox="0 0 48 36" fill="none">
      <path d="M13 29h23a8 8 0 0 0 1.4-15.9A11 11 0 0 0 16.5 9 9 9 0 0 0 13 29z" fill="${fillBg}" stroke="${stroke}" stroke-width="2.2" stroke-linejoin="round"/>
      <text x="24" y="22" text-anchor="middle" fill="${stroke}" font-size="7.5" font-family="JetBrains Mono, monospace" font-weight="800">ISP</text>
    </svg>`;
  }
  if (nodeType === 'gateway' || nodeType === 'router') {
    return `<svg width="40" height="34" viewBox="0 0 44 36" fill="none">
      <ellipse cx="22" cy="18" rx="16" ry="12" fill="${fillBg}" stroke="${stroke}" stroke-width="2.2"/>
      <path d="M14 14l6 3-6 3M30 14l-6 3 6 3M22 8v6M22 22v6" stroke="${stroke}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  }
  if (nodeType === 'switch') {
    return `<svg width="44" height="34" viewBox="0 0 48 34" fill="none">
      <rect x="4" y="8" width="40" height="18" rx="3" fill="${fillBg}" stroke="${stroke}" stroke-width="2.2"/>
      <path d="M11 14h11m-3-2.5l3 2.5-3 2.5M37 20H26m3-2.5L26 20l3 2.5" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="10" cy="22" r="1.3" fill="${stroke}"/><circle cx="14" cy="22" r="1.3" fill="${stroke}"/>
    </svg>`;
  }
  if (nodeType === 'ap') {
    return `<svg width="40" height="34" viewBox="0 0 44 36" fill="none">
      <path d="M10 15a16 16 0 0 1 24 0M14.5 19a10 10 0 0 1 15 0" stroke="${stroke}" stroke-width="2" stroke-linecap="round"/>
      <rect x="11" y="22" width="22" height="9" rx="2.5" fill="${fillBg}" stroke="${stroke}" stroke-width="2"/>
      <circle cx="22" cy="18.5" r="2" fill="${stroke}"/>
    </svg>`;
  }
  if (nodeType === 'firewall') {
    return `<svg width="40" height="34" viewBox="0 0 44 36" fill="none">
      <rect x="6" y="7" width="32" height="22" rx="3" fill="${fillBg}" stroke="${stroke}" stroke-width="2.2"/>
      <line x1="6" y1="14" x2="38" y2="14" stroke="${stroke}" stroke-width="1.5"/>
      <line x1="6" y1="21" x2="38" y2="21" stroke="${stroke}" stroke-width="1.5"/>
      <line x1="17" y1="7" x2="17" y2="14" stroke="${stroke}" stroke-width="1.5"/>
      <line x1="27" y1="14" x2="27" y2="21" stroke="${stroke}" stroke-width="1.5"/>
    </svg>`;
  }
  if (nodeType === 'server') {
    return `<svg width="38" height="34" viewBox="0 0 40 36" fill="none">
      <rect x="9" y="5" width="22" height="26" rx="3" fill="${fillBg}" stroke="${stroke}" stroke-width="2.2"/>
      <line x1="14" y1="11" x2="26" y2="11" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round"/>
      <line x1="14" y1="16" x2="26" y2="16" stroke="${stroke}" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="20" cy="24" r="2" fill="${stroke}"/>
    </svg>`;
  }
  return `<svg width="40" height="34" viewBox="0 0 44 36" fill="none">
    <rect x="8" y="6" width="28" height="18" rx="2.5" fill="${fillBg}" stroke="${stroke}" stroke-width="2.1"/>
    <path d="M16 28h12M22 24v4" stroke="${stroke}" stroke-width="2" stroke-linecap="round"/>
  </svg>`;
}

function getTopologyData() {
  return (
    appState.topology || {
      nodes: [],
      links: [],
      summary: { totalNodes: 0, totalLinks: 0, online: 0, down: 0, disconnected: 0, noInternet: 0, degraded: 0, problemCount: 0 },
      logs: []
    }
  );
}

function setTopoToolMode(mode) {
  topoToolMode = mode || 'select';
  topoCableSourceId = null;
  topoPduSourceId = null;
  clearTopoRubberBandLine();
  document.querySelectorAll('[data-topo-tool]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-topo-tool') === topoToolMode);
  });
  updateTopoModeBanner();
  renderTopologyCanvas();
}

function updateTopoModeBanner(customMsg = '', tone = '') {
  const banner = document.getElementById('topoModeBanner');
  const txt = document.getElementById('topoModeText');
  if (!banner || !txt) return;
  banner.className = `topo-mode-banner${tone ? ` ${tone}` : ''}`;
  if (customMsg) {
    txt.textContent = customMsg;
    return;
  }
  if (topoToolMode === 'link') {
    txt.textContent = topoCableSourceId
      ? 'Cable Mode: Now click the SECOND device to finish connecting the cable.'
      : 'Cable Mode: Click the SOURCE device first, then click a target device to wire them together.';
  } else if (topoToolMode === 'pdu') {
    txt.textContent = topoPduSourceId
      ? 'Test Ping Mode: Now click the DESTINATION device to check the cable path and test the connection.'
      : 'Test Ping Mode: Click any starting device (or double-click a target) to send a live test ping.';
  } else {
    txt.textContent =
      'Move Mode: Drag device icons to organize your map, click any device or cable to view details, or pick a tool above.';
  }
}

function toggleTopoProblemsHighlight() {
  topoProblemsOnly = !topoProblemsOnly;
  const btn = document.getElementById('btnTopoProblemsOnly');
  if (btn) btn.classList.toggle('active', topoProblemsOnly);
  if (topoProblemsOnly) topoDeviceFilter = 'problems';
  renderTopologySection();
}

function adjustTopoZoom(delta) {
  topoZoom = Math.max(0.6, Math.min(1.5, Number((topoZoom + delta).toFixed(2))));
  const stage = document.getElementById('topoStage');
  const lbl = document.getElementById('topoZoomLabel');
  if (stage) stage.style.transform = `scale(${topoZoom})`;
  if (lbl) lbl.textContent = `${Math.round(topoZoom * 100)}%`;
}

function setTopoDeviceFilter(filter) {
  topoDeviceFilter = filter || 'problems';
  renderTopologyTables();
  renderTopologyKpis(getTopologyData());
}

function handleTopoDeviceSearch(val) {
  topoDeviceSearch = String(val || '').trim().toLowerCase();
  renderTopologyDevicesTable(getTopologyData());
}

function setTopoLogFilter(filter) {
  topoLogFilter = filter || 'all';
  document.querySelectorAll('#topoLogFilterTabs [data-topo-log-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-topo-log-filter') === topoLogFilter);
  });
  renderTopologyLogsTable(getTopologyData());
}

function renderTopologyKpis(topo) {
  const s = topo.summary || {};
  const setTxt = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  setTxt('topoStatTotal', s.totalNodes ?? 0);
  setTxt('topoStatLinksSub', `${s.totalLinks ?? 0} cabled links`);
  setTxt('topoStatDown', s.down ?? 0);
  setTxt('topoStatDisconnected', s.disconnected ?? 0);
  setTxt('topoStatNoNet', s.noInternet ?? 0);
  setTxt('topoStatDegraded', s.degraded ?? 0);
  setTxt('topoStatOnline', s.online ?? 0);

  setTxt('topoTabProblems', s.problemCount ?? 0);
  setTxt('topoTabAll', s.totalNodes ?? 0);
  setTxt('topoTabDown', s.down ?? 0);
  setTxt('topoTabDisconnected', s.disconnected ?? 0);
  setTxt('topoTabNoNet', s.noInternet ?? 0);
  setTxt('topoTabDegraded', s.degraded ?? 0);
  setTxt('topoTabOnline', s.online ?? 0);

  const badge = document.getElementById('topoStatusBadge');
  const headIcon = document.getElementById('topoHeaderIcon');
  const sideBadge = document.getElementById('sideBadgeTopology');
  const probs = s.problemCount ?? 0;
  const critCount = (s.down ?? 0) + (s.disconnected ?? 0);

  if (badge) {
    if (critCount > 0) {
      badge.className = 'status-pill offline';
      badge.textContent = `🚨 ${critCount} DOWN / ${probs} TOTAL ISSUE(S)`;
    } else if (probs > 0) {
      badge.className = 'status-pill warning';
      badge.textContent = `⚠️ ${probs} DEGRADED / NO-INTERNET`;
    } else if ((s.totalNodes ?? 0) === 0) {
      badge.className = 'status-pill new';
      badge.textContent = 'MANUAL SETUP READY';
    } else {
      badge.className = 'status-pill online';
      badge.textContent = `🟢 ALL ${s.totalNodes} TOPOLOGY NODES ONLINE`;
    }
  }
  if (headIcon) {
    headIcon.style.background =
      critCount > 0 ? 'var(--status-down-bg)' : probs > 0 ? 'var(--status-warn-bg)' : 'var(--status-up-bg)';
    headIcon.style.color =
      critCount > 0 ? 'var(--status-down-text)' : probs > 0 ? 'var(--status-warn-text)' : 'var(--status-up-text)';
  }
  if (sideBadge) {
    if (critCount > 0) {
      sideBadge.className = 'side-badge red';
      sideBadge.textContent = `${critCount} Down`;
    } else if (probs > 0) {
      sideBadge.className = 'side-badge amber';
      sideBadge.textContent = `${probs} Warn`;
    } else {
      sideBadge.className = 'side-badge green';
      sideBadge.textContent = `${s.totalNodes ?? 0}`;
    }
  }

  document.querySelectorAll('#topoKpiStrip [data-topo-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-topo-filter') === topoDeviceFilter);
  });
  document.querySelectorAll('#topoDeviceFilterTabs [data-topo-dev-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-topo-dev-filter') === topoDeviceFilter);
  });
}

function renderTopoDockIcons() {
  if (typeof document.querySelectorAll !== 'function') return;
  document.querySelectorAll('[data-dock-svg]').forEach(el => {
    if (el.getAttribute('data-svg-rendered') === '1') return;
    const type = el.getAttribute('data-dock-svg') || 'device';
    el.innerHTML = getTopologyDeviceSvg(type, 'online');
    el.setAttribute('data-svg-rendered', '1');
  });
}

function ensureTopoStageListeners() {
  if (topoStageListenersBound) return;
  const stage = document.getElementById('topoStage');
  if (!stage || typeof stage.addEventListener !== 'function') return;
  topoStageListenersBound = true;

  stage.addEventListener('pointermove', e => {
    if (topoToolMode !== 'link' || !topoCableSourceId) return;
    const rect = stage.getBoundingClientRect ? stage.getBoundingClientRect() : null;
    if (!rect) return;
    const mx = (e.clientX - rect.left) / topoZoom;
    const my = (e.clientY - rect.top) / topoZoom;
    updateTopoRubberBandLine(mx, my);
  });

  if (typeof document.addEventListener === 'function') {
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && (topoCableSourceId || topoPduSourceId)) {
        topoCableSourceId = null;
        topoPduSourceId = null;
        clearTopoRubberBandLine();
        updateTopoModeBanner();
        renderTopologyCanvas();
      }
    });
  }
}

function updateTopoRubberBandLine(mx, my) {
  const svg = document.getElementById('topoSvgLayer');
  if (!svg || !topoCableSourceId) return;
  const topo = getTopologyData();
  const src = (topo.nodes || []).find(n => n.id === topoCableSourceId);
  if (!src) return;
  let rb = document.getElementById('topoRubberBandLine');
  if (!rb && typeof document.createElementNS === 'function' && typeof svg.appendChild === 'function') {
    rb = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    rb.id = 'topoRubberBandLine';
    rb.setAttribute('class', 'topo-rubberband-line');
    svg.appendChild(rb);
  }
  if (rb && typeof rb.setAttribute === 'function') {
    rb.setAttribute('x1', src.x);
    rb.setAttribute('y1', src.y);
    rb.setAttribute('x2', Math.round(mx));
    rb.setAttribute('y2', Math.round(my));
    rb.style.display = '';
  }
}

function clearTopoRubberBandLine() {
  const rb = document.getElementById('topoRubberBandLine');
  if (rb && typeof rb.remove === 'function') rb.remove();
}

function onTopoDockDragStart(event, nodeType) {
  topoDraggedType = nodeType || 'gateway';
  if (event && event.dataTransfer) {
    event.dataTransfer.setData('text/plain', topoDraggedType);
    event.dataTransfer.effectAllowed = 'copy';
  }
}

function onTopoCanvasDragOver(event) {
  if (event) event.preventDefault();
  const vp = document.getElementById('topoViewport');
  if (vp && vp.classList) vp.classList.add('drag-over');
}

function onTopoCanvasDragLeave() {
  const vp = document.getElementById('topoViewport');
  if (vp && vp.classList) vp.classList.remove('drag-over');
}

function onTopoCanvasDrop(event) {
  if (event) event.preventDefault();
  const vp = document.getElementById('topoViewport');
  if (vp && vp.classList) vp.classList.remove('drag-over');
  const stage = document.getElementById('topoStage');
  const rawType =
    (event && event.dataTransfer && event.dataTransfer.getData('text/plain')) || topoDraggedType || 'gateway';
  topoDraggedType = '';
  let coords = null;
  if (stage && typeof stage.getBoundingClientRect === 'function' && event) {
    const rect = stage.getBoundingClientRect();
    const rawX = (event.clientX - rect.left) / topoZoom;
    const rawY = (event.clientY - rect.top) / topoZoom;
    coords = {
      x: Math.max(70, Math.min(1050, Math.round(rawX / 10) * 10)),
      y: Math.max(55, Math.min(625, Math.round(rawY / 10) * 10))
    };
  }
  openAddTopologyNodeModal(rawType, coords);
}

function startQuickCableFromNode(event, nodeId) {
  if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
  topoToolMode = 'link';
  topoCableSourceId = nodeId;
  topoPduSourceId = null;
  document.querySelectorAll('[data-topo-tool]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-topo-tool') === 'link');
  });
  const topo = getTopologyData();
  const src = (topo.nodes || []).find(n => n.id === nodeId);
  updateTopoModeBanner(
    src
      ? `Cable Mode: Click the TARGET device to connect to "${src.name}" (or press Esc to cancel).`
      : ''
  );
  renderTopologyCanvas();
}

function renderTopologySection() {
  const topo = getTopologyData();
  renderTopoDockIcons();
  ensureTopoStageListeners();
  renderTopologyKpis(topo);
  renderTopologyCanvas();
  renderTopologyInspector();
  renderTopologyTables();

  const syncEl = document.getElementById('topoLastSyncText');
  if (syncEl) syncEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

function renderTopologyCanvas() {
  const topo = getTopologyData();
  const nodes = topo.nodes || [];
  const links = topo.links || [];
  const svg = document.getElementById('topoSvgLayer');
  const layer = document.getElementById('topoNodesLayer');
  const empty = document.getElementById('topoEmptyOverlay');
  if (!svg || !layer) return;

  if (empty) empty.style.display = nodes.length === 0 ? 'flex' : 'none';

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  // Draw SVG cables + link status triangles/LEDs
  svg.innerHTML = links
    .map(ln => {
      const s = nodeMap.get(ln.sourceId);
      const d = nodeMap.get(ln.targetId);
      if (!s || !d) return '';
      const dx = d.x - s.x;
      const dy = d.y - s.y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const ux = dx / dist;
      const uy = dy / dist;

      // Position LED indicators outside the node box boundaries
      const ledOffset = Math.min(52, dist * 0.28);
      const sxLed = s.x + ux * ledOffset;
      const syLed = s.y + uy * ledOffset;
      const dxLed = d.x - ux * ledOffset;
      const dyLed = d.y - uy * ledOffset;

      const ledCls = st =>
        st === 'down' || st === 'disconnected'
          ? 'topo-led-down'
          : st === 'no_internet' || st === 'degraded'
          ? 'topo-led-warn'
          : st === 'online'
          ? 'topo-led-up'
          : 'topo-led-muted';

      const dimmed = topoProblemsOnly && !s.isProblem && !d.isProblem;
      const isSelected = topoSelectedLinkId === ln.id;
      const midX = (s.x + d.x) / 2;
      const midY = (s.y + d.y) / 2;
      const cableHealth = ln.linkHealth || 'online';
      const brokenBadge =
        cableHealth === 'down' || cableHealth === 'disconnected'
          ? `<g transform="translate(${midX}, ${midY})">
               <circle r="9" fill="var(--bg-card)" stroke="#f43f5e" stroke-width="1.8"></circle>
               <path d="M-3.5-3.5L3.5 3.5M3.5-3.5L-3.5 3.5" stroke="#f43f5e" stroke-width="2" stroke-linecap="round"></path>
             </g>`
          : '';

      const portLabel = [ln.sourcePort, ln.targetPort].filter(Boolean).join(' ↔ ');
      return `
        <g>
          <line class="topo-link-hit" x1="${s.x}" y1="${s.y}" x2="${d.x}" y2="${d.y}" onclick="selectTopologyLink('${esc(ln.id)}')"></line>
          <line class="topo-link-line ${esc(ln.cableType)} state-${esc(cableHealth)} ${dimmed ? 'dimmed' : ''}"
                style="${isSelected ? 'stroke-width:4.2;' : ''}"
                x1="${s.x}" y1="${s.y}" x2="${d.x}" y2="${d.y}"></line>
          <circle class="${ledCls(ln.sourceState)}" cx="${sxLed.toFixed(1)}" cy="${syLed.toFixed(1)}" r="4.5"></circle>
          <circle class="${ledCls(ln.targetState)}" cx="${dxLed.toFixed(1)}" cy="${dyLed.toFixed(1)}" r="4.5"></circle>
          ${brokenBadge}
          ${
            portLabel
              ? `<text class="topo-port-label" x="${midX}" y="${midY - 8}" text-anchor="middle">${esc(portLabel)}</text>`
              : ''
          }
        </g>
      `;
    })
    .join('');

  // Render draggable network device nodes
  layer.innerHTML = nodes
    .map(n => {
      const hs = n.healthState || 'unknown';
      const dimmed = topoProblemsOnly && !n.isProblem;
      const isSelected = topoSelectedNodeId === n.id;
      const isSrc = topoCableSourceId === n.id || topoPduSourceId === n.id;
      const latTxt =
        hs === 'down'
          ? 'OFFLINE · DOWN'
          : hs === 'disconnected'
          ? 'DISCONNECTED'
          : hs === 'no_internet'
          ? `${n.latencyMs != null ? `${n.latencyMs} ms · ` : ''}NO INTERNET`
          : hs === 'degraded'
          ? `${n.latencyMs ?? '—'} ms · ${n.packetLossPct ?? 0}% loss`
          : n.latencyMs != null
          ? `${n.latencyMs} ms · OK`
          : n.monitored
          ? 'Checking…'
          : 'Map Device';

      return `
        <div class="topo-node state-${esc(hs)} ${isSelected ? 'selected' : ''} ${isSrc ? 'cable-source' : ''} ${dimmed ? 'dimmed' : ''}"
             data-topo-node-id="${esc(n.id)}"
             style="left: ${n.x}px; top: ${n.y}px;">
          <button type="button" class="topo-node-cable-btn" title="Connect cable from ${esc(n.name)}" onclick="startQuickCableFromNode(event, '${esc(n.id)}')">⚡</button>
          <div class="topo-node-icon">${getTopologyDeviceSvg(n.node_type, hs)}</div>
          <span class="topo-node-badge ${esc(hs)}">${esc(n.statusLabel || hs)}</span>
          <div class="topo-node-name" title="${esc(n.name)}">${esc(n.name)}</div>
          <div class="topo-node-ip">${esc(n.ip || 'WAN / Cloud')}</div>
          <div class="topo-node-lat">${esc(latTxt)}</div>
        </div>
      `;
    })
    .join('');

  bindTopoNodeInteractions();
}

function bindTopoNodeInteractions() {
  const layer = document.getElementById('topoNodesLayer');
  const stage = document.getElementById('topoStage');
  if (!layer || !stage) return;

  layer.querySelectorAll('.topo-node').forEach(el => {
    el.addEventListener('pointerdown', e => {
      if (e.button !== 0) return;
      if (e.target && typeof e.target.closest === 'function' && e.target.closest('.topo-node-cable-btn')) {
        return;
      }
      const nodeId = el.getAttribute('data-topo-node-id');
      if (topoToolMode === 'link' || topoToolMode === 'pdu') {
        e.stopPropagation();
        handleTopoNodeClick(nodeId);
        return;
      }

      const startX = e.clientX;
      const startY = e.clientY;
      const origLeft = parseFloat(el.style.left) || 0;
      const origTop = parseFloat(el.style.top) || 0;
      let moved = false;

      el.setPointerCapture(e.pointerId);
      const onMove = ev => {
        const dx = (ev.clientX - startX) / topoZoom;
        const dy = (ev.clientY - startY) / topoZoom;
        if (!moved && Math.hypot(dx, dy) > 5) {
          moved = true;
          el.style.cursor = 'grabbing';
        }
        if (moved) {
          const nx = Math.max(70, Math.min(1050, Math.round((origLeft + dx) / 10) * 10));
          const ny = Math.max(55, Math.min(625, Math.round((origTop + dy) / 10) * 10));
          el.style.left = `${nx}px`;
          el.style.top = `${ny}px`;
          const topo = getTopologyData();
          const nd = (topo.nodes || []).find(n => n.id === nodeId);
          if (nd) {
            nd.x = nx;
            nd.y = ny;
          }
          renderTopologyCanvasLiveLines();
        }
      };

      const onUp = async ev => {
        el.removeEventListener('pointermove', onMove);
        el.removeEventListener('pointerup', onUp);
        el.style.cursor = 'grab';
        if (!moved) {
          handleTopoNodeClick(nodeId);
        } else {
          const finalX = parseFloat(el.style.left) || origLeft;
          const finalY = parseFloat(el.style.top) || origTop;
          try {
            await apiJson(`/api/topology/node/${encodeURIComponent(nodeId)}/position`, {
              method: 'POST',
              body: JSON.stringify({ x: finalX, y: finalY })
            });
          } catch (_) {}
        }
      };

      el.addEventListener('pointermove', onMove);
      el.addEventListener('pointerup', onUp);
    });
  });
}

function renderTopologyCanvasLiveLines() {
  const topo = getTopologyData();
  const nodeMap = new Map((topo.nodes || []).map(n => [n.id, n]));
  const svg = document.getElementById('topoSvgLayer');
  if (!svg) return;
  // Re-render SVG links smoothly during drag without destroying the dragged DOM element
  const linesHtml = (topo.links || [])
    .map(ln => {
      const s = nodeMap.get(ln.sourceId);
      const d = nodeMap.get(ln.targetId);
      if (!s || !d) return '';
      const cableHealth = ln.linkHealth || 'online';
      return `<line class="topo-link-line ${esc(ln.cableType)} state-${esc(cableHealth)}" x1="${s.x}" y1="${s.y}" x2="${d.x}" y2="${d.y}"></line>`;
    })
    .join('');
  svg.innerHTML = linesHtml;
}

function handleTopoNodeClick(nodeId) {
  if (topoToolMode === 'link') {
    if (!topoCableSourceId) {
      topoCableSourceId = nodeId;
      updateTopoModeBanner();
      renderTopologyCanvas();
      return;
    }
    if (topoCableSourceId === nodeId) {
      topoCableSourceId = null;
      clearTopoRubberBandLine();
      updateTopoModeBanner();
      renderTopologyCanvas();
      return;
    }
    const fastToggle = document.getElementById('topoFastCableCheckbox');
    if (fastToggle && fastToggle.checked) {
      quickConnectTopologyNodes(topoCableSourceId, nodeId);
      return;
    }
    openTopologyLinkModal(topoCableSourceId, nodeId);
    return;
  }

  if (topoToolMode === 'pdu') {
    if (!topoPduSourceId) {
      topoPduSourceId = nodeId;
      updateTopoModeBanner();
      renderTopologyCanvas();
      return;
    }
    const srcId = topoPduSourceId;
    topoPduSourceId = null;
    sendTopologyPduPing(srcId, nodeId);
    return;
  }

  topoSelectedNodeId = nodeId;
  topoSelectedLinkId = null;
  renderTopologyCanvas();
  renderTopologyInspector();
}

function selectTopologyLink(linkId) {
  topoSelectedLinkId = linkId;
  topoSelectedNodeId = null;
  renderTopologyCanvas();
  renderTopologyInspector();
}

function locateTopologyNode(nodeId) {
  topoSelectedNodeId = nodeId;
  topoSelectedLinkId = null;
  renderTopologyCanvas();
  renderTopologyInspector();
  const vp = document.getElementById('topoViewport');
  const el = document.querySelector(`[data-topo-node-id="${CSS.escape(nodeId)}"]`);
  if (el && vp) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
  }
}

function renderTopologyInspector() {
  const box = document.getElementById('topoInspector');
  if (!box) return;
  const topo = getTopologyData();

  if (topoSelectedLinkId) {
    const ln = (topo.links || []).find(l => l.id === topoSelectedLinkId);
    if (ln) {
      box.innerHTML = `
        <div class="topo-inspector-head">
          <strong style="font-size:0.88rem;">🔌 Cable Connection</strong>
          <span class="status-pill ${
            ln.linkHealth === 'online' ? 'online' : ln.linkHealth === 'down' || ln.linkHealth === 'disconnected' ? 'offline' : 'warning'
          }">${esc(String(ln.linkHealth || '').toUpperCase())}</span>
        </div>
        <div class="topo-inspector-kv">
          <span>Source</span><strong>${esc(ln.sourceName)} ${ln.sourcePort ? `(${esc(ln.sourcePort)})` : ''}</strong>
          <span>Target</span><strong>${esc(ln.targetName)} ${ln.targetPort ? `(${esc(ln.targetPort)})` : ''}</strong>
          <span>Medium</span><strong class="mono">${esc(String(ln.cableType || 'copper').toUpperCase())}</strong>
        </div>
        <button type="button" class="btn btn-secondary btn-xs" style="border-color:var(--accent-red); color:var(--accent-red);" onclick="deleteTopologyLink('${esc(ln.id)}')">
          ✕ Disconnect / Delete Cable
        </button>
      `;
      return;
    }
  }

  const node = (topo.nodes || []).find(n => n.id === topoSelectedNodeId);
  if (!node) {
    const problems = (topo.nodes || []).filter(n => n.isProblem);
    box.innerHTML = `
      <div class="topo-inspector-head">
        <strong style="font-size:0.86rem;">🔍 Topology Inspector</strong>
        <span class="status-pill ${problems.length ? 'offline' : 'online'}">${problems.length} Issue(s)</span>
      </div>
      <div style="font-size:0.78rem; color:var(--text-muted);">
        Click any device or cable on the map to view its status, connected wires, and troubleshooting steps.
      </div>
      ${
        problems.length
          ? `<div style="font-size:0.74rem; font-weight:800; color:var(--accent-red); margin-top:4px;">DOWN / PROBLEM NODES:</div>
             <div style="display:flex; flex-direction:column; gap:6px;">
               ${problems
                 .slice(0, 6)
                 .map(
                   p => `<button type="button" class="btn btn-secondary btn-xs" style="justify-content:space-between;" onclick="locateTopologyNode('${esc(p.id)}')">
                     <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(p.name)}</span>
                     <span style="color:var(--accent-red); font-weight:800;">${esc(p.statusLabel)}</span>
                   </button>`
                 )
                 .join('')}
             </div>`
          : `<div style="font-size:0.78rem; color:var(--accent-green);">All topology nodes are healthy.</div>`
      }
    `;
    return;
  }

  const connectedLinks = (topo.links || []).filter(l => l.sourceId === node.id || l.targetId === node.id);
  const pillCls =
    node.healthState === 'online'
      ? 'online'
      : node.healthState === 'down' || node.healthState === 'disconnected'
      ? 'offline'
      : node.healthState === 'unknown'
      ? 'new'
      : 'warning';

  box.innerHTML = `
    <div class="topo-inspector-head">
      <div style="min-width:0;">
        <strong style="font-size:0.88rem; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(node.name)}</strong>
        <span class="mono" style="font-size:0.73rem; color:var(--accent-cyan);">${esc(node.ip || 'WAN / Cloud Node')}</span>
      </div>
      <span class="status-pill ${pillCls}">${esc(node.statusLabel)}</span>
    </div>

    <div class="topo-inspector-kv">
      <span>Role</span><strong>${esc(String(node.node_type).toUpperCase())}</strong>
      <span>Latency</span><strong class="mono">${node.latencyMs != null ? `${node.latencyMs} ms` : '—'}</strong>
      <span>Packet Loss</span><strong class="mono">${node.packetLossPct != null ? `${node.packetLossPct}%` : '—'}</strong>
      <span>MAC</span><strong class="mono">${esc(node.mac || '—')}</strong>
      <span>Location</span><strong>${esc(node.location || 'Office')}</strong>
    </div>

    ${
      node.likelyFault || node.diagnosisSummary
        ? `<div style="background:var(--bg-card); border:1px solid var(--border-subtle); border-left:3px solid ${
            node.isProblem ? 'var(--accent-red)' : 'var(--accent-green)'
          }; border-radius:var(--radius-sm); padding:8px 10px; font-size:0.76rem;">
             ${node.likelyFault ? `<div style="font-weight:800; color:var(--accent-red); margin-bottom:2px;">⚠️ ${esc(node.likelyFault)}</div>` : ''}
             <div style="color:var(--text-muted);">${esc(node.diagnosisSummary)}</div>
             ${
               Array.isArray(node.fixSteps) && node.fixSteps.length
                 ? `<ol style="margin:5px 0 0 16px; color:var(--text-main); line-height:1.4;">${node.fixSteps
                     .map(s => `<li>${esc(s)}</li>`)
                     .join('')}</ol>`
                 : ''
             }
           </div>`
        : ''
    }

    <div>
      <div style="font-size:0.71rem; font-weight:800; text-transform:uppercase; color:var(--text-dim); margin-bottom:4px;">Connected Cables (${connectedLinks.length})</div>
      ${
        connectedLinks.length
          ? connectedLinks
              .map(ln => {
                const peer = ln.sourceId === node.id ? ln.targetName : ln.sourceName;
                return `<div style="display:flex; align-items:center; justify-content:space-between; gap:6px; font-size:0.74rem; padding:3px 0; border-bottom:1px solid var(--border-subtle);">
                  <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(peer)} (${esc(ln.cableType)})</span>
                  <button type="button" class="btn btn-secondary btn-xs" onclick="deleteTopologyLink('${esc(ln.id)}')">Unlink</button>
                </div>`;
              })
              .join('')
          : '<div style="font-size:0.74rem; color:var(--text-dim);">No cables connected yet. Use Connect Cable tool.</div>'
      }
    </div>

    <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:auto;">
      <button type="button" class="btn btn-primary btn-xs" onclick="sendTopologyPduPing('${esc(node.id)}', '${esc(node.id)}')">⚡ Test Ping</button>
      <button type="button" class="btn btn-secondary btn-xs" onclick="startQuickCableFromNode(event, '${esc(node.id)}')">🔌 Connect Cable</button>
      ${
        node.ip
          ? `<button type="button" class="btn btn-secondary btn-xs" onclick="scanDevicePorts('${esc(node.ip)}', '${esc(node.name)}')">🛡️ Nmap</button>`
          : ''
      }
      <button type="button" class="btn btn-secondary btn-xs" onclick="openEditTopologyNodeModal('${esc(node.id)}')">✎ Edit</button>
      <button type="button" class="btn btn-secondary btn-xs" style="color:var(--accent-red);" onclick="deleteTopologyNode('${esc(node.id)}')">✕ Remove</button>
    </div>
  `;
}

function renderTopologyTables() {
  const topo = getTopologyData();
  renderTopologyDevicesTable(topo);
  renderTopologyLogsTable(topo);
}

function renderTopologyDevicesTable(topo) {
  const tbody = document.getElementById('topoDevicesTableBody');
  if (!tbody) return;
  const nodes = topo.nodes || [];
  const links = topo.links || [];

  let rows = nodes;
  if (topoDeviceFilter === 'problems') {
    rows = nodes.filter(n => n.isProblem);
  } else if (topoDeviceFilter !== 'all') {
    rows = nodes.filter(n => n.healthState === topoDeviceFilter);
  }

  if (topoDeviceSearch) {
    rows = rows.filter(
      n =>
        n.name.toLowerCase().includes(topoDeviceSearch) ||
        (n.ip && n.ip.toLowerCase().includes(topoDeviceSearch)) ||
        (n.likelyFault && n.likelyFault.toLowerCase().includes(topoDeviceSearch)) ||
        (n.diagnosisSummary && n.diagnosisSummary.toLowerCase().includes(topoDeviceSearch))
    );
  }

  if (rows.length === 0) {
    const emptyMsg =
      nodes.length === 0
        ? 'No devices added to the topology yet. Click "+ Add Network Device" above to build your company network map.'
        : topoDeviceFilter === 'problems'
        ? 'Zero downed, disconnected, or problem devices detected across your topology right now.'
        : 'No topology devices match the selected filter.';
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-dim);">${esc(emptyMsg)}</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map((n, idx) => {
      const peers = links
        .filter(l => l.sourceId === n.id || l.targetId === n.id)
        .map(l => (l.sourceId === n.id ? l.targetName : l.sourceName));
      const uplinkTxt = peers.length ? `Linked: ${peers.join(', ')}` : 'Not cabled yet';
      const pillCls =
        n.healthState === 'online'
          ? 'online'
          : n.healthState === 'down' || n.healthState === 'disconnected'
          ? 'offline'
          : n.healthState === 'unknown'
          ? 'new'
          : 'warning';
      const faultTxt = n.likelyFault || n.diagnosisSummary || (n.isProblem ? 'Connection check failing' : 'Healthy');

      return `
        <tr class="${n.isProblem ? 'port-row-at-risk' : ''}">
          <td class="mono" style="color:var(--text-dim);">${idx + 1}</td>
          <td>
            <span class="dev-row-title">${esc(n.name)}</span>
            <span class="dev-row-sub">${esc(uplinkTxt)}</span>
          </td>
          <td><span class="status-pill new" style="font-size:0.65rem;">${esc(String(n.node_type).toUpperCase())}</span></td>
          <td class="mono" style="color:var(--accent-cyan); font-weight:700;">
            ${esc(n.ip || 'Cloud WAN')}
            <div class="dev-row-sub">TCP/${n.port || 80}</div>
          </td>
          <td class="mono">
            ${n.latencyMs != null ? `${n.latencyMs} ms` : '—'}
            <div class="dev-row-sub">${n.packetLossPct != null ? `${n.packetLossPct}% loss` : ''}</div>
          </td>
          <td>
            <div><span class="status-pill ${pillCls}">${esc(n.statusLabel)}</span></div>
            <div style="font-size:0.74rem; color:${n.isProblem ? 'var(--accent-red)' : 'var(--text-muted)'}; margin-top:3px; font-weight:${n.isProblem ? '700' : '400'};">
              ${esc(faultTxt)}
            </div>
          </td>
          <td style="text-align:right;">
            <div class="row-actions-group">
              <button type="button" class="btn btn-secondary btn-xs" onclick="locateTopologyNode('${esc(n.id)}')">Map</button>
              <button type="button" class="btn btn-secondary btn-xs" onclick="sendTopologyPduPing('${esc(n.id)}', '${esc(n.id)}')">Ping</button>
              <button type="button" class="btn btn-secondary btn-xs" style="color:var(--accent-red);" onclick="deleteTopologyNode('${esc(n.id)}')">Remove</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function renderTopologyLogsTable(topo) {
  const tbody = document.getElementById('topoLogsTableBody');
  if (!tbody) return;
  let logs = topo.logs || [];

  if (topoLogFilter === 'critical') {
    logs = logs.filter(ev => ev.severity === 'CRITICAL' || /OFFLINE|OUTAGE/i.test(ev.eventType || ''));
  } else if (topoLogFilter === 'warning') {
    logs = logs.filter(ev => ev.severity === 'WARNING' || /MISSING|DEGRADED/i.test(ev.eventType || ''));
  } else if (topoLogFilter === 'topology') {
    logs = logs.filter(ev => String(ev.eventType || '').startsWith('TOPOLOGY_'));
  }

  if (logs.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-dim);">No topology or fault log events recorded for this filter yet.</td></tr>';
    return;
  }

  tbody.innerHTML = logs
    .map(ev => {
      const sev = String(ev.severity || 'INFO').toUpperCase();
      const cls = sev === 'CRITICAL' ? 'offline' : sev === 'WARNING' ? 'warning' : 'online';
      return `
        <tr class="${sev === 'CRITICAL' ? 'port-row-at-risk' : ''}">
          <td><span class="status-pill ${cls}">${esc(sev)}</span></td>
          <td class="mono" style="font-size:0.76rem; color:var(--text-muted);">${esc(fmtTime(ev.timestamp))}</td>
          <td>
            <strong>${esc(ev.deviceName || ev.ip || 'Topology')}</strong>
            ${ev.ip ? `<div class="dev-row-sub mono">${esc(ev.ip)}</div>` : ''}
          </td>
          <td style="font-size:0.79rem;">
            <strong>${esc(ev.title)}</strong> — <span style="color:var(--text-muted);">${esc(ev.message)}</span>
          </td>
        </tr>
      `;
    })
    .join('');
}

// Modals & API Actions for Manual Topology Building (Packet Tracer Style)
function renderTopoModalTypeGrid(selectedType) {
  const grid = document.getElementById('topoModalTypeGrid');
  if (!grid) return;
  const active = selectedType === 'router' ? 'gateway' : selectedType || 'gateway';
  grid.innerHTML = TOPO_DEVICE_TYPES.map(
    d => `
      <button type="button" class="topo-type-card ${d.type === active ? 'selected' : ''}" onclick="selectTopoModalDeviceType('${d.type}')">
        <span style="display:flex;align-items:center;justify-content:center;width:42px;height:34px;">${getTopologyDeviceSvg(d.type, 'online')}</span>
        <span>${esc(d.label)}</span>
      </button>
    `
  ).join('');
}

function selectTopoModalDeviceType(type) {
  const normalized = type === 'router' ? 'gateway' : type || 'gateway';
  const sel = document.getElementById('topoNodeTypeSelect');
  if (sel) sel.value = normalized;
  const editEl = document.getElementById('topoNodeEditId');
  const monEl = document.getElementById('topoNodeMonitorCheckbox');
  if (monEl && (!editEl || !editEl.value.trim())) {
    monEl.checked = normalized !== 'cloud';
  }
  renderTopoModalTypeGrid(normalized);
}

function renderTopoModalCableGrid(selectedCable) {
  const grid = document.getElementById('topoModalCableGrid');
  if (!grid) return;
  const active = selectedCable || 'auto';
  grid.innerHTML = TOPO_CABLE_TYPES.map(
    c => `
      <button type="button" class="topo-cable-pill ${c.value === active ? 'selected' : ''}" onclick="selectTopoModalCableType('${c.value}')">
        ${esc(c.label)}
      </button>
    `
  ).join('');
}

function selectTopoModalCableType(cableType) {
  const active = cableType || 'auto';
  const sel = document.getElementById('topoNodeCableSelect');
  if (sel) sel.value = active;
  renderTopoModalCableGrid(active);
}

function renderTopoConnectVisualGrid(editingNodeId = '') {
  const grid = document.getElementById('topoConnectVisualGrid');
  if (!grid) return;
  const topo = getTopologyData();
  const alreadyLinked = new Set();
  if (editingNodeId) {
    (topo.links || []).forEach(ln => {
      if (ln.sourceId === editingNodeId) alreadyLinked.add(ln.targetId);
      if (ln.targetId === editingNodeId) alreadyLinked.add(ln.sourceId);
    });
  }
  const peerNodes = (topo.nodes || []).filter(n => n.id !== editingNodeId);
  if (!peerNodes.length) {
    grid.innerHTML =
      '<div style="grid-column:1/-1; padding:10px; border:1px dashed var(--border-subtle); border-radius:var(--radius-sm); font-size:0.76rem; color:var(--text-dim); text-align:center;">No other devices on the map yet — this device will be placed ready to wire to future devices.</div>';
    return;
  }

  grid.innerHTML = peerNodes
    .map(n => {
      const hs = n.healthState || 'unknown';
      const isLinked = alreadyLinked.has(n.id);
      const isPicked = !isLinked && topoModalSelectedPeers.has(n.id);
      const tagTxt = isLinked ? '✓ Already Linked' : isPicked ? '✓ Will Connect Cable' : '🔌 Click to Connect';
      return `
        <button type="button"
                class="topo-connect-card ${isPicked ? 'selected' : ''} ${isLinked ? 'already-linked' : ''}"
                ${isLinked ? 'disabled' : `onclick="toggleTopoModalConnectNode('${esc(n.id)}')"`}>
          <span style="display:flex;align-items:center;justify-content:center;width:30px;height:26px;flex-shrink:0;">${getTopologyDeviceSvg(n.node_type, hs)}</span>
          <span class="topo-connect-card-info">
            <div class="topo-connect-card-name" title="${esc(n.name)}">${esc(n.name)}</div>
            <div class="topo-connect-card-sub">${esc(n.ip || 'WAN / Cloud')}</div>
            <span class="topo-connect-card-tag">${tagTxt}</span>
          </span>
        </button>
      `;
    })
    .join('');
}

function toggleTopoModalConnectNode(nodeId) {
  if (!nodeId) return;
  if (topoModalSelectedPeers.has(nodeId)) {
    topoModalSelectedPeers.delete(nodeId);
  } else {
    topoModalSelectedPeers.add(nodeId);
  }
  const sel = document.getElementById('topoNodeConnectSelect');
  if (sel) {
    const first = topoModalSelectedPeers.values().next().value || '';
    sel.value = first;
  }
  const editEl = document.getElementById('topoNodeEditId');
  renderTopoConnectVisualGrid(editEl ? editEl.value.trim() : '');
}

function openAddTopologyNodeModal(defaultType = 'gateway', coords = null) {
  const normalizedType = defaultType === 'router' ? 'gateway' : defaultType || 'gateway';
  const formEl = document.getElementById('topologyNodeForm');
  if (formEl) formEl.reset();
  topoModalSelectedPeers.clear();
  document.getElementById('topoNodeEditId').value = '';
  document.getElementById('topoModalTitle').textContent = 'Add Device to Company Topology';
  document.getElementById('topoModalSubmitBtn').textContent = 'Add Device to Map';

  const pxEl = document.getElementById('topoNodePlaceX');
  const pyEl = document.getElementById('topoNodePlaceY');
  const badgeEl = document.getElementById('topoPlaceCoordsBadge');
  if (coords && coords.x != null && coords.y != null) {
    if (pxEl) pxEl.value = String(coords.x);
    if (pyEl) pyEl.value = String(coords.y);
    if (badgeEl) {
      badgeEl.style.display = 'inline-flex';
      badgeEl.textContent = `📍 Map Spot (${Math.round(coords.x)}, ${Math.round(coords.y)})`;
    }
  } else {
    if (pxEl) pxEl.value = '';
    if (pyEl) pyEl.value = '';
    if (badgeEl) badgeEl.style.display = 'none';
  }

  document.getElementById('topoNodeTypeSelect').value = normalizedType;
  document.getElementById('topoNodePortInput').value = 80;
  document.getElementById('topoNodeMonitorCheckbox').checked = normalizedType !== 'cloud';
  const toolbarCable = document.getElementById('topoCableTypeSelect')?.value || 'auto';
  document.getElementById('topoNodeCableSelect').value = toolbarCable;

  document.getElementById('topoExistingPickerGroup').style.display = '';
  document.getElementById('topoConnectParentRow').style.display = '';
  document.getElementById('topoMonitorCheckRow').style.display = 'flex';

  populateTopoModalSelectors('');
  renderTopoModalTypeGrid(normalizedType);
  renderTopoModalCableGrid(toolbarCable);
  renderTopoConnectVisualGrid('');
  openModal('topologyNodeModal');
}

function openEditTopologyNodeModal(nodeId) {
  const topo = getTopologyData();
  const node = (topo.nodes || []).find(n => n.id === nodeId);
  if (!node) return;
  topoModalSelectedPeers.clear();
  const nodeType = node.node_type === 'router' ? 'gateway' : node.node_type || 'device';

  document.getElementById('topoNodeEditId').value = node.id;
  document.getElementById('topoModalTitle').textContent = `Edit Topology Device: ${node.name}`;
  document.getElementById('topoModalSubmitBtn').textContent = 'Save Changes';
  const pxEl = document.getElementById('topoNodePlaceX');
  const pyEl = document.getElementById('topoNodePlaceY');
  const badgeEl = document.getElementById('topoPlaceCoordsBadge');
  if (pxEl) pxEl.value = '';
  if (pyEl) pyEl.value = '';
  if (badgeEl) badgeEl.style.display = 'none';

  document.getElementById('topoNodeNameInput').value = node.name || '';
  document.getElementById('topoNodeIpInput').value = node.ip || '';
  document.getElementById('topoNodeTypeSelect').value = nodeType;
  document.getElementById('topoNodePortInput').value = node.port || 80;
  document.getElementById('topoNodeLocInput').value = node.location || '';
  const toolbarCable = document.getElementById('topoCableTypeSelect')?.value || 'auto';
  document.getElementById('topoNodeCableSelect').value = toolbarCable;

  document.getElementById('topoExistingPickerGroup').style.display = 'none';
  document.getElementById('topoConnectParentRow').style.display = '';
  document.getElementById('topoMonitorCheckRow').style.display = 'none';

  populateTopoModalSelectors(node.id);
  renderTopoModalTypeGrid(nodeType);
  renderTopoModalCableGrid(toolbarCable);
  renderTopoConnectVisualGrid(node.id);
  openModal('topologyNodeModal');
}

function populateTopoModalSelectors(editingNodeId = '') {
  const topo = getTopologyData();
  const existingIpsOnMap = new Set((topo.nodes || []).map(n => n.ip).filter(Boolean));
  const existingPicker = document.getElementById('topoExistingSelect');
  if (existingPicker) {
    const unified = typeof buildUnifiedDeviceRows === 'function' ? buildUnifiedDeviceRows() : [];
    const avail = unified.filter(r => !r.archived && r.ip && !existingIpsOnMap.has(r.ip));
    existingPicker.innerHTML =
      '<option value="">— Enter a new device manually below —</option>' +
      avail
        .map(
          r =>
            `<option value="${esc(r.ip)}" data-name="${esc(r.name)}" data-type="${esc(
              r.monitored ? r.type : 'device'
            )}" data-loc="${esc(r.location)}" data-port="${r.port || 80}">${esc(r.name)} (${esc(r.ip)})</option>`
        )
        .join('');
  }

  const parentSelect = document.getElementById('topoNodeConnectSelect');
  if (parentSelect) {
    parentSelect.innerHTML =
      '<option value="">— Place unconnected on map —</option>' +
      (topo.nodes || [])
        .filter(n => n.id !== editingNodeId)
        .map(n => `<option value="${esc(n.id)}">${esc(n.name)}${n.ip ? ` (${esc(n.ip)})` : ''}</option>`)
        .join('');
  }
}

function prefillTopoFromExisting(ipVal) {
  const sel = document.getElementById('topoExistingSelect');
  if (!sel || !ipVal) return;
  const opt = sel.options[sel.selectedIndex];
  const rawType = opt.getAttribute('data-type') || 'device';
  const normalized = rawType === 'router' ? 'gateway' : rawType;
  document.getElementById('topoNodeIpInput').value = ipVal;
  document.getElementById('topoNodeNameInput').value = opt.getAttribute('data-name') || ipVal;
  document.getElementById('topoNodeLocInput').value = opt.getAttribute('data-loc') || '';
  document.getElementById('topoNodePortInput').value = opt.getAttribute('data-port') || 80;
  selectTopoModalDeviceType(normalized);
}

async function submitTopologyNodeForm(event) {
  event.preventDefault();
  const editId = document.getElementById('topoNodeEditId').value.trim();
  const selectVal = document.getElementById('topoNodeConnectSelect')?.value || '';
  const connectToIds = Array.from(topoModalSelectedPeers);
  if (selectVal && !connectToIds.includes(selectVal)) {
    connectToIds.push(selectVal);
  }
  const pxVal = document.getElementById('topoNodePlaceX')?.value?.trim();
  const pyVal = document.getElementById('topoNodePlaceY')?.value?.trim();
  const payload = {
    name: document.getElementById('topoNodeNameInput').value.trim(),
    ip: document.getElementById('topoNodeIpInput').value.trim(),
    nodeType: document.getElementById('topoNodeTypeSelect').value,
    port: parseInt(document.getElementById('topoNodePortInput').value, 10) || 80,
    location: document.getElementById('topoNodeLocInput').value.trim(),
    connectToId: connectToIds[0] || '',
    connectToIds,
    cableType: document.getElementById('topoNodeCableSelect').value || 'auto',
    monitorDevice: document.getElementById('topoNodeMonitorCheckbox').checked
  };
  if (!editId && pxVal !== '' && pyVal !== '' && !isNaN(Number(pxVal)) && !isNaN(Number(pyVal))) {
    payload.x = Number(pxVal);
    payload.y = Number(pyVal);
  }

  try {
    const res = editId
      ? await apiJson(`/api/topology/node/${encodeURIComponent(editId)}`, {
          method: 'PUT',
          body: JSON.stringify(payload)
        })
      : await apiJson('/api/topology/node', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
    topoModalSelectedPeers.clear();
    if (res.topology) appState.topology = res.topology;
    if (res.node && res.node.id) topoSelectedNodeId = res.node.id;
    closeModal('topologyNodeModal');
    renderTopologySection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function quickConnectTopologyNodes(srcId, dstId) {
  const topo = getTopologyData();
  const src = (topo.nodes || []).find(n => n.id === srcId);
  const dst = (topo.nodes || []).find(n => n.id === dstId);
  const cableType = document.getElementById('topoCableTypeSelect')?.value || 'auto';
  try {
    const res = await apiJson('/api/topology/link', {
      method: 'POST',
      body: JSON.stringify({
        sourceId: srcId,
        targetId: dstId,
        cableType,
        autoPorts: true
      })
    });
    if (res.topology) appState.topology = res.topology;
    topoCableSourceId = null;
    clearTopoRubberBandLine();
    setTopoToolMode('select');
    renderTopologySection();
    if (src && dst) {
      updateTopoModeBanner(`Connected cable: ${src.name} ↔ ${dst.name}.`, '');
    }
  } catch (err) {
    topoCableSourceId = null;
    clearTopoRubberBandLine();
    setTopoToolMode('select');
    updateTopoModeBanner(err.message || 'Could not connect these two devices.', 'warning');
  }
}

function openTopologyLinkModal(srcId, dstId) {
  const topo = getTopologyData();
  const src = (topo.nodes || []).find(n => n.id === srcId);
  const dst = (topo.nodes || []).find(n => n.id === dstId);
  if (!src || !dst) return;
  document.getElementById('topoLinkSrcId').value = srcId;
  document.getElementById('topoLinkDstId').value = dstId;
  document.getElementById('topoLinkCableModalSelect').value =
    document.getElementById('topoCableTypeSelect').value || 'auto';
  document.getElementById('topoLinkSummaryBox').innerHTML = `<strong>${esc(
    src.name
  )}</strong> <span style="color:var(--accent-cyan);">↔</span> <strong>${esc(dst.name)}</strong>`;
  document.getElementById('topoLinkSrcPortInput').value = '';
  document.getElementById('topoLinkDstPortInput').value = '';
  openModal('topologyLinkModal');
}

async function submitTopologyLinkModal(event) {
  event.preventDefault();
  const srcPort = document.getElementById('topoLinkSrcPortInput').value.trim();
  const dstPort = document.getElementById('topoLinkDstPortInput').value.trim();
  const payload = {
    sourceId: document.getElementById('topoLinkSrcId').value,
    targetId: document.getElementById('topoLinkDstId').value,
    cableType: document.getElementById('topoLinkCableModalSelect').value || 'auto',
    sourcePort: srcPort,
    targetPort: dstPort,
    autoPorts: !srcPort && !dstPort
  };
  try {
    const res = await apiJson('/api/topology/link', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (res.topology) appState.topology = res.topology;
    topoCableSourceId = null;
    clearTopoRubberBandLine();
    closeModal('topologyLinkModal');
    setTopoToolMode('select');
    renderTopologySection();
  } catch (err) {
    topoCableSourceId = null;
    clearTopoRubberBandLine();
    alert(err.message);
  }
}

async function deleteTopologyNode(nodeId) {
  if (!window.confirm('Remove this device from the Company Topology map?')) return;
  try {
    const res = await apiJson(`/api/topology/node/${encodeURIComponent(nodeId)}`, {
      method: 'DELETE'
    });
    if (res.topology) appState.topology = res.topology;
    if (topoSelectedNodeId === nodeId) topoSelectedNodeId = null;
    renderTopologySection();
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}

async function deleteTopologyLink(linkId) {
  try {
    const res = await apiJson(`/api/topology/link/${encodeURIComponent(linkId)}`, {
      method: 'DELETE'
    });
    if (res.topology) appState.topology = res.topology;
    if (topoSelectedLinkId === linkId) topoSelectedLinkId = null;
    renderTopologySection();
  } catch (err) {
    alert(err.message);
  }
}

async function importMonitoredToTopology() {
  const btn = document.getElementById('btnTopoImport');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Importing...';
  }
  try {
    const res = await apiJson('/api/topology/import-monitored', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.topology) appState.topology = res.topology;
    renderTopologySection();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⇄ Import Monitored Devices';
    }
  }
}

async function autoLayoutTopology() {
  try {
    const res = await apiJson('/api/topology/auto-layout', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.topology) appState.topology = res.topology;
    renderTopologySection();
  } catch (err) {
    alert(err.message);
  }
}

async function clearAllTopology() {
  const topo = getTopologyData();
  const nodeCount = (topo.nodes || []).length;
  const linkCount = (topo.links || []).length;
  if (nodeCount === 0 && linkCount === 0) {
    updateTopoModeBanner('Topology map is already empty.', '');
    return;
  }
  if (!window.confirm(`Clear all ${nodeCount} device(s) and ${linkCount} cable(s) from the topology map?`)) {
    return;
  }
  const btn = document.getElementById('btnTopoClearAll');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Clearing...';
  }
  try {
    const res = await apiJson('/api/topology/clear', {
      method: 'POST',
      body: JSON.stringify({})
    });
    topoSelectedNodeId = null;
    topoSelectedLinkId = null;
    topoCableSourceId = null;
    topoPduSourceId = null;
    if (res.topology) appState.topology = res.topology;
    renderTopologySection();
    updateTopoModeBanner('Cleared all devices and cables from the topology map.', '');
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🗑️ Clear All';
    }
  }
}

async function probeTopologyNow() {
  const btn = document.getElementById('btnTopoProbeAll');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Probing...';
  }
  try {
    await apiJson('/api/devices/probe-all', {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Probe Devices Now';
    }
  }
}

async function sendTopologyPduPing(sourceId, targetId) {
  updateTopoModeBanner('Sending live test ping...', '');
  try {
    const res = await apiJson('/api/topology/pdu-ping', {
      method: 'POST',
      body: JSON.stringify({ sourceId, targetId })
    });
    if (res.topology) appState.topology = res.topology;
    renderTopologySection();
    animateTopoPduPacket(res.pathNodeIds || [], res.reachable, res.failedAtNodeId);
    updateTopoModeBanner(res.message, res.reachable ? '' : 'critical');
  } catch (err) {
    updateTopoModeBanner(`Test Ping Error: ${err.message}`, 'critical');
  }
}

function animateTopoPduPacket(pathIds, reachable, failedNodeId) {
  const stage = document.getElementById('topoStage');
  if (!stage || !Array.isArray(pathIds) || pathIds.length < 1) return;
  const topo = getTopologyData();
  const nodeMap = new Map((topo.nodes || []).map(n => [n.id, n]));
  const coords = pathIds.map(id => nodeMap.get(id)).filter(Boolean);
  if (!coords.length) return;

  const pkt = document.createElement('div');
  pkt.className = 'topo-pdu-packet';
  pkt.textContent = '✉';
  pkt.style.left = `${coords[0].x}px`;
  pkt.style.top = `${coords[0].y}px`;
  stage.appendChild(pkt);

  let step = 1;
  const advance = () => {
    if (step >= coords.length) {
      pkt.classList.add(reachable ? 'ok' : 'fail');
      pkt.textContent = reachable ? '✓' : '✕';
      setTimeout(() => pkt.remove(), 900);
      return;
    }
    const target = coords[step];
    pkt.style.left = `${target.x}px`;
    pkt.style.top = `${target.y}px`;
    if (failedNodeId && target.id === failedNodeId) {
      pkt.classList.add('fail');
      pkt.textContent = '✕';
      setTimeout(() => pkt.remove(), 1100);
      return;
    }
    step += 1;
    setTimeout(advance, 440);
  };
  setTimeout(advance, 40);
}

