// Pulse Network Monitor — Uptime Kuma Monitor Panel (Heartbeats, Metrics, Area Ping Graph & Outage History Log)

let selectedKumaTarget = 'all';
let currentKumaLogFilter = 'all';
let customSimulatedKumaLogs = [];
let clearedKumaLogsBefore = 0;

let lastPingChartData = null;
let lastPingChartLayout = null;
let pingChartHover = { active: false, clientX: 0, clientY: 0, idx: null, targetId: null };
let kumaBarHoverState = { active: false, clientX: 0, clientY: 0 };

function normalizeKumaTargetId(targetId) {
  if (targetId === 'google_dns') return 'googledns';
  if (targetId === 'google_web') return 'google';
  return targetId || 'all';
}

// CVD-safe (Okabe-Ito / IBM) & theme-adaptive target colors + line dash styles
function getTargetAccessibleColor(targetId, fallbackColor) {
  const isLight =
    document.documentElement.getAttribute('data-theme') === 'light';
  const id = String(targetId || '').toLowerCase();
  if (id.includes('cloudflare')) return isLight ? '#c2410c' : '#fb923c'; // Vermilion-Orange
  if (id.includes('dns')) return isLight ? '#0f766e' : '#14b8a6'; // Bluish-Teal
  if (id.includes('google')) return isLight ? '#1d4ed8' : '#3b82f6'; // Royal/Sky Blue
  if (id.includes('gateway') || id.includes('router'))
    return isLight ? '#6d28d9' : '#a78bfa'; // Violet-Purple
  return fallbackColor || (isLight ? '#0f766e' : '#14b8a6');
}

function getTargetLineDash(targetId, idx) {
  const id = String(targetId || '').toLowerCase();
  if (id.includes('cloudflare')) return [6, 3];
  if (id.includes('dns')) return [2, 3];
  if (id.includes('gateway') || id.includes('router')) return [8, 3, 2, 3];
  if (idx === 1) return [6, 3];
  if (idx === 2) return [2, 3];
  if (idx === 3) return [8, 3, 2, 3];
  return [];
}

function selectKumaTarget(targetId) {
  selectedKumaTarget = normalizeKumaTargetId(targetId);
  document.querySelectorAll('#kumaMonitorTargetTabs [data-kuma-target]').forEach(btn => {
    btn.classList.toggle('active', normalizeKumaTargetId(btn.getAttribute('data-kuma-target')) === selectedKumaTarget);
  });
  renderPingGraphSection();
}

function setKumaLogFilter(filter) {
  currentKumaLogFilter = filter || 'all';
  document.querySelectorAll('#kumaLogFilterPills [data-kuma-log-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-kuma-log-filter') === currentKumaLogFilter);
  });
  renderKumaStatusLogTable();
}

function clearKumaLogHistory() {
  clearedKumaLogsBefore = Date.now();
  customSimulatedKumaLogs = [];
  renderKumaStatusLogTable();
}

function simulateKumaConnectionDrop() {
  const now = new Date();
  const dropTime = new Date(now.getTime() - 12000);
  const fmt = d => {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  customSimulatedKumaLogs.unshift(
    {
      status: 'UP',
      dateTime: fmt(now),
      timestampMs: now.getTime(),
      targetId: 'cloudflare',
      message: '200 - OK • Connection RESTORED to Cloudflare Anycast (1.1.1.1) — Responded in 13.2 ms'
    },
    {
      status: 'DOWN',
      dateTime: fmt(dropTime),
      timestampMs: dropTime.getTime(),
      targetId: 'cloudflare',
      message: 'Connection LOST • Timeout reaching Cloudflare Anycast (1.1.1.1:53) — 100% packet loss (Simulated Outage)'
    }
  );
  renderPingGraphSection();
}

function formatKumaDateTime(isoOrStr) {
  if (!isoOrStr) return '—';
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(String(isoOrStr))) {
    return String(isoOrStr);
  }
  const d = new Date(isoOrStr);
  if (isNaN(d.getTime())) return String(isoOrStr);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function fmtMegabytesPerSec(mbps) {
  const n = Math.max(0, Number(mbps) || 0) / 8;
  return `${n.toFixed(2)} MB/s`;
}

function updateKumaLiveSpeed(live) {
  const el = document.getElementById('kumaStatLiveSpeed');
  if (!el) return;
  const periodEl = document.getElementById('kumaStatSpeedPeriod');
  const titleEl = document.getElementById('kumaStatSpeedTitle');
  if (titleEl) titleEl.textContent = 'Internet Speed';

  const isp = (window.appState && window.appState.isp) || {};
  const st =
    (live && live.lastDownloadMbps != null
      ? { downloadMbps: live.lastDownloadMbps, uploadMbps: live.lastUploadMbps }
      : null) ||
    isp.lastSpeedTest ||
    (typeof lastCompletedSpeedTest !== 'undefined' ? lastCompletedSpeedTest : null);

  const rxMbps = Math.max(0, Number(live && live.rxMbps) || 0);
  const txMbps = Math.max(0, Number(live && live.txMbps) || 0);
  const rxMB = (rxMbps / 8).toFixed(2);
  const txMB = (txMbps / 8).toFixed(2);

  // Active transfer threshold: real active download/upload activity (> 2 Mbps)
  const isActiveTransfer = rxMbps >= 2.0 || txMbps >= 2.0;

  if (st && st.downloadMbps != null && Number(st.downloadMbps) > 0) {
    const dlMbps = Number(st.downloadMbps);
    const ulMbps = Number(st.uploadMbps) || 0;
    const dlMB = (dlMbps / 8).toFixed(1);
    const ulMB = (ulMbps / 8).toFixed(1);

    if (isActiveTransfer) {
      if (periodEl) periodEl.textContent = '(Active Live Transfer)';
      el.innerHTML = `
        <div style="font-size: 1.05rem; font-weight: 800; white-space: nowrap; color: var(--accent-cyan);">↓ ${rxMB} MB/s</div>
        <div style="font-size: 0.72rem; color: var(--accent-amber); font-weight: 600; margin-top: 2px;">↑ ${txMB} MB/s · Active Transfer</div>
      `;
    } else {
      if (periodEl) periodEl.textContent = '(Measured Line Speed)';
      el.innerHTML = `
        <div style="font-size: 1.02rem; font-weight: 800; white-space: nowrap; color: var(--accent-cyan);">↓ ${dlMB} MB/s · ↑ ${ulMB} MB/s</div>
        <div style="font-size: 0.72rem; color: var(--text-dim); font-weight: 600; margin-top: 2px;">${Math.round(dlMbps)} Mbps Down · ${Math.round(ulMbps)} Mbps Up</div>
      `;
    }
    el.title = `Measured Line Speed: ${dlMB} MB/s (${dlMbps.toFixed(1)} Mbps) Down · ${ulMB} MB/s (${ulMbps.toFixed(1)} Mbps) Up\nCurrent Real-Time NIC Transfer: ${rxMB} MB/s (${rxMbps.toFixed(1)} Mbps) Down · ${txMB} MB/s (${txMbps.toFixed(1)} Mbps) Up`;
  } else {
    if (periodEl) periodEl.textContent = '(Live NIC Throughput)';
    el.innerHTML = `
      <div style="font-size: 1.02rem; font-weight: 800; white-space: nowrap; color: var(--accent-cyan);">↓ ${rxMB} MB/s · ↑ ${txMB} MB/s</div>
      <div style="font-size: 0.72rem; color: var(--text-dim); font-weight: 600; margin-top: 2px;">Measuring Internet Line...</div>
    `;
    el.title = `Current NIC Transfer: ${rxMB} MB/s Down · ${txMB} MB/s Up`;
  }
}

async function pingInternetNow() {
  const btn = document.getElementById('btnPingInternetNow');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Pinging...';
  }
  try {
    const res = await apiJson('/api/isp/probe', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res && res.isp) {
      appState.isp = res.isp;
      renderPingGraphSection();
      if (typeof renderIspSection === 'function') renderIspSection();
      if (typeof renderExecutiveBanner === 'function') renderExecutiveBanner();
    }
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Ping Internet Now';
    }
  }
}

function renderPingGraphSection() {
  const isp = appState.isp || {};
  const pg = isp.pingGraph || {};
  const targets = pg.targets || [];
  const stats = pg.stats || {};

  // 1. Compute active target or actual external internet metrics (excluding local router from Combined Internet Ping)
  let activeHeartbeats = [];
  let currentPingMs = null;
  let avgResponseMs = null;
  let uptime24h = 100.0;
  let uptime30d = 100.0;
  let lossPct = 0;
  let isUp = true;
  let targetDesc = 'Live Check every 5s • Actual Internet Ping (excluding local router) & Speed in MB/s';
  let activeTargetLabel = 'Actual Internet Ping (External)';

  if (selectedKumaTarget !== 'all' && stats[selectedKumaTarget]) {
    const tObj = targets.find(t => t.id === selectedKumaTarget) || { name: selectedKumaTarget, host: '' };
    const st = stats[selectedKumaTarget];
    activeHeartbeats = (st.heartbeats || []).slice(-45).map(hb => ({ ...hb }));
    currentPingMs = st.currentMs;
    avgResponseMs = st.avgMs != null ? st.avgMs : st.currentMs;
    uptime24h = st.uptime24hPct != null ? st.uptime24hPct : (st.uptimePct != null ? st.uptimePct : 100.0);
    uptime30d = st.uptime30dPct != null ? st.uptime30dPct : uptime24h;
    lossPct = st.lossPct ?? 0;
    isUp = lossPct < 100 && (activeHeartbeats.length === 0 || activeHeartbeats[activeHeartbeats.length - 1].status !== 'offline');
    activeTargetLabel = `${tObj.name}${tObj.host || tObj.ip ? ` (${tObj.host || tObj.ip})` : ''}`;
    targetDesc = `Target: ${activeTargetLabel} • ${st.probeMethod || 'ICMP Echo'} • Live speed in MB/s`;
  } else {
    // External internet targets only (1.1.1.1, 8.8.8.8, google.com) — local gateway stays separate
    const internetTargets = targets.filter(t => t.id !== 'gateway');
    const externalPool = internetTargets.length ? internetTargets : targets;
    const primarySt = stats.cloudflare || stats.googledns || stats[externalPool[0]?.id] || Object.values(stats)[0] || {};
    const baseHeartbeats = (primarySt.heartbeats || []).slice(-45);
    const curVals = [];
    const avgVals = [];
    const up24Vals = [];
    const up30Vals = [];
    let anyOnline = false;

    externalPool.forEach(t => {
      const s = stats[t.id];
      if (!s) return;
      if (s.currentMs != null) {
        curVals.push(s.currentMs);
        anyOnline = true;
      }
      if (s.avgMs != null) avgVals.push(s.avgMs);
      if (s.uptime24hPct != null) up24Vals.push(s.uptime24hPct);
      else if (s.uptimePct != null) up24Vals.push(s.uptimePct);
      if (s.uptime30dPct != null) up30Vals.push(s.uptime30dPct);
    });

    currentPingMs = curVals.length
      ? Number((curVals.reduce((a, b) => a + b, 0) / curVals.length).toFixed(1))
      : isp.tier1LatencyMs;
    avgResponseMs = avgVals.length
      ? Number((avgVals.reduce((a, b) => a + b, 0) / avgVals.length).toFixed(1))
      : currentPingMs;
    uptime24h = up24Vals.length
      ? Number((up24Vals.reduce((a, b) => a + b, 0) / up24Vals.length).toFixed(2))
      : 100.0;
    uptime30d = up30Vals.length
      ? Number((up30Vals.reduce((a, b) => a + b, 0) / up30Vals.length).toFixed(2))
      : uptime24h;
    lossPct = isp.packetLossPct ?? 0;
    isUp = anyOnline || isp.overallHealth !== 'OUTAGE';

    // Align per-target samples at each heartbeat timestamp for Actual Internet Ping hover readout
    const baseLen = baseHeartbeats.length;
    activeHeartbeats = baseHeartbeats.map((hb, i) => {
      const fromEnd = baseLen - 1 - i;
      const sampleVals = [];
      const parts = [];
      let onlineCnt = 0;
      let offlineCnt = 0;
      externalPool.forEach(t => {
        const s = stats[t.id];
        const list = (s && s.heartbeats) || [];
        const match =
          list.find(x => x.dateTime === hb.dateTime && x.time === hb.time) ||
          (list.length - 1 - fromEnd >= 0 ? list[list.length - 1 - fromEnd] : null);
        if (!match) return;
        if (match.status === 'online') {
          onlineCnt += 1;
          if (match.ms != null) sampleVals.push(match.ms);
        } else {
          offlineCnt += 1;
        }
        parts.push(`${t.name}: ${match.ms != null ? `${match.ms} ms` : 'DOWN'}`);
      });
      const avgSample = sampleVals.length
        ? Number((sampleVals.reduce((a, b) => a + b, 0) / sampleVals.length).toFixed(1))
        : hb.ms;
      let combStatus = hb.status;
      if (offlineCnt > 0 && onlineCnt === 0) combStatus = 'offline';
      else if (offlineCnt > 0) combStatus = 'warning';
      return {
        ...hb,
        ms: avgSample,
        status: combStatus,
        breakdown: parts.join(' | ')
      };
    });
  }

  // Render 45-bar Uptime Kuma Hero Strip (fills Left -> Right)
  const mainStrip = document.getElementById('kumaMainHeartbeatStrip');
  if (mainStrip) {
    const totalBars = 45;
    const padCount = Math.max(0, totalBars - activeHeartbeats.length);
    const bars = [];
    const curStr = currentPingMs != null ? String(currentPingMs) : '';
    activeHeartbeats.forEach(hb => {
      let cls = hb.status === 'online' ? 'online' : hb.status === 'warning' ? 'warning' : 'offline';
      if (cls === 'online' && hb.ms != null && hb.ms > 120) {
        cls = 'warning';
      }
      const label = `${hb.dateTime || hb.time || ''} — ${hb.ms != null ? `${hb.ms} ms` : 'DOWN'}`;
      bars.push(
        `<span class="kuma-hero-bar ${cls}" data-hb-status="${esc(cls)}" data-hb-target="${esc(activeTargetLabel)}" data-hb-time="${esc(hb.dateTime || hb.time || '')}" data-hb-ping="${hb.ms != null ? esc(hb.ms) : ''}" data-hb-current="${esc(curStr)}" data-hb-breakdown="${esc(hb.breakdown || '')}" aria-label="${esc(label)}"></span>`
      );
    });
    for (let i = 0; i < padCount; i++) {
      bars.push(
        `<span class="kuma-hero-bar" data-hb-status="pending" data-hb-target="${esc(activeTargetLabel)}" data-hb-time="Pending" data-hb-ping="" data-hb-current="${esc(curStr)}" aria-label="Waiting for telemetry sample"></span>`
      );
    }
    mainStrip.innerHTML = bars.join('');
    bindKumaBarHoverHandlers(mainStrip);
  }

  const descEl = document.getElementById('kumaMainTargetDesc');
  if (descEl) descEl.textContent = targetDesc;

  const lastCheckEl = document.getElementById('kumaMainLastCheckTime');
  if (lastCheckEl && activeHeartbeats.length > 0) {
    const lastHb = activeHeartbeats[activeHeartbeats.length - 1];
    lastCheckEl.textContent = `Last check: ${lastHb.time || 'Live'}`;
  }

  const bigBadge = document.getElementById('kumaMainBigStatusBadge');
  if (bigBadge) {
    if (!isUp) {
      bigBadge.textContent = 'DOWN';
      bigBadge.className = 'kuma-big-status-pill down';
    } else if (lossPct > 0 || (currentPingMs != null && currentPingMs > 140)) {
      bigBadge.textContent = 'DEGRADED';
      bigBadge.className = 'kuma-big-status-pill degraded';
    } else {
      bigBadge.textContent = 'UP';
      bigBadge.className = 'kuma-big-status-pill';
    }
  }

  // Update the 5 Uptime Kuma Stat Boxes
  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  setTxt('kumaStatCurrentPing', currentPingMs != null ? `${currentPingMs} ms` : 'Probing...');
  setTxt('kumaStatAvgResponse', avgResponseMs != null ? `${avgResponseMs} ms` : 'Probing...');
  setTxt('kumaStatUptime24h', `${uptime24h}%`);
  setTxt('kumaStatUptime30d', `${uptime30d}%`);
  setTxt('kumaStatPacketLoss', `${lossPct}% Loss`);
  updateKumaLiveSpeed(isp.liveThroughput);

  const lossEl = document.getElementById('kumaStatPacketLoss');
  if (lossEl) {
    lossEl.style.color = lossPct > 0 ? 'var(--accent-red)' : 'var(--accent-green)';
  }

  // Render 4 Individual Target Heartbeat Cards
  const grid = document.getElementById('kumaTargetsGrid');
  if (grid) {
    grid.innerHTML = targets
      .map(t => {
        const st = stats[t.id] || {};
        const tColor = getTargetAccessibleColor(t.id, t.color);
        const tLabel = `${t.name}${t.host || t.ip ? ` (${t.host || t.ip})` : ''}`;
        const curStr = st.currentMs != null ? String(st.currentMs) : '';
        const heartbeats = (st.heartbeats || []).slice(-30);
        const pad = Math.max(0, 30 - heartbeats.length);
        const barsHtml = [
          ...heartbeats.map(hb => {
            let cls = hb.status === 'online' ? 'online' : 'offline';
            if (cls === 'online' && hb.ms != null && hb.ms > 120) {
              cls = 'warning';
            }
            const label = `${hb.dateTime || hb.time || ''}: ${hb.ms != null ? `${hb.ms} ms` : 'DOWN'}`;
            return `<span class="kuma-bar ${cls}" data-hb-status="${esc(cls)}" data-hb-target="${esc(tLabel)}" data-hb-color="${esc(tColor)}" data-hb-time="${esc(hb.dateTime || hb.time || '')}" data-hb-ping="${hb.ms != null ? esc(hb.ms) : ''}" data-hb-current="${esc(curStr)}" aria-label="${esc(label)}"></span>`;
          }),
          ...Array.from({ length: pad }).map(
            () => `<span class="kuma-bar" data-hb-status="pending" data-hb-target="${esc(tLabel)}" data-hb-color="${esc(tColor)}" data-hb-time="Pending" data-hb-ping="" data-hb-current="${esc(curStr)}" aria-label="Waiting for telemetry sample"></span>`
          )
        ].join('');
        const up24 = st.uptime24hPct != null ? st.uptime24hPct : (st.uptimePct != null ? st.uptimePct : 100);
        return `
          <div class="kuma-card" style="cursor:pointer;" onclick="selectKumaTarget('${esc(t.id)}')">
            <div class="kuma-header">
              <div>
                <strong style="color:${esc(tColor)};">● ${esc(t.name)}</strong>
                <small style="color:var(--text-dim); margin-left:6px;">${esc(t.host || t.ip || '')}</small>
              </div>
              <div class="mono" style="font-size:0.82rem;">
                <strong>${st.currentMs != null ? `${st.currentMs} ms` : '—'}</strong>
                <span style="color:var(--text-dim); margin-left:6px;">(24h: ${up24}%)</span>
              </div>
            </div>
            <div class="kuma-bars">${barsHtml}</div>
          </div>
        `;
      })
      .join('');
    bindKumaBarHoverHandlers(grid);
  }

  if (kumaBarHoverState.active) {
    refreshHoveredKumaBarTooltip();
  }

  // Render Chart Legend Pills
  const pills = document.getElementById('chartLegendPills');
  if (pills) {
    pills.innerHTML = targets
      .map(t => {
        const hidden = hiddenChartSeries.has(t.id);
        const tColor = getTargetAccessibleColor(t.id, t.color);
        return `
          <button type="button" class="legend-pill" style="opacity:${
            hidden ? 0.45 : 1
          };" onclick="toggleChartSeries('${esc(t.id)}')">
            <span style="width:10px; height:10px; border-radius:50%; background:${esc(
              tColor
            )}; display:inline-block;"></span>
            ${esc(t.name)}
          </button>
        `;
      })
      .join('');
  }

  drawPingChart(targets, pg.timeseries || {});
  renderKumaStatusLogTable();
}

function renderKumaStatusLogTable() {
  const tbody = document.getElementById('kumaStatusLogTableBody');
  if (!tbody) return;

  const isp = appState.isp || {};
  const pg = isp.pingGraph || {};
  const stats = pg.stats || {};

  // Gather status logs from Uptime Kuma probe logs + networkEvents (outages/recoveries) + custom simulated drops
  let combinedLogs = [...customSimulatedKumaLogs];

  if (selectedKumaTarget !== 'all' && stats[selectedKumaTarget] && stats[selectedKumaTarget].statusLog) {
    combinedLogs.push(...stats[selectedKumaTarget].statusLog);
  } else if (Array.isArray(pg.statusLog)) {
    combinedLogs.push(...pg.statusLog);
  }

  // Also include historical connection loss / recovery events from SQLite networkEvents
  const netEvents = appState.networkEvents || [];
  netEvents.forEach(ev => {
    const isDownEvent =
      ev.severity === 'CRITICAL' ||
      /offline|outage|down|lost|disconnected/i.test(ev.type || '') ||
      /offline|stopped responding|unreachable|disconnected/i.test(ev.title || '');
    const isUpEvent =
      /online|restored|recovered|healthy/i.test(ev.type || '') ||
      /recovered|responding again|restored/i.test(ev.title || '');

    if (isDownEvent || isUpEvent || selectedKumaTarget === 'all') {
      combinedLogs.push({
        status: isDownEvent ? 'DOWN' : 'UP',
        dateTime: formatKumaDateTime(ev.timestamp),
        timestampMs: ev.timestamp ? new Date(ev.timestamp).getTime() : 0,
        targetId: 'event',
        message: `${ev.title ? `${ev.title} — ` : ''}${ev.message || ''}`
      });
    }
  });

  // Deduplicate by dateTime + message and apply clear timestamp
  const seen = new Set();
  const deduped = [];
  combinedLogs.forEach(item => {
    const tsMs = item.timestampMs || (item.timestamp ? new Date(item.timestamp).getTime() : Date.now());
    if (clearedKumaLogsBefore && tsMs < clearedKumaLogsBefore) return;
    const dt = formatKumaDateTime(item.dateTime || item.timestamp);
    const key = `${item.status}|${dt}|${item.message}`;
    if (seen.has(key)) return;
    seen.add(key);
    deduped.push({
      status: item.status || 'UP',
      dateTime: dt,
      message: item.message || '200 - OK'
    });
  });

  let filtered = deduped;
  if (currentKumaLogFilter === 'DOWN') {
    filtered = deduped.filter(r => r.status === 'DOWN');
  } else if (currentKumaLogFilter === 'UP') {
    filtered = deduped.filter(r => r.status === 'UP');
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; padding: 22px; color: var(--text-dim);">
          No status events match the current filter (<strong>${esc(currentKumaLogFilter)}</strong>).
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .slice(0, 35)
    .map(row => {
      const isDown = row.status === 'DOWN';
      const badgeClass = isDown ? 'offline' : 'online';
      const statusText = isDown ? '✕ DOWN' : '✓ UP';
      return `
        <tr class="${isDown ? 'port-row-at-risk' : ''}">
          <td>
            <span class="status-pill ${badgeClass}" style="min-width: 72px; justify-content: center;">
              ${esc(statusText)}
            </span>
          </td>
          <td class="mono" style="font-size: 0.82rem; color: var(--text-muted); white-space: nowrap;">
            ${esc(row.dateTime)}
          </td>
          <td style="font-size: 0.84rem; font-weight: ${isDown ? '700' : '500'}; color: ${isDown ? 'var(--accent-red)' : 'var(--text-main)'};">
            ${esc(row.message)}
          </td>
        </tr>
      `;
    })
    .join('');
}

function toggleChartSeries(id) {
  if (hiddenChartSeries.has(id)) hiddenChartSeries.delete(id);
  else hiddenChartSeries.add(id);
  renderPingGraphSection();
}

function ensureKumaBarTooltipEl() {
  let el = document.getElementById('kumaBarTooltip');
  if (!el) {
    el = document.createElement('div');
    el.id = 'kumaBarTooltip';
    el.className = 'kuma-bar-tooltip';
    el.style.display = 'none';
    document.body.appendChild(el);
  }
  return el;
}

function showKumaBarTooltip(barEl, clientX, clientY) {
  if (!barEl) {
    hideKumaBarTooltip();
    return;
  }
  const tipEl = ensureKumaBarTooltipEl();
  const status = barEl.getAttribute('data-hb-status') || 'pending';
  const targetName = barEl.getAttribute('data-hb-target') || 'SLA Target';
  const timeStr = barEl.getAttribute('data-hb-time') || '';
  const pingStr = barEl.getAttribute('data-hb-ping') || '';
  const curStr = barEl.getAttribute('data-hb-current') || '';
  const color = barEl.getAttribute('data-hb-color') || '';
  const breakdown = barEl.getAttribute('data-hb-breakdown') || '';

  let badgeClass = 'online';
  let badgeText = 'UP';
  let pingHtml = `<span class="sla-tip-main-ping">${esc(pingStr)} ms</span>`;
  if (status === 'offline') {
    badgeClass = 'offline';
    badgeText = 'DOWN';
    pingHtml = `<span class="sla-tip-main-ping down">Timeout (DOWN)</span>`;
  } else if (status === 'warning') {
    badgeClass = 'warning';
    badgeText = 'DEGRADED';
    pingHtml = pingStr
      ? `<span class="sla-tip-main-ping warn">${esc(pingStr)} ms</span>`
      : `<span class="sla-tip-main-ping warn">Partial Loss</span>`;
  } else if (status === 'pending') {
    badgeClass = 'new';
    badgeText = 'PENDING';
    pingHtml = `<span style="color:var(--text-dim); font-weight:600;">Waiting for telemetry sample...</span>`;
  }

  const dotStyle = color ? `background:${esc(color)};` : 'background:var(--accent-cyan);';
  const currentRow = curStr
    ? `<div class="sla-tip-sub">Current Live Ping: <strong class="mono" style="color:var(--accent-green);">${esc(curStr)} ms</strong></div>`
    : '';
  const breakdownHtml = breakdown
    ? `<div style="margin-top:6px; padding-top:5px; border-top:1px solid var(--border-subtle); font-size:0.71rem; color:var(--text-dim);">${esc(breakdown)}</div>`
    : '';
  const timeRow =
    timeStr && status !== 'pending'
      ? `<div class="sla-tip-sub" style="color:var(--text-dim);">Checked: <span class="mono">${esc(timeStr)}</span></div>`
      : '';

  tipEl.innerHTML = `
    <div class="sla-tip-head">
      <span class="sla-tip-name"><span class="sla-tip-dot" style="${dotStyle}"></span>${esc(targetName)}</span>
      <span class="status-pill ${badgeClass}" style="font-size:0.65rem; padding:2px 7px;">${badgeText}</span>
    </div>
    <div style="display:flex; align-items:baseline; justify-content:space-between; gap:10px;">
      <span style="font-size:0.74rem; color:var(--text-muted); font-weight:600;">Ping:</span>
      ${pingHtml}
    </div>
    ${currentRow}
    ${timeRow}
    ${breakdownHtml}
  `;

  tipEl.style.display = 'block';
  const rect = tipEl.getBoundingClientRect();
  const pad = 12;
  let left = clientX + 14;
  let top = clientY - rect.height - 14;
  if (left + rect.width > window.innerWidth - pad) {
    left = Math.max(pad, clientX - rect.width - 14);
  }
  if (top < pad) {
    top = Math.min(window.innerHeight - rect.height - pad, clientY + 18);
  }
  tipEl.style.left = `${Math.round(left)}px`;
  tipEl.style.top = `${Math.round(top)}px`;
}

function hideKumaBarTooltip() {
  const tipEl = document.getElementById('kumaBarTooltip');
  if (tipEl) tipEl.style.display = 'none';
}

function resetSlaHoverTooltips() {
  kumaBarHoverState = { active: false, clientX: 0, clientY: 0 };
  pingChartHover = { active: false, clientX: 0, clientY: 0, idx: null, targetId: null };
  hideKumaBarTooltip();
  hidePingChartTooltip();
}

function refreshHoveredKumaBarTooltip() {
  if (!kumaBarHoverState.active) return;
  const hit = document.elementFromPoint(kumaBarHoverState.clientX, kumaBarHoverState.clientY);
  const bar = hit && hit.closest ? hit.closest('.kuma-hero-bar, .kuma-bar') : null;
  if (bar) {
    showKumaBarTooltip(bar, kumaBarHoverState.clientX, kumaBarHoverState.clientY);
  } else {
    hideKumaBarTooltip();
  }
}

function bindKumaBarHoverHandlers(container) {
  if (!container || container.dataset.hoverBound) return;
  container.dataset.hoverBound = '1';
  const onMove = e => {
    const bar = e.target.closest('.kuma-hero-bar, .kuma-bar');
    if (!bar) {
      kumaBarHoverState.active = false;
      hideKumaBarTooltip();
      return;
    }
    kumaBarHoverState = { active: true, clientX: e.clientX, clientY: e.clientY };
    showKumaBarTooltip(bar, e.clientX, e.clientY);
  };
  container.addEventListener('mouseover', onMove);
  container.addEventListener('mousemove', onMove);
  container.addEventListener('mouseleave', () => {
    kumaBarHoverState.active = false;
    hideKumaBarTooltip();
  });
  if (!window._kumaScrollBound) {
    window._kumaScrollBound = true;
    window.addEventListener(
      'scroll',
      () => {
        if (kumaBarHoverState.active) {
          kumaBarHoverState.active = false;
          hideKumaBarTooltip();
        }
      },
      { passive: true }
    );
  }
}

function drawPingChart(targets, timeseries) {
  lastPingChartData = {
    targets: targets || [],
    timeseries: timeseries || {}
  };
  const canvas = document.getElementById('pingChartCanvas');
  if (!canvas) return;
  bindPingChartHoverHandlers(canvas);
  renderPingChartCanvas();
}

function bindPingChartHoverHandlers(canvas) {
  if (!canvas || canvas.dataset.hoverBound) return;
  canvas.dataset.hoverBound = '1';

  const handlePoint = (clientX, clientY) => {
    pingChartHover.active = true;
    pingChartHover.clientX = clientX;
    pingChartHover.clientY = clientY;
    updatePingChartHoverFromCoords();
  };

  canvas.addEventListener('mousemove', e => {
    handlePoint(e.clientX, e.clientY);
  });

  canvas.addEventListener('mouseleave', () => {
    pingChartHover = { active: false, clientX: 0, clientY: 0, idx: null, targetId: null };
    canvas.style.cursor = 'default';
    hidePingChartTooltip();
    renderPingChartCanvas();
  });

  canvas.addEventListener(
    'touchstart',
    e => {
      if (e.touches && e.touches[0]) {
        handlePoint(e.touches[0].clientX, e.touches[0].clientY);
      }
    },
    { passive: true }
  );

  canvas.addEventListener(
    'touchmove',
    e => {
      if (e.touches && e.touches[0]) {
        handlePoint(e.touches[0].clientX, e.touches[0].clientY);
      }
    },
    { passive: true }
  );
}

function hidePingChartTooltip() {
  const tipEl = document.getElementById('chartTooltip');
  if (tipEl) tipEl.style.display = 'none';
}

function updatePingChartHoverFromCoords() {
  const canvas = document.getElementById('pingChartCanvas');
  if (!canvas || !lastPingChartLayout || !lastPingChartLayout.timestamps.length) {
    hidePingChartTooltip();
    return;
  }

  const { padL, padT, w, h, timestamps, points } = lastPingChartLayout;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;

  const scaleX = canvas.width / rect.width;
  const scaleY = canvas.height / rect.height;
  const mx = (pingChartHover.clientX - rect.left) * scaleX;
  const my = (pingChartHover.clientY - rect.top) * scaleY;

  if (mx < padL - 12 || mx > padL + w + 12 || my < padT - 12 || my > padT + h + 12) {
    pingChartHover.idx = null;
    pingChartHover.targetId = null;
    canvas.style.cursor = 'default';
    hidePingChartTooltip();
    renderPingChartCanvas(true);
    return;
  }

  // 1. Check direct proximity to any plotted dot on the graph
  let bestDot = null;
  let bestDist = 14;
  for (const pt of points) {
    const d = Math.hypot(mx - pt.x, my - pt.y);
    if (d <= bestDist) {
      bestDist = d;
      bestDot = pt;
    }
  }

  if (bestDot) {
    pingChartHover.idx = bestDot.idx;
    pingChartHover.targetId = bestDot.targetId;
    canvas.style.cursor = 'pointer';
  } else {
    const ratio = w > 0 ? Math.max(0, Math.min(1, (mx - padL) / w)) : 0;
    const nearestIdx =
      timestamps.length > 1 ? Math.round(ratio * (timestamps.length - 1)) : 0;
    pingChartHover.idx = nearestIdx;
    pingChartHover.targetId = null;
    canvas.style.cursor = 'crosshair';
  }

  renderPingChartCanvas(true);
  renderPingChartTooltip(rect, scaleX, my / scaleY);
}

function renderPingChartTooltip(canvasRect, scaleX, cssY) {
  const tipEl = document.getElementById('chartTooltip');
  const wrapper = document.getElementById('pingChartWrapper');
  if (!tipEl || !wrapper || !lastPingChartLayout || pingChartHover.idx == null) {
    hidePingChartTooltip();
    return;
  }

  const { padL, w, timestamps, activeTargets, timeseries } = lastPingChartLayout;
  const idx = pingChartHover.idx;
  const tsLabel = timestamps[idx] || 'Sample';
  const isLatest = idx === timestamps.length - 1;
  const stats = (appState.isp && appState.isp.pingGraph && appState.isp.pingGraph.stats) || {};

  // Put directly hovered dot's target first
  const ordered = [...activeTargets].sort((a, b) => {
    if (a.id === pingChartHover.targetId) return -1;
    if (b.id === pingChartHover.targetId) return 1;
    return 0;
  });

  const rowsHtml = ordered
    .map(t => {
      const series = timeseries[t.id] || [];
      const val = series[idx];
      const st = stats[t.id] || {};
      const curMs = st.currentMs;
      const color = getTargetAccessibleColor(t.id, t.color);
      const focused = pingChartHover.targetId === t.id;

      const pingText = val != null ? `${val} ms` : 'Timeout';
      const curBadge =
        isLatest && val != null
          ? `<small style="color:var(--accent-green); font-weight:700;">CURRENT</small>`
          : curMs != null
          ? `<small>Now: ${curMs} ms</small>`
          : '';

      return `
        <div class="sla-tip-row ${focused ? 'focused' : ''}">
          <span class="sla-tip-name">
            <span class="sla-tip-dot" style="background:${esc(color)};"></span>
            ${esc(t.name)}
          </span>
          <span class="sla-tip-vals">
            <strong class="${val == null ? 'down' : ''}">${esc(pingText)}</strong>
            ${curBadge}
          </span>
        </div>
      `;
    })
    .join('');

  tipEl.innerHTML = `
    <div class="sla-tip-head">
      <span>Time: <strong class="mono" style="color:var(--text-main);">${esc(tsLabel)}</strong></span>
      <span class="status-pill ${isLatest ? 'online' : 'new'}" style="font-size:0.62rem; padding:1px 6px;">${
    isLatest ? 'LIVE / CURRENT' : 'SAMPLE'
  }</span>
    </div>
    <div class="sla-tip-rows">${rowsHtml}</div>
  `;

  tipEl.style.display = 'block';

  const colCanvasX =
    padL + (timestamps.length > 1 ? (w * idx) / (timestamps.length - 1) : w / 2);
  const dotCssX = colCanvasX / (scaleX || 1);
  const tipW = tipEl.offsetWidth || 230;
  const tipH = tipEl.offsetHeight || 110;
  const wrapW = wrapper.clientWidth || canvasRect.width || 700;
  const wrapH = wrapper.clientHeight || canvasRect.height || 240;

  let left = dotCssX + 14;
  if (left + tipW > wrapW - 6) {
    left = Math.max(6, dotCssX - tipW - 14);
  }
  const top = Math.max(6, Math.min(wrapH - tipH - 6, cssY - tipH / 2));

  tipEl.style.left = `${Math.round(left)}px`;
  tipEl.style.top = `${Math.round(top)}px`;
}

function renderPingChartCanvas(skipHoverRecompute = false) {
  const canvas = document.getElementById('pingChartCanvas');
  if (!canvas || !lastPingChartData) return;
  const { targets, timeseries } = lastPingChartData;
  const ctx = canvas.getContext('2d');
  const rect = canvas.parentElement.getBoundingClientRect();
  const targetW = Math.max(400, Math.round(rect.width) || 700);
  const targetH = 240;
  if (canvas.width !== targetW) canvas.width = targetW;
  if (canvas.height !== targetH) canvas.height = targetH;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const timestamps = timeseries.timestamps || [];
  const padL = 48;
  const padR = 20;
  const padT = 18;
  const padB = 30;
  const w = canvas.width - padL - padR;
  const h = canvas.height - padT - padB;

  const activeTargets =
    selectedKumaTarget !== 'all'
      ? targets.filter(t => t.id === selectedKumaTarget)
      : targets.filter(t => !hiddenChartSeries.has(t.id));

  let maxVal = 50;
  activeTargets.forEach(t => {
    (timeseries[t.id] || []).forEach(v => {
      if (v != null && v > maxVal) maxVal = v;
    });
  });
  maxVal = Math.ceil(maxVal * 1.2);

  // Horizontal grid lines & Y-axis labels (theme-adaptive contrast)
  const isLight =
    document.documentElement.getAttribute('data-theme') === 'light';
  const isCvd =
    document.documentElement.getAttribute('data-cvd') === 'true';
  ctx.strokeStyle = isLight
    ? 'rgba(15, 23, 42, 0.1)'
    : 'rgba(148, 163, 184, 0.16)';
  ctx.fillStyle = isLight ? '#334155' : '#cbd5e1';
  ctx.font = '600 11px JetBrains Mono, monospace';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (h * i) / 4;
    const val = Math.round(maxVal * (1 - i / 4));
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + w, y);
    ctx.stroke();
    ctx.fillText(`${val} ms`, 4, y + 4);
  }

  if (timestamps.length === 0) {
    lastPingChartLayout = {
      padL, padR, padT, padB, w, h, maxVal, timestamps, activeTargets, timeseries, points: []
    };
    ctx.fillText('Collecting live ping telemetry samples...', padL + 20, padT + h / 2);
    hidePingChartTooltip();
    return;
  }

  // X-axis time labels
  const step = Math.max(1, Math.floor(timestamps.length / 6));
  for (let idx = 0; idx < timestamps.length; idx += step) {
    const x =
      padL + (timestamps.length > 1 ? (w * idx) / (timestamps.length - 1) : w / 2);
    ctx.fillStyle = isLight ? '#475569' : '#94a3b8';
    ctx.fillText(timestamps[idx] || '', Math.max(padL, x - 22), padT + h + 20);
  }

  const allPoints = [];

  // Draw Uptime Kuma style smooth area & line curves (CVD-accessible colors + dash patterns)
  activeTargets.forEach((t, seriesIdx) => {
    const series = timeseries[t.id] || [];
    const pts = [];
    series.forEach((val, idx) => {
      if (val == null) return;
      const x =
        padL + (timestamps.length > 1 ? (w * idx) / (timestamps.length - 1) : w / 2);
      const y = padT + h - (Math.min(val, maxVal) / maxVal) * h;
      const pt = { x, y, val, idx, targetId: t.id };
      pts.push(pt);
      allPoints.push(pt);
    });
    if (pts.length === 0) return;

    const color = getTargetAccessibleColor(t.id, t.color);

    // Filled gradient area under curve
    const grad = ctx.createLinearGradient(0, padT, 0, padT + h);
    grad.addColorStop(0, `${color}30`);
    grad.addColorStop(1, `${color}03`);
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.moveTo(pts[0].x, padT + h);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, padT + h);
    ctx.closePath();
    ctx.fill();

    // Main line (with distinct dash patterns when CVD mode is active)
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.4;
    ctx.setLineDash(isCvd ? getTargetLineDash(t.id, seriesIdx) : []);
    ctx.beginPath();
    pts.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
    });
    ctx.stroke();
    ctx.setLineDash([]);

    // Plotted dots
    pts.forEach(p => {
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3.2, 0, Math.PI * 2);
      ctx.fill();
    });
  });

  lastPingChartLayout = {
    padL,
    padR,
    padT,
    padB,
    w,
    h,
    maxVal,
    timestamps,
    activeTargets,
    timeseries,
    points: allPoints
  };

  if (pingChartHover.active && !skipHoverRecompute) {
    updatePingChartHoverFromCoords();
    return;
  }

  // Draw hover crosshair & highlighted dots when hovering on dots or graph
  if (pingChartHover.active && pingChartHover.idx != null && pingChartHover.idx < timestamps.length) {
    const colX =
      padL +
      (timestamps.length > 1 ? (w * pingChartHover.idx) / (timestamps.length - 1) : w / 2);

    ctx.save();
    ctx.strokeStyle = isLight ? 'rgba(0, 118, 168, 0.55)' : 'rgba(56, 189, 248, 0.6)';
    ctx.lineWidth = 1.25;
    ctx.setLineDash([4, 3]);
    ctx.beginPath();
    ctx.moveTo(colX, padT);
    ctx.lineTo(colX, padT + h);
    ctx.stroke();

    const focusedPt = pingChartHover.targetId
      ? allPoints.find(
          p => p.idx === pingChartHover.idx && p.targetId === pingChartHover.targetId
        )
      : null;

    if (focusedPt) {
      ctx.beginPath();
      ctx.moveTo(padL, focusedPt.y);
      ctx.lineTo(focusedPt.x, focusedPt.y);
      ctx.stroke();
    }
    ctx.restore();

    allPoints
      .filter(p => p.idx === pingChartHover.idx)
      .forEach(p => {
        const targetObj = activeTargets.find(t => t.id === p.targetId);
        const color = getTargetAccessibleColor(p.targetId, targetObj ? targetObj.color : null);
        const isFocused = pingChartHover.targetId === p.targetId;
        if (isFocused) {
          ctx.fillStyle = `${color}38`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 9.5, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.fillStyle = color;
        ctx.strokeStyle = isLight ? '#ffffff' : '#0f1b2d';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(p.x, p.y, isFocused ? 5.6 : 4.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
      });
  }
}

// Section 6: Live Auto-Refreshing Terminal / PowerShell Network Logs
let eventsAutoRefresh = true;
let terminalAutoScroll = true;
let showLiveTerminalTicks = true;
let currentEventLogFilter = 'all';
let currentEventLogSearch = '';
let liveTerminalTicks = [];
let lastTerminalSignature = '';
let userScrolledUpInTerminal = false;
let terminalScrollListenerAttached = false;
let terminalHasVisibleRender = false;
let lastRoutineIspTickAt = 0;

function scrollTerminalToBottom(force = false) {
  const container = document.getElementById('incidentsContainer');
  if (!container || container.clientHeight === 0) return;
  if (force || (terminalAutoScroll && !userScrolledUpInTerminal)) {
    container.scrollTop = container.scrollHeight;
  }
}

function ensureTerminalScrollListener(container) {
  if (!container || terminalScrollListenerAttached || typeof container.addEventListener !== 'function') return;
  terminalScrollListenerAttached = true;
  container.addEventListener('scroll', () => {
    if (container.clientHeight === 0) return;
    const distFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    userScrolledUpInTerminal = distFromBottom > 36;
    const promptTxt = document.getElementById('psTerminalPromptText');
    if (promptTxt && eventsAutoRefresh) {
      promptTxt.textContent = userScrolledUpInTerminal
        ? 'Scrollback paused while reading history — scroll to bottom to resume auto-follow'
        : 'Streaming live network telemetry...';
    }
  });
}

function setEventLogFilter(filter) {
  currentEventLogFilter = filter || 'all';
  document.querySelectorAll('#eventLogFilterTabs [data-ev-filter]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-ev-filter') === currentEventLogFilter);
  });
  lastTerminalSignature = '';
  renderTimeline();
}

function handleEventLogSearch(value) {
  currentEventLogSearch = String(value || '').trim().toLowerCase();
  lastTerminalSignature = '';
  renderTimeline();
}

function toggleTerminalAutoScroll() {
  terminalAutoScroll = !terminalAutoScroll;
  const btn = document.getElementById('btnToggleTerminalScroll');
  if (btn) btn.textContent = terminalAutoScroll ? '⬇ Auto-Scroll: ON' : '⬇ Auto-Scroll: OFF';
  if (terminalAutoScroll) {
    userScrolledUpInTerminal = false;
    const container = document.getElementById('incidentsContainer');
    if (container) container.scrollTop = container.scrollHeight;
    const promptTxt = document.getElementById('psTerminalPromptText');
    if (promptTxt && eventsAutoRefresh) {
      promptTxt.textContent = 'Streaming live network telemetry...';
    }
  }
}

function toggleTerminalTicks() {
  showLiveTerminalTicks = !showLiveTerminalTicks;
  const btn = document.getElementById('btnToggleTerminalTicks');
  if (btn) btn.textContent = showLiveTerminalTicks ? '📡 Live Updates: ON' : '📡 Live Updates: OFF';
  lastTerminalSignature = '';
  renderTimeline();
}

function toggleEventsAutoRefresh() {
  eventsAutoRefresh = !eventsAutoRefresh;
  const badge = document.getElementById('eventsLiveBadge');
  const btn = document.getElementById('btnToggleEventsAuto');
  const promptTxt = document.getElementById('psTerminalPromptText');
  if (badge) {
    badge.className = `status-pill ${eventsAutoRefresh ? 'online' : 'warning'}`;
    badge.textContent = eventsAutoRefresh ? '● Auto-Refresh ON (5s)' : '⏸ Stream Paused';
  }
  if (btn) {
    btn.textContent = eventsAutoRefresh ? '⏸ Pause Stream' : '▶ Resume Stream';
  }
  if (promptTxt) {
    promptTxt.textContent = eventsAutoRefresh
      ? 'Streaming live network telemetry...'
      : 'Stream paused — click Resume Stream to continue';
  }
  if (eventsAutoRefresh) {
    refreshNetworkLogsNow();
  }
}

async function refreshNetworkLogsNow() {
  try {
    const events = await apiJson('/api/network/events?limit=200');
    if (Array.isArray(events)) {
      appState.networkEvents = events;
      renderTimeline();
    }
  } catch (err) {
    console.warn('Failed to refresh network logs:', err);
  }
}

function pushLiveNetworkEvent(ev) {
  if (!ev || !eventsAutoRefresh) return;
  const list = Array.isArray(appState.networkEvents) ? [...appState.networkEvents] : [];
  if (ev.id != null && list.some(item => item.id === ev.id)) return;
  list.unshift(ev);
  if (list.length > 200) list.length = 200;
  appState.networkEvents = list;
  renderTimeline();
}

function pushTerminalTick(severity, eventType, title, message, target = '') {
  if (!eventsAutoRefresh) return;
  const sevUpper = String(severity || 'LIVE').toUpperCase();
  const nowMs = Date.now();
  // Pace routine LIVE heartbeat lines cleanly (every ~12s) so real alerts & changes stay easy to read
  if (sevUpper === 'LIVE' && eventType === 'ISP_PING') {
    if (nowMs - lastRoutineIspTickAt < 12000) return;
    lastRoutineIspTickAt = nowMs;
  }
  liveTerminalTicks.push({
    id: `tick-${nowMs}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: new Date(nowMs).toISOString(),
    severity: sevUpper,
    eventType: eventType || 'HEARTBEAT',
    title: title || '',
    message: message || '',
    ip: target || '',
    deviceName: '',
    mac: '',
    isTick: true
  });
  if (liveTerminalTicks.length > 40) {
    liveTerminalTicks.splice(0, liveTerminalTicks.length - 40);
  }
  renderTimeline();
}

function formatTerminalTime(isoStr) {
  if (!isoStr) return '--:--:--';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return String(isoStr).slice(0, 19);
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function renderTimeline() {
  const container = document.getElementById('incidentsContainer');
  const events = appState.networkEvents || [];
  const combined = showLiveTerminalTicks ? [...events, ...liveTerminalTicks] : [...events];

  const sideBadge = document.getElementById('sideBadgeEvents');
  if (sideBadge) sideBadge.textContent = events.length;

  const updatedEl = document.getElementById('eventsLastUpdated');
  if (updatedEl) {
    updatedEl.textContent = `Updated: ${new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })}`;
  }

  let filtered = combined;
  if (currentEventLogFilter === 'critical') {
    filtered = combined.filter(ev => ev.severity === 'CRITICAL');
  } else if (currentEventLogFilter === 'warning') {
    filtered = combined.filter(ev => ev.severity === 'WARNING');
  } else if (currentEventLogFilter === 'info') {
    filtered = combined.filter(ev => !ev.severity || ev.severity === 'INFO' || ev.severity === 'LIVE');
  } else if (currentEventLogFilter === 'device') {
    filtered = combined.filter(ev => {
      const t = String(ev.eventType || '');
      return (
        t.startsWith('DEVICE_') ||
        t.startsWith('ROUTER_') ||
        t === 'NEW_DEVICE' ||
        t === 'IP_CHANGED' ||
        t === 'PORT_SCAN' ||
        t === 'NETWORK_SCAN'
      );
    });
  } else if (currentEventLogFilter === 'topology') {
    filtered = combined.filter(ev => {
      const t = String(ev.eventType || '');
      return (
        t.startsWith('TOPOLOGY_') ||
        t.startsWith('WAN_') ||
        t.startsWith('ISP_') ||
        t === 'SPEED_TEST' ||
        t === 'DIAGNOSTICS_RUN'
      );
    });
  }

  if (currentEventLogSearch) {
    filtered = filtered.filter(ev =>
      `${ev.title || ''} ${ev.message || ''} ${ev.ip || ''} ${ev.mac || ''} ${ev.deviceName || ''} ${ev.eventType || ''}`
        .toLowerCase()
        .includes(currentEventLogSearch)
    );
  }

  // Chronological order (oldest -> newest at bottom, just like PowerShell / tail -f)
  const ordered = [...filtered].sort((a, b) => {
    const ta = new Date(a.timestamp || 0).getTime() || 0;
    const tb = new Date(b.timestamp || 0).getTime() || 0;
    if (ta !== tb) return ta - tb;
    return (Number(a.id) || 0) - (Number(b.id) || 0);
  });

  const countChip = document.getElementById('eventsShowingCount');
  if (countChip) {
    countChip.textContent =
      ordered.length === combined.length
        ? `${ordered.length} lines`
        : `${ordered.length} of ${combined.length} lines`;
  }

  if (!container) return;
  ensureTerminalScrollListener(container);

  const signature = `${currentEventLogFilter}|${currentEventLogSearch}|${showLiveTerminalTicks}|` + ordered.map(ev => `${ev.id ?? ''}:${ev.timestamp ?? ''}`).join(',');
  if (signature === lastTerminalSignature) {
    return;
  }

  const isVisible = container.clientHeight > 0;
  const prevScrollTop = container.scrollTop;
  const distFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
  const wasNearBottom = distFromBottom <= 40;
  const shouldPinBottom = terminalAutoScroll && (
    (!terminalHasVisibleRender && isVisible) ||
    (!userScrolledUpInTerminal && wasNearBottom)
  );
  if (isVisible) terminalHasVisibleRender = true;
  lastTerminalSignature = signature;

  if (ordered.length === 0) {
    container.innerHTML =
      '<div class="ps-log-line ps-lvl-info"><span class="ps-ts">[--:--:--]</span><span class="ps-sev">[INFO]</span><span class="ps-tag">[SYSTEM]</span><span class="ps-body-col"><span class="ps-msg">Waiting for network events matching current filter...</span></span></div>';
    return;
  }

  container.innerHTML = ordered
    .map(ev => {
      const sev = String(ev.severity || 'INFO').toUpperCase();
      const lvlCls =
        sev === 'CRITICAL'
          ? 'ps-lvl-crit'
          : sev === 'WARNING'
          ? 'ps-lvl-warn'
          : ev.isTick || sev === 'LIVE'
          ? 'ps-lvl-live'
          : 'ps-lvl-info';
      const ts = formatTerminalTime(ev.timestamp);
      const tag = String(ev.eventType || 'EVENT').slice(0, 18);
      const target = [ev.ip, ev.deviceName].filter(Boolean).join(' · ');
      const title = String(ev.title || '');
      const msg = String(ev.message || '');
      const showTitle =
        title &&
        title !== msg &&
        (!ev.deviceName || !title.toLowerCase().includes(ev.deviceName.toLowerCase()));
      const headline = showTitle ? `${title}: ` : '';
      return `<div class="ps-log-line ${lvlCls}"><span class="ps-ts">[${esc(ts)}]</span><span class="ps-sev">[${esc(sev)}]</span><span class="ps-tag">[${esc(tag)}]</span><span class="ps-body-col">${target ? `<span class="ps-target">${esc(target)}</span> — ` : ''}<span class="ps-msg">${esc(headline + msg)}</span></span></div>`;
    })
    .join('');

  if (shouldPinBottom) {
    container.scrollTop = container.scrollHeight;
  } else {
    container.scrollTop = prevScrollTop;
  }
}

async function clearEventLogs() {
  if (!window.confirm('Clear all terminal logs and event history?')) return;
  try {
    await apiJson('/api/network/events/clear', {
      method: 'POST',
      body: JSON.stringify({})
    });
    appState.networkEvents = [];
    liveTerminalTicks = [];
    renderTimeline();
  } catch (err) {
    alert(err.message);
  }
}

async function clearAlertHistory() {
  try {
    await apiJson('/api/alerts/clear', {
      method: 'POST',
      body: JSON.stringify({})
    });
    await loadInitialState();
  } catch (err) {
    alert(err.message);
  }
}
