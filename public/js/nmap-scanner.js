// Pulse Network Monitor — Designated Nmap Port Scanner & Security Risk Auditor Module

let lastNmapReport = null;
let currentNmapPortFilter = 'open';
let currentNmapPortSearch = '';
let nmapHistoryList = [];
let nmapCatalogReports = {};
let nmapScanInProgress = false;
let lastRenderedNmapReportId = null;

function onNmapProfileChange(profileVal) {
  const customGroup = document.getElementById('nmapCustomPortsGroup');
  if (customGroup) {
    customGroup.style.display = profileVal === 'custom' ? 'block' : 'none';
  }
}

function syncNmapChipHighlight(targetIp) {
  const ip = String(targetIp || '').trim();
  document.querySelectorAll('#nmapDeviceChipsContainer .preset-chip').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-chip-ip') === ip);
  });
}

function onNmapHostInputChange(val) {
  const ip = String(val || '').trim();
  const lbl = document.getElementById('nmapTargetSelectedLabel');
  if (lbl) lbl.textContent = ip ? `Target: ${ip}` : 'Target: —';
  const spHost = document.getElementById('singlePortHostInput');
  if (spHost && ip) spHost.value = ip;
  syncNmapChipHighlight(ip);
}

function selectNmapTargetPreset(ip, label) {
  const input = document.getElementById('nmapHostInput');
  if (input) input.value = ip;
  const spHost = document.getElementById('singlePortHostInput');
  if (spHost && ip) spHost.value = ip;
  const lbl = document.getElementById('nmapTargetSelectedLabel');
  if (lbl) lbl.textContent = label ? `Selected: ${label} (${ip})` : `Target: ${ip}`;
  syncNmapChipHighlight(ip);
}

function renderNmapDeviceChips() {
  const wrap = document.getElementById('nmapDeviceChipsContainer');
  if (!wrap) return;
  const rows = typeof buildUnifiedDeviceRows === 'function' ? buildUnifiedDeviceRows() : [];
  const active = rows.filter(r => !r.archived).slice(0, 10);
  const routerIp =
    (appState.router && appState.router.ip) ||
    (appState.config && appState.config.routerConfig && appState.config.routerConfig.ip) ||
    '192.168.0.1';
  const selectedIp =
    (document.getElementById('nmapHostInput') && document.getElementById('nmapHostInput').value.trim()) ||
    routerIp;

  const chips = [
    `<button type="button" class="preset-chip ${
      selectedIp === routerIp ? 'active' : ''
    }" data-chip-ip="${esc(routerIp)}" onclick="selectNmapTargetPreset('${esc(
      routerIp
    )}', 'Main Gateway Router')">🔌 Gateway (${esc(routerIp)})</button>`,
    `<button type="button" class="preset-chip ${
      selectedIp === '127.0.0.1' ? 'active' : ''
    }" data-chip-ip="127.0.0.1" onclick="selectNmapTargetPreset('127.0.0.1', 'Local Monitoring Host')">💻 Localhost (127.0.0.1)</button>`
  ];

  active.forEach(r => {
    if (r.ip === routerIp) return;
    const icon = r.monitored ? '📡' : '🖧';
    chips.push(
      `<button type="button" class="preset-chip ${
        selectedIp === r.ip ? 'active' : ''
      }" data-chip-ip="${esc(r.ip)}" onclick="selectNmapTargetPreset('${esc(r.ip)}', '${esc(
        r.name
      )}')">${icon} ${esc(r.name)} (${esc(r.ip)})</button>`
    );
  });

  wrap.innerHTML =
    `<span style="font-size: 0.78rem; color: var(--text-dim); font-weight: 700;">Quick LAN Targets:</span> ` +
    chips.join('');
}

async function loadNmapCatalog() {
  try {
    const data = await apiJson('/api/tools/port-scan/catalog');
    const engineBadge = document.getElementById('nmapEngineBadge');
    if (engineBadge) {
      if (data.nmapAvailable) {
        engineBadge.className = 'status-pill online';
        engineBadge.textContent = '🛡️ Nmap CLI + Banner Engine Active';
      } else {
        engineBadge.className = 'status-pill new';
        engineBadge.textContent = '🛡️ Parallel TCP & Banner Engine';
      }
    }
    if (Array.isArray(data.history)) {
      nmapHistoryList = data.history;
    }
    if (data.reports && typeof data.reports === 'object') {
      nmapCatalogReports = { ...nmapCatalogReports, ...data.reports };
    }
    renderNmapScanHistory();
  } catch (_) {}
}

function estimateNmapPortCount(profile, customPorts) {
  const counts = {
    quick_audit: 25,
    at_risk_only: 27,
    full_office: 46,
    web_admin: 14,
    database_storage: 15
  };
  if (profile !== 'custom') return counts[profile] || 25;
  let total = 0;
  for (const part of String(customPorts || '').split(',')) {
    const tok = part.trim();
    if (!tok) continue;
    if (tok.includes('-')) {
      const [a, b] = tok.split('-').map(x => parseInt(x.trim(), 10));
      if (!Number.isNaN(a) && !Number.isNaN(b) && b >= a) total += b - a + 1;
    } else if (!Number.isNaN(parseInt(tok, 10))) {
      total += 1;
    }
  }
  return total || 25;
}

function showNmapError(msg) {
  const box = document.getElementById('nmapErrorBanner');
  const txt = document.getElementById('nmapErrorText');
  if (txt) txt.textContent = `Port Scan Error: ${msg}`;
  if (box) box.style.display = 'flex';
}

function hideNmapError() {
  const box = document.getElementById('nmapErrorBanner');
  if (box) box.style.display = 'none';
}

async function runNmapPortScan(event) {
  if (event) event.preventDefault();
  if (nmapScanInProgress) return;

  const hostInput = document.getElementById('nmapHostInput');
  const profileSelect = document.getElementById('nmapProfileSelect');
  const customInput = document.getElementById('nmapCustomPortsInput');
  const timeoutSelect = document.getElementById('nmapTimeoutSelect');
  const btn = document.getElementById('btnStartNmapScan');

  const host = (hostInput && hostInput.value.trim()) || '192.168.0.1';
  const profile = (profileSelect && profileSelect.value) || 'quick_audit';
  const customPorts = (customInput && customInput.value.trim()) || '';
  const timeoutMs = parseInt((timeoutSelect && timeoutSelect.value) || '650', 10);

  hideNmapError();
  nmapScanInProgress = true;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Scanning Ports...';
  }

  handlePortScanProgress({
    host,
    ip: host,
    phase: 'starting',
    progressPct: 4,
    scannedCount: 0,
    totalPorts: estimateNmapPortCount(profile, customPorts),
    openCount: 0,
    atRiskCount: 0,
    message: `Initializing Nmap & TCP Banner Audit on ${host}...`
  });

  try {
    const report = await apiJson('/api/tools/port-scan', {
      method: 'POST',
      body: JSON.stringify({
        host,
        profile,
        customPorts,
        timeoutMs
      })
    });
    renderNmapScanReport(report, true);
  } catch (err) {
    const progBanner = document.getElementById('nmapProgressBanner');
    if (progBanner) progBanner.style.display = 'none';
    showNmapError(err.message);
  } finally {
    nmapScanInProgress = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🛡️ Start Nmap Port & Risk Scan';
    }
  }
}

function handlePortScanProgress(data) {
  const banner = document.getElementById('nmapProgressBanner');
  if (!banner) return;
  banner.style.display = 'block';

  const msgEl = document.getElementById('nmapProgressMessage');
  const pctEl = document.getElementById('nmapProgressPct');
  const barEl = document.getElementById('nmapProgressBarFill');
  const statsEl = document.getElementById('nmapProgressCounters');

  const pct = Math.max(0, Math.min(100, Number(data.progressPct || 0)));
  if (msgEl) msgEl.textContent = data.message || 'Scanning target ports...';
  if (pctEl) pctEl.textContent = `${pct}%`;
  if (barEl) barEl.style.width = `${pct}%`;
  if (statsEl) {
    statsEl.innerHTML = `
      <span>Probed: <strong>${data.scannedCount ?? 0}/${data.totalPorts ?? '--'}</strong></span>
      <span style="color: var(--accent-green);">Open: <strong>${data.openCount ?? 0}</strong></span>
      <span style="color: var(--accent-red);">At-Risk: <strong>${data.atRiskCount ?? 0}</strong></span>
    `;
  }
}

function setNmapPortFilter(filter) {
  currentNmapPortFilter = filter;
  if (lastNmapReport) {
    renderNmapPortsTable(lastNmapReport);
  }
  document.querySelectorAll('[data-nmap-filter]').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-nmap-filter') === filter);
  });
}

function handleNmapPortSearch(val) {
  currentNmapPortSearch = String(val || '').trim().toLowerCase();
  if (lastNmapReport) {
    renderNmapPortsTable(lastNmapReport);
  }
}

function renderNmapScanReport(report, fromDirectCall = false) {
  if (!report) return;
  const rptKey = report.reportId || `${report.ip}|${report.timestamp}`;
  const isAlreadyRendered = rptKey && rptKey === lastRenderedNmapReportId;
  lastRenderedNmapReportId = rptKey;
  lastNmapReport = report;
  if (rptKey) nmapCatalogReports[rptKey] = report;

  hideNmapError();
  const progBanner = document.getElementById('nmapProgressBanner');
  if (progBanner) progBanner.style.display = 'none';

  const emptyState = document.getElementById('nmapInitialEmptyState');
  if (emptyState) emptyState.style.display = 'none';

  const reportContainer = document.getElementById('nmapReportContainer');
  if (reportContainer) reportContainer.style.display = 'block';

  const counts = report.counts || {};
  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  // Update sidebar badge with at-risk or open count
  const sideBadge = document.getElementById('sideBadgeNmap');
  if (sideBadge) {
    if (counts.atRisk > 0) {
      sideBadge.textContent = `${counts.atRisk} Risk`;
      sideBadge.className = 'side-badge red';
    } else {
      sideBadge.textContent = `${counts.open || 0} Open`;
      sideBadge.className = 'side-badge green';
    }
  }

  const engineBadge = document.getElementById('nmapEngineBadge');
  if (engineBadge && report.engine) {
    engineBadge.className = `status-pill ${report.nmapAvailable ? 'online' : 'new'}`;
    engineBadge.textContent = `🛡️ ${report.engine}`;
  }

  // Update Posture Grade Ring & Summary
  const ring = document.getElementById('nmapGradeRing');
  if (ring) {
    ring.className = `nmap-grade-ring grade-${String(report.securityGrade || 'A').toLowerCase()}`;
  }
  setTxt('nmapGradeLetter', report.securityGrade || 'A');
  setTxt('nmapGradeScore', `${report.securityScore ?? 100}/100 SCORE`);
  setTxt('nmapPostureVerdict', report.postureVerdict || 'HARDENED');
  setTxt('nmapPostureSummary', report.postureSummary || '');
  const metaParts = [
    `Target: ${report.deviceLabel || report.host} (${report.ip})`,
    `Profile: ${report.profileLabel}`,
    `Engine: ${report.engine || 'TCP Auditor'}`,
    report.osGuess ? `OS: ${report.osGuess}` : null,
    `Completed in ${report.durationMs} ms`
  ].filter(Boolean);
  setTxt('nmapScanMetaLine', metaParts.join(' · '));

  // Update 6 KPI Cards
  setTxt('nmapKpiTotal', counts.totalScanned ?? 0);
  setTxt('nmapKpiOpen', counts.open ?? 0);
  setTxt('nmapKpiAtRisk', counts.atRisk ?? 0);
  setTxt('nmapKpiCritHigh', (counts.critical || 0) + (counts.high || 0));
  setTxt('nmapKpiMedium', counts.medium ?? 0);
  setTxt('nmapKpiClosed', counts.closed ?? 0);

  // Update Filter Pill Counts
  setTxt('nmapTabCountAll', counts.totalScanned ?? 0);
  setTxt('nmapTabCountOpen', counts.open ?? 0);
  setTxt('nmapTabCountRisk', counts.atRisk ?? 0);
  setTxt('nmapTabCountCrit', (counts.critical || 0) + (counts.high || 0));
  setTxt('nmapTabCountMed', counts.medium ?? 0);
  setTxt('nmapTabCountClosed', counts.closed ?? 0);

  // Reset filter intelligently for each brand-new scan
  if (!isAlreadyRendered) {
    currentNmapPortFilter = (counts.open || 0) > 0 ? 'open' : 'all';
  }

  renderAtRiskSpotlight(report.atRiskPorts || []);
  renderNmapPortsTable(report);

  const pre = document.getElementById('nmapTranscriptPre');
  if (pre) {
    pre.textContent = report.nmapTranscript || '';
  }

  if (!isAlreadyRendered) {
    nmapHistoryList = [
      {
        reportId: rptKey,
        timestamp: report.timestamp,
        host: report.host,
        ip: report.ip,
        deviceLabel: report.deviceLabel,
        profileLabel: report.profileLabel,
        securityScore: report.securityScore,
        securityGrade: report.securityGrade,
        postureVerdict: report.postureVerdict,
        openCount: counts.open,
        atRiskCount: counts.atRisk,
        durationMs: report.durationMs
      },
      ...nmapHistoryList.filter(h => (h.reportId || `${h.ip}|${h.timestamp}`) !== rptKey)
    ].slice(0, 15);
    renderNmapScanHistory();
  }
}

function viewSavedNmapReport(reportId) {
  const rep = nmapCatalogReports[reportId];
  if (rep) {
    lastRenderedNmapReportId = null;
    renderNmapScanReport(rep, true);
    const cont = document.getElementById('nmapReportContainer');
    if (cont) cont.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function renderAtRiskSpotlight(atRiskPorts) {
  const section = document.getElementById('nmapAtRiskSpotlightSection');
  const grid = document.getElementById('nmapAtRiskSpotlightGrid');
  const countBadge = document.getElementById('nmapAtRiskBadgeCount');
  if (!section || !grid) return;

  if (countBadge) {
    countBadge.textContent = `${atRiskPorts.length} At-Risk Open Port(s)`;
    countBadge.className = `status-pill ${atRiskPorts.length > 0 ? 'offline' : 'online'}`;
  }

  if (!atRiskPorts.length) {
    grid.innerHTML = `
      <div class="friendly-tip-box" style="margin-bottom: 0; border-color: var(--status-up-border); background: var(--status-up-bg);">
        <span style="font-size: 1.4rem;">🛡️</span>
        <div>
          <strong style="color: var(--status-up-text);">Zero At-Risk Ports Exposed on Target</strong>
          <div style="font-size: 0.84rem; color: var(--text-muted); margin-top: 2px;">
            No vulnerable cleartext protocols (Telnet, FTP), exposed databases (MySQL, Redis, MSSQL), or high-risk file/remote services (SMB 445, RDP 3389, VNC 5900) responded on this host.
          </div>
        </div>
      </div>
    `;
    return;
  }

  grid.innerHTML = atRiskPorts
    .map(p => {
      const riskLower = String(p.riskLevel || 'MEDIUM').toLowerCase();
      return `
        <div class="at-risk-card ${riskLower}">
          <div class="at-risk-card-head">
            <div class="at-risk-port-title">
              <span class="mono" style="color: var(--accent-cyan);">TCP/${p.port}</span> — ${esc(p.service)}
              <small style="display: block; font-size: 0.75rem; color: var(--text-dim); font-weight: 600;">Category: ${esc(p.category)} · Response: ${p.latencyMs != null ? `${p.latencyMs} ms` : 'Active'}</small>
            </div>
            <span class="risk-badge ${riskLower}">⚠️ ${esc(p.riskLevel)} RISK</span>
          </div>
          <div style="font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">
            <strong>Detected Banner / Version:</strong> <code class="mono" style="color: var(--accent-cyan);">${esc(p.banner)}</code>
          </div>
          <div class="at-risk-section-lbl">Why This Port Is At Risk</div>
          <div style="font-size: 0.82rem; color: var(--text-muted);">
            ${esc(p.exposureRisk)}
          </div>
          <div class="at-risk-remediation">
            <strong>🛡️ Suggested Fix:</strong> ${esc(p.remediation)}
          </div>
        </div>
      `;
    })
    .join('');
}

function renderNmapPortsTable(report) {
  const tbody = document.getElementById('nmapPortsTableBody');
  if (!tbody || !report) return;

  document.querySelectorAll('[data-nmap-filter]').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-nmap-filter') === currentNmapPortFilter);
  });

  const allPorts = report.allPorts || [];
  let rows = allPorts;
  if (currentNmapPortFilter === 'open') {
    rows = allPorts.filter(p => p.open);
  } else if (currentNmapPortFilter === 'at_risk') {
    rows = allPorts.filter(p => p.atRisk);
  } else if (currentNmapPortFilter === 'crit_high') {
    rows = allPorts.filter(
      p => p.open && (p.riskLevel === 'CRITICAL' || p.riskLevel === 'HIGH')
    );
  } else if (currentNmapPortFilter === 'medium') {
    rows = allPorts.filter(p => p.open && p.riskLevel === 'MEDIUM');
  } else if (currentNmapPortFilter === 'closed') {
    rows = allPorts.filter(p => !p.open);
  }

  if (currentNmapPortSearch) {
    rows = rows.filter(
      p =>
        String(p.port).includes(currentNmapPortSearch) ||
        p.service.toLowerCase().includes(currentNmapPortSearch) ||
        p.category.toLowerCase().includes(currentNmapPortSearch) ||
        p.riskLevel.toLowerCase().includes(currentNmapPortSearch) ||
        (p.state && p.state.toLowerCase().includes(currentNmapPortSearch)) ||
        (p.banner && p.banner.toLowerCase().includes(currentNmapPortSearch)) ||
        (p.exposureRisk && p.exposureRisk.toLowerCase().includes(currentNmapPortSearch))
    );
  }

  if (!rows.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 26px; color: var(--text-dim);">
          No ports match the current filter (<strong>${esc(currentNmapPortFilter.toUpperCase())}</strong>). Click <strong>"All Scanned Ports"</strong> to inspect closed/filtered ports.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows
    .map(p => {
      const isFiltered = !p.open && String(p.state || '').includes('filtered');
      const stateBadge = p.open
        ? `<span class="status-pill online" style="font-size:0.65rem; padding:2px 7px;">● OPEN</span>`
        : isFiltered
        ? `<span class="status-pill warning" style="font-size:0.65rem; padding:2px 7px;">◈ FILTERED</span>`
        : `<span class="status-pill" style="background:rgba(148,163,184,0.12); color:var(--text-dim); font-size:0.65rem; padding:2px 7px;">CLOSED</span>`;

      const riskLower = p.open ? String(p.riskLevel || 'LOW').toLowerCase() : isFiltered ? 'filtered' : 'none';
      const riskLabel = p.open
        ? `${p.atRisk ? '⚠️ ' : '✓ '}${p.riskLevel} RISK`
        : isFiltered
        ? 'FIREWALL DROP'
        : `SAFE · ${p.riskLevel} IF OPEN`;

      const latLine =
        p.latencyMs != null
          ? `<div class="dev-row-sub mono" style="margin-top:3px;">${p.latencyMs} ms</div>`
          : `<div class="dev-row-sub" style="margin-top:3px;">${esc(p.reason || '—')}</div>`;

      const cpeLine = p.cpe
        ? `<div class="dev-row-sub mono" style="margin-top:2px; font-size:0.68rem;">${esc(p.cpe)}</div>`
        : '';

      return `
        <tr class="${p.atRisk ? 'port-row-at-risk' : ''}">
          <td>
            <div class="mono" style="font-weight: 700; color: var(--accent-cyan);">
              ${p.port}<span style="color: var(--text-dim); font-weight: 400;">/${esc(p.protocol)}</span>
            </div>
            ${latLine}
          </td>
          <td>
            <div>${stateBadge}</div>
            <div style="margin-top:4px;"><span class="risk-badge ${riskLower}" style="font-size:0.64rem; padding:2px 7px;">${esc(riskLabel)}</span></div>
          </td>
          <td>
            <span class="dev-row-title">${esc(p.service)}</span>
            <span class="dev-row-sub">${esc(p.category)}</span>
          </td>
          <td class="mono" style="font-size: 0.74rem; color: var(--text-muted);">
            ${esc(p.banner)}${cpeLine}
          </td>
          <td style="font-size: 0.76rem; color: var(--text-muted);">
            <strong style="color:var(--text-main);">${esc(p.summary)}</strong>
            <div style="margin-top:2px;">${esc(p.exposureRisk)}</div>
          </td>
          <td style="font-size: 0.76rem; color: var(--text-main);">
            ${esc(p.remediation)}
          </td>
          <td style="text-align: right;">
            <button type="button" class="btn btn-secondary btn-xs" onclick="retestSinglePortFromTable('${esc(report.ip)}', ${p.port})">
              Test
            </button>
          </td>
        </tr>
      `;
    })
    .join('');
}

async function retestSinglePortFromTable(host, port) {
  const hostInput = document.getElementById('singlePortHostInput');
  const portInput = document.getElementById('singlePortNumInput');
  if (hostInput) hostInput.value = host;
  if (portInput) portInput.value = port;
  await runDeepSinglePortTest();
  const card = document.getElementById('singlePortTesterBox');
  if (card) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function runDeepSinglePortTest(event) {
  if (event) event.preventDefault();
  const host = document.getElementById('singlePortHostInput').value.trim();
  const port = parseInt(document.getElementById('singlePortNumInput').value, 10) || 80;
  const out = document.getElementById('singlePortTestResultArea');
  if (!out) return;

  out.innerHTML = `<div class="tool-empty-state" style="padding: 18px;"><div class="spinner-ring"></div><p>Probing TCP/${port} on ${esc(host)} and inspecting service banner...</p></div>`;
  try {
    const res = await apiJson('/api/tools/port-check', {
      method: 'POST',
      body: JSON.stringify({ host, port })
    });
    const riskLower = String(res.riskLevel || 'LOW').toLowerCase();
    out.innerHTML = `
      <div class="at-risk-card ${res.open && res.atRisk ? riskLower : 'low'}" style="margin-top: 12px; border-left-color: ${
      res.open ? (res.atRisk ? 'var(--accent-red)' : 'var(--accent-green)') : 'var(--text-dim)'
    };">
        <div class="at-risk-card-head">
          <div>
            <span class="status-pill ${res.open ? 'online' : 'offline'}">
              ${res.open ? '● PORT OPEN & LISTENING' : '○ PORT CLOSED / FILTERED'}
            </span>
            <strong class="mono" style="font-size: 1rem; margin-left: 8px; color: var(--accent-cyan);">
              ${esc(res.host)}:${res.port} (${esc(res.service || `TCP/${res.port}`)})
            </strong>
          </div>
          <span class="risk-badge ${res.open ? riskLower : 'none'}">
            ${res.open ? `${esc(res.riskLevel)} RISK` : `CLOSED (${esc(res.riskLevel)} IF OPEN)`}
          </span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 8px; font-size: 0.83rem;">
          <div>
            <span style="color: var(--text-dim);">Handshake Latency:</span>
            <strong class="mono">${res.latencyMs != null ? `${res.latencyMs} ms` : 'Timed out / Refused'}</strong>
          </div>
          <div>
            <span style="color: var(--text-dim);">Category:</span>
            <strong>${esc(res.category || 'Custom Service')}</strong>
          </div>
          <div>
            <span style="color: var(--text-dim);">Service Banner:</span>
            <code class="mono" style="color: var(--accent-cyan);">${esc(res.banner || res.error || 'None')}</code>
          </div>
        </div>
        <div class="at-risk-section-lbl" style="margin-top: 10px;">Security &amp; Risk Analysis</div>
        <div style="font-size: 0.83rem; color: var(--text-muted);">${esc(res.exposureRisk || '')}</div>
        <div class="at-risk-remediation">
          <strong>🛡️ How to Fix:</strong> ${esc(res.remediation || '')}
        </div>
      </div>
    `;
  } catch (err) {
    out.innerHTML = `<div class="tool-empty-state"><p style="color: var(--accent-red);">${esc(err.message)}</p></div>`;
  }
}

function copyNmapTranscript() {
  const pre = document.getElementById('nmapTranscriptPre');
  if (!pre || !pre.textContent) return;
  navigator.clipboard.writeText(pre.textContent).then(() => {
    const btn = document.getElementById('btnCopyNmapTranscript');
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = '✓ Copied CLI Output';
      setTimeout(() => {
        btn.textContent = prev;
      }, 1800);
    }
  });
}

function renderNmapScanHistory() {
  const tbody = document.getElementById('nmapHistoryTableBody');
  if (!tbody) return;
  if (!nmapHistoryList.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 18px; color: var(--text-dim);">
          No port scans run in this session yet.
        </td>
      </tr>
    `;
    return;
  }
  tbody.innerHTML = nmapHistoryList
    .map(h => {
      const rid = h.reportId || `${h.ip}|${h.timestamp}`;
      const hasCached = Boolean(nmapCatalogReports[rid]);
      return `
      <tr>
        <td style="font-size: 0.76rem; color: var(--text-dim);">${esc(fmtTime(h.timestamp))}</td>
        <td><strong>${esc(h.deviceLabel || h.host)}</strong></td>
        <td class="mono" style="color: var(--accent-cyan);">${esc(h.ip)}</td>
        <td style="font-size: 0.76rem;">${esc(h.profileLabel)}</td>
        <td>
          <div class="row-actions-group" style="justify-content:flex-start;">
            <span class="status-pill online" style="font-size:0.64rem; padding:2px 7px;">${h.openCount} Open</span>
            ${
              h.atRiskCount > 0
                ? `<span class="status-pill offline" style="font-size:0.64rem; padding:2px 7px;">⚠️ ${h.atRiskCount} Risk</span>`
                : `<span class="status-pill online" style="font-size:0.64rem; padding:2px 7px;">0 Risk</span>`
            }
          </div>
        </td>
        <td style="font-size:0.78rem;"><strong>Grade ${esc(h.securityGrade)}</strong> (${h.securityScore}/100)</td>
        <td style="text-align: right;">
          <div class="row-actions-group">
            ${
              hasCached
                ? `<button type="button" class="btn btn-secondary btn-xs" onclick="viewSavedNmapReport('${esc(rid)}')">View</button>`
                : ''
            }
            <button type="button" class="btn btn-secondary btn-xs" onclick="selectNmapTargetPreset('${esc(h.ip)}', '${esc(h.deviceLabel)}'); runNmapPortScan();">
              Re-Scan
            </button>
          </div>
        </td>
      </tr>
    `;
    })
    .join('');
}
