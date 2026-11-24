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
    }" data-chip-ip="${esc(routerIp)}" onclick="selectNmapTargetPreset(${inlineString(
      routerIp
    )}, 'Main Gateway Router')">🔌 Gateway (${esc(routerIp)})</button>`,
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
      }" data-chip-ip="${esc(r.ip)}" onclick="selectNmapTargetPreset(${inlineString(r.ip)}, ${inlineString(
        r.name
      )})">${icon} ${esc(r.name)} (${esc(r.ip)})</button>`
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
    if (engineBadge && !lastNmapReport) {
      if (data.nmapAvailable) {
        engineBadge.className = 'status-pill online';
        engineBadge.textContent = 'Nmap available';
      } else {
        engineBadge.className = 'status-pill new';
        engineBadge.textContent = 'TCP connect available';
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
  const submit = document.getElementById('btnSubmitNmapScan');

  const host = hostInput?.value.trim();
  if (!host) {
    showNmapError('Enter a device IP address or hostname.');
    hostInput?.focus();
    return;
  }
  const profile = (profileSelect && profileSelect.value) || 'quick_audit';
  const customPorts = (customInput && customInput.value.trim()) || '';
  const timeoutMs = parseInt((timeoutSelect && timeoutSelect.value) || '650', 10);

  hideNmapError();
  nmapScanInProgress = true;
  if (submit) submit.disabled = true;
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
    openCount: 0,
    atRiskCount: 0,
    message: `Preparing TCP port check on ${host}...`
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
    if (submit) submit.disabled = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🛡️ Start Security Scan';
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
    engineBadge.className = `status-pill ${report.nmapResultCount ? 'online' : 'new'}`;
    engineBadge.textContent = `🛡️ ${report.engine}`;
  }

  setTxt('nmapPostureVerdict', report.scope ? report.postureVerdict : 'Port check results');
  setTxt('nmapPostureSummary', report.postureSummary || '');
  const scopePorts = report.scope?.ports || (report.allPorts || []).map(p => p.port);
  setTxt('nmapScopePorts', scopePorts.join(', '));
  const metaParts = [
    `Target: ${report.deviceLabel || report.host} (${report.ip})`,
    `Profile: ${report.profileLabel}`,
    `Engine: ${report.engine || 'TCP Auditor'}`,
    'From this monitor over TCP/IPv4',
    report.nmapScannedCount ? `Nmap results: ${report.nmapResultCount}/${report.nmapScannedCount}` : null,
    report.osGuess ? `Nmap OS guess: ${report.osGuess}` : null,
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
  setTxt('nmapTabCountFiltered', counts.filtered ?? 0);
  setTxt('nmapTabCountUnconfirmed', counts.unconfirmed ?? 0);

  // Reset filter intelligently for each brand-new scan
  if (!isAlreadyRendered) {
    currentNmapPortFilter = 'all';
    currentNmapPortSearch = '';
    const searchInput = document.getElementById('nmapPortSearchInput');
    if (searchInput) searchInput.value = '';
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
        totalScanned: counts.totalScanned,
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

function rerunSavedNmapReport(reportId) {
  const report = nmapCatalogReports[reportId];
  if (!report?.scope) return;
  selectNmapTargetPreset(report.ip, report.deviceLabel);
  document.getElementById('nmapProfileSelect').value = report.profile;
  onNmapProfileChange(report.profile);
  document.getElementById('nmapCustomPortsInput').value = report.scope.ports.join(', ');
  const timeoutSelect = document.getElementById('nmapTimeoutSelect');
  const timeout = String(report.scope.timeoutMs);
  if (![...timeoutSelect.options].some(option => option.value === timeout)) {
    timeoutSelect.add(new Option(`${timeout} ms`, timeout));
  }
  timeoutSelect.value = timeout;
  runNmapPortScan();
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
    grid.innerHTML = '<p class="friendly-tip-box">This scan found no open ports flagged for review.</p>';
    return;
  }

  grid.innerHTML = atRiskPorts
    .map(p => {
      const riskLower = String(p.riskLevel || 'MEDIUM').toLowerCase();
      return `
        <div class="at-risk-card ${riskLower}">
          <div class="at-risk-card-head">
            <div class="at-risk-port-title">
              <span class="mono" style="color: var(--accent-cyan);">TCP/${p.port}</span> — ${esc(p.observedService || p.service)}
              <small style="display: block; font-size: 0.75rem; color: var(--text-dim); font-weight: 600;">Category: ${esc(p.category)} · Evidence: ${esc(nmapServiceEvidence(p))}</small>
            </div>
            <span class="risk-badge ${riskLower}">⚠️ ${esc(p.riskLevel)} RISK</span>
          </div>
          <div style="font-size: 0.82rem; color: var(--text-main); margin-bottom: 6px;">
            <strong>Banner / Version:</strong> <code class="mono" style="color: var(--accent-cyan);">${esc(p.banner || "No banner received")}</code>
          </div>
          <div class="at-risk-section-lbl">${esc(nmapReviewEvidence(p))}</div>
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

function nmapServiceEvidence(port) {
  return {
    'nmap-probe': 'Nmap service probe',
    banner: 'Service response',
    'port-number': 'Port-number hint'
  }[port.serviceSource] || 'Service evidence unavailable';
}

function nmapReviewEvidence(port) {
  return port.reviewSource === 'nmap-probe' ? 'Review based on detected service' : 'Review based on port catalog';
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
  } else if (['closed', 'filtered', 'unconfirmed'].includes(currentNmapPortFilter)) {
    rows = allPorts.filter(p => p.state === currentNmapPortFilter);
  }

  if (currentNmapPortSearch) {
    rows = rows.filter(
      p =>
        String(p.port).includes(currentNmapPortSearch) ||
        p.service.toLowerCase().includes(currentNmapPortSearch) ||
        (p.observedService && p.observedService.toLowerCase().includes(currentNmapPortSearch)) ||
        (p.reason && p.reason.toLowerCase().includes(currentNmapPortSearch)) ||
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
          No ports match the current filter (<strong>${esc(currentNmapPortFilter.toUpperCase())}</strong>). Click <strong>"All Scanned Ports"</strong> to inspect every result.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows
    .map(p => {
      const state = p.state || 'unconfirmed';
      const stateStyle = state === 'open' ? 'online' : state === 'closed' ? '' : 'warning';
      const stateBadge = `<span class="status-pill ${stateStyle}" style="font-size:0.65rem; padding:2px 7px;">${esc(state.toUpperCase())}</span>`;
      const riskLower = String(p.riskLevel || 'LOW').toLowerCase();
      const riskBadge = p.open
        ? `<span class="risk-badge ${riskLower}" style="font-size:0.64rem; padding:2px 7px;">${esc(p.riskLevel)} REVIEW</span>`
        : '';
      const latency = p.latencyMs != null ? ` · ${p.latencyMs} ms` : '';
      const evidenceLine = `<div class="dev-row-sub" style="margin-top:3px;">${esc((p.reason || '').replaceAll('-', ' '))}${latency}</div>`;

      const cpeLine = p.cpe
        ? `<div class="dev-row-sub mono" style="margin-top:2px; font-size:0.68rem;">${esc(p.cpe)}</div>`
        : '';

      return `
        <tr class="${p.atRisk ? 'port-row-at-risk' : ''}">
          <td>
            <div class="mono" style="font-weight: 700; color: var(--accent-cyan);">
              ${p.port}<span style="color: var(--text-dim); font-weight: 400;">/${esc(p.protocol)}</span>
            </div>
            ${evidenceLine}
          </td>
          <td>
            <div>${stateBadge}</div>
            <div style="margin-top:4px;">${riskBadge}</div>
          </td>
          <td>
            <span class="dev-row-title">${p.open ? esc(p.observedService || p.service) : '—'}</span>
            ${p.open ? `<span class="dev-row-sub">${esc(nmapServiceEvidence(p))}</span>` : ''}
          </td>
          <td class="mono" style="font-size: 0.74rem; color: var(--text-muted);">
            ${p.open ? esc(p.banner || "No banner received") : "—"}${cpeLine}
          </td>
          <td style="font-size: 0.76rem; color: var(--text-muted);">
            ${p.open ? `<strong>${esc(nmapReviewEvidence(p))}</strong><div>${esc(p.exposureRisk)}</div>` : "—"}
          </td>
          <td style="font-size: 0.76rem; color: var(--text-main);">
            ${p.open ? esc(p.remediation) : "—"}
          </td>
          <td style="text-align: right;">
            <button type="button" class="btn btn-secondary btn-xs" onclick="retestSinglePortFromTable(${inlineString(report.ip)}, ${p.port})">
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
  const port = Number(document.getElementById('singlePortNumInput').value);
  const out = document.getElementById('singlePortTestResultArea');
  if (!out) return;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    out.textContent = 'Enter a host and a TCP port from 1 to 65535.';
    return;
  }

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
            <span class="status-pill ${res.open ? 'online' : res.state === 'closed' ? '' : 'warning'}">
              ${esc(String(res.state || 'unconfirmed').toUpperCase())}
            </span>
            <strong class="mono" style="font-size: 1rem; margin-left: 8px; color: var(--accent-cyan);">
              ${esc(res.ip || res.host)}:${res.port}
            </strong>
          </div>
          ${res.open ? `<span class="risk-badge ${riskLower}">${esc(res.riskLevel)} REVIEW</span>` : ''}
        </div>
        ${res.open ? `
          <p>${res.latencyMs == null ? 'Nmap confirmed the port is open.' : `TCP handshake: <strong>${res.latencyMs} ms</strong>`}</p>
          <p>${esc(nmapServiceEvidence(res))}: <strong>${esc(res.observedService || res.service)}</strong></p>
          <p>Banner: <code class="mono">${esc(res.banner || 'No banner received')}</code></p>
          <p><strong>${esc(nmapReviewEvidence(res))}</strong> ${esc(res.exposureRisk)}</p>
          <div class="at-risk-remediation">${esc(res.remediation)}</div>
        ` : `<p>${esc(res.error || 'The monitor could not confirm the port state.')}</p>`}
      </div>
    `;
  } catch (err) {
    out.innerHTML = `<div class="tool-empty-state"><p style="color: var(--accent-red);">${esc(err.message)}</p></div>`;
  }
}

async function copyNmapTranscript() {
  const pre = document.getElementById('nmapTranscriptPre');
  const btn = document.getElementById('btnCopyNmapTranscript');
  if (!pre?.textContent || !btn) return;
  btn.disabled = true;
  try {
    await navigator.clipboard.writeText(pre.textContent);
    btn.textContent = '✓ Copied Transcript';
  } catch (_) {
    const range = document.createRange();
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    btn.textContent = 'Transcript selected. Press Ctrl+C to copy.';
  } finally {
    setTimeout(() => {
      btn.textContent = 'Copy Transcript';
      btn.disabled = false;
    }, 2500);
  }
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
        <td style="font-size:0.78rem;">${h.totalScanned == null ? "—" : `${h.totalScanned} TCP ports`}</td>
        <td style="text-align: right;">
          <div class="row-actions-group">
            ${
              hasCached
                ? `<button type="button" class="btn btn-secondary btn-xs" onclick="viewSavedNmapReport(${inlineString(rid)})">View</button>`
                : ''
            }
            ${nmapCatalogReports[rid]?.scope
              ? `<button type="button" class="btn btn-secondary btn-xs" onclick="rerunSavedNmapReport(${inlineString(rid)})">Re-Scan</button>`
              : ''}
          </div>
        </td>
      </tr>
    `;
    })
    .join('');
}
