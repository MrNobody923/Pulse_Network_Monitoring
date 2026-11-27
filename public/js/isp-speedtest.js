// Pulse Network Monitor — Section 3: ISP Health, Live Animated Speedometer & ISP Diagnostics

let speedTestInProgress = false;
let speedTestRequestPending = false;
let speedTestFailure = '';
let currentGaugeMbps = 0;
let targetGaugeMbps = 0;
let gaugeAnimFrame = null;
let lastCompletedSpeedTest = null;
let selectedSpeedTestTarget = 'isp|cloudflare|Internet (ISP · Cloudflare)';

function getSelectedSpeedTestTarget() {
  const sel = document.getElementById('speedTestTargetSelect');
  const raw = (sel && sel.value) || selectedSpeedTestTarget || 'isp|cloudflare|Internet (ISP · Cloudflare)';
  const [targetType = 'isp', targetIp = 'cloudflare', ...rest] = raw.split('|');
  return {
    raw,
    targetType,
    targetIp,
    targetName: rest.join('|') || (targetType === 'isp' ? 'Internet (ISP · Cloudflare)' : targetIp)
  };
}

function syncSpeedTestTargets() {
  const sel = document.getElementById('speedTestTargetSelect');
  if (!sel) return;
  const previous = sel.value || selectedSpeedTestTarget;
  const routers = [];
  const seenIps = new Set();
  const addRouter = (ip, name) => {
    if (!ip || seenIps.has(ip)) return;
    seenIps.add(ip);
    routers.push({ ip, name: name || `Router (${ip})` });
  };
  if (appState.router?.ip) {
    addRouter(appState.router.ip, appState.router.model || appState.router.name || `Main Router (${appState.router.ip})`);
  }
  for (const r of appState.routers || []) {
    if (r?.ip) addRouter(r.ip, r.name || r.model || `Router (${r.ip})`);
  }
  for (const d of appState.devices || []) {
    if (d?.ip && !d.archived && ['gateway', 'router', 'ap', 'switch'].includes(String(d.type || '').toLowerCase())) {
      addRouter(d.ip, d.name || `${String(d.type).toUpperCase()} (${d.ip})`);
    }
  }

  const devices = [];
  for (const d of appState.devices || []) {
    if (d?.ip && !d.archived && !seenIps.has(d.ip)) {
      seenIps.add(d.ip);
      devices.push({ ip: d.ip, name: d.name || d.ip });
    }
  }
  for (const inv of appState.networkInventory || []) {
    if (inv?.ip && inv.isOnline && !inv.archived && !seenIps.has(inv.ip)) {
      seenIps.add(inv.ip);
      devices.push({ ip: inv.ip, name: inv.name || inv.suggestedName || inv.ip });
    }
  }
  devices.sort((a, b) => a.name.localeCompare(b.name));

  const frag = document.createDocumentFragment();
  const ispGroup = document.createElement('optgroup');
  ispGroup.label = 'Internet (ISP)';
  const detectedIsp = appState.isp?.provider?.provider || appState.isp?.provider?.isp || '';
  const ispName = detectedIsp && detectedIsp !== 'Unknown ISP' ? `Internet (${detectedIsp} · Cloudflare)` : 'Internet (ISP · Cloudflare)';
  const ispOpt = new Option(`🌐 ${ispName}`, `isp|cloudflare|${ispName}`);
  ispGroup.appendChild(ispOpt);
  frag.appendChild(ispGroup);

  if (routers.length) {
    const rGroup = document.createElement('optgroup');
    rGroup.label = 'Routers, Gateways & APs';
    for (const r of routers) {
      rGroup.appendChild(new Option(`📡 ${r.name} (${r.ip})`, `router|${r.ip}|${r.name}`));
    }
    frag.appendChild(rGroup);
  }
  if (devices.length) {
    const dGroup = document.createElement('optgroup');
    dGroup.label = 'Connected LAN Devices';
    for (const d of devices.slice(0, 60)) {
      dGroup.appendChild(new Option(`💻 ${d.name} (${d.ip})`, `device|${d.ip}|${d.name}`));
    }
    frag.appendChild(dGroup);
  }

  sel.replaceChildren(frag);
  const matching = Array.from(sel.options).find(o => o.value === previous || (previous.startsWith('isp|') && o.value.startsWith('isp|')));
  sel.value = matching ? matching.value : sel.options[0]?.value || '';
  selectedSpeedTestTarget = sel.value;
}

function onSpeedTestTargetChange() {
  const sel = document.getElementById('speedTestTargetSelect');
  if (sel) selectedSpeedTestTarget = sel.value;
  renderIspSection();
}

// Non-linear scale matching ticks: 0 (0%), 50 (25%), 250 (50%), 500 (75%), 1000+ (100%)
function speedMbpsToFraction(mbps) {
  const v = Math.max(0, Number(mbps) || 0);
  if (v <= 50) return (v / 50) * 0.25;
  if (v <= 250) return 0.25 + ((v - 50) / 200) * 0.25;
  if (v <= 500) return 0.5 + ((v - 250) / 250) * 0.25;
  if (v <= 1000) return 0.75 + ((v - 500) / 500) * 0.25;
  return 1.0;
}

function applyGaugeVisuals(mbps) {
  const frac = Math.min(1, Math.max(0, speedMbpsToFraction(mbps)));
  const arcEl = document.getElementById('speedGaugeArc');
  const needleEl = document.getElementById('speedGaugeNeedle');
  const liveNumEl = document.getElementById('speedGaugeLiveMbps');

  if (arcEl) {
    const maxDash = 267;
    const offset = maxDash * (1 - frac);
    arcEl.style.strokeDashoffset = offset.toFixed(2);
  }
  if (needleEl) {
    const deg = -90 + frac * 180;
    needleEl.style.transform = `rotate(${deg.toFixed(1)}deg)`;
  }
  if (liveNumEl) {
    liveNumEl.textContent =
      mbps >= 100 ? Math.round(mbps).toString() : mbps.toFixed(1);
  }
}

function stepGaugeAnimation() {
  const diff = targetGaugeMbps - currentGaugeMbps;
  if (Math.abs(diff) < 0.15) {
    currentGaugeMbps = targetGaugeMbps;
    applyGaugeVisuals(currentGaugeMbps);
    gaugeAnimFrame = null;
    return;
  }
  currentGaugeMbps += diff * 0.22;
  applyGaugeVisuals(currentGaugeMbps);
  gaugeAnimFrame = requestAnimationFrame(stepGaugeAnimation);
}

function setSpeedGaugeTarget(mbps, immediate = false) {
  targetGaugeMbps = Math.max(0, Number(mbps) || 0);
  if (immediate) {
    currentGaugeMbps = targetGaugeMbps;
    if (gaugeAnimFrame) {
      cancelAnimationFrame(gaugeAnimFrame);
      gaugeAnimFrame = null;
    }
    applyGaugeVisuals(currentGaugeMbps);
    return;
  }
  if (!gaugeAnimFrame) {
    gaugeAnimFrame = requestAnimationFrame(stepGaugeAnimation);
  }
}

function setActiveSpeedCard(phase) {
  const dlCard = document.getElementById('speedCardDownload');
  const ulCard = document.getElementById('speedCardUpload');
  const pingCard = document.getElementById('speedCardPing');
  const jitterCard = document.getElementById('speedCardJitter');
  [dlCard, ulCard, pingCard, jitterCard].forEach(el => {
    if (el) el.classList.remove('active-phase');
  });
  if (phase === 'download' && dlCard) dlCard.classList.add('active-phase');
  else if (phase === 'upload' && ulCard) ulCard.classList.add('active-phase');
  else if (phase === 'ping') {
    if (pingCard) pingCard.classList.add('active-phase');
    if (jitterCard) jitterCard.classList.add('active-phase');
  }
}

function handleSpeedTestProgress(data) {
  if (!data) return;
  const box = document.getElementById('speedLiveGaugeBox');
  const badge = document.getElementById('speedGaugePhaseBadge');
  const pctEl = document.getElementById('speedGaugePctText');
  const labelEl = document.getElementById('speedGaugePhaseLabel');
  const barEl = document.getElementById('speedGaugeProgressBar');
  const noteEl = document.getElementById('speedGaugeSubNote');

  const dlEl = document.getElementById('speedDownloadText');
  const ulEl = document.getElementById('speedUploadText');
  const pingEl = document.getElementById('speedPingText');
  const jitterEl = document.getElementById('speedJitterText');
  const ratingEl = document.getElementById('speedRatingSub');

  const phase = data.phase || 'download';
  const pct = Math.min(100, Math.max(0, Number(data.progressPct) || 0));

  if (phase === 'error') {
    speedTestInProgress = false;
    speedTestFailure = data.message || 'Speed test failed.';
    if (appState.isp) {
      appState.isp.speedTestRunning = false;
      appState.isp.speedTestError = speedTestFailure;
    }
    if (box) box.classList.remove('testing');
    setActiveSpeedCard(null);
    setSpeedGaugeTarget(0);
    if (badge) {
      badge.textContent = 'TEST FAILED';
      badge.className = 'status-pill offline';
    }
    if (labelEl) labelEl.textContent = 'The latest test did not finish.';
    if (noteEl) noteEl.textContent = lastCompletedSpeedTest ? 'The readings below are from the last successful test.' : '';
    if (barEl) barEl.style.width = '0%';
    if (pctEl) pctEl.textContent = '0%';
    renderIspSection();
    return;
  }

  speedTestFailure = '';
  if (appState.isp) appState.isp.speedTestError = null;
  if (phase !== 'complete') {
    speedTestInProgress = true;
    if (box) box.classList.add('testing');
  } else {
    speedTestInProgress = false;
    if (appState.isp) appState.isp.speedTestRunning = false;
    if (box) box.classList.remove('testing');
  }

  setActiveSpeedCard(phase);

  if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
  if (barEl) barEl.style.width = `${pct}%`;
  const phaseMsg = data.message || data.phaseLabel;
  if (labelEl && phaseMsg) labelEl.textContent = phaseMsg;

  if (phase === 'ping') {
    if (dlEl) dlEl.textContent = '— Mbps';
    if (ulEl) ulEl.textContent = '— Mbps';
    if (pingEl) pingEl.textContent = '— ms';
    if (jitterEl) jitterEl.textContent = '— ms';
    if (ratingEl) ratingEl.textContent = 'Test in progress';
    if (badge) {
      badge.textContent = 'CHECKING PING';
      badge.className = 'status-pill warning';
    }
    if (noteEl) {
      noteEl.textContent = 'Checking internet response time...';
    }
    setSpeedGaugeTarget(0);
  } else if (phase === 'download') {
    if (badge) {
      badge.textContent = 'DOWNLOAD TEST';
      badge.className = 'status-pill new';
    }
    const liveMbps = Number(data.currentMbps ?? data.downloadMbps ?? 0);
    setSpeedGaugeTarget(liveMbps);
    if (dlEl && liveMbps > 0) dlEl.textContent = `${liveMbps.toFixed(1)} Mbps`;
    if (ratingEl) ratingEl.textContent = 'Testing download speed...';
    if (noteEl) {
      noteEl.textContent = `Current download speed: ${liveMbps.toFixed(
        1
      )} Mbps`;
    }
  } else if (phase === 'upload') {
    if (badge) {
      badge.textContent = 'LIVE UPLOAD';
      badge.className = 'status-pill online';
    }
    const liveMbps = Number(data.currentMbps ?? data.uploadMbps ?? 0);
    setSpeedGaugeTarget(liveMbps);
    if (dlEl && data.downloadMbps != null) {
      dlEl.textContent = `${Number(data.downloadMbps).toFixed(1)} Mbps`;
    }
    if (ulEl && liveMbps > 0) ulEl.textContent = `${liveMbps.toFixed(1)} Mbps`;
    if (noteEl) {
      noteEl.textContent = `Measured live: ${liveMbps.toFixed(
        1
      )} Mbps across parallel HTTPS upload streams`;
    }
  } else if (phase === 'complete') {
    if (badge) {
      badge.textContent = 'COMPLETE';
      badge.className = 'status-pill online';
    }
    const finalDl = data.downloadMbps ?? null;
    const finalUl = data.uploadMbps ?? null;
    lastCompletedSpeedTest = {
      ...data,
      downloadMbps: finalDl,
      uploadMbps: finalUl,
      pingMs: data.pingMs,
      jitterMs: data.jitterMs,
      rating: data.rating || 'High-Speed Broadband'
    };
    if (appState.isp) appState.isp.lastSpeedTest = lastCompletedSpeedTest;
    setSpeedGaugeTarget(finalDl ?? 0);
    if (dlEl) dlEl.textContent = fmtMbps(finalDl);
    if (ulEl) ulEl.textContent = fmtMbps(finalUl);
    if (ratingEl && data.rating) ratingEl.textContent = data.rating;
    if (noteEl) {
      const targetPrefix = data.targetName ? `Target: ${data.targetName} • ` : '';
      noteEl.textContent = `${targetPrefix}Completed at ${new Date().toLocaleTimeString()} • Download ${fmtMbps(finalDl)} / Upload ${fmtMbps(finalUl)}`;
    }
    setActiveSpeedCard(null);
    if (typeof updateKumaLiveSpeed === 'function') {
      updateKumaLiveSpeed();
    }
  }

  if (pingEl && data.pingMs != null) pingEl.textContent = `${data.pingMs} ms`;
  if (jitterEl && data.jitterMs != null)
    jitterEl.textContent = `${data.jitterMs} ms`;
}

function renderIspSection() {
  const isp = appState.isp || {};
  const hasScore = isp.healthScore != null;
  const score = hasScore ? isp.healthScore : 0;
  const scoreEl = document.getElementById('ispScoreNumber');
  const circleEl = document.getElementById('ispScoreCircle');
  const badgeEl = document.getElementById('ispStatusBadge');
  const dnsEl = document.getElementById('ispDnsTime');

  renderIspIdentity(isp);
  syncSpeedTestTargets();
  const target = getSelectedSpeedTestTarget();
  const testing = speedTestInProgress || (speedTestRequestPending && !speedTestFailure) || isp.speedTestRunning === true;
  const failure = testing ? '' : (speedTestFailure || isp.speedTestError || '');
  const speedTestButton = document.getElementById('btnRunSpeedTest');
  if (speedTestButton) {
    speedTestButton.disabled = isp.speedTestsEnabled !== true || testing;
    speedTestButton.title = isp.speedTestsEnabled === true ? '' : 'Active bandwidth tests are disabled in the server settings';
    const targetDesc =
      target.targetType === 'isp'
        ? 'Measures WAN download, upload, ping & jitter from the monitoring PC to Cloudflare.'
        : `Measures latency, variation, unanswered probes, and HTTP response rate when available for ${target.targetName} (${target.targetIp}).`;
    document.getElementById('speedTestAvailability').textContent =
      failure || (testing ? `Measuring speed to ${target.targetName}…` : isp.speedTestsEnabled === true
        ? targetDesc
        : 'Active speed tests are disabled in the server settings.');
    document.getElementById('speedTestBrowserLink').hidden = !failure || target.targetType !== 'isp';
  }
  renderLiveIspTelemetry();

  if (scoreEl) scoreEl.textContent = hasScore ? score : '—';
  if (circleEl) {
    const offset = Math.max(0, 283 - (283 * score) / 100);
    circleEl.style.strokeDashoffset = String(offset);
  }
  if (badgeEl) {
    const health =
      isp.overallHealth && isp.overallHealth !== 'UNKNOWN'
        ? isp.overallHealth
        : null;
    badgeEl.textContent = health ? `${health} (${score}/100)` : 'CHECKING…';
    const cls = !health
      ? 'warning'
      : health === 'EXCELLENT' || health === 'GOOD'
      ? 'excellent'
      : health === 'DEGRADED'
      ? 'warning'
      : 'critical';
    badgeEl.className = `isp-status-badge ${cls}`;
  }
  if (dnsEl) {
    const dMs = isp.dnsResolutionMs;
    if (dMs != null) {
      const dnsQuality = dMs <= 30 ? 'Instant' : dMs <= 80 ? 'Normal' : 'Slow DNS';
      dnsEl.textContent = `${dMs} ms (${dnsQuality})`;
      dnsEl.style.color =
        dMs <= 80 ? 'var(--accent-green)' : 'var(--accent-amber)';
    } else {
      dnsEl.textContent = '—';
      dnsEl.style.color = 'var(--text-dim)';
    }
  }

  if (isp.lastSpeedTest?.timestamp) {
    lastCompletedSpeedTest = isp.lastSpeedTest;
  }
  const st = isp.lastSpeedTest || lastCompletedSpeedTest;
  const dlEl = document.getElementById('speedDownloadText');
  const ulEl = document.getElementById('speedUploadText');
  const ratingEl = document.getElementById('speedRatingSub');
  const pingEl = document.getElementById('speedPingText');
  const jitterEl = document.getElementById('speedJitterText');

  if (!testing) {
    if (dlEl) dlEl.textContent = st?.downloadMbps != null ? `${Number(st.downloadMbps).toFixed(1)} Mbps` : '— Mbps';
    if (failure) {
      const badge = document.getElementById('speedGaugePhaseBadge');
      badge.textContent = 'TEST FAILED';
      badge.className = 'status-pill offline';
      document.getElementById('speedGaugePhaseLabel').textContent = 'The latest test did not finish.';
      document.getElementById('speedGaugePctText').textContent = '0%';
      document.getElementById('speedGaugeProgressBar').style.width = '0%';
      document.getElementById('speedGaugeSubNote').textContent =
        st?.timestamp ? `Readings below were measured ${new Date(st.timestamp).toLocaleString()}.` : '';
      if (targetGaugeMbps !== 0) setSpeedGaugeTarget(0);
    } else if (st?.timestamp) {
      setSpeedGaugeTarget(st.downloadMbps ?? 0);
      const badge = document.getElementById('speedGaugePhaseBadge');
      const pctEl = document.getElementById('speedGaugePctText');
      const barEl = document.getElementById('speedGaugeProgressBar');
      const labelEl = document.getElementById('speedGaugePhaseLabel');
      if (badge) {
        badge.textContent = 'LAST SPEED TEST';
        badge.className = 'status-pill online';
      }
      if (pctEl) pctEl.textContent = '100%';
      if (barEl) barEl.style.width = '100%';
      if (labelEl) {
        labelEl.textContent = st.downloadMbps == null ? st.rating : `Measured ${Number(st.downloadMbps).toFixed(1)} Mbps Down${
          st.uploadMbps != null ? ` • ${Number(st.uploadMbps).toFixed(1)} Mbps Up` : ''
        }`;
      }
      const note = document.getElementById('speedGaugeSubNote');
      if (note && st.timestamp) {
        note.textContent = `Measured from the monitoring PC to ${st.server || 'Cloudflare'} · ${new Date(st.timestamp).toLocaleString()}`;
      }
    }
    if (ulEl) ulEl.textContent = st?.uploadMbps != null ? `${Number(st.uploadMbps).toFixed(1)} Mbps` : '— Mbps';
    if (ratingEl) ratingEl.textContent = st?.rating || '';
    if (pingEl) pingEl.textContent = st?.pingMs != null ? `${st.pingMs} ms` : '— ms';
    if (jitterEl) jitterEl.textContent = st?.jitterMs != null ? `${st.jitterMs} ms` : '— ms';
  }

  // Render Major Internet Gateway Checks Table (merging pingGraph.stats fallback so latency is never stuck on Probing)
  const tbody = document.getElementById('ispProbesTableBody');
  if (tbody) {
    const pgStats = (isp.pingGraph && isp.pingGraph.stats) || {};
    const probes =
      isp.probes && isp.probes.length
        ? isp.probes
        : (isp.pingGraph && isp.pingGraph.targets) || [];
    tbody.innerHTML = probes
      .map(p => {
        const s = pgStats[p.id] || {};
        const latVal = p.alive === undefined ? s.currentMs : p.latencyMs;
        const alive = p.alive ?? (latVal != null ? true : null);
        const latText = latVal != null ? `${latVal} ms` : (alive === false ? 'Timeout' : '—');
        return `
          <tr>
            <td><strong>${esc(p.name)}</strong></td>
            <td class="mono" style="color:var(--accent-cyan);">${esc(p.host || p.ip)}</td>
            <td class="mono">${esc(latText)}</td>
            <td class="mono">${esc(p.method || s.probeMethod || '—')}</td>
            <td><span class="status-pill ${alive == null ? 'warning' : alive ? 'online' : 'offline'}">${
          alive == null ? 'CHECKING' : alive ? 'ONLINE' : 'UNREACHABLE'
        }</span></td>
          </tr>
        `;
      })
      .join('');
  }

  // Render ISP Connection Diagnostics & Solutions Panel
  renderIspDiagnosticsBox(isp);
}

function renderIspDiagnosticsBox(isp) {
  const box = document.getElementById('ispDiagnosticsBox');
  if (!box) return;

  const diag = isp.diagnosis || {};
  const isUnknown = !isp.overallHealth || isp.overallHealth === 'UNKNOWN';
  const verdict =
    diag.verdict ||
    (isUnknown
      ? 'CHECKING'
      : isp.overallHealth === 'OUTAGE'
      ? 'CRITICAL'
      : isp.overallHealth === 'DEGRADED'
      ? 'WARNING'
      : 'OPTIMAL');
  const headlineEl = document.getElementById('ispDiagHeadline');
  const badgeEl = document.getElementById('ispDiagVerdictBadge');
  const summaryEl = document.getElementById('ispDiagSummary');
  const bottleneckEl = document.getElementById('ispDiagBottleneck');
  const listEl = document.getElementById('ispDiagSolutionsList');

  if (verdict === 'CHECKING') {
    box.style.borderColor = 'var(--border-subtle)';
    box.style.borderLeftColor = 'var(--accent-cyan)';
    if (badgeEl) {
      badgeEl.className = 'status-pill new';
      badgeEl.textContent = '⏳ PROBING…';
    }
  } else if (verdict === 'CRITICAL') {
    box.style.borderColor = 'var(--status-down-border)';
    box.style.borderLeftColor = 'var(--accent-red)';
    if (badgeEl) {
      badgeEl.className = 'status-pill offline';
      badgeEl.textContent = '🚨 CONNECTIVITY ISSUE';
    }
  } else if (verdict === 'WARNING') {
    box.style.borderColor = 'var(--status-warn-border)';
    box.style.borderLeftColor = 'var(--accent-amber)';
    if (badgeEl) {
      badgeEl.className = 'status-pill warning';
      badgeEl.textContent = '⚠️ DEGRADED PROBES';
    }
  } else {
    box.style.borderColor = 'var(--status-up-border)';
    box.style.borderLeftColor = 'var(--accent-green)';
    if (badgeEl) {
      badgeEl.className = 'status-pill online';
      badgeEl.textContent = '🟢 PROBES HEALTHY';
    }
  }

  if (headlineEl) {
    headlineEl.textContent =
      diag.headline || 'Checking gateway, internet reachability and DNS…';
  }
  if (summaryEl) {
    const fmt = v => (v != null ? `${v} ms` : '—');
    summaryEl.textContent =
      diag.summary ||
      `Local gateway ${fmt(isp.wanGatewayLatencyMs)}, external probes ${fmt(
        isp.tier1LatencyMs
      )}, DNS ${fmt(isp.dnsResolutionMs)}.`;
  }
  if (bottleneckEl) {
    bottleneckEl.hidden = !diag.bottleneckLayer;
    bottleneckEl.textContent = diag.bottleneckLayer ? `Bottleneck: ${diag.bottleneckLayer}` : '';
  }
  if (listEl) {
    const solutions = diag.solutions || [];
    listEl.innerHTML = solutions.map(s => `<li>${esc(s)}</li>`).join('');
  }

  const benchmark = isp.lastSpeedTest || lastCompletedSpeedTest;
  const result = document.getElementById('ispDiagBenchmarkResult');
  const measuredAt = document.getElementById('ispDiagBenchmarkTime');
  const hasRates = Number.isFinite(benchmark?.downloadMbps) && Number.isFinite(benchmark?.uploadMbps);
  result.textContent = hasRates
    ? `Last bandwidth benchmark from this PC: ${benchmark.downloadMbps} Mbps down / ${benchmark.uploadMbps} Mbps up.`
    : 'No bandwidth benchmark recorded.';
  const timestamp = Date.parse(benchmark?.timestamp);
  measuredAt.hidden = !hasRates || !Number.isFinite(timestamp);
  if (!measuredAt.hidden) {
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    const [unit, size] = seconds >= 86400 ? ['day', 86400]
      : seconds >= 3600 ? ['hour', 3600]
      : seconds >= 60 ? ['minute', 60] : ['second', 1];
    const age = new Intl.RelativeTimeFormat(undefined, {numeric: 'auto'}).format(-Math.floor(seconds / size), unit);
    const date = new Date(timestamp);
    measuredAt.dateTime = date.toISOString();
    measuredAt.title = date.toLocaleString();
    measuredAt.textContent = `Measured ${age}.`;
  }
}

async function recheckIspConnectionNow() {
  const btn = document.getElementById('btnRecheckIsp');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Checking ISP & DNS...';
  }
  try {
    const res = await apiJson('/api/isp/probe', {
      method: 'POST',
      body: JSON.stringify({})
    });
    if (res.isp) {
      applyIspSnapshot(res.isp);
      renderIspSection();
      renderPingGraphSection();
      renderExecutiveBanner();
    }
  } catch (err) {
    alert(`ISP check error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔄 Re-Check ISP & DNS';
    }
  }
}

function openDnsBenchmarkFromIsp() {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('toolkit');
  } else if (typeof scrollToToolkit === 'function') {
    scrollToToolkit();
  }
  if (typeof switchToolkitTab === 'function') {
    switchToolkitTab('dnsTab');
  }
  if (typeof runDnsBenchmarkTool === 'function') {
    runDnsBenchmarkTool();
  }
}

function openIspTracerouteFromIsp() {
  if (typeof navigateSidebar === 'function') {
    navigateSidebar('toolkit');
  } else if (typeof scrollToToolkit === 'function') {
    scrollToToolkit();
  }
  if (typeof switchToolkitTab === 'function') {
    switchToolkitTab('tracerouteTab');
  }
  const input = document.getElementById('traceTargetInput');
  if (input) input.value = '1.1.1.1';
  if (typeof runTracerouteTool === 'function') {
    runTracerouteTool();
  }
}

async function runSpeedTestNow() {
  if (speedTestInProgress || appState.isp?.speedTestRunning || appState.isp?.speedTestsEnabled !== true) return;
  speedTestRequestPending = true;
  const btn = document.getElementById('btnRunSpeedTest');
  const box = document.getElementById('speedLiveGaugeBox');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Measuring Live Speed...';
  }
  speedTestInProgress = true;
  if (box) {
    box.classList.add('testing');
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  const target = getSelectedSpeedTestTarget();
  setSpeedGaugeTarget(0, true);
  handleSpeedTestProgress({
    phase: 'ping',
    currentMbps: 0,
    progressPct: 2,
    message: target.targetType === 'isp'
      ? 'Connecting the monitoring PC to Cloudflare…'
      : `Connecting to ${target.targetName} (${target.targetIp})…`
  });

  // All live gauge frames come from real server measurements streamed over SSE
  // ("speedtest_progress"); nothing is animated or estimated client-side.
  try {
    const payload = target.targetType === 'isp'
      ? { targetType: 'isp' }
      : { targetType: target.targetType, targetIp: target.targetIp, targetName: target.targetName };
    const res = await apiJson('/api/speedtest/run', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    const st = res.speedTest || res;
    if (st?.timestamp) {
      if (!appState.isp) appState.isp = {};
      appState.isp.lastSpeedTest = st;
      handleSpeedTestProgress({
        ...st,
        phase: 'complete',
        currentMbps: st.downloadMbps,
        progressPct: 100
      });
    }
    await loadInitialState();
  } catch (err) {
    handleSpeedTestProgress({ phase: 'error', message: err.message });
  } finally {
    speedTestRequestPending = false;
    speedTestInProgress = false;
    if (box) box.classList.remove('testing');
    setActiveSpeedCard(null);
    if (btn) {
      btn.disabled = appState.isp?.speedTestsEnabled !== true || appState.isp?.speedTestRunning === true;
      btn.textContent = '⚡ Test Internet Speed Now';
    }
    renderIspSection();
  }
}

// ---------------------------------------------------------------------------
// Real ISP identity (provider / ASN / public IP) and live throughput graph
// ---------------------------------------------------------------------------

const liveIspFields = ['liveThroughput', 'routerWanThroughput'];

function fmtMbps(v) {
  if (!Number.isFinite(v)) return '—';
  const n = v;
  if (n >= 100) return `${Math.round(n)} Mbps`;
  if (n >= 1) return `${n.toFixed(1)} Mbps`;
  return `${(n * 1000).toFixed(0)} kbps`;
}

function renderIspIdentity(isp) {
  const p = isp.provider || null;
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = val;
      el.title = val;
    }
  };
  if (p) {
    set('ispProviderName', p.provider || 'Unknown ISP');
    set('ispProviderAsn', p.asn || '—');
    set('ispPublicIp', p.publicIp || '—');
    set('ispEdgeLocation', [p.edgeColo, p.location].filter(Boolean).join(' · ') || '—');
  } else {
    set('ispProviderName', isp.providerError ? 'Unreachable' : 'Detecting…');
  }

  const st = isp.lastSpeedTest;
  set(
    'ispLastTestAt',
    st && st.timestamp
      ? `${fmtMbps(st.downloadMbps)}↓ / ${fmtMbps(st.uploadMbps)}↑ · ${new Date(
          st.timestamp
        ).toLocaleString()}`
      : 'Never'
  );
  const nextEl = document.getElementById('ispNextTestAt');
  if (nextEl) {
    if (isp.speedTestsEnabled !== true) nextEl.textContent = 'Speed tests disabled';
    else if (isp.speedTestRunning) nextEl.textContent = 'Test running now…';
    else if (speedTestFailure || isp.speedTestError) nextEl.textContent = 'Last test failed';
    else if (isp.nextAutoTestAt)
      nextEl.textContent = `Next auto test ${new Date(isp.nextAutoTestAt * 1000).toLocaleTimeString()}`;
    else nextEl.textContent = 'On demand';
  }
}

function applyLiveIspTelemetry(incoming) {
  const isp = appState.isp ||= {};
  for (const key of liveIspFields) {
    const sample = incoming[key];
    const previous = isp[key];
    if (!sample?.timestamp || (previous?.timestamp && sample.timestamp < previous.timestamp)) continue;
    if (key === 'liveThroughput' && !Array.isArray(sample.history)) {
      if (sample.timestamp === previous?.timestamp) continue;
      const sameSource = sample.source === previous?.source;
      const history = sameSource ? previous.history || [] : [];
      sample.history = Number.isFinite(sample.rxMbps) && Number.isFinite(sample.txMbps)
        ? [...history, {t: sample.timestamp, rx: sample.rxMbps, tx: sample.txMbps}].slice(-120)
        : [];
    }
    isp[key] = sample;
  }
}

function applyIspSnapshot(incoming) {
  if (!incoming) return;
  const current = appState.isp || {};
  const {liveThroughput, routerWanThroughput, ...snapshot} = incoming;
  if (current.lastSpeedTest?.timestamp > (snapshot.lastSpeedTest?.timestamp || '')) {
    snapshot.lastSpeedTest = current.lastSpeedTest;
  }
  if (!current.probeTimestamp || snapshot.probeTimestamp >= current.probeTimestamp) {
    appState.isp = {...current, ...snapshot};
    if (!speedTestRequestPending && !gameEventStreamConnected && snapshot.speedTestRunning === false) {
      speedTestInProgress = false;
      speedTestFailure = snapshot.speedTestError || '';
      document.getElementById('speedLiveGaugeBox')?.classList.remove('testing');
      setActiveSpeedCard(null);
    }
  }
  applyLiveIspTelemetry({liveThroughput, routerWanThroughput});
}

function renderLiveIspTelemetry() {
  renderGatewayHealth();
  const isp = appState.isp || {};
  const d = isp.liveThroughput || {};
  const hostFresh = Date.now() - Date.parse(d.timestamp) < 6000;
  const rxEl = document.getElementById('wanLiveRx');
  const txEl = document.getElementById('wanLiveTx');
  const signalEl = document.getElementById('wanWifiSignal');
  const srcEl = document.getElementById('wanLiveSource');
  if (rxEl) rxEl.textContent = fmtMbps(hostFresh ? d.rxMbps : null);
  if (txEl) txEl.textContent = fmtMbps(hostFresh ? d.txMbps : null);
  if (signalEl) {
    const { signalPercent, rssiDbm } = hostFresh ? d.wifiSignal || {} : {};
    signalEl.textContent = [
      Number.isFinite(signalPercent) && `${signalPercent}%`,
      Number.isFinite(rssiDbm) && `${rssiDbm} dBm`
    ].filter(Boolean).join(' · ') || 'Unavailable';
  }
  if (srcEl) {
    srcEl.textContent = hostFresh && Number.isFinite(d.rxMbps)
      ? `${d.source} · peak ${fmtMbps(d.peakRxMbps)} ↓ / ${fmtMbps(d.peakTxMbps)} ↑`
      : 'Waiting for monitoring PC interface counters';
  }
  drawWanLiveChart(d.history || []);

  const router = isp.routerWanThroughput;
  const routerIp = appState.config?.routerConfig?.ip || appState.router?.ip;
  const routerStatus = router && (!routerIp || router.routerIp === routerIp) ? router.status : 'sampling';
  const routerFresh = routerStatus === 'live' && Date.now() - Date.parse(router.timestamp) < 8000;
  const routerSource = document.getElementById('routerWanSource');
  const routerRx = document.getElementById('routerWanRx');
  const routerTx = document.getElementById('routerWanTx');
  if (routerRx) routerRx.textContent = fmtMbps(routerFresh ? router.rxMbps : null);
  if (routerTx) routerTx.textContent = fmtMbps(routerFresh ? router.txMbps : null);
  if (routerSource) {
    routerSource.textContent = routerFresh ? `${router.routerIp} · ${router.source}`
      : routerStatus === 'unavailable' ? `WAN counters unavailable from ${router.routerIp}`
      : routerStatus === 'live' ? 'Waiting for a fresh router sample' : 'Waiting for router counters…';
  }
}

function drawWanLiveChart(pts = appState.isp?.liveThroughput?.history || []) {
  const canvas = document.getElementById('wanLiveCanvas');
  if (!canvas || !canvas.offsetParent) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  if (canvas.width !== Math.round(w * dpr)) {
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const css = getComputedStyle(document.documentElement);
  const rxColor = css.getPropertyValue('--accent-cyan').trim() || '#00bceb';
  const txColor = css.getPropertyValue('--accent-amber').trim() || '#f59e0b';
  const gridColor = css.getPropertyValue('--border-subtle').trim() || 'rgba(148,163,184,0.3)';
  const textColor = css.getPropertyValue('--text-dim').trim() || '#94a3b8';

  const maxVal = Math.max(1, ...pts.map(p => Math.max(p.rx, p.tx))) * 1.15;

  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.font = '10px JetBrains Mono, monospace';
  ctx.fillStyle = textColor;
  for (let i = 0; i <= 2; i++) {
    const y = Math.round((h - 4) * (i / 2)) + 0.5;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
  ctx.fillText(fmtMbps(maxVal), 4, 11);

  if (pts.length < 2) return;
  const step = w / 119;
  const offset = w - (pts.length - 1) * step;
  const drawLine = (key, color, fill, dash) => {
    ctx.beginPath();
    pts.forEach((p, i) => {
      const x = offset + i * step;
      const y = h - 4 - (p[key] / maxVal) * (h - 8);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.setLineDash(dash);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.setLineDash([]);
    if (fill) {
      ctx.lineTo(offset + (pts.length - 1) * step, h);
      ctx.lineTo(offset, h);
      ctx.closePath();
      ctx.globalAlpha = 0.12;
      ctx.fillStyle = color;
      ctx.fill();
      ctx.globalAlpha = 1;
    }
  };
  drawLine('rx', rxColor, true, []);
  drawLine('tx', txColor, false, [5, 3]); // dashed = upload (colour-blind safe)
}
