// Pulse Network Monitor — Section 3: ISP Health, Live Animated Speedometer & ISP Diagnostics

let speedTestInProgress = false;
let currentGaugeMbps = 0;
let targetGaugeMbps = 0;
let gaugeAnimFrame = null;
let speedTestVisualTimer = null;
let lastCompletedSpeedTest = null;

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
    if (box) box.classList.remove('testing');
    setActiveSpeedCard(null);
    setSpeedGaugeTarget(0);
    if (badge) {
      badge.textContent = 'TEST FAILED';
      badge.className = 'status-pill offline';
    }
    if (labelEl) labelEl.textContent = data.message || 'Speed test failed';
    if (barEl) barEl.style.width = '0%';
    if (pctEl) pctEl.textContent = '0%';
    return;
  }

  if (phase !== 'complete') {
    speedTestInProgress = true;
    if (box) box.classList.add('testing');
  } else {
    speedTestInProgress = false;
    if (speedTestVisualTimer) {
      clearInterval(speedTestVisualTimer);
      speedTestVisualTimer = null;
    }
    if (box) box.classList.remove('testing');
  }

  setActiveSpeedCard(phase);

  if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
  if (barEl) barEl.style.width = `${pct}%`;
  const phaseMsg = data.message || data.phaseLabel;
  if (labelEl && phaseMsg) labelEl.textContent = phaseMsg;

  if (phase === 'ping') {
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
    const finalDl = Number(data.downloadMbps ?? data.currentMbps ?? 0);
    const finalUl = Number(data.uploadMbps ?? 0);
    lastCompletedSpeedTest = {
      downloadMbps: finalDl,
      uploadMbps: finalUl,
      pingMs: data.pingMs,
      jitterMs: data.jitterMs,
      rating: data.rating || 'High-Speed Broadband'
    };
    setSpeedGaugeTarget(finalDl);
    if (dlEl && finalDl > 0) dlEl.textContent = `${finalDl.toFixed(1)} Mbps`;
    if (ulEl && finalUl > 0) ulEl.textContent = `${finalUl.toFixed(1)} Mbps`;
    if (ratingEl && data.rating) ratingEl.textContent = data.rating;
    if (noteEl) {
      noteEl.textContent = `Completed at ${new Date().toLocaleTimeString()} • Download ${finalDl.toFixed(
        1
      )} Mbps / Upload ${finalUl.toFixed(1)} Mbps`;
    }
    setActiveSpeedCard(null);
    if (typeof updateKumaLiveSpeed === 'function') {
      updateKumaLiveSpeed(
        (window.appState && window.appState.isp && window.appState.isp.liveThroughput) || null
      );
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
  if (isp.liveThroughput) {
    if (Array.isArray(isp.liveThroughput.history) && isp.liveThroughput.history.length && !wanLiveSeeded) {
      seedWanLiveHistory(isp.liveThroughput);
    } else {
      handleWanThroughput(isp.liveThroughput, false);
    }
  }

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

  if (isp.lastSpeedTest && isp.lastSpeedTest.downloadMbps) {
    lastCompletedSpeedTest = isp.lastSpeedTest;
  }
  const st = isp.lastSpeedTest || lastCompletedSpeedTest;
  const dlEl = document.getElementById('speedDownloadText');
  const ulEl = document.getElementById('speedUploadText');
  const ratingEl = document.getElementById('speedRatingSub');
  const pingEl = document.getElementById('speedPingText');
  const jitterEl = document.getElementById('speedJitterText');

  if (!speedTestInProgress) {
    if (dlEl && st && st.downloadMbps != null) {
      dlEl.textContent = `${Number(st.downloadMbps).toFixed(1)} Mbps`;
      setSpeedGaugeTarget(st.downloadMbps);
      const badge = document.getElementById('speedGaugePhaseBadge');
      const pctEl = document.getElementById('speedGaugePctText');
      const barEl = document.getElementById('speedGaugeProgressBar');
      const labelEl = document.getElementById('speedGaugePhaseLabel');
      if (badge) {
        badge.textContent = 'VERIFIED SPEED';
        badge.className = 'status-pill online';
      }
      if (pctEl) pctEl.textContent = '100%';
      if (barEl) barEl.style.width = '100%';
      if (labelEl) {
        labelEl.textContent = `Measured ${Number(st.downloadMbps).toFixed(1)} Mbps Down${
          st.uploadMbps != null ? ` • ${Number(st.uploadMbps).toFixed(1)} Mbps Up` : ''
        }`;
      }
    }
    if (ulEl && st && st.uploadMbps != null) {
      ulEl.textContent = `${Number(st.uploadMbps).toFixed(1)} Mbps`;
    }
    if (ratingEl && st && st.rating) {
      ratingEl.textContent = st.rating;
    }
    if (pingEl) {
      const pVal =
        st && st.pingMs != null ? st.pingMs : isp.tier1LatencyMs;
      pingEl.textContent = pVal != null ? `${pVal} ms` : '— ms';
    }
    if (jitterEl) {
      const jVal =
        st && st.jitterMs != null
          ? st.jitterMs
          : isp.jitterMs != null
          ? isp.jitterMs
          : null;
      jitterEl.textContent = jVal != null ? `${jVal} ms` : '— ms';
    }
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
        const latVal = p.latencyMs != null ? p.latencyMs : s.currentMs;
        const alive = p.alive !== undefined ? Boolean(p.alive) : latVal != null;
        const lossVal = p.packetLoss != null ? p.packetLoss : (s.lossPct ?? (alive ? 0 : 100));
        const latText = latVal != null ? `${latVal} ms` : (alive ? '—' : 'Timeout');
        return `
          <tr>
            <td><strong>${esc(p.name)}</strong></td>
            <td class="mono" style="color:var(--accent-cyan);">${esc(p.host || p.ip)}</td>
            <td class="mono">${esc(latText)}</td>
            <td class="mono">${lossVal}%</td>
            <td><span class="status-pill ${alive ? 'online' : 'offline'}">${
          alive ? 'ONLINE' : 'UNREACHABLE'
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
      badgeEl.textContent = '🚨 ISP / WAN OUTAGE';
    }
  } else if (verdict === 'WARNING') {
    box.style.borderColor = 'var(--status-warn-border)';
    box.style.borderLeftColor = 'var(--accent-amber)';
    if (badgeEl) {
      badgeEl.className = 'status-pill warning';
      badgeEl.textContent = '⚠️ DEGRADED / BOTTLENECK';
    }
  } else {
    box.style.borderColor = 'var(--status-up-border)';
    box.style.borderLeftColor = 'var(--accent-green)';
    if (badgeEl) {
      badgeEl.className = 'status-pill online';
      badgeEl.textContent = '🟢 ISP HEALTHY';
    }
  }

  if (headlineEl) {
    headlineEl.textContent =
      diag.headline || 'ISP Fiber Connection, Gateway & DNS Are Healthy & Fast';
  }
  if (summaryEl) {
    const fmt = v => (v != null ? `${v} ms` : '—');
    summaryEl.textContent =
      diag.summary ||
      `Local gateway ${fmt(isp.wanGatewayLatencyMs)}, ISP backbone ${fmt(
        isp.tier1LatencyMs
      )} (${isp.packetLossPct ?? 0}% packet loss), DNS ${fmt(isp.dnsResolutionMs)}.`;
  }
  if (bottleneckEl) {
    bottleneckEl.textContent = `Bottleneck Layer: ${
      diag.bottleneckLayer || 'None — Local Router, ISP Fiber & DNS Operating Optimally'
    }`;
  }
  if (listEl) {
    const solutions =
      Array.isArray(diag.solutions) && diag.solutions.length
        ? diag.solutions
        : [
            'Keep Primary DNS set to 1.1.1.1 (Cloudflare) and Secondary DNS to 8.8.8.8 (Google) on the main router for fastest domain resolution.',
            'Click "⚡ Test Internet Speed Now" or "🔄 Re-Check ISP & DNS" anytime to verify live ISP throughput.'
          ];
    listEl.innerHTML = solutions.map(s => `<li>${esc(s)}</li>`).join('');
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
      appState.isp = res.isp;
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
  if (speedTestInProgress) return;
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
  setSpeedGaugeTarget(0, true);
  handleSpeedTestProgress({
    phase: 'ping',
    currentMbps: 0,
    progressPct: 2,
    message: 'Connecting to speed.cloudflare.com and identifying your ISP...'
  });

  // All live gauge frames come from real server measurements streamed over SSE
  // ("speedtest_progress"); nothing is animated or estimated client-side.
  try {
    const res = await apiJson('/api/speedtest/run', {
      method: 'POST',
      body: JSON.stringify({})
    });
    const st = res.speedTest || res;
    if (st && st.downloadMbps != null) {
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
    handleSpeedTestProgress({ phase: 'error', message: `Speed test failed: ${err.message}` });
  } finally {
    speedTestInProgress = false;
    if (box) box.classList.remove('testing');
    setActiveSpeedCard(null);
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Test Internet Speed Now';
    }
  }
}

// ---------------------------------------------------------------------------
// Real ISP identity (provider / ASN / public IP) and live throughput graph
// ---------------------------------------------------------------------------

let wanLiveHistory = [];
let wanLiveSeeded = false;

function fmtMbps(v) {
  const n = Number(v) || 0;
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
      ? `${Number(st.downloadMbps).toFixed(0)}↓ / ${Number(st.uploadMbps).toFixed(0)}↑ · ${new Date(
          st.timestamp
        ).toLocaleTimeString()}`
      : 'Never'
  );
  const nextEl = document.getElementById('ispNextTestAt');
  if (nextEl) {
    if (isp.speedTestRunning) nextEl.textContent = 'Test running now…';
    else if (isp.speedTestError) nextEl.textContent = `Last error: ${isp.speedTestError}`;
    else if (isp.nextAutoTestAt)
      nextEl.textContent = `Next auto test ${new Date(isp.nextAutoTestAt * 1000).toLocaleTimeString()}`;
    else nextEl.textContent = '';
  }
}

function seedWanLiveHistory(live) {
  if (wanLiveSeeded || !live.history.length) return;
  wanLiveHistory = live.history.map(p => ({ rx: p.rx, tx: p.tx }));
  wanLiveSeeded = true;
  handleWanThroughput(live, false);
}

function handleWanThroughput(d, push = true) {
  if (!d) return;
  if (push) {
    wanLiveSeeded = true;
    wanLiveHistory.push({ rx: d.rxMbps, tx: d.txMbps });
    if (wanLiveHistory.length > 120) wanLiveHistory.shift();
  }
  if (typeof updateKumaLiveSpeed === 'function') {
    updateKumaLiveSpeed(d);
  }
  const rxEl = document.getElementById('wanLiveRx');
  const txEl = document.getElementById('wanLiveTx');
  const utilEl = document.getElementById('wanLiveUtil');
  const srcEl = document.getElementById('wanLiveSource');
  const fmtMb = v => `${(Math.max(0, Number(v) || 0) / 8).toFixed(2)} MB/s`;
  if (rxEl) rxEl.textContent = `${fmtMb(d.rxMbps)} (${fmtMbps(d.rxMbps)})`;
  if (txEl) txEl.textContent = `${fmtMb(d.txMbps)} (${fmtMbps(d.txMbps)})`;

  const st = (appState.isp && appState.isp.lastSpeedTest) || lastCompletedSpeedTest;
  if (utilEl) {
    utilEl.textContent =
      st && st.downloadMbps
        ? `${Math.min(100, (d.rxMbps / st.downloadMbps) * 100).toFixed(0)}%`
        : '—';
  }
  if (srcEl) {
    srcEl.textContent = `Measured from this server's network interface counters (${
      d.source || 'OS'
    }) · peak ${fmtMbps(d.peakRxMbps)}↓ / ${fmtMbps(d.peakTxMbps)}↑`;
  }
  drawWanLiveChart();
}

function drawWanLiveChart() {
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

  const pts = wanLiveHistory;
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
