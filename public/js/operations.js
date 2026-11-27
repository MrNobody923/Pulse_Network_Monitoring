function formatProbeAge(timestamp, interval) {
  const checked = Date.parse(timestamp);
  if (!Number.isFinite(checked)) return 'Awaiting first check';
  const seconds = Math.max(0, Math.floor((Date.now() - checked) / 1000));
  const age = seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;
  const stale = interval && seconds > interval * 2;
  return `${stale ? 'Stale · ' : ''}Checked ${age}${interval ? ` · every ${interval}s` : ''}`;
}

let incidentRequest = 0;

function prepareIncidentDialog(text) {
  const dialog = document.getElementById('incidentDialog');
  document.getElementById('incidentTitle').textContent = 'Incident details';
  document.getElementById('incidentFeedback').textContent = text;
  document.getElementById('incidentDetails').replaceChildren();
  document.getElementById('incidentActions').replaceChildren();
  document.getElementById('incidentHandoff').hidden = true;
  if (!dialog.open) dialog.showModal();
  return dialog;
}

async function openIncidentList() {
  const request = ++incidentRequest;
  const dialog = prepareIncidentDialog('Loading incidents…');
  try {
    const {active, history} = await apiJson('/api/alerts');
    if (request !== incidentRequest || !dialog.open) return;
    const recent = history.filter(alert => alert.status === 'RESOLVED')
      .sort((a, b) => Date.parse(b.resolvedAt || b.timestamp) - Date.parse(a.resolvedAt || a.timestamp))
      .slice(0, 10);
    const list = (items, handler, idField, timeField) => `<ol class="device-history-events">${items.map(alert =>
      `<li><button type="button" class="btn btn-secondary btn-xs" onclick="${handler}(${inlineString(alert[idField])})">${esc(alert.title)}</button>
      <time>${esc(fmtTime(alert[timeField]))}</time></li>`).join('')}</ol>`;
    document.getElementById('incidentFeedback').textContent = active.length ? 'Choose an incident to review.' : 'No active incidents.';
    document.getElementById('incidentDetails').innerHTML = `
      ${active.length ? `<h3>Active</h3>${list(active, 'openIncident', 'key', 'firstSeen')}` : ''}
      <h3>Recently resolved</h3>
      ${recent.length ? list(recent, 'openResolvedIncident', 'id', 'resolvedAt') : '<p class="gateway-note">No resolved incidents recorded.</p>'}`;
  } catch (error) {
    if (request === incidentRequest) document.getElementById('incidentFeedback').textContent = error.message;
  }
}

function openResolvedIncident(id) {
  return openIncident('', '', id);
}

async function openIncident(key, message = '', resolvedId = '') {
  const request = ++incidentRequest;
  const dialog = prepareIncidentDialog('Loading incident…');
  const title = document.getElementById('incidentTitle');
  const feedback = document.getElementById('incidentFeedback');
  const details = document.getElementById('incidentDetails');
  const actions = document.getElementById('incidentActions');
  const handoff = document.getElementById('incidentHandoff');
  const backButton = '<button type="button" class="btn btn-secondary" onclick="openIncidentList()">Back to incidents</button>';
  actions.innerHTML = backButton;
  try {
    let incident;
    if (resolvedId) {
      const {history} = await apiJson('/api/alerts');
      const alert = history.find(item => item.id === resolvedId && item.status === 'RESOLVED');
      if (!alert) throw new Error('This incident is no longer in the recorded history.');
      incident = {alert, affected: []};
    } else {
      incident = await apiJson(`/api/operations/incident?${new URLSearchParams({key})}`);
    }
    const {alert, affected, probe, deviceId, connection, lastInventoryObservation, observationSource} = incident;
    if (request !== incidentRequest || !dialog.open) return;
    title.textContent = alert.title;
    feedback.textContent = message || alert.message;
    const reply = value => value === true ? 'Reply received' : value === false ? 'No reply' : 'No reading';
    const sourceLabel = source => ({dynamic: 'ARP cache', static: 'ARP cache', icmp: 'ICMP', dhcp: 'Router DHCP'})[source] || 'LAN observation';
    const evidence = resolvedId ? [
      ['Status', 'Resolved'],
      ['Started', fmtTime(alert.firstSeen)],
      ['Resolved', fmtTime(alert.resolvedAt)],
      ['Device or target', alert.target || alert.ip || '—'],
    ] : [
      ['Started', fmtTime(alert.firstSeen)],
      ['Last check', fmtTime(probe?.lastChecked || alert.lastChecked)],
      ['ICMP', reply(probe?.icmpAlive)],
      ['TCP', probe?.tcpPortsChecked?.length
        ? `${reply(probe.tcpReachable)} on ports checked (${probe.tcpPortsChecked.join(', ')})`
        : 'No individual port results'],
      ['Observation', lastInventoryObservation
        ? `${fmtTime(lastInventoryObservation)} · ${sourceLabel(observationSource)}`
        : connection?.lastObservedAt
        ? `${fmtTime(connection.lastObservedAt)} · ${sourceLabel(connection.observationSource)} for this address`
        : 'No linked inventory observation'],
      ['Possible upstream cause', alert.upstreamIncident?.name || 'No correlated upstream alert'],
    ];
    details.innerHTML = `<dl class="device-connection-data">${evidence.map(([label, value]) =>
      `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>
      ${affected.length ? `<h3>Related alerts</h3><ul>${affected.map(item =>
        `<li><button type="button" class="btn btn-secondary btn-xs" onclick="openIncident(${inlineString(item.key)})">${esc(item.title)}</button></li>`).join('')}</ul>` : ''}
      ${alert.notes?.length ? `<h3>Incident notes</h3><ul>${alert.notes.map(note =>
        `<li>${esc(note.author)} · ${esc(note.text)}</li>`).join('')}</ul>` : ''}`;
    handoff.value = [alert.title, alert.message, ...evidence.map(pair => pair.join(' — ')),
      ...affected.map(item => `Related — ${item.title}`),
      ...(alert.notes || []).map(note => `Note — ${note.author}: ${note.text}`)].join('\n');
    actions.innerHTML = `
      ${alert.isDrill || resolvedId ? '' : `<button type="button" class="btn btn-primary" onclick="retestIncident(${inlineString(key)}, this)">Re-test</button>`}
      ${deviceId ? `<button type="button" class="btn btn-secondary" onclick="this.closest('dialog').close(); openDeviceHistory(${inlineString(deviceId)}, '')">Device History</button>` : ''}
      ${/^https?:\/\//i.test(connection?.managementUrl || '') ? `<a class="btn btn-secondary" href="${esc(connection.managementUrl)}" target="_blank" rel="noopener noreferrer">Open management page</a>` : ''}
      <button type="button" class="btn btn-secondary" onclick="copyIncidentSummary()">Copy summary</button>
      ${deviceId ? `<button type="button" class="btn btn-secondary" onclick="this.closest('dialog').close(); openOperations(${inlineString(deviceId)})">Schedule maintenance</button>` : ''}
      ${backButton}`;
    title.focus({preventScroll: true});
  } catch (error) {
    if (request === incidentRequest) feedback.textContent = message || error.message;
  }
}

async function retestIncident(key, button) {
  const request = incidentRequest;
  const feedback = document.getElementById('incidentFeedback');
  button.disabled = true;
  feedback.textContent = 'Re-testing…';
  try {
    const result = await apiJson(`/api/alerts/${encodeURIComponent(key)}/retest`, {
      method: 'POST', body: '{}'
    });
    await loadInitialState();
    if (request !== incidentRequest) return;
    if (result.resolved) {
      feedback.textContent = result.probeResult?.feedback || 'The incident has recovered.';
      button.remove();
    } else {
      await openIncident(key, result.probeResult?.feedback || 'Re-test completed.');
    }
  } catch (error) {
    if (request === incidentRequest) feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function copyIncidentSummary() {
  const handoff = document.getElementById('incidentHandoff');
  try {
    await navigator.clipboard.writeText(handoff.value);
    document.getElementById('incidentFeedback').textContent = 'Incident summary copied.';
  } catch (_) {
    handoff.hidden = false;
    handoff.select();
  }
}

function openOperations(deviceId = '') {
  const dialog = document.getElementById('operationsDialog');
  const scope = document.getElementById('maintenanceScope');
  scope.replaceChildren(new Option('All monitored equipment', ''));
  for (const device of appState.devices || []) {
    if (!device.archived) scope.add(new Option(`${device.name} · ${device.ip}`, device.id));
  }
  scope.value = deviceId;
  const local = date => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const now = new Date();
  document.getElementById('maintenanceStarts').value = local(now);
  document.getElementById('maintenanceEnds').value = local(new Date(now.getTime() + 30 * 60000));
  document.getElementById('maintenanceReason').value = '';
  document.getElementById('operationsFeedback').textContent = '';
  if (!dialog.open) dialog.showModal();
  refreshOperations();
}

async function refreshOperations() {
  try {
    const data = await apiJson('/api/operations');
    if (!document.getElementById('operationsDialog').open) return;
    const devices = new Map((appState.devices || []).map(device => [device.id, device.name]));
    renderDashboardControls(document.getElementById('maintenanceWindows'), data.maintenance.map(window => `
      <li><strong>${esc(window.reason)}</strong><p>${esc(devices.get(window.device_id) || (window.device_id ? 'Removed device' : 'All monitored equipment'))}
        · ${esc(fmtTime(window.starts_at))} to ${esc(fmtTime(window.ends_at))}</p>
        <button type="button" class="btn btn-secondary btn-xs" onclick="cancelMaintenanceWindow(${inlineString(window.id)}, this)">Cancel window</button></li>`).join('') || '<li>No windows scheduled.</li>');
    const channels = ['In-app'];
    if (data.emailEnabled) channels.push('Email');
    if (data.webhookEnabled) channels.push('Webhook');
    if (data.telegramEnabled) channels.push('Telegram');
    document.getElementById('notificationMode').textContent =
      `Active alert channels: ${channels.join(' · ')}.`;
    const ns = data.notificationSettings || {};
    const form = document.getElementById('notificationSettingsForm');
    if (form && !form.contains(document.activeElement)) {
      const enabledEl = document.getElementById('notifEnabled');
      const webhookEl = document.getElementById('notifWebhookUrl');
      const tokenEl = document.getElementById('notifTelegramToken');
      const chatEl = document.getElementById('notifTelegramChatId');
      const confirmEl = document.getElementById('notifOfflineConfirm');
      if (enabledEl) enabledEl.checked = Boolean(ns.enabled);
      if (webhookEl) webhookEl.placeholder = ns.hasWebhookUrl ? 'Configured · enter a replacement URL' : 'https://hooks.slack.com/services/...';
      if (tokenEl) tokenEl.placeholder = ns.hasTelegramToken ? 'Configured · enter a replacement token' : 'Telegram bot token';
      if (chatEl) chatEl.value = ns.telegramChatId || '';
      if (confirmEl) confirmEl.value = String(ns.offlineConfirmCount || 1);
    }
    document.getElementById('incidentNotices').innerHTML = data.notifications.map(notice => `
      <li><time>${esc(fmtTime(notice.created_at))}</time><strong>${esc(notice.title)}</strong>
        <p>${esc(notice.message)}</p><p>${esc(({in_app: 'In app', pending: 'Delivery pending', failed: 'Delivery failed', sent: 'Delivered'})[notice.delivery] || notice.delivery)}</p></li>`).join('') || '<li>No incident notifications recorded.</li>';
  } catch (error) {
    document.getElementById('operationsFeedback').textContent = error.message;
  }
}

async function saveNotificationSettings(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const feedback = document.getElementById('notifSettingsFeedback');
  if (button) button.disabled = true;
  if (feedback) feedback.textContent = 'Saving alert settings…';
  const webhook = document.getElementById('notifWebhookUrl');
  const removeWebhook = document.getElementById('notifRemoveWebhook');
  const tokenInput = document.getElementById('notifTelegramToken');
  try {
    await apiJson('/api/operations/notifications', {
      method: 'POST',
      body: JSON.stringify({
        enabled: Boolean(document.getElementById('notifEnabled')?.checked),
        webhookUrl: removeWebhook?.checked ? '' : (webhook?.value.trim() || undefined),
        telegramBotToken: (tokenInput?.value || '').trim(),
        telegramChatId: (document.getElementById('notifTelegramChatId')?.value || '').trim(),
        offlineConfirmCount: Number(document.getElementById('notifOfflineConfirm')?.value || 1)
      })
    });
    if (webhook) webhook.value = '';
    if (removeWebhook) removeWebhook.checked = false;
    if (tokenInput) tokenInput.value = '';
    if (feedback) feedback.textContent = 'Alert settings saved.';
    await refreshOperations();
  } catch (error) {
    if (feedback) feedback.textContent = error.message;
  } finally {
    if (button) button.disabled = false;
  }
}

async function testNotificationChannels(button) {
  const feedback = document.getElementById('notifSettingsFeedback');
  if (button) button.disabled = true;
  if (feedback) feedback.textContent = 'Sending test alert…';
  try {
    const res = await apiJson('/api/operations/notifications/test', {
      method: 'POST',
      body: '{}'
    });
    const summary = Object.entries(res.results || {})
      .map(([channel, status]) => `${channel}: ${status}`)
      .join(' · ');
    if (feedback) feedback.textContent = summary || res.message || 'Test completed.';
  } catch (error) {
    if (feedback) feedback.textContent = error.message;
  } finally {
    if (button) button.disabled = false;
  }
}

setInterval(() => {
  if (document.getElementById('operationsDialog')?.open && !document.hidden) refreshOperations();
}, 15000);

async function saveMaintenanceWindow(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  const feedback = document.getElementById('operationsFeedback');
  button.disabled = true;
  try {
    await apiJson('/api/operations/maintenance', {method: 'POST', body: JSON.stringify({
      deviceId: document.getElementById('maintenanceScope').value,
      startsAt: new Date(document.getElementById('maintenanceStarts').value).toISOString(),
      endsAt: new Date(document.getElementById('maintenanceEnds').value).toISOString(),
      reason: document.getElementById('maintenanceReason').value
    })});
    feedback.textContent = 'Maintenance scheduled. Device checks will continue.';
    await refreshOperations();
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function cancelMaintenanceWindow(id, button) {
  const feedback = document.getElementById('operationsFeedback');
  button.disabled = true;
  try {
    await apiJson('/api/operations/maintenance/cancel', {method: 'POST', body: JSON.stringify({id})});
    feedback.textContent = 'Maintenance window canceled.';
    await refreshOperations();
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

let switchPortsDeviceId = '';
let switchPortsRequest = 0;

async function openSwitchPorts(deviceId) {
  switchPortsDeviceId = deviceId;
  const request = ++switchPortsRequest;
  const dialog = document.getElementById('switchPortsDialog');
  const device = appState.devices?.find(item => item.id === deviceId);
  document.getElementById('switchPortsTitle').textContent = device ? `${device.name} · Switch ports` : 'Switch port health';
  document.getElementById('switchPortsForm').reset();
  document.getElementById('switchPortsForm').querySelector('button').disabled = false;
  document.getElementById('switchPortsTable').replaceChildren();
  document.getElementById('switchPortsFeedback').textContent = 'Loading latest sample…';
  if (!dialog.open) dialog.showModal();
  try {
    const data = await apiJson(`/api/operations/switch-ports?${new URLSearchParams({deviceId})}`);
    if (request === switchPortsRequest) renderSwitchPorts(data);
  } catch (error) {
    if (request === switchPortsRequest) document.getElementById('switchPortsFeedback').textContent = error.message;
  }
}

function renderSwitchPorts(sample) {
  const feedback = document.getElementById('switchPortsFeedback');
  const prefix = sample.configured ? 'Background polling configured. ' : '';
  const age = sample.sampledAt ? `Sampled ${fmtTime(sample.sampledAt)}.` : 'No sample recorded.';
  feedback.textContent = prefix + age + (sample.status === 'unavailable' ? ' Latest attempt produced no readings.' : '') +
    (sample.requestedIndices?.length > sample.ports.length ? ` ${sample.ports.length} of ${sample.requestedIndices.length} indices replied.` : '');
  const counter = (port, key) => port[key] == null ? '—' : `${port[key]}${port.change?.[key] == null ? '' : ` (+${port.change[key]})`}`;
  document.getElementById('switchPortsTable').innerHTML = sample.ports.length ? `
    <table class="device-list-table">
      <caption>Total counters. Values in parentheses are changes since the comparable sample.</caption>
      <thead><tr><th scope="col">Interface</th><th scope="col">Link</th><th scope="col">Reported Mbps</th>
        <th scope="col">RX errors</th><th scope="col">TX errors</th><th scope="col">RX drops</th><th scope="col">TX drops</th></tr></thead>
      <tbody>${sample.ports.map(port => `<tr><td>${esc(port.name)} (${esc(port.index)})</td>
        <td>${esc(port.state)}</td><td>${esc(port.speedMbps ?? '—')}</td>
        ${['inErrors', 'outErrors', 'inDrops', 'outDrops'].map(key => `<td>${esc(counter(port, key))}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>` : '';
}

async function readSwitchPorts(event) {
  event.preventDefault();
  const request = ++switchPortsRequest;
  const button = event.currentTarget.querySelector('button');
  const field = document.getElementById('switchCommunity');
  const community = field.value;
  const indices = document.getElementById('switchIndices').value.trim();
  const feedback = document.getElementById('switchPortsFeedback');
  field.value = '';
  if (!!community !== !!indices) {
    feedback.textContent = 'Enter both a read-only community and interface indices, or leave both blank for the saved profile.';
    return;
  }
  button.disabled = true;
  feedback.textContent = 'Requesting read-only SNMP measurements…';
  try {
    const sample = await apiJson('/api/operations/switch-ports', {method: 'POST', body: JSON.stringify({
      deviceId: switchPortsDeviceId, community, indices: indices ? indices.split(',').map(item => Number(item.trim())) : []
    })});
    if (request === switchPortsRequest) renderSwitchPorts(sample);
  } catch (error) {
    if (request === switchPortsRequest) feedback.textContent = error.message;
  } finally {
    if (request === switchPortsRequest) button.disabled = false;
  }
}
