const $ = (id) => document.getElementById(id);

function setMessage(text, isError = false) {
  const el = $('message');
  el.textContent = text;
  el.classList.toggle('error', isError);
}

async function send(message) {
  return chrome.runtime.sendMessage(message);
}

async function refresh() {
  const res = await send({ type: 'status' });
  if (!res || !res.ok) {
    setMessage('Could not read sensor status.', true);
    return;
  }
  const stats = res.stats || {};
  $('pairing').textContent = stats.paired === false
    ? 'Not paired — is the OshoosiClaw agent running?'
    : (res.pairedAt ? `Paired automatically (${new Date(res.pairedAt).toLocaleString()})` : 'Pairing on first capture');
  $('browser').textContent = `${res.browser?.name || 'browser'} ${res.browser?.version || ''}`.trim();
  $('daemon').textContent = res.daemonUrl;
  $('forwarded').textContent = String(stats.forwarded || 0);
  $('detections').textContent = String(stats.detections || 0);
  $('pending').textContent = String(res.pending || 0);
  const last = stats.lastDetection;
  $('last-detection').textContent = last
    ? `${new Date(last.at).toLocaleString()} — ${last.decision} → ${last.url} [${(last.categories || []).join(', ')}]`
    : 'None';
  $('last-error').textContent = stats.lastError || 'None';
  if (!$('daemon-url').value) $('daemon-url').value = res.daemonUrl;
}

$('repair').addEventListener('click', async () => {
  setMessage('Pairing…');
  const res = await send({ type: 'repair' });
  setMessage(res && res.ok ? 'Paired with the local agent.' : `Pairing failed: ${res?.error || 'unknown error'}`, !(res && res.ok));
  await refresh();
});

$('reset').addEventListener('click', async () => {
  await send({ type: 'resetDetections' });
  setMessage('Detection counter cleared.');
  await refresh();
});

$('daemon-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const res = await send({ type: 'setDaemonUrl', daemonUrl: $('daemon-url').value });
  setMessage(res && res.ok ? `Saved ${res.daemonUrl}. The sensor will re-pair automatically.` : `Rejected: ${res?.error || 'invalid address'}`, !(res && res.ok));
  await refresh();
});

chrome.storage.onChanged.addListener(() => {
  refresh().catch(() => {});
});

refresh().catch((err) => setMessage(String(err), true));
