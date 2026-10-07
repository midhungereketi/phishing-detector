const get = id => document.getElementById(id);
async function status() {
  const state = await chrome.storage.local.get(['token', 'enabled', 'username', 'hosts', 'syncError']);
  get('enabled').checked = state.enabled !== false;
  get('status').textContent = state.token ? `Paired${state.username ? ` as ${state.username}` : ''}. ${state.hosts || 0} blocked hosts synced.${state.syncError ? ` ${state.syncError}` : ''}` : 'Not paired. Generate a token in the app’s Protection page.';
}
async function action(message) {
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage(message);
    if (result.error) throw new Error(result.error);
    get('result').textContent = result.risk_level ? `${result.risk_level} risk · ${result.score}/100 · ${result.action}` : 'Done.';
    get('token').value = '';
  } catch (error) { get('result').textContent = error.message; }
  finally { await status(); for (const button of document.querySelectorAll('button')) button.disabled = false; }
}
get('pair').onclick = () => action({ action: 'pair', token: get('token').value });
get('sync').onclick = () => action({ action: 'sync' });
get('disconnect').onclick = () => action({ action: 'disconnect' });
get('enabled').onchange = () => action({ action: 'toggle', enabled: get('enabled').checked });
get('scan').onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url?.startsWith('http')) { get('result').textContent = 'Open a normal web page to check it.'; return; }
  await action({ action: 'check', url: tab.url });
};
status();
