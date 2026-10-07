const API = 'http://127.0.0.1:8000/api';
let syncQueue = Promise.resolve();

async function configureStorage() {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}
configureStorage().catch(() => {});

async function call(path, body) {
  const { token } = await chrome.storage.local.get('token');
  if (!token) throw new Error('Pair the extension from PhishGuard’s Protection page first.');
  const response = await fetch(API + path, {
    method: body ? 'POST' : 'GET', credentials: 'omit',
    headers: { 'Content-Type': 'application/json', 'X-PhishGuard': '1', Authorization: `Bearer ${token}` },
    ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(8000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'The local API rejected this check.');
  return result;
}

async function syncRules() {
  const { enabled = true, token } = await chrome.storage.local.get(['enabled', 'token']);
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  if (!enabled || !token) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(rule => rule.id) });
    return;
  }
  const result = await call('/extension/blocklist');
  const hosts = result.hosts.slice(0, 1000);
  const rules = hosts.map((host, index) => {
    const authority = host.includes(':') ? `[${host}]` : host;
    const escaped = authority.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return { id: index + 1, priority: 1, action: { type: 'block' }, condition: { regexFilter: `^https?://${escaped}(:[0-9]+)?/`, resourceTypes: ['main_frame', 'sub_frame'] } };
  });
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(rule => rule.id), addRules: rules });
  await chrome.storage.local.set({ lastSync: Date.now(), hosts: hosts.length, username: result.username, syncError: result.hosts.length > 1000 ? 'Only the first 1000 hosts were synced.' : '' });
}

function queueSync() {
  syncQueue = syncQueue.catch(() => {}).then(syncRules).catch(async error => {
    await chrome.storage.local.set({ syncError: error.message });
    throw error;
  });
  return syncQueue;
}

chrome.runtime.onInstalled.addListener(() => {
  configureStorage();
  chrome.alarms.create('sync', { periodInMinutes: 1 });
});
chrome.runtime.onStartup.addListener(() => {
  configureStorage();
  chrome.alarms.create('sync', { periodInMinutes: 1 });
  queueSync().catch(() => {});
});
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'sync') queueSync().catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  const trusted = sender.url === chrome.runtime.getURL('popup.html');
  (async () => {
    if (message.action === 'check') {
      const { enabled = true } = await chrome.storage.local.get('enabled');
      if (!enabled) return { disabled: true };
      const url = new URL(message.url);
      if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only web links can be checked.');
      return call('/extension/check', { url: url.href });
    }
    if (!trusted) throw new Error('This action is restricted to the extension popup.');
    if (message.action === 'pair') {
      if (typeof message.token !== 'string' || message.token.length < 20 || message.token.length > 200) throw new Error('Enter a valid pairing token.');
      await configureStorage();
      await chrome.storage.local.set({ token: message.token.trim(), enabled: true });
      await queueSync();
      return { ok: true };
    }
    if (message.action === 'toggle') {
      await chrome.storage.local.set({ enabled: Boolean(message.enabled) });
      await queueSync();
      return { ok: true };
    }
    if (message.action === 'sync') { await queueSync(); return { ok: true }; }
    if (message.action === 'disconnect') {
      await chrome.storage.local.remove(['token', 'username', 'hosts', 'lastSync']);
      await queueSync();
      return { ok: true };
    }
    throw new Error('Unknown extension action');
  })().then(reply).catch(error => reply({ error: error.message || 'Local backend unavailable. The link was not checked.' }));
  return true;
});
