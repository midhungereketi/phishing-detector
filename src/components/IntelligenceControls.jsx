import { useState } from 'react';
import { api, send, formatDate } from '../api';
import { useResource } from '../hooks';

export default function IntelligenceControls() {
  const feed = useResource('/intelligence');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState('');
  async function run(action) {
    setBusy(true); setMessage('');
    try {
      if (action === 'refresh') { await send('/intelligence/refresh', {}); setMessage('Threat feed refreshed.'); await feed.refresh(); }
      if (action === 'pair') { const result = await send('/extension/pair', {}); setToken(result.token); setMessage(`Pairing token created. Expires in ${result.expires_in_days} days.`); }
      if (action === 'revoke') { await api('/extension/pair', { method: 'DELETE' }); setToken(''); setMessage('All your extension tokens were revoked. Disconnect the extension to remove already-synced browser rules.'); }
    } catch (error) { setMessage(error.message); if (action === 'refresh') await feed.refresh(); }
    finally { setBusy(false); }
  }
  return <><section className="card"><div className="eyebrow">KNOWN THREATS</div><h2>Phishing intelligence cache</h2><p>Exact URL matches are checked locally on every scan. A feed match adds an explicit policy warning; a missing entry never proves safety.</p>{feed.data && <dl className="metadata"><dt>Feed</dt><dd>{feed.data.source} · {feed.data.status.replaceAll('_', ' ')}</dd><dt>Verified entries</dt><dd>{feed.data.entries.toLocaleString()}</dd><dt>Updated</dt><dd>{feed.data.updated_at ? formatDate(feed.data.updated_at) : 'Not loaded'}</dd><dt>VirusTotal</dt><dd>{feed.data.virustotal_configured ? 'Server API key configured' : 'Optional server API key not configured'}</dd></dl>}{feed.data?.last_refresh_error && <div className="notice warning">{feed.data.last_refresh_error}</div>}<button className="secondary-btn" disabled={busy} onClick={() => run('refresh')}>Refresh PhishTank feed</button><p className="small">Refresh contacts PhishTank; limited to once per hour. Provider access may require an application key. Existing cached data is retained on failure.</p>{feed.error && <div className="notice error">{feed.error}</div>}</section>
    <section className="card extension-card"><div className="eyebrow">BROWSER PREVENTION</div><h2>Take PhishGuard into your browser</h2><p>The Chrome / Edge extension checks ordinary clicked links with your local backend and blocks synced personal hosts before navigation.</p><ol className="setup-steps"><li><a className="text-link" href="/api/extension/download">Download the extension ZIP</a>, unzip it, and use “Load unpacked” in your browser’s Extensions page with Developer mode enabled.</li><li>Generate a pairing token below and paste it into the extension popup.</li><li>Pair and sync your blocklist. Keep the local backend running for new ML checks.</li></ol><p className="small">If your browser requires extension CORS access, add its ID to the server configuration as described in the included README. Tokens expire after 30 days and only allow URL checks and blocklist reads.</p><div className="button-row"><button className="primary-btn" disabled={busy} onClick={() => run('pair')}>Generate pairing token</button><button className="secondary-btn" disabled={busy} onClick={() => run('revoke')}>Revoke all extension tokens</button></div>{token && <div className="pairing-token"><label htmlFor="pairing-token">Copy this token into the extension. Treat it like a password.</label><input id="pairing-token" readOnly value={token} onFocus={event => event.target.select()} /><button className="text-btn" onClick={() => setToken('')}>Hide token</button></div>}<p className="small">New ML checks cover link clicks, not all address-bar, form or scripted navigation. Synced exact-host blocks cover navigation and remain available offline. Up to 1,000 hosts; sync every minute. You can pause or disconnect the extension.</p></section>{message && <div className="notice" role="status">{message}</div>}</>;
}
