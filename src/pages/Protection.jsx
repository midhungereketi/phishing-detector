import { useState } from 'react';
import { api, send, formatDate } from '../api';
import { useResource } from '../hooks';
import IntelligenceControls from '../components/IntelligenceControls';

export default function Protection() {
  const blocked = useResource('/blocklist');
  const [host, setHost] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function add(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { await send('/blocklist', { host }); setHost(''); await blocked.refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function remove(value) {
    setBusy(true);
    try { await api(`/blocklist/${encodeURIComponent(value)}`, { method: 'DELETE' }); await blocked.refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <><div className="page-heading"><div><div className="eyebrow">PREVENTION CONTROLS</div><h1>Pause the risky click<span className="heading-dot">.</span></h1><p>Your personal list of destinations to avoid.</p></div></div><div className="notice">Blocking applies to PhishGuard’s link-opening controls. Install and pair the browser extension below to add link-click checks and synced browser blocks. Email-inbox filtering is not included.</div>
    <section className="card"><h2>Blocked hosts</h2><p>Exact host matching. Blocking <code>example.com</code> does not automatically block its subdomains.</p><form className="inline-form" onSubmit={add}><input aria-label="Host to block" required maxLength={253} value={host} onChange={e => setHost(e.target.value)} placeholder="suspicious.example.com" /><button className="primary-btn" disabled={busy}>Add host</button></form>{(error || blocked.error) && <div className="notice error" role="alert">{error || blocked.error}</div>}
      {blocked.loading ? <p>Loading blocklist…</p> : blocked.data?.length ? <div className="link-list">{blocked.data.map(item => <div key={item.host} className="link-row"><div><code>{item.host}</code><span className="small">Added {formatDate(item.created_at)}</span></div><button className="secondary-btn small-btn" disabled={busy} onClick={() => remove(item.host)}>Remove</button></div>)}</div> : <div className="empty-state">No blocked hosts yet. Add one here or from a scan report.</div>}
    </section><section className="card"><h2>How prevention works</h2><div className="workflow-strip"><div><span>01</span><strong>Warn immediately</strong><p>Medium/high risk scans show an in-app alert.</p></div><div><span>02</span><strong>Gate link opening</strong><p>Only low risk targets can pass the server’s access check.</p></div><div><span>03</span><strong>Remember blocked hosts</strong><p>A blocked host is denied even when the model score is low.</p></div></div><p className="small">Optional automatic blocking can be enabled in Settings. False positives can be reviewed and removed here.</p></section><IntelligenceControls /></>;
}
