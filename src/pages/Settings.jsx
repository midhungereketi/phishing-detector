import { useState } from 'react';
import { send } from '../api';
import { useResource } from '../hooks';

function SettingsForm({ initial }) {
  const [values, setValues] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  async function save(event) {
    event.preventDefault(); setBusy(true);
    try { await send('/settings', values, 'PUT'); setMessage('Protection settings saved. They apply to your next scan and link access check.'); }
    catch (err) { setMessage(err.message); }
    finally { setBusy(false); }
  }
  return <form onSubmit={save} className="card settings-card"><h2>Detection preferences</h2><label htmlFor="threshold">High risk threshold <strong>{values.high_threshold}/100</strong></label><input id="threshold" type="range" min="50" max="95" value={values.high_threshold} onChange={e => setValues({ ...values, high_threshold: Number(e.target.value) })} /><p className="small">Lower thresholds generate more alerts. Medium risk begins at 30. Model estimates are calibrated on held-out corpus data. The combined policy score is not a safety probability.</p>
    {[['auto_block', 'Automatically block high risk URL hosts', 'Adds URL hosts exceeding your threshold to your personal in-app blocklist. Review possible false positives under Protection.'], ['show_alerts', 'Show in-app risk alerts', 'Show a prominent alert after medium/high risk scans. Reports always include the risk level.']].map(([key, label, note]) => <label className="setting-row" key={key}><div><strong>{label}</strong><p className="small">{note}</p></div><input type="checkbox" checked={values[key]} onChange={e => setValues({ ...values, [key]: e.target.checked })} /></label>)}
    {message && <div className="notice" role="status">{message}</div>}<button className="primary-btn" disabled={busy}>{busy ? 'Saving…' : 'Save preferences'}</button><p className="small">Settings are saved to your account in SQLite.</p>
  </form>;
}

export default function Settings() {
  const resource = useResource('/settings');
  return <><div className="page-heading"><div><div className="eyebrow">MAKE IT YOURS</div><h1>Protection settings<span className="heading-dot">.</span></h1><p>Choose when to warn and what to remember.</p></div></div>{resource.error && <div className="notice error">{resource.error}</div>}{resource.loading ? <p>Loading preferences…</p> : resource.data && <SettingsForm initial={resource.data} />}</>;
}
