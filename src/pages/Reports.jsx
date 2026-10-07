import { useState } from 'react';
import { api, formatDate } from '../api';
import { useResource } from '../hooks';
import ReportDetail, { RiskBadge } from '../components/ReportDetail';

export default function Reports() {
  const history = useResource('/history');
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('All');
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const rows = (history.data || []).filter(row => (filter === 'All' || row.risk_level === filter) && (row.url || row.subject || '').toLowerCase().includes(query.toLowerCase()));
  async function clear() {
    if (!window.confirm('Permanently delete your saved scan reports?')) return;
    setBusy(true);
    try { await api('/history', { method: 'DELETE' }); setSelected(null); await history.refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <><div className="page-heading"><div><div className="eyebrow">YOUR AUDIT TRAIL</div><h1>Scan reports<span className="heading-dot">.</span></h1><p>Review findings and export detailed security reports.</p></div><button className="secondary-btn" disabled={busy || !history.data?.length} onClick={clear}>Clear my history</button></div>
    {(error || history.error) && <div className="notice error" role="alert">{error || history.error}</div>}
    <section className="card"><div className="report-filters"><input aria-label="Search report targets" placeholder="Search a URL or subject…" value={query} onChange={e => setQuery(e.target.value)} /><select aria-label="Filter by risk" value={filter} onChange={e => setFilter(e.target.value)}>{['All', 'Low', 'Medium', 'High'].map(value => <option key={value}>{value}</option>)}</select></div>
      {history.loading ? <p>Loading reports…</p> : !rows.length ? <div className="empty-state">No matching reports. Run a scan in the detection center.</div> : <div className="table-responsive"><table><thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Score</th><th>Analyzed</th><th /></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td className="target-cell">{row.url || row.subject || '(no subject)'}</td><td>{row.kind.toUpperCase()}</td><td><RiskBadge level={row.risk_level} /></td><td>{row.score}/100</td><td className="small">{formatDate(row.created_at)}</td><td><button className="text-btn" onClick={() => setSelected(row)}>View →</button></td></tr>)}</tbody></table></div>}<p className="small">Latest 200 reports, visible only to your account. Raw email bodies are not retained.</p>
    </section>{selected && <ReportDetail key={selected.id} report={selected} />}</>;
}
