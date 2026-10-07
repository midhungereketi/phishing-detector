import { formatDate } from '../api';

function Status({ value }) { return <span className={`evidence-status ${['match', 'invalid', 'refused'].includes(value) ? 'warning' : ''}`}>{String(value || 'unknown').replaceAll('_', ' ')}</span>; }

export default function EvidencePanel({ report }) {
  const intel = report.intelligence;
  const network = report.network;
  const registration = report.registration;
  const reputation = report.reputation;
  if (!intel && !network) return null;
  return <div className="evidence-panel"><div className="eyebrow">EVIDENCE LAYERS / {report.host}</div><div className="evidence-grid">
    <section><div className="section-heading"><h3>Known phishing feed</h3><Status value={intel?.status} /></div><p>{intel?.message}</p>{intel?.updated_at && <p className="small">{intel.source} · {intel.cache_status} cache · {formatDate(intel.updated_at)}</p>}{intel?.phish_id && <p className="small">Feed entry #{intel.phish_id}</p>}</section>
    <section><div className="section-heading"><h3>DNS, TLS & redirects</h3><Status value={network?.status} /></div><p>{network?.message || network?.tls?.message}</p>{network?.chain && <><p className="small">{network.chain[0]?.addresses.join(', ')} · {network.chain.length - 1} redirects followed</p><ol className="redirect-chain">{network.chain.map(hop => <li key={hop.url}><code>{hop.status} · {hop.url}</code></li>)}</ol></>}{network?.tls?.issuer && <p className="small">Issuer: {network.tls.issuer}<br />Expires: {network.tls.expires_at}</p>}</section>
    <section><div className="section-heading"><h3>Domain registration</h3><Status value={registration?.status} /></div><p>{registration?.message || (registration?.age_days != null ? `${registration.domain} was registered ${registration.age_days.toLocaleString()} days ago.` : 'Registration lookup was not requested.')}</p>{registration?.registered_at && <p className="small">Registered: {formatDate(registration.registered_at)} · {registration.source}</p>}</section>
    <section><div className="section-heading"><h3>VirusTotal reputation</h3><Status value={reputation?.status} /></div><p>{reputation?.message || 'External reputation lookup was not requested.'}</p>{reputation?.counts && <><div className="reputation-counts">{Object.entries(reputation.counts).map(([label, count]) => <span key={label}><strong>{count}</strong>{label}</span>)}</div><p className="small">{reputation.analyzed_at ? formatDate(reputation.analyzed_at) : 'Date unknown'} · {reputation.fresh ? 'Within 7 days' : 'Older or undated; excluded from score policy'}{reputation.cached ? ' · cached' : ''}</p></>}</section>
  </div><p className="small">Observations are separate from the ML estimate. Missing checks and feed misses do not establish safety. Registration age and valid TLS alone do not prove legitimacy.</p></div>;
}
