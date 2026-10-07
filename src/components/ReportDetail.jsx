import { useState } from 'react';
import { send, formatDate } from '../api';
import { downloadJSON, downloadPDF } from '../utils/report';
import EvidencePanel from './EvidencePanel';

export function RiskBadge({ level }) {
  return <span className={`risk-badge ${level.toLowerCase()}`}><i />{level} risk</span>;
}

export default function ReportDetail({ report }) {
  const [feedback, setFeedback] = useState('');
  const [busy, setBusy] = useState(false);
  async function exportPDF() {
    setBusy(true);
    try { await downloadPDF(report); }
    catch (err) { setFeedback(`Could not export the PDF: ${err.message}`); }
    finally { setBusy(false); }
  }
  async function block(host) {
    setBusy(true);
    try { await send('/blocklist', { host }); setFeedback(`${host} added to your in-app blocklist.`); }
    catch (err) { setFeedback(err.message); }
    finally { setBusy(false); }
  }
  async function openTarget(url) {
    setBusy(true);
    try {
      const result = await send('/link-access', { url });
      if (!result.allowed) { setFeedback(result.reason); return; }
      if (window.confirm('Low risk does not guarantee safety. Open this URL in a new tab?')) window.open(result.url, '_blank', 'noopener,noreferrer');
    } catch (err) { setFeedback(err.message); }
    finally { setBusy(false); }
  }
  const candidates = report.kind === 'url' ? [report] : report.links;
  return <section className="card report-detail" aria-label="Analysis report">
    <div className="section-heading"><div><div className="eyebrow">ANALYSIS COMPLETE / #{report.id}</div><h2>{report.kind === 'url' ? 'URL security report' : 'Email security report'}</h2></div><RiskBadge level={report.risk_level} /></div>
    <div className="report-top"><div className={`score-circle ${report.risk_level.toLowerCase()}`}><strong>{Math.round(report.score)}</strong><span>RISK / 100</span></div><div><p className="report-target">{report.url || report.subject || '(no subject)'}</p><h3>{report.action}</h3><p className="small">{formatDate(report.created_at)} · {report.model_version}</p><p className="small">{report.score_method}. Primary model estimate: {report.model_score}/100.</p></div></div>
    <div className="report-columns"><div><h3>Observed warning signs</h3><ul className="signal-list">{(report.signals.length ? report.signals : ['No structural warnings found. A low score does not prove a target is legitimate.']).map(signal => <li key={signal}>{signal}</li>)}</ul></div><div className="recommendation"><div className="eyebrow">NEXT STEPS</div><h3>{report.risk_level === 'High' ? 'Pause. Verify independently.' : 'Check the sender and destination.'}</h3><p>Use a known bookmark or type the organization’s address yourself. Never share a password, OTP, or payment details through an unexpected message.</p>{report.blocked_hosts.length > 0 && <p className="danger-text">Blocked hosts: {report.blocked_hosts.join(', ')}</p>}</div></div>
    {report.policy_reasons?.length > 0 && <div className="notice warning"><strong>Policy evidence</strong><ul>{report.policy_reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul></div>}
    {report.kind === 'url' && <EvidencePanel report={report} />}
    {report.explanation?.length > 0 && <details open><summary>Why the URL model reacted</summary><p className="small">{report.explanation_method}</p><div className="sensitivity-list">{report.explanation.map(item => <div key={item.feature}><span>{item.feature.replaceAll('_', ' ')} <small>{item.observed} → {item.baseline}</small></span><strong className={item.score_change > 0 ? 'danger-text' : ''}>{item.score_change > 0 ? '+' : ''}{item.score_change} points</strong></div>)}</div><p className="small">Positive values mean the observed feature raised the prediction relative to its synthetic baseline.</p></details>}
    {report.redirects?.length > 0 && <details><summary>Redirect destination models</summary>{report.redirects.map(link => <div key={link.url}><p className="small">{link.url} · ML {link.model_score}/100</p><EvidencePanel report={link} /></div>)}</details>}
    {report.kind === 'email' && <>
      <details open><summary>Email headers & metadata</summary><dl className="metadata"><dt>From</dt><dd>{report.sender || 'Missing'}</dd><dt>Reply-To</dt><dd>{report.reply_to || 'Missing'}</dd><dt>Authentication-Results</dt><dd>{report.authentication_results || 'Unknown / header missing'}<p className="small">Pasted headers are unverified. No SPF, DKIM or DMARC validation was performed.</p></dd><dt>Attachments</dt><dd>{report.attachments.join(', ') || 'None'} <span className="small">(not opened)</span></dd></dl></details>
      {report.influential_terms.length > 0 && <div className="token-section"><h3>Text terms contributing toward phishing</h3><div className="chips">{report.influential_terms.map(item => <span key={item.term} title={`Signed contribution to model log odds: ${item.contribution}`}>{item.term}</span>)}</div><p className="small">Positive TF-IDF contributions from the email model; individual words are not proof of phishing.</p></div>}
    </>}
    {candidates.length > 0 && <div><h3>{report.kind === 'email' ? 'Embedded URLs' : 'Destination controls'}</h3><div className="link-list">{candidates.map(link => <div key={link.url} className="link-row"><div><code>{link.url}</code><span className="small">Host: {link.host} · URL ML estimate: {link.model_score}/100</span></div><div className="button-row"><button className="secondary-btn small-btn" disabled={busy} onClick={() => block(link.host)}>Block host</button><button className="secondary-btn small-btn" disabled={busy || link.model_score >= 30 || report.blocked_hosts.includes(link.host)} onClick={() => openTarget(link.url)}>Check & open ↗</button></div></div>)}</div><p className="small">Medium/high risk links cannot be opened from this app. Low risk links are checked again against your current blocklist before opening.</p></div>}
    {report.links_truncated && <div className="notice warning">Only the first 20 distinct links were analyzed. Inspect the remaining links separately.</div>}
    {report.kind === 'email' && candidates.some(link => link.intelligence) && <details><summary>Embedded link threat evidence</summary>{candidates.map(link => <EvidencePanel key={link.url} report={link} />)}</details>}
    <details><summary>Extracted features ({Object.keys(report.features).length})</summary><div className="feature-grid">{Object.entries(report.features).map(([key, value]) => <div key={key}><span>{key.replaceAll('_', ' ')}</span><code>{Number.isInteger(value) ? value : Number(value).toFixed(3)}</code></div>)}</div><p className="small">Observed features and warning rules are separate from the learned model prediction.</p></details>
    {feedback && <div className="notice" role="status">{feedback}</div>}
    <div className="report-actions"><button className="primary-btn" disabled={busy} onClick={exportPDF}>↓ Download PDF</button><button className="secondary-btn" onClick={() => downloadJSON(report)}>Export JSON</button><span className="small">Full report · locally generated</span></div>
  </section>;
}
