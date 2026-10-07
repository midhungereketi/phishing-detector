import { useState } from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { api, send, formatDate } from '../api';
import { useResource } from '../hooks';
import ReportDetail, { RiskBadge } from './ReportDetail';
import { AnimatedNumber, Icon, ScanActivity, SecurityPipeline } from './CyberVisuals';

ChartJS.register(ArcElement, Tooltip, Legend);
ChartJS.defaults.animation = false;
const sampleEmail = `From: Account Security <security@account-check.example>
Reply-To: recovery@support-verification.example
Subject: Action required: verify your account within 24 hours
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Authentication-Results: example.local; spf=fail; dkim=fail; dmarc=fail

<p>Your account will be suspended. Confirm your password immediately.</p>
<a href="http://192.0.2.15/verify/account">https://bank.example/login</a>`;
const benignEmail = `From: Project Team <team@college.example>
Reply-To: team@college.example
Subject: Computer Networks presentation schedule
Content-Type: text/plain; charset=utf-8

Hi team, our project presentation is scheduled for Friday. Please bring the report and slides. We will meet in the lab at 10 AM. Thanks!`;

export default function Scanner() {
  const [kind, setKind] = useState('url');
  const [url, setUrl] = useState('');
  const [raw, setRaw] = useState('');
  const [emailFile, setEmailFile] = useState(null);
  const [networkChecks, setNetworkChecks] = useState(false);
  const [reputationCheck, setReputationCheck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const history = useResource('/history');
  const models = useResource('/models');
  const settings = useResource('/settings');
  const intelligence = useResource('/intelligence');
  const entries = history.data || [];
  const counts = ['Low', 'Medium', 'High'].map(level => entries.filter(item => item.risk_level === level).length);
  function viewReport(entry) {
    setResult(entry);
    requestAnimationFrame(() => document.querySelector('.report-detail')?.scrollIntoView({
      behavior: document.documentElement.dataset.motion === 'off' || window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',
      block: 'start',
    }));
  }
  async function scan(event) {
    event.preventDefault(); setBusy(true); setError(''); setResult(null);
    try { setResult(kind === 'email' && emailFile ? await api('/scan/email-file', { method: 'POST', body: emailFile, headers: { 'Content-Type': 'message/rfc822' } }) : await send(`/scan/${kind}`, kind === 'url' ? { url, network_checks: networkChecks, reputation_check: reputationCheck } : { raw })); await history.refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function upload(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 300000) { setError('Choose an .eml or text file under 300 KB.'); return; }
    if (!/\.(eml|txt)$/i.test(file.name)) { setError('Choose an .eml or .txt file.'); return; }
    try { setRaw(await file.text()); setEmailFile(file); setError(''); }
    catch { setError('Could not read that email file.'); }
    event.target.value = '';
  }
  return <>
    <section className="detection-hero"><div className="hero-copy"><div className="eyebrow">THREAT ANALYSIS WORKSPACE</div><h1>Detection center<span className="heading-dot">.</span></h1><p className="hero-lead">A clearer view of every threat.</p><p className="hero-description">Analyze URLs and emails. Follow the evidence. Decide with confidence.</p><div className="hero-status"><span className={`engine-badge ${models.data?.ready ? 'ready' : ''}`}>{models.loading ? 'Checking models…' : models.data?.ready ? '● ML engine ready' : '○ Models unavailable'}</span><span className="hero-status-note">LOCAL INFERENCE · TWO TRAINED MODELS</span></div></div><div className="hero-visual"><SecurityPipeline /><div className="hero-visual-caption"><span>DETECTION PIPELINE</span><span>FEATURES → CLASSIFICATION → REVIEW</span></div></div></section>
    <div className="stats-grid">{[['Recent scans', entries.length, 'neutral', 'activity', 'Your latest 200 analyses'], ['Low risk', counts[0], 'low', 'shield', 'No strong signal detected'], ['Needs review', counts[1], 'medium', 'search', 'Inspect before interacting'], ['High risk', counts[2], 'high', 'warning', 'Verify independently']].map(([label, value, color, icon, note]) => <div className={`stat-card ${color}`} key={label}><div className="stat-heading"><span>{label}</span><Icon name={icon} size={18} /></div><strong><AnimatedNumber value={value} /></strong><div className="stat-bottom"><span>{note}</span><div className="stat-line" /></div></div>)}</div>
    {(history.error || models.error) && <div className="notice error" role="alert">{history.error || models.error}</div>}
    {models.data && !models.data.ready && <div className="notice warning">Train the models with <code>python -m backend.train --download</code>, then restart the API.</div>}
    <div className="scanner-grid"><section className={`card scan-card ${busy ? 'is-scanning' : ''}`}><div className="section-heading"><div><div className="eyebrow">NEW ANALYSIS</div><h2>What looks suspicious?</h2></div><span className="scanner-heading-icon"><Icon name="scan" size={25} /></span></div><div className={`tabs ${kind === 'email' ? 'email-selected' : ''}`} role="tablist" aria-label="Scan type"><span className="tab-slider" aria-hidden="true" /><button id="url-tab" role="tab" disabled={busy} aria-selected={kind === 'url'} aria-controls="scan-panel" className={kind === 'url' ? 'selected' : ''} onClick={() => { setKind('url'); setError(''); }}><Icon name="link" size={16} />URL scanner</button><button id="email-tab" role="tab" disabled={busy} aria-selected={kind === 'email'} aria-controls="scan-panel" className={kind === 'email' ? 'selected' : ''} onClick={() => { setKind('email'); setError(''); }}><Icon name="mail" size={16} />Email scanner</button></div>
      <form onSubmit={scan} id="scan-panel" role="tabpanel" aria-labelledby={`${kind}-tab`} className="scan-panel-enter" key={kind}>
        {kind === 'url' ? <><label htmlFor="target-url">Website address</label><input id="target-url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/sign-in" maxLength={4096} required disabled={busy} /><p className="small">HTTP/HTTPS URLs only. A missing scheme defaults to HTTPS.</p><div className="sample-row"><span>Try a sample</span><button type="button" disabled={busy} onClick={() => setUrl('https://www.wikipedia.org/')}>Ordinary URL</button><button type="button" disabled={busy} onClick={() => setUrl('http://192.0.2.15/verify/account?login=confirm')}>Suspicious pattern</button></div></> : <><label htmlFor="raw-email">Email source or message text</label><textarea id="raw-email" value={raw} onChange={e => { setRaw(e.target.value); setEmailFile(null); }} placeholder={'From: sender@example.com\nSubject: Your message\n\nPaste the email body here…'} required maxLength={300000} rows={10} disabled={busy} /><p className="small">Paste raw headers + body to analyze metadata, or paste just the message. HTML and attachments are never executed.</p><div className="sample-row"><label className="upload-btn">↑ Import .eml<input type="file" accept=".eml,.txt,message/rfc822,text/plain" disabled={busy} onChange={upload} /></label><button type="button" disabled={busy} onClick={() => { setRaw(sampleEmail); setEmailFile(null); }}>Suspicious sample</button><button type="button" disabled={busy} onClick={() => { setRaw(benignEmail); setEmailFile(null); }}>Ordinary sample</button></div></>}
        {kind === 'url' && <fieldset className="scan-options" disabled={busy}><legend>Additional evidence</legend><label><input type="checkbox" checked={networkChecks} onChange={e => setNetworkChecks(e.target.checked)} />Live DNS, TLS, redirects & domain age</label><p className="small">Contacts the target with HEAD requests and queries RDAP. Public destinations only; no cookies or page rendering.</p><label><input type="checkbox" checked={reputationCheck} disabled={!intelligence.data?.virustotal_configured} onChange={e => setReputationCheck(e.target.checked)} />VirusTotal reputation lookup</label><p className="small">{intelligence.data?.virustotal_configured ? 'Sends this URL, including its query, to VirusTotal to retrieve an existing report.' : 'Optional server API key required. Local ML and feed checks remain available.'}</p></fieldset>}{kind === 'email' && emailFile && <div className="notice" role="status">Ready to analyze: {emailFile.name} · original bytes preserved for MIME decoding.<button type="button" className="text-btn" onClick={() => setEmailFile(null)}>Use pasted text instead</button></div>}{error && <div className="notice error" role="alert">{error}</div>}
        {busy && <ScanActivity />}
        <button className="primary-btn scan-submit" disabled={busy || !models.data?.ready}>{busy ? 'Analyzing with the trained model…' : `Analyze ${kind === 'url' ? 'URL' : 'email'} →`}</button>
      </form><div className="scan-privacy"><span>◇</span> Processed by your local API. Local ML + cached feed checks. Network contact only when you enable additional checks.</div>
    </section><aside className="card insight-card"><div className="eyebrow">WORKSPACE SNAPSHOT</div><div className="section-heading"><h2>Risk distribution</h2><Icon name="activity" size={19} /></div>{entries.length ? <><div className="chart-wrapper"><Doughnut aria-label={`Risk distribution: ${counts[0]} low, ${counts[1]} medium, ${counts[2]} high risk scans`} role="img" data={{ labels: ['Low', 'Medium', 'High'], datasets: [{ data: counts, backgroundColor: ['#159974', '#e6a329', '#df5266'], borderColor: '#ffffff', borderWidth: 5, borderRadius: 5, spacing: 3 }] }} options={{ cutout: '78%', plugins: { legend: { display: false }, tooltip: { backgroundColor: '#142137', titleColor: '#ffffff', bodyColor: '#e2e8f0', padding: 12 } } }} /><div className="chart-center"><strong><AnimatedNumber value={entries.length} /></strong><span>ANALYSES</span></div></div><div className="chart-legend">{['Low', 'Medium', 'High'].map((level, index) => <div key={level} className={level.toLowerCase()}><span><i />{level} risk</span><strong>{counts[index]}</strong></div>)}</div></> : <div className="empty-chart"><div className="empty-radar"><i /><Icon name="shield" size={30} /></div><strong>Your first scan starts here</strong><p>Completed scans will appear in this chart.</p></div>}<div className="insight-note"><span>VERIFY BEFORE YOU TRUST</span><p>Risk scores support your judgment.<br />Always verify before sharing sensitive data.</p></div></aside></div>
    {result && <>{settings.data?.show_alerts && result.risk_level !== 'Low' && <div className={`notice ${result.risk_level === 'High' ? 'error' : 'warning'}`} role="alert">{result.risk_level} risk detected. {result.action}.</div>}<ReportDetail key={result.id} report={result} /></>}
    <section className="card recent-activity"><div className="section-heading"><div><div className="eyebrow">YOUR RECENT ACTIVITY</div><h2>Recent analyses</h2></div><span className="activity-count">{entries.length} saved</span></div>{history.loading ? <div className="activity-skeleton" aria-label="Loading recent activity" /> : entries.length ? <div className="recent-list">{entries.slice(0, 3).map(entry => <button className="recent-row" key={entry.id} onClick={() => viewReport(entry)}><span className="recent-type"><Icon name={entry.kind === 'url' ? 'link' : 'mail'} size={18} /></span><span className="recent-target"><strong>{entry.url || entry.subject || '(no subject)'}</strong><span>{entry.kind.toUpperCase()} ANALYSIS · {formatDate(entry.created_at)}</span></span><RiskBadge level={entry.risk_level} /><Icon name="arrow" size={17} /></button>)}</div> : <div className="recent-empty"><Icon name="reports" size={25} /><div><strong>A clear starting point.</strong><p>Your recent scans will appear here. Start with a URL or an email above.</p></div></div>}</section>
    <section className="workflow-strip"><div><span>01</span><strong>Extract features</strong><p>URL structure, text and metadata</p></div><div><span>02</span><strong>Run trained models</strong><p>Random Forest + Logistic Regression</p></div><div><span>03</span><strong>Review & protect</strong><p>Alerts, reports and a personal blocklist</p></div></section>
  </>;
}
