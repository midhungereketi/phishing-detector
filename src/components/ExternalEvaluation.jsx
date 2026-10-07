import { useState } from 'react';
import { send, formatDate } from '../api';
import { useResource } from '../hooks';

export default function ExternalEvaluation() {
  const [file, setFile] = useState(null);
  const [source, setSource] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const history = useResource('/evaluation');
  async function evaluate(event) {
    event.preventDefault(); setBusy(true); setMessage('');
    try {
      if (!file || file.size > 500000) throw new Error('Choose a URL CSV no larger than 500 KB.');
      await send('/evaluation/urls', { csv: await file.text(), source });
      await history.refresh();
      setMessage('Evaluation saved. No model training or website visits occurred.');
    } catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  return <section className="card external-evaluation"><div className="eyebrow">GENERALIZATION CHECK</div><h2>Test a separate URL dataset</h2><p>Upload independently collected, labeled URLs. We exclude domains present anywhere in the original training, calibration and test corpus, and report false positives at several thresholds.</p><form onSubmit={evaluate}><label htmlFor="evaluation-source">Dataset source and collection date</label><input id="evaluation-source" value={source} onChange={event => setSource(event.target.value)} required minLength={3} maxLength={200} placeholder="Provider / dataset name / collected YYYY-MM-DD" /><label htmlFor="evaluation-csv">URL CSV · url,label · legitimate = 0, phishing = 1</label><input id="evaluation-csv" type="file" accept=".csv,text/csv" required disabled={busy} onChange={event => setFile(event.target.files[0])} /><p className="small">Up to 1,000 rows, 500 KB; at least 10 eligible rows with both classes. Your source description and labels are not independently verified.</p><button className="primary-btn" disabled={busy}>{busy ? 'Evaluating held-out URLs…' : 'Evaluate dataset'}</button></form>{(message || history.error) && <div className="notice" role="status">{message || history.error}</div>}{history.data?.map((run, index) => <details className="evaluation-run" key={`${run.sha256}-${index}`} open={index === 0}><summary>{run.source} · {formatDate(run.evaluated_at)}</summary><div className="model-stats">{[['Eligible samples', run.metrics.test_samples], ['Precision', `${(run.metrics.precision * 100).toFixed(2)}%`], ['Recall', `${(run.metrics.recall * 100).toFixed(2)}%`], ['Brier score', run.metrics.brier_score]].map(([label, value]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}</div><p className="small">Excluded: {Object.entries(run.excluded).map(([key, value]) => `${key.replaceAll('_', ' ')} ${value}`).join(' · ')}</p><p className="small">{run.limitations}</p><button className="secondary-btn small-btn" onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(run, null, 2)], { type: 'application/json' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'external-evaluation.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }}>Export evaluation JSON</button></details>)}{!history.loading && !history.data?.length && <p className="small">No independent dataset has been evaluated yet. The existing metrics are same-source held-out results.</p>}</section>;
}
