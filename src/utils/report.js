export function downloadJSON(report) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = `phishguard-report-${report.id}.json`; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function downloadPDF(report) {
  const [{ jsPDF }, { default: autoTable }] = await Promise.all([import('jspdf'), import('jspdf-autotable')]);
  const doc = new jsPDF();
  doc.setFontSize(22); doc.setTextColor(15, 90, 85); doc.text('PhishGuard / Security Report', 14, 22);
  autoTable(doc, {
    startY: 32, theme: 'striped', head: [['Analysis', 'Result']],
    body: [
      ['Report ID', String(report.id)], ['Analyzed at', new Date(report.created_at).toLocaleString()],
      ['Input type', report.kind.toUpperCase()], ['Target', report.url || report.subject || '(no subject)'],
      ['Risk level', report.risk_level], ['Policy risk score', `${report.score}/100`],
      ['Primary ML estimate', `${report.model_score}/100 (${report.calibrated ? 'dataset calibrated' : 'uncalibrated'})`], ['Score method', report.score_method],
      ['Recommended action', report.action], ['Model version', report.model_version],
      ['Blocked hosts', report.blocked_hosts.join(', ') || 'None'],
    ], styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' }, columnStyles: { 0: { cellWidth: 45 } },
    headStyles: { fillColor: [15, 90, 85] },
  });
  autoTable(doc, {
    startY: doc.lastAutoTable.finalY + 10, head: [['Observed security signals']],
    body: (report.signals.length ? report.signals : ['No structural warning signals found; this is not proof of safety.']).map(signal => [signal]),
    styles: { fontSize: 9, overflow: 'linebreak' }, headStyles: { fillColor: [15, 90, 85] },
  });
  if (report.kind === 'email') {
    autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Email metadata', 'Value']],
      body: [['From', report.sender || 'Missing'], ['Reply-To', report.reply_to || 'Missing'], ['Authentication-Results (unverified)', report.authentication_results || 'Unknown'], ['Attachments (not opened)', report.attachments.join(', ') || 'None']],
      styles: { fontSize: 9 }, headStyles: { fillColor: [15, 90, 85] },
    });
    autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Embedded URL (local analysis)', 'ML estimate']],
      body: report.links.map(link => [link.url, `${link.model_score}/100`]), styles: { fontSize: 8 }, headStyles: { fillColor: [15, 90, 85] } });
  }
  autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Extracted feature', 'Value']],
    body: Object.entries(report.features).map(([key, value]) => [key.replaceAll('_', ' '), String(typeof value === 'number' ? Math.round(value * 1000) / 1000 : value)]),
    styles: { fontSize: 8 }, headStyles: { fillColor: [15, 90, 85] },
  });
  if (report.policy_reasons?.length) autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Explicit risk policy']], body: report.policy_reasons.map(reason => [reason]), styles: { fontSize: 9 }, headStyles: { fillColor: [15, 90, 85] } });
  const candidates = report.kind === 'url' ? [report, ...(report.redirects || [])] : report.links;
  for (const link of candidates.filter(item => item.intelligence)) {
    autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Evidence', link.host]], body: [
      ['Phishing feed', `${link.intelligence.status}; ${link.intelligence.cache_status}; ${link.intelligence.message}`],
      ['Network check', `${link.network?.status || 'not requested'}; ${link.network?.message || link.network?.tls?.message || ''}`],
      ['Redirect observations', link.network?.chain?.map(hop => `${hop.status} ${hop.url}`).join('\n') || 'None observed'],
      ['Domain registration', link.registration?.age_days != null ? `${link.registration.domain}: ${link.registration.age_days} days old` : link.registration?.status || 'not requested'],
      ['VirusTotal', `${link.reputation?.status || 'not requested'}; ${JSON.stringify(link.reputation?.counts || {})}`],
    ], styles: { fontSize: 8, overflow: 'linebreak' }, headStyles: { fillColor: [15, 90, 85] } });
  }
  if (report.explanation?.length) autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, head: [['Model sensitivity (not causal)', 'Observed → baseline', 'Score change']], body: report.explanation.map(item => [item.feature, `${item.observed} -> ${item.baseline}`, `${item.score_change} points`]), styles: { fontSize: 8 }, headStyles: { fillColor: [15, 90, 85] } });
  autoTable(doc, { startY: doc.lastAutoTable.finalY + 10, body: [['Research prototype. Dataset-calibrated ML estimates do not establish real-world safety. The combined score uses explicit policy floors and is not a probability. Live checks run only when requested; missing checks are not clean verdicts. Email headers remain unverified. In-app controls and the optional paired browser extension have separate coverage limits.']], styles: { fontSize: 8, textColor: [90, 90, 90] } });
  doc.save(`phishguard-report-${report.id}.pdf`);
}
