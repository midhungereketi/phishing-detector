// Complete new-feature flows in an isolated browser, including a real loaded extension.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const output = path.resolve('artifacts/upgrades-browser');
fs.mkdirSync(output, { recursive: true });
const username = `upgrade_test_${Date.now()}`;
const base = 'http://127.0.0.1:8000';
const headers = { 'X-PhishGuard': '1' };

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [], passed = [];
  let extensionContext;
  page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto(base);
    await page.getByRole('button', { name: 'New here? Create an account' }).click();
    await page.getByLabel('Username', { exact: true }).fill(username);
    await page.getByLabel('Password', { exact: true }).fill('UpgradeBrowser!123');
    await page.getByRole('button', { name: 'Create account →' }).click();
    await page.getByText('ML engine ready').waitFor();
    await page.getByRole('button', { name: 'Ordinary URL', exact: true }).click();
    await page.getByRole('checkbox', { name: 'Live DNS, TLS, redirects & domain age' }).check();
    const response = page.waitForResponse(r => r.url().endsWith('/api/scan/url') && r.request().method() === 'POST', { timeout: 45000 });
    await page.getByRole('button', { name: 'Analyze URL →' }).click();
    const report = await (await response).json();
    assert(report.intelligence && report.network.status !== 'not_requested');
    assert(report.registration.status !== 'not_requested');
    await page.getByRole('heading', { name: 'DNS, TLS & redirects' }).waitFor();
    await page.screenshot({ path: path.join(output, 'network-report.png'), fullPage: true });
    passed.push(`Live optional check → API → evidence report (network=${report.network.status}, registration=${report.registration.status})`);
    const pdfDownload = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download PDF' }).click();
    await (await pdfDownload).saveAs(path.join(output, 'enriched-report.pdf'));
    assert.equal(fs.readFileSync(path.join(output, 'enriched-report.pdf')).subarray(0, 5).toString(), '%PDF-');
    passed.push('Enriched PDF export');
    await page.getByRole('tab', { name: 'Email scanner' }).click();
    await page.locator('input[type=file]').setInputFiles({ name: 'encoded-message.eml', mimeType: 'message/rfc822', buffer: Buffer.from('From: team@college.example\r\nSubject: =?iso-8859-1?Q?R=E9union_de_projet?=\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nR\xe9union de notre groupe vendredi pour pr\xe9parer la pr\xe9sentation.', 'latin1') });
    const emailResponse = page.waitForResponse(r => r.url().endsWith('/api/scan/email-file'));
    await page.getByRole('button', { name: 'Analyze email →' }).click();
    const email = await (await emailResponse).json();
    assert.equal(email.subject, 'Réunion de projet');
    assert.equal(email.input_method, 'eml_file');
    await page.getByRole('heading', { name: 'Email security report' }).waitFor();
    passed.push('Original-byte .eml upload → MIME decoding → saved report');
    await page.getByRole('button', { name: 'Model lab', exact: true }).click();
    await page.getByRole('heading', { name: 'URL calibration', exact: true }).waitFor();
    await page.getByLabel('Dataset source and collection date').fill('Synthetic browser fixture — not a performance benchmark');
    await page.getByLabel('URL CSV').setInputFiles({ name: 'fixture.csv', mimeType: 'text/csv', buffer: Buffer.from('url,label\n' + Array.from({ length: 12 }, (_, i) => `https://browser-fixture${i}.example/path,${i % 2}`).join('\n')) });
    await page.getByRole('button', { name: 'Evaluate dataset', exact: true }).click();
    await page.getByText('Evaluation saved. No model training or website visits occurred.').waitFor();
    await page.screenshot({ path: path.join(output, 'evaluation.png'), fullPage: true });
    passed.push('Independent-evaluation upload → predictions → metrics → account-scoped saved evaluation');
    await page.getByRole('button', { name: 'Protection', exact: true }).click();
    await page.getByRole('heading', { name: 'Phishing intelligence cache' }).waitFor();
    const feed = await (await context.request.get(base + '/api/intelligence')).json();
    assert(feed.entries > 0);
    await page.getByRole('button', { name: 'Generate pairing token', exact: true }).click();
    const token = await page.getByLabel('Copy this token into the extension.').inputValue();
    assert(token.length > 20);
    const zipDownload = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download the extension ZIP' }).click();
    await (await zipDownload).saveAs(path.join(output, 'extension.zip'));
    passed.push('Fresh phishing feed status, scoped pairing token and downloadable extension');
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: path.join(output, 'protection-mobile.png'), fullPage: true });
    passed.push('Mobile protection page without overflow');

    // Install only into a disposable automation profile, not the user's normal browser.
    const extensionPath = path.resolve('extension');
    extensionContext = await chromium.launchPersistentContext(path.join(output, `extension-profile-${Date.now()}`), {
      channel: 'msedge', headless: true, ignoreDefaultArgs: ['--disable-extensions'],
      args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
    });
    const worker = extensionContext.serviceWorkers()[0] || await extensionContext.waitForEvent('serviceworker', { timeout: 15000 });
    const id = new URL(worker.url()).host;
    const popup = await extensionContext.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);
    await popup.getByLabel('Pairing token from Protection').fill(token);
    await popup.getByRole('button', { name: 'Pair extension', exact: true }).click();
    await popup.getByText(`Paired as ${username}`, { exact: false }).waitFor();
    await context.request.post(base + '/api/blocklist', { headers, data: { host: 'www.wikipedia.org' } });
    await popup.getByRole('button', { name: 'Sync blocklist' }).click();
    await popup.getByText('1 blocked hosts synced', { exact: false }).waitFor();
    const rules = await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
    assert.equal(rules.length, 1);
    const blocked = await extensionContext.newPage();
    let blockedError = '';
    try { await blocked.goto('https://www.wikipedia.org/', { timeout: 10000 }); } catch (error) { blockedError = error.message; }
    assert(/BLOCKED_BY_CLIENT|ERR_BLOCKED/.test(blockedError), blockedError);
    passed.push('Real loaded MV3 extension pairs, syncs and blocks navigation before request');
    const fixture = await extensionContext.newPage();
    await fixture.route('https://extension-fixture.example/', route => route.fulfill({ contentType: 'text/html', body: '<html><body><a id="risky" href="http://192.0.2.15/verify/account">Open risky link</a></body></html>' }));
    await fixture.goto('https://extension-fixture.example/');
    await fixture.locator('#risky').click();
    await fixture.locator('[data-phishguard-warning]').waitFor({ timeout: 10000 });
    assert.equal(fixture.url(), 'https://extension-fixture.example/');
    await fixture.screenshot({ path: path.join(output, 'extension-warning.png') });
    const warningResult = await worker.evaluate(async () => chrome.runtime.id && (await chrome.storage.local.get('token')).token != null);
    assert(warningResult);
    passed.push('Risky click remains on source page with extension warning');
    await popup.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await popup.getByText('Not paired.', { exact: false }).waitFor();
    assert.equal((await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules())).length, 0);
    passed.push('Disconnect removes browser block rules');
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ username, passed, errors, feed, liveReport: { network: report.network, registration: report.registration } }, null, 2));
    console.log(JSON.stringify({ username, passed, errors }, null, 2));
  } catch (error) {
    fs.writeFileSync(path.join(output, 'failure.json'), JSON.stringify({ username, passed, error: error.message, errors }, null, 2));
    await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true }).catch(() => {});
    throw error;
  } finally { await extensionContext?.close(); await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
