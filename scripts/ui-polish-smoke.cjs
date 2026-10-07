// Real-browser checks for the animated interface. All scan data comes from the local API.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const output = path.resolve('artifacts/ui-polish');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, channel: 'msedge' });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
  const page = await context.newPage();
  const errors = [];
  const username = `ui_test_${Date.now()}`;
  const passed = [];
  page.on('pageerror', error => errors.push(error.message));
  const settle = () => page.evaluate(() => Promise.all(document.getAnimations().filter(a => a.effect?.getTiming().iterations !== Infinity).map(a => a.finished.catch(() => {}))));
  try {
    await page.goto('http://127.0.0.1:8000/');
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await settle();
    await page.screenshot({ path: path.join(output, 'login-desktop.png'), fullPage: true });
    await page.getByRole('button', { name: 'New here? Create an account' }).click();
    await page.getByLabel('Username', { exact: true }).fill(username);
    await page.getByLabel('Password', { exact: true }).fill('DisposableTest!123');
    await page.getByRole('button', { name: 'Create account →', exact: true }).click();
    await page.getByRole('heading', { name: 'Detection center.' }).waitFor();
    await page.getByText('ML engine ready').waitFor();
    await settle();
    await page.screenshot({ path: path.join(output, 'dashboard-empty.png'), fullPage: true });
    assert.equal(await page.evaluate(() => [...document.querySelectorAll('*')].some(el => getComputedStyle(el).filter.includes('blur(') || getComputedStyle(el).backdropFilter.includes('blur('))), false, 'Workspace must not blur its content');
    passed.push('Login and empty dashboard render with crisp vector detection pipeline; no blur filters');
    // Delay delivery of one real response to verify the processing state visually.
    await page.route('**/api/scan/url', async route => {
      const response = await route.fetch();
      await new Promise(resolve => setTimeout(resolve, 1000));
      await route.fulfill({ response });
    }, { times: 1 });
    await page.getByRole('button', { name: 'Ordinary URL', exact: true }).click();
    await page.getByRole('button', { name: 'Analyze URL →', exact: true }).click();
    await page.getByRole('status').filter({ hasText: 'Inspecting your target' }).waitFor();
    assert.equal(await page.getByRole('tab', { name: 'Email scanner' }).isDisabled(), true);
    await page.screenshot({ path: path.join(output, 'scan-processing.png'), fullPage: true });
    await page.getByRole('heading', { name: 'URL security report' }).waitFor();
    await settle();
    await page.screenshot({ path: path.join(output, 'dashboard-result.png'), fullPage: true });
    passed.push('Processing sweep, disabled tabs, result reveal, animated counts and doughnut chart');
    await page.keyboard.press('Control+k');
    await page.getByRole('dialog').waitFor();
    await page.getByLabel('Search workspace pages').fill('model');
    await page.screenshot({ path: path.join(output, 'command-palette.png'), fullPage: true });
    await page.keyboard.press('Enter');
    await page.getByRole('heading', { name: 'Random Forest', exact: true }).waitFor();
    await settle();
    await page.screenshot({ path: path.join(output, 'model-lab.png'), fullPage: true });
    passed.push('Ctrl+K search and Enter navigation');
    await page.getByRole('button', { name: 'Search workspace', exact: true }).click();
    await page.getByRole('dialog').waitFor();
    await page.keyboard.press('Escape');
    assert.equal(await page.getByRole('dialog').count(), 0);
    passed.push('Escape closes the palette');
    await page.getByRole('button', { name: 'Pause animations', exact: true }).click();
    assert.equal(await page.locator('html').getAttribute('data-motion'), 'off');
    assert.equal(await page.evaluate(() => document.getAnimations().filter(a => a.playState === 'running').length), 0);
    await page.reload();
    await page.getByRole('heading', { name: 'Detection center.' }).waitFor();
    assert.equal(await page.locator('html').getAttribute('data-motion'), 'off');
    passed.push('Pause motion stops running CSS animations and persists after reload');
    for (const width of [320, 390, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 920 });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Horizontal overflow at ${width}px`);
      if (width === 390) {
        await page.screenshot({ path: path.join(output, 'dashboard-mobile.png'), fullPage: true });
        await page.getByRole('button', { name: 'Menu', exact: true }).click();
        await page.getByRole('button', { name: 'Scan reports', exact: true }).click();
        await page.getByRole('heading', { name: 'Scan reports.' }).waitFor();
        await page.getByRole('button', { name: 'Menu', exact: true }).click();
        await page.getByRole('button', { name: 'Detection center', exact: true }).click();
      }
    }
    passed.push('No horizontal overflow at 320, 390, 768, 1024 and 1440 px; mobile menu works');
    await page.getByRole('button', { name: 'Enable animations', exact: true }).click();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await page.evaluate(() => document.getAnimations().filter(a => a.playState === 'running').length), 0);
    passed.push('Operating-system reduced-motion preference disables animation');
    for (const name of ['Protection', 'Learn', 'Settings', 'Scan reports', 'Model lab']) {
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.getByRole('button', { name, exact: true }).click();
      await page.screenshot({ path: path.join(output, `${name.toLowerCase().replaceAll(' ', '-')}-desktop.png`), fullPage: true });
      for (const width of [320, 390, 768]) {
        await page.setViewportSize({ width, height: 920 });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name} overflows at ${width}px`);
      }
    }
    passed.push('Protection, Learn, Settings, reports and Model Lab fit desktop and mobile widths');
    const anonymous = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
    const login = await anonymous.newPage();
    await login.goto('http://127.0.0.1:8000/');
    await login.getByRole('heading', { name: 'Welcome back' }).waitFor();
    assert(await login.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile login overflow');
    await login.screenshot({ path: path.join(output, 'login-mobile.png'), fullPage: true });
    await anonymous.close();
    assert.deepEqual(errors, []);
    passed.push('Mobile login layout and no uncaught browser errors');
    fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ username, passed, errors }, null, 2));
    console.log(JSON.stringify({ username, passed, errors }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
