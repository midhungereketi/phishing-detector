(() => {
  // Inspect explicit clicks only. No background browsing-history collection.
  let pending = false;
  let host;
  function warning(message, url, allowOverride = true) {
    host?.remove();
    host = document.createElement('div');
    host.dataset.phishguardWarning = 'true';
    const root = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `:host{all:initial;position:fixed;inset:0;z-index:2147483647;font:15px system-ui;color:#eee8fa} .shade{position:fixed;inset:0;background:#08060ce8;display:grid;place-items:center;padding:24px} .card{max-width:480px;background:#181320;border:1px solid #77509e;border-radius:20px;padding:28px;box-shadow:0 20px 80px #000} h2{font-size:25px;margin:0 0 15px} p{line-height:1.5;overflow-wrap:anywhere} .url{font:12px monospace;color:#c7aedf} button{border:1px solid #765896;background:#ae84df;color:#140b20;padding:12px 16px;border-radius:8px;font:600 14px system-ui;cursor:pointer;margin:8px 8px 0 0} .other{background:transparent;color:#cbb8df} .note{font-size:12px;color:#b09ebf}`;
    const shade = document.createElement('div'); shade.className = 'shade';
    const card = document.createElement('div'); card.className = 'card'; card.setAttribute('role', 'alertdialog'); card.setAttribute('aria-modal', 'true'); card.setAttribute('aria-label', 'PhishGuard link warning'); card.tabIndex = -1;
    const heading = document.createElement('h2'); heading.textContent = 'PhishGuard · Pause this click';
    const detail = document.createElement('p'); detail.textContent = message;
    const target = document.createElement('p'); target.className = 'url'; target.textContent = url;
    const dismiss = document.createElement('button'); dismiss.textContent = 'Stay on this page'; dismiss.onclick = () => { host.remove(); host = null; };
    card.append(heading, detail, target, dismiss);
    if (allowOverride) {
      const override = document.createElement('button'); override.className = 'other'; override.textContent = 'Open once anyway';
      override.onclick = () => { host.remove(); host = null; window.location.assign(url); };
      card.append(override);
    }
    const note = document.createElement('p'); note.className = 'note'; note.textContent = 'ML estimates can be wrong. Synced blocked hosts remain blocked by the browser.'; card.append(note);
    card.onkeydown = event => {
      if (event.key === 'Escape') dismiss.click();
      if (event.key === 'Tab') {
        const buttons = [...card.querySelectorAll('button')];
        if (event.shiftKey && root.activeElement === buttons[0]) { event.preventDefault(); buttons.at(-1).focus(); }
        if (!event.shiftKey && root.activeElement === buttons.at(-1)) { event.preventDefault(); buttons[0].focus(); }
      }
    };
    shade.append(card); root.append(style, shade); document.documentElement.append(host); dismiss.focus();
  }
  function navigate(anchor, event, url) {
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.type === 'auxclick' || anchor.target === '_blank') window.open(url, '_blank', 'noopener,noreferrer');
    else window.location.assign(url);
  }
  async function inspect(event) {
    if (!event.isTrusted || event.defaultPrevented || (event.button !== 0 && event.button !== 1)) return;
    const anchor = event.composedPath().find(node => node instanceof HTMLAnchorElement);
    if (!anchor || anchor.hasAttribute('download')) return;
    let url;
    try { url = new URL(anchor.href); } catch { return; }
    if (!['http:', 'https:'].includes(url.protocol) || (url.origin === location.origin && url.pathname === location.pathname && url.search === location.search)) return;
    if (url.hostname === '127.0.0.1' && url.port === '8000') return;
    event.preventDefault(); event.stopImmediatePropagation();
    if (pending) return;
    pending = true;
    try {
      const result = await chrome.runtime.sendMessage({ action: 'check', url: url.href });
      if (result?.disabled || (result?.risk_level === 'Low' && !result.blocked_hosts?.length)) navigate(anchor, event, url.href);
      else warning(result?.error || `${result?.risk_level || 'Unknown'} risk (${result?.score ?? '?'}/100). ${result?.action || 'The link could not be checked.'}`, url.href, !result?.blocked_hosts?.length);
    } catch { warning('The local backend is unavailable. This link was not checked.', url.href); }
    finally { pending = false; }
  }
  document.addEventListener('click', inspect, true);
  document.addEventListener('auxclick', inspect, true);
})();
