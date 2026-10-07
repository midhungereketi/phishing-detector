# PhishGuard browser extension (Chrome / Edge, Manifest V3)

1. Keep the Python backend running at `http://127.0.0.1:8000`.
2. Open `chrome://extensions` or `edge://extensions`, enable Developer mode, choose **Load unpacked**, and select this `extension` directory (or unzip the app download first).
3. Copy the extension ID. Add `PHISHGUARD_EXTENSION_ORIGINS=chrome-extension://YOUR_ID` to the project `.env` if your browser requires CORS preflight, then restart the API. Only this configured origin is allowed; no wildcard origins.
4. Sign in to PhishGuard, open **Protection**, generate a 30-day pairing token, and paste it in the extension popup. Tokens grant only URL checks and reading your own blocklist. They cannot access scan history, email contents or account settings.
5. Click **Sync blocklist**. Dynamic rules persist while the backend is offline and cover exact hosts (not subdomains), including typed navigation. Up to 1,000 hosts are supported. Sync runs each minute while the browser is running.

Ordinary web-link clicks are paused until the local classifier replies. Low risk proceeds; medium/high or failed checks show a warning. The user can explicitly override a warning once, except personal blocks. This is a research prototype: content scripts do not cover the address bar, forms, scripted navigation, context-menu actions, browser-internal pages or every frame/context. Site scripts can interfere. Only synced blocklist rules provide pre-request blocking of known hosts. Disabling protection or disconnecting removes those rules.

Clicked URLs, including queries, go to your **local** backend. The extension does not run external reputation/network checks or store browsing history. The popup's current-tab check is explicitly initiated. Pairing tokens stay in trusted extension storage, expire after 30 days, and can all be revoked from Protection. Revocation prevents future server access; an already-synced local rule stays until disconnect, protection disable, removal or a successful sync.
