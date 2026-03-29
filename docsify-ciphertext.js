/**
 * docsify-ciphertext.js — v3.1
 *
 * Docsify 4 + 5 plugin — AES-256-GCM encrypted content blocks.
 * Single <script> tag installation — auto-registers with Docsify.
 *
 * Usage (place after window.$docsify config, before docsify.min.js):
 *
 *   <script src="docsify-ciphertext.js"></script>
 *
 * Markdown syntax:
 *
 *   ```ciphertext
 *   <base64-encoded ciphertext>
 *   ```
 *
 * Cipher format: salt(16) | iv(12) | authTag(16) | ciphertext(N) — Base64 encoded
 * KDF: PBKDF2-SHA256 — 310 000 iterations (100 000 legacy fallback)
 */
(function () {
  'use strict';

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // CONSTANTS
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  var ITER_CURRENT = 310000; // NIST SP 800-132 (2023) recommended minimum
  var ITER_LEGACY  = 100000; // v1 backward-compat fallback
  var SESSION_KEY  = 'docsify-ciphertext:passphrase'; // sessionStorage — cleared on tab close
  var PERSIST_KEY  = 'docsify-ciphertext:keycache';   // localStorage  — AES key bytes, TTL-bound
  var KEY_TTL_MS   = Infinity;                         // never expires by default (override via $docsify.ciphertext.keyTTL)
  var CSS_ID       = 'docsify-ciphertext-css';

  // Regex for markdown syntax indicators (headings, lists, blockquotes, bold,
  // italic, fenced code, links).  Used by renderContent() to decide whether to
  // run the plaintext through marked or preserve it verbatim in a <pre>.
  var HAS_MD = /(?:^|\n) {0,3}#{1,6} |(?:^|\n) {0,3}[*\-+] |(?:^|\n) {0,3}> |(?:^|\n) {0,3}\d+\. |\*\*|__|```|\[.+?\]\(.+?\)/;

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // CRYPTO
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  function b64ToBuffer(b64) {
    var bin = atob(b64.trim());
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  async function _decryptWithIterations(ciphertextB64, passphrase, iterations) {
    var buf     = b64ToBuffer(ciphertextB64);
    var salt    = buf.slice(0, 16);
    var iv      = buf.slice(16, 28);
    var authTag = buf.slice(28, 44);
    var data    = buf.slice(44);

    var enc = new TextEncoder();
    var km = await crypto.subtle.importKey(
      'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Web Crypto AES-GCM expects data+authTag concatenated
    var payload = new Uint8Array(data.byteLength + authTag.byteLength);
    payload.set(new Uint8Array(data));
    payload.set(new Uint8Array(authTag), data.byteLength);

    var result = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key,
      payload.buffer
    );
    return new TextDecoder().decode(result);
  }

  /**
   * Decrypt a Base64-encoded ciphertext with the given passphrase.
   * Tries 310 000 iterations first; falls back to 100 000 for v1 content.
   */
  async function decryptCiphertext(ciphertextB64, passphrase) {
    try {
      return await _decryptWithIterations(ciphertextB64, passphrase, ITER_CURRENT);
    } catch (_) {
      // Legacy content encrypted with v1 (100 000 iterations)
      return await _decryptWithIterations(ciphertextB64, passphrase, ITER_LEGACY);
    }
  }

  /**
   * Like _decryptWithIterations but derives the AES key with extractable=true,
   * allowing the caller to export and cache it.  Returns { plaintext, key }.
   */
  async function _decryptExtractable(ciphertextB64, passphrase, iterations) {
    var buf     = b64ToBuffer(ciphertextB64);
    var salt    = buf.slice(0, 16);
    var iv      = buf.slice(16, 28);
    var authTag = buf.slice(28, 44);
    var data    = buf.slice(44);

    var enc = new TextEncoder();
    var km = await crypto.subtle.importKey(
      'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      true,        // extractable — required for key export/caching
      ['decrypt']
    );

    var payload = new Uint8Array(data.byteLength + authTag.byteLength);
    payload.set(new Uint8Array(data));
    payload.set(new Uint8Array(authTag), data.byteLength);

    var result = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
      key, payload.buffer
    );
    return { plaintext: new TextDecoder().decode(result), key: key };
  }

  /**
   * Return the Base64-encoded 16-byte salt from a ciphertext blob.
   * Used as the localStorage key-cache slot's identifier.
   */
  function saltB64FromCT(ciphertextB64) {
    var buf  = b64ToBuffer(ciphertextB64);
    var salt = new Uint8Array(buf.slice(0, 16));
    return btoa(String.fromCharCode.apply(null, salt));
  }

  /**
   * Decrypt with the given passphrase, then fire-and-forget export the
   * derived key to localStorage (keyed by salt, bounded by TTL).
   * Tries 310k iterations first; falls back to 100k for legacy content.
   */
  async function decryptAndCache(ciphertextB64, passphrase) {
    var saltB64 = saltB64FromCT(ciphertextB64);
    var res;
    try {
      res = await _decryptExtractable(ciphertextB64, passphrase, ITER_CURRENT);
    } catch (_) {
      res = await _decryptExtractable(ciphertextB64, passphrase, ITER_LEGACY);
    }
    _saveKeyToCache(saltB64, res.key); // async, fire-and-forget
    return res.plaintext;
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // INSECURE-CONTEXT POLYFILL
  //
  // crypto.subtle is restricted to Secure Contexts (HTTPS / localhost) by spec.
  // On plain HTTP we dynamically load the webcrypto-liner shim (backed by
  // asmcrypto.js) which patches window.crypto.subtle with a pure-JS fallback.
  // All existing crypto code runs unchanged after the shim is installed.
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  var _cryptoReady = null;

  function _loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.onload  = resolve;
      s.onerror = function () { reject(new Error('Failed to load ' + src)); };
      document.head.appendChild(s);
    });
  }

  /**
   * Returns a Promise that resolves once crypto.subtle is guaranteed available.
   * If already available (HTTPS / localhost) resolves immediately.
   * Otherwise loads the asmcrypto.js + webcrypto-liner shim from jsDelivr.
   */
  function ensureCrypto() {
    if (_cryptoReady) return _cryptoReady;
    if (window.crypto && window.crypto.subtle) {
      return (_cryptoReady = Promise.resolve());
    }
    _cryptoReady = _loadScript(
      'https://cdn.jsdelivr.net/npm/asmcrypto.js/asmcrypto.all.es5.min.js'
    ).then(function () {
      return _loadScript(
        'https://cdn.jsdelivr.net/npm/webcrypto-liner/build/webcrypto-liner.shim.min.js'
      );
    }).then(function () {
      if (!(window.crypto && window.crypto.subtle)) {
        throw new Error('webcrypto-liner polyfill did not expose crypto.subtle.');
      }
    });
    return _cryptoReady;
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // PASSPHRASE — two-layer cache
  //   Layer 1 (session):  sessionStorage — passphrase string, tab-scoped
  //   Layer 2 (persist):  localStorage   — derived AES key bytes per salt, TTL-bound
  //
  // Why store the key, not the passphrase?
  //   An attacker reading localStorage gets 32 bytes of AES key material.
  //   They cannot reverse-engineer the passphrase from it (PBKDF2 is one-way),
  //   so reuse of the passphrase elsewhere is not exposed.
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  /* --- session layer (current tab only) --- */
  function getPassphrase()        { return sessionStorage.getItem(SESSION_KEY); }
  function setPassphrase(p)       { sessionStorage.setItem(SESSION_KEY, p); }
  function clearSessionPassphrase() { sessionStorage.removeItem(SESSION_KEY); }

  /* --- key-cache helpers --- */
  function _getKeyTTL() {
    return (window.$docsify && window.$docsify.ciphertext && window.$docsify.ciphertext.keyTTL != null)
      ? window.$docsify.ciphertext.keyTTL
      : KEY_TTL_MS;
  }
  function _readCache()  { try { return JSON.parse(localStorage.getItem(PERSIST_KEY) || '{}'); } catch (_) { return {}; } }
  function _writeCache(c) { try { localStorage.setItem(PERSIST_KEY, JSON.stringify(c)); } catch (_) {} }

  /** Export a CryptoKey and store it in localStorage keyed by the ciphertext's salt. */
  function _saveKeyToCache(saltB64, cryptoKey) {
    crypto.subtle.exportKey('raw', cryptoKey).then(function (raw) {
      var keyB64 = btoa(String.fromCharCode.apply(null, new Uint8Array(raw)));
      var ttl    = _getKeyTTL();
      var cache  = _readCache();
      // exp === null means never expires
      cache[saltB64] = { k: keyB64, exp: isFinite(ttl) ? Date.now() + ttl : null };
      // Prune entries that have a finite expiry and are past it
      var now = Date.now();
      Object.keys(cache).forEach(function (k) {
        if (cache[k].exp !== null && cache[k].exp < now) delete cache[k];
      });
      _writeCache(cache);
    }).catch(function () { /* exportKey not supported — skip caching silently */ });
  }

  /**
   * Return an importable CryptoKey from the localStorage cache for the given
   * salt, or null if missing / expired / invalid.
   */
  async function _loadKeyFromCache(saltB64) {
    var cache = _readCache();
    var entry = cache[saltB64];
    if (!entry) return null;
    // entry.exp === null means no expiry; otherwise check TTL
    if (entry.exp !== null && Date.now() > entry.exp) {
      delete cache[saltB64]; _writeCache(cache);
      return null;
    }
    try {
      var bin = atob(entry.k);
      var raw = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
      return await crypto.subtle.importKey('raw', raw.buffer, { name: 'AES-GCM' }, false, ['decrypt']);
    } catch (_) {
      delete cache[saltB64];
      _writeCache(cache);
      return null;
    }
  }

  /**
   * Try to decrypt using the AES key stored in localStorage.
   * Returns plaintext string, or null if no valid cached key exists.
   * On success: instant — no PBKDF2 needed.
   */
  async function decryptWithCachedKey(ciphertextB64) {
    var saltB64 = saltB64FromCT(ciphertextB64);
    var key = await _loadKeyFromCache(saltB64);
    if (!key) return null;
    try {
      var buf     = b64ToBuffer(ciphertextB64);
      var iv      = buf.slice(16, 28);
      var authTag = buf.slice(28, 44);
      var data    = buf.slice(44);
      var payload = new Uint8Array(data.byteLength + authTag.byteLength);
      payload.set(new Uint8Array(data));
      payload.set(new Uint8Array(authTag), data.byteLength);
      var result = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        key, payload.buffer
      );
      return new TextDecoder().decode(result);
    } catch (_) {
      // Cached key is stale / mismatch — evict it
      var cache = _readCache();
      delete cache[saltB64];
      _writeCache(cache);
      return null;
    }
  }

  /** Clear the session passphrase AND the entire localStorage key cache. */
  function clearPassphrase() {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(PERSIST_KEY);
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // STYLES
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  var CSS = [
    /* ── locked block — single compact row ───────────────────────────── */
    '.cipher-block{margin:1em 0;}',
    '.cipher-row{display:flex;align-items:center;gap:10px;padding:9px 12px;',
    '  border-radius:6px;',
    '  background:var(--mono-tint3,var(--sidebar-bg,rgba(0,0,0,.04)));',
    '  border:1px solid var(--border-color,var(--mono-tint2,#ddd));}',
    '.cipher-row--busy{opacity:.65;pointer-events:none;}',
    '.cipher-icon{font-size:.95em;flex-shrink:0;user-select:none;line-height:1;}',
    '.cipher-fp{font-family:monospace;font-size:.78em;flex:1;min-width:0;',
    '  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;',
    '  color:var(--mono-shade2,var(--text-color,#333));opacity:.55;}',
    /* unlock button uses the site theme color */
    '.cipher-unlock{flex-shrink:0;padding:5px 15px;border-radius:4px;border:none;',
    '  cursor:pointer;font-size:.82em;font-weight:500;letter-spacing:.01em;',
    '  background:var(--theme-color,#1a73e8);color:#fff;',
    '  transition:filter .15s,opacity .15s;}',
    '.cipher-unlock:hover:not(:disabled){filter:brightness(1.12);}',
    '.cipher-unlock:disabled{opacity:.45;cursor:default;}',
    /* ── decrypted content wrapper — left accent border only ─────────── */
    '.cipher-decrypted{position:relative;',
    '  border-left:3px solid var(--theme-color,#2a9d5c);',
    '  padding:10px 34px 10px 15px;border-radius:0 5px 5px 0;',
    '  background:var(--mono-tint3,rgba(0,0,0,.025));}',
    '.cipher-decrypted>*:first-child{margin-top:0!important;}',
    '.cipher-decrypted>*:last-child{margin-bottom:0!important;}',
    /* plain-text pre — no double box, just preserves whitespace */
    '.cipher-plain{margin:0!important;padding:0!important;',
    '  white-space:pre-wrap!important;word-break:break-word;',
    '  background:transparent!important;border:none!important;box-shadow:none!important;',
    '  font-size:.9em;line-height:1.65;}',
    /* re-lock button */
    '.cipher-relock{position:absolute;top:6px;right:6px;',
    '  background:none;border:none;cursor:pointer;line-height:1;',
    '  font-size:.8em;padding:3px 5px;border-radius:3px;opacity:.3;',
    '  transition:opacity .15s,background .15s;}',
    '.cipher-relock:hover{opacity:.85;',
    '  background:var(--border-color,rgba(0,0,0,.08));}',
    /* ── passphrase modal ─────────────────────────────────────────────── */
    '.cipher-overlay{position:fixed;inset:0;',
    '  background:rgba(0,0,0,.45);',
    '  backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);',
    '  display:flex;align-items:center;justify-content:center;z-index:99999;}',
    '.cipher-modal{',
    '  background:var(--body-bg,var(--background,#fff));',
    '  color:var(--text-color,#333);',
    '  border-radius:10px;padding:24px 26px;width:340px;max-width:92vw;',
    '  box-shadow:0 16px 48px rgba(0,0,0,.22);}',
    '.cipher-modal h3{margin:0 0 16px;font-size:1em;font-weight:600;',
    '  display:flex;align-items:center;gap:8px;}',
    '.cipher-modal label{display:block;font-size:.82em;margin-bottom:5px;',
    '  opacity:.7;}',
    /* password input */
    '.cipher-pw{display:block;width:100%;padding:9px 11px;box-sizing:border-box;',
    '  border:1px solid var(--border-color,#ccc);border-radius:5px;',
    '  font-size:1em;',
    '  background:var(--body-bg,var(--background,#fff));',
    '  color:var(--text-color,#333);}',
    '.cipher-pw:focus{outline:none;',
    '  border-color:var(--theme-color,#1a73e8);',
    '  box-shadow:0 0 0 3px color-mix(in srgb,var(--theme-color,#1a73e8) 20%,transparent);}',
    '.cipher-modal-err{min-height:1.2em;color:#d32f2f;font-size:.8em;margin-top:5px;}',
    '.cipher-modal-btns{display:flex;justify-content:flex-end;gap:8px;margin-top:20px;}',
    '.cipher-modal-btns button{padding:8px 18px;border-radius:5px;font-size:.9em;',
    '  border:1px solid var(--border-color,#ccc);cursor:pointer;}',
    '.cipher-submit{',
    '  background:var(--theme-color,#1a73e8)!important;',
    '  color:#fff!important;border-color:var(--theme-color,#1a73e8)!important;}',
    '.cipher-submit:hover{filter:brightness(1.1);}',
    '.cipher-cancel:hover{',
    '  background:var(--mono-tint3,rgba(0,0,0,.05));}',
    /* ── HTTP insecure-context warning banner ────────────────────────── */
    '.cipher-http-warn{display:flex;align-items:flex-start;gap:10px;',
    '  margin:0 0 1.4em;padding:11px 14px;border-radius:6px;',
    '  background:rgba(234,128,20,.08);border:1px solid rgba(234,128,20,.4);',
    '  font-size:.82em;line-height:1.55;color:var(--text-color,#333);}',
    '.cipher-http-warn-icon{flex-shrink:0;font-size:1.1em;line-height:1.55;}',
    '.cipher-http-warn strong{opacity:.9;}',
    '.cipher-http-warn-close{margin-left:auto;flex-shrink:0;background:none;',
    '  border:none;cursor:pointer;opacity:.4;font-size:1.1em;padding:0 3px;',
    '  line-height:1;transition:opacity .15s;}',
    '.cipher-http-warn-close:hover{opacity:.85;}',
  ].join('');

  function injectStyles() {
    if (document.getElementById(CSS_ID)) return;
    var s = document.createElement('style');
    s.id = CSS_ID;
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /**
   * Show a one-time dismissible banner warning that the page is on HTTP.
   * Decryption still works via the polyfill; the warning explains the
   * trust model (local-only) and recommends HTTPS for best security.
   * Inserts before the first cipher-block, or at the top of #main.
   */
  function showInsecureWarning() {
    var WARN_ID = 'cipher-http-warn';
    if (document.getElementById(WARN_ID)) return;
    var el = document.createElement('div');
    el.id = WARN_ID;
    el.className = 'cipher-http-warn';
    el.setAttribute('role', 'status');
    el.innerHTML =
      '<span class="cipher-http-warn-icon" aria-hidden="true">⚠️</span>' +
      '<span><strong>HTTP page</strong> — decryption is still fully local ' +
      '(your passphrase never leaves the browser), but a network attacker ' +
      'could tamper with this page’s content. ' +
      'For best security serve over <strong>HTTPS</strong>.</span>' +
      '<button class="cipher-http-warn-close" type="button" ' +
             'aria-label="Dismiss">×</button>';
    el.querySelector('.cipher-http-warn-close').addEventListener('click', function () {
      el.parentNode && el.parentNode.removeChild(el);
    });
    var anchor = document.querySelector('.cipher-block');
    if (anchor && anchor.parentNode) {
      anchor.parentNode.insertBefore(el, anchor);
    } else {
      var main = document.getElementById('main') || document.querySelector('.content') || document.body;
      main.insertBefore(el, main.firstChild);
    }
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // MODAL
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  /**
   * Show a passphrase modal. Returns a Promise that resolves to the entered
   * passphrase string, or null if the user cancels.
   */
  function askPassphrase(errorMsg) {
    return new Promise(function (resolve) {
      var overlay = document.createElement('div');
      overlay.className = 'cipher-overlay';
      overlay.setAttribute('role', 'presentation');

      var modal = document.createElement('div');
      modal.className = 'cipher-modal';
      modal.setAttribute('role', 'dialog');
      modal.setAttribute('aria-modal', 'true');
      modal.setAttribute('aria-labelledby', 'cipher-modal-title');
      modal.innerHTML =
        '<h3 id="cipher-modal-title"><span aria-hidden="true">🔑</span> Passphrase</h3>' +
        '<label for="cipher-pw-input">Enter passphrase to decrypt</label>' +
        '<input id="cipher-pw-input" class="cipher-pw" type="password"' +
               ' autocomplete="current-password" placeholder="Passphrase…">' +
        '<div class="cipher-modal-err" role="alert">' + (errorMsg ? esc(errorMsg) : '') + '</div>' +
        '<div class="cipher-modal-btns">' +
          '<button class="cipher-cancel" type="button">Cancel</button>' +
          '<button class="cipher-submit" type="button">Decrypt</button>' +
        '</div>';

      overlay.appendChild(modal);
      document.body.appendChild(overlay);

      var input = modal.querySelector('#cipher-pw-input');
      setTimeout(function () { input.focus(); }, 30);

      function done(val) {
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        resolve(val);
      }

      modal.querySelector('.cipher-submit').addEventListener('click', function () {
        done(input.value || null);
      });
      modal.querySelector('.cipher-cancel').addEventListener('click', function () {
        done(null);
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter')  done(input.value || null);
        if (e.key === 'Escape') done(null);
      });
      overlay.addEventListener('click', function (e) {
        if (e.target === overlay) done(null);
      });
    });
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // DOM HELPERS
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  /** HTML-escape a plain-text string for safe insertion into HTML. */
  function esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Short identifier shown in the locked row.
   * Reveals the first 8 and last 4 characters — enough to identify which
   * block is which without exposing the ciphertext.
   */
  function fingerprint(ct) {
    return ct.length > 14 ? ct.slice(0, 8) + '\u2026' + ct.slice(-4) : ct;
  }

  /**
   * Smart content renderer:
   * - Text that contains markdown syntax (headings, bold, lists, links, code
   *   fences…) is rendered through marked so formatting is preserved.
   * - Everything else (JSON, plain text, code, URLs…) is placed in a <pre>
   *   so whitespace and indentation are preserved exactly as encrypted.
   */
  function renderContent(text) {
    if (HAS_MD.test(text)) {
      // Try marked — Docsify 4 exposes it as window.marked or Docsify.marked;
      // Docsify 5 also keeps window.marked after library load.
      var m = window.marked
        || (window.Docsify && window.Docsify.marked)
        || (window.Docsify && window.Docsify.utils && window.Docsify.utils.marked);
      if (m) {
        try { return m.parse ? m.parse(text) : m(text); } catch (_) {}
      }
    }
    // Plain text / JSON / code — preserve exactly as written
    return '<pre class="cipher-plain">' + esc(text) + '</pre>';
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // BLOCK LIFECYCLE
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  /** Generate the inner HTML for a locked row from a ciphertext string. */
  function lockedRowHTML(ct) {
    return (
      '<div class="cipher-row">' +
        '<span class="cipher-icon" aria-hidden="true">\uD83D\uDD12</span>' +
        '<code class="cipher-fp" title="' + esc(ct) + '">' + esc(fingerprint(ct)) + '</code>' +
        '<button class="cipher-unlock" type="button">Unlock</button>' +
      '</div>'
    );
  }

  /** Replace a cipher-block with the rendered, decrypted content. */
  function showDecrypted(block, ciphertextB64, plaintext) {
    var wrapper = document.createElement('div');
    wrapper.className = 'cipher-decrypted';
    wrapper.innerHTML = renderContent(plaintext);

    var relock = document.createElement('button');
    relock.className = 'cipher-relock';
    relock.type = 'button';
    relock.title = 'Re-lock';
    relock.setAttribute('aria-label', 'Re-lock — hide decrypted content');
    relock.textContent = '\uD83D\uDD12';
    relock.addEventListener('click', function () {
      var locked = buildLockedBlock(ciphertextB64);
      if (wrapper.parentNode) wrapper.parentNode.replaceChild(locked, wrapper);
    });
    wrapper.appendChild(relock);

    if (block.parentNode) block.parentNode.replaceChild(wrapper, block);
  }

  /** Build a locked cipher-block element and attach event listeners. */
  function buildLockedBlock(ciphertextB64) {
    var outer = document.createElement('div');
    outer.className = 'cipher-block';
    outer.dataset.ct = ciphertextB64;
    outer.innerHTML = lockedRowHTML(ciphertextB64);
    bindBlock(outer);
    return outer;
  }

  /** Wire the "Unlock" button of a locked block. */
  function bindBlock(block) {
    var row  = block.querySelector('.cipher-row');
    var btn  = block.querySelector('.cipher-unlock');
    var icon = block.querySelector('.cipher-icon');

    btn.addEventListener('click', async function () {
      var ct = block.dataset.ct;
      btn.disabled = true;
      btn.textContent = 'Unlocking\u2026';
      if (icon) icon.textContent = '\u23F3';
      row.classList.add('cipher-row--busy');

      // Ensure Web Crypto is available (loads polyfill on HTTP if needed)
      try { await ensureCrypto(); } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Unlock';
        if (icon) icon.textContent = '\u274C';
        row.classList.remove('cipher-row--busy');
        console.error('docsify-ciphertext: Web Crypto unavailable —', e.message);
        return;
      }

      // 1. Fast path: AES key cached in localStorage — no passphrase, no PBKDF2
      var plaintext = await decryptWithCachedKey(ct);
      if (plaintext) { showDecrypted(block, ct, plaintext); return; }

      // 2. Session passphrase (same tab, still open)
      var passphrase    = getPassphrase();
      var hadPassphrase = !!passphrase;
      if (passphrase) {
        try { plaintext = await decryptAndCache(ct, passphrase); } catch (_) {}
        if (plaintext) { showDecrypted(block, ct, plaintext); return; }
        // Wrong passphrase in session cache — clear only the session entry
        clearSessionPassphrase();
      }

      // 3. Ask the user
      passphrase = await askPassphrase(hadPassphrase ? 'Incorrect passphrase \u2014 try again.' : '');
      if (!passphrase) {
        btn.disabled = false;
        btn.textContent = 'Unlock';
        if (icon) icon.textContent = '\uD83D\uDD12';
        row.classList.remove('cipher-row--busy');
        return;
      }

      try { plaintext = await decryptAndCache(ct, passphrase); } catch (_) {}
      if (!plaintext) {
        btn.disabled = false;
        btn.textContent = 'Unlock';
        if (icon) icon.textContent = '\u274C';
        row.classList.remove('cipher-row--busy');
        return;
      }

      setPassphrase(passphrase);
      showDecrypted(block, ct, plaintext);
    });
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // DOCSIFY HOOK
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  function install(hook) {
    /**
     * afterEach: transform ```ciphertext … ``` blocks in the rendered HTML
     * string into cipher-block div placeholders before the DOM is updated.
     */
    hook.afterEach(function (html, next) {
      // Match both lang-ciphertext (Docsify 4) and language-ciphertext (Docsify 5 / standard marked)
      var out = html.replace(
        /<pre\b[^>]*>\s*<code\b[^>]*\bclass="[^"]*\b(?:lang|language)-ciphertext\b[^"]*"[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/g,
        function (_, encoded) {
          var ct = encoded.trim()
            .replace(/&amp;/g,  '&')
            .replace(/&lt;/g,   '<')
            .replace(/&gt;/g,   '>')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g,  "'");

          // data-ct is safe: Base64 chars are all [A-Za-z0-9+/=]
          return (
            '<div class="cipher-block" data-ct="' + ct + '">' +
              '<div class="cipher-row">' +
                '<span class="cipher-icon" aria-hidden="true">\uD83D\uDD12</span>' +
                '<code class="cipher-fp" title="' + esc(ct) + '">' + esc(fingerprint(ct)) + '</code>' +
                '<button class="cipher-unlock" type="button">Unlock</button>' +
              '</div>' +
            '</div>'
          );
        }
      );
      next(out);
    });

    /**
     * doneEach: wire event listeners after the DOM is live.
     * Uses data-wired to avoid double-binding on re-renders.
     * Auto-decrypts via (in order of priority):
     *   1. localStorage AES key cache — instant, cross-session
     *   2. sessionStorage passphrase  — current tab only
     */
    hook.doneEach(function () {
      injectStyles();

      var blocks = document.querySelectorAll('.cipher-block:not([data-wired])');
      if (!blocks.length) return;

      // Show HTTP warning if needed (non-blocking — decryption still works via polyfill)
      if (window.isSecureContext === false || !(window.crypto && window.crypto.subtle)) {
        showInsecureWarning();
      }

      var passphrase = getPassphrase();

      blocks.forEach(function (block) {
        block.dataset.wired = '1';
        bindBlock(block);

        var ct = block.dataset.ct;

        // Ensure crypto is ready (loads polyfill on HTTP), then auto-decrypt
        ensureCrypto().then(function () {
          // Try cached key first (works across sessions)
          return decryptWithCachedKey(ct);
        }).then(function (plain) {
          if (plain) { showDecrypted(block, ct, plain); return; }
          // Fallback: session passphrase (same tab, no cached key yet)
          if (passphrase) {
            return decryptCiphertext(ct, passphrase)
              .then(function (p) { if (p) showDecrypted(block, ct, p); });
          }
        }).catch(function () {});
      });
    });
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // AUTO-REGISTER WITH DOCSIFY
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  // Automatically push into window.$docsify.plugins so callers only need:
  //   <script src="docsify-ciphertext.js"></script>
  // (placed after window.$docsify config, before docsify.min.js)
  window.$docsify = window.$docsify || {};
  window.$docsify.plugins = [install].concat(window.$docsify.plugins || []);

  // Expose public API for external use
  window.DocsifyCiphertext = {
    install:         install,
    clearPassphrase: clearPassphrase,
  };

})();
