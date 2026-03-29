/**
 * docsify-ciphertext.js — v3.0
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
  var SESSION_KEY  = 'docsify-ciphertext:passphrase';
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

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // PASSPHRASE — session-scoped, cleared on tab close
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  function getPassphrase()   { return sessionStorage.getItem(SESSION_KEY); }
  function setPassphrase(p)  { sessionStorage.setItem(SESSION_KEY, p); }
  function clearPassphrase() { sessionStorage.removeItem(SESSION_KEY); }

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
  ].join('');

  function injectStyles() {
    if (document.getElementById(CSS_ID)) return;
    var s = document.createElement('style');
    s.id = CSS_ID;
    s.textContent = CSS;
    document.head.appendChild(s);
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

      var passphrase = getPassphrase();
      var plaintext  = null;

      // 1. Try the cached passphrase first
      if (passphrase) {
        try { plaintext = await decryptCiphertext(ct, passphrase); } catch (_) {}
      }

      // 2. If that failed (or no cached passphrase), ask the user
      if (!plaintext) {
        var hadPassphrase = !!passphrase;
        if (hadPassphrase) clearPassphrase();

        passphrase = await askPassphrase(hadPassphrase ? 'Incorrect passphrase \u2014 try again.' : '');

        if (!passphrase) {
          // User cancelled
          btn.disabled = false;
          btn.textContent = 'Unlock';
          if (icon) icon.textContent = '\uD83D\uDD12';
          row.classList.remove('cipher-row--busy');
          return;
        }

        try { plaintext = await decryptCiphertext(ct, passphrase); } catch (_) {}

        if (!plaintext) {
          clearPassphrase();
          btn.disabled = false;
          btn.textContent = 'Unlock';
          if (icon) icon.textContent = '\u274C';
          row.classList.remove('cipher-row--busy');
          return;
        }

        setPassphrase(passphrase);
      }

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
     * Auto-decrypts any block when a valid passphrase is in sessionStorage.
     */
    hook.doneEach(function () {
      injectStyles();

      var passphrase = getPassphrase();

      document.querySelectorAll('.cipher-block:not([data-wired])').forEach(function (block) {
        block.dataset.wired = '1';
        bindBlock(block);

        if (passphrase) {
          var ct = block.dataset.ct;
          decryptCiphertext(ct, passphrase)
            .then(function (plain) {
              if (plain) showDecrypted(block, ct, plain);
            })
            .catch(function () { /* wrong passphrase — just leave it locked */ });
        }
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
