(function () {
  // Function to decode Base64 string to ArrayBuffer
  function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Function to decrypt ciphertext using Web Crypto API
  async function decrypt(encryptedData, passphrase) {
    try {
      const encryptedArrayBuffer = base64ToArrayBuffer(encryptedData);

      const salt = encryptedArrayBuffer.slice(0, 16);
      const iv = encryptedArrayBuffer.slice(16, 28);
      const authTag = encryptedArrayBuffer.slice(28, 44);
      const data = encryptedArrayBuffer.slice(44);

      const enc = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      const key = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128,
        },
        key,
        new Uint8Array([...new Uint8Array(data), ...new Uint8Array(authTag)]).buffer
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }

  // Store passphrase in local storage
  function getPassphrase() {
    return localStorage.getItem('passphrase') || null;
  }

  function setPassphrase(passphrase) {
    localStorage.setItem('passphrase', passphrase);
  }

  function clearPassphrase() {
    localStorage.removeItem('passphrase');
  }

  // Function to prompt for passphrase and decrypt the content
  function requestPassphrase(ciphertextElement, ciphertext, toggleButton) {
    const passphrase = prompt('Enter passphrase:');
    if (passphrase !== null) {
      setPassphrase(passphrase);
      decrypt(ciphertext, passphrase).then(decryptedText => {
        if (decryptedText) {
          toggleDecryptedContent(ciphertextElement, decryptedText, ciphertext, toggleButton);
        } else {
          alert("Decryption failed.");
        }
      });
    }
  }

  // Function to toggle between encrypted and decrypted content
  function toggleDecryptedContent(ciphertextElement, decryptedText, ciphertext, toggleButton) {
    const isDecrypted = ciphertextElement.getAttribute('data-decrypted') === 'true';
    if (isDecrypted) {
      const originalCiphertext = ciphertextElement.getAttribute('data-encrypted-content');
      ciphertextElement.textContent = originalCiphertext;
      ciphertextElement.setAttribute('data-decrypted', 'false');
      toggleButton.innerHTML = "🔒";
    } else {
      ciphertextElement.setAttribute('data-encrypted-content', ciphertext);
      ciphertextElement.textContent = decryptedText;
      ciphertextElement.setAttribute('data-decrypted', 'true');
      toggleButton.innerHTML = "🔓";
    }
  }

  // Docsify plugin to handle decryption and preserve copy functionality
  function decryptContent(hook, vm) {
    hook.afterEach(function (html, next) {
      const regex = /<pre[^>]*><code[^>]*class="lang-ciphertext"[^>]*>([\s\S]*?)<\/code><\/pre>/g;
      let match;
      let modifiedHtml = html;

      while ((match = regex.exec(html)) !== null) {
        const ciphertext = match[1].trim();
        const keyButton = `<span class="decrypt-key" style="cursor: pointer;">🔑</span>`;
        const lockButton = `<span class="decrypt-toggle" style="cursor: pointer;">🔒</span>`;

        // Insert buttons before the ciphertext block, and ensure 'data-lang' is set
        const placeholder = `<pre data-lang="ciphertext"><code class="lang-ciphertext" data-decrypted="false">${ciphertext}</code></pre>`;
        const buttonsAndCiphertext = keyButton + lockButton + placeholder;

        modifiedHtml = modifiedHtml.replace(match[0], buttonsAndCiphertext);
      }

      next(modifiedHtml);
    });

    // Ensure copy code functionality is preserved by handling clicks separately
    hook.doneEach(function () {
      document.querySelectorAll('.decrypt-key').forEach(keyButton => {
        keyButton.addEventListener('click', function () {
          const ciphertextElement = keyButton.nextElementSibling.nextElementSibling.querySelector('code');
          const ciphertext = ciphertextElement.textContent.trim();
          requestPassphrase(ciphertextElement, ciphertext, keyButton.nextElementSibling);
        });
      });

      document.querySelectorAll('.decrypt-toggle').forEach(lockButton => {
        lockButton.addEventListener('click', function () {
          const ciphertextElement = lockButton.nextElementSibling.querySelector('code');
          const ciphertext = ciphertextElement.textContent.trim();
          const passphrase = getPassphrase();

          if (ciphertextElement.getAttribute('data-decrypted') === 'true') {
            toggleDecryptedContent(ciphertextElement, null, ciphertext, lockButton);
          } else if (passphrase) {
            decrypt(ciphertext, passphrase).then(decryptedText => {
              if (decryptedText) {
                toggleDecryptedContent(ciphertextElement, decryptedText, ciphertext, lockButton);
              } else {
                alert("Decryption failed. Please enter the correct key.");
              }
            });
          }
        });
      });
    });
  }

  // Expose the plugin to global scope
  window.decryptContentPlugin = decryptContent;
})();
