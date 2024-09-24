(function() {
  // Function to decode Base64 string to ArrayBuffer
  function base64ToArrayBuffer(base64) {
    console.log("Converting Base64 to ArrayBuffer...");
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    console.log("Conversion complete. ArrayBuffer size:", len);
    return bytes.buffer;
  }

  // Function to decrypt ciphertext using Web Crypto API
  async function decrypt(encryptedData, passphrase) {
    try {
      console.log("Starting decryption process...");
      const encryptedArrayBuffer = base64ToArrayBuffer(encryptedData);

      // Extract salt, iv, authTag, and encrypted content
      const salt = encryptedArrayBuffer.slice(0, 16);   // First 16 bytes = salt
      const iv = encryptedArrayBuffer.slice(16, 28);    // Next 12 bytes = IV (AES-GCM)
      const authTag = encryptedArrayBuffer.slice(28, 44); // Next 16 bytes = Auth Tag
      const data = encryptedArrayBuffer.slice(44);      // Remainder = Encrypted content

      console.log("Extracted salt, iv, authTag, and data.");
      console.log("Salt:", new Uint8Array(salt));
      console.log("IV:", new Uint8Array(iv));
      console.log("AuthTag:", new Uint8Array(authTag));
      console.log("Encrypted Data Size:", data.byteLength);

      // Import the passphrase key using PBKDF2 with the salt
      const enc = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      console.log("Key material imported successfully.");

      // Derive the encryption key
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

      console.log("Key derived successfully.");

      // Decrypt the data using AES-GCM
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv, // Initialization vector (IV)
          tagLength: 128, // 16 bytes (128 bits) for auth tag
        },
        key,
        new Uint8Array([...new Uint8Array(data), ...new Uint8Array(authTag)]).buffer // Appending the authTag back to the data
      );

      console.log("Decryption successful.");
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }

  // Store passphrase in local storage
  function getPassphrase() {
    const passphrase = localStorage.getItem('passphrase') || null;
    console.log("Retrieved passphrase from localStorage:", passphrase ? "Exists" : "Not found");
    return passphrase;
  }

  function setPassphrase(passphrase) {
    console.log("Setting passphrase in localStorage.");
    localStorage.setItem('passphrase', passphrase);
  }

  function clearPassphrase() {
    console.log("Clearing passphrase from localStorage.");
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
          console.error("Failed to decrypt content.");
          alert("Decryption failed.");
        }
      });
    }
  }

  // Function to toggle between encrypted and decrypted content
  function toggleDecryptedContent(ciphertextElement, decryptedText, ciphertext, toggleButton) {
    const isDecrypted = ciphertextElement.getAttribute('data-decrypted') === 'true';
    if (isDecrypted) {
      // Restore encrypted content from the saved `data-encrypted-content`
      const originalCiphertext = ciphertextElement.getAttribute('data-encrypted-content');
      ciphertextElement.textContent = originalCiphertext;
      ciphertextElement.setAttribute('data-decrypted', 'false');
      toggleButton.innerHTML = "🔒"; // Show lock icon
    } else {
      // Save the original ciphertext in `data-encrypted-content`
      ciphertextElement.setAttribute('data-encrypted-content', ciphertext);
      // Show decrypted content
      ciphertextElement.textContent = decryptedText;
      ciphertextElement.setAttribute('data-decrypted', 'true');
      toggleButton.innerHTML = "🔓"; // Show unlock icon
    }
  }

  // Docsify plugin to handle decryption
  function decryptContent(hook, vm) {
    hook.afterEach(function(html, next) {
      console.log("Docsify hook afterEach triggered.");

      // Find all ciphertext blocks
      const regex = /<pre[^>]*><code[^>]*class="lang-ciphertext"[^>]*>([\s\S]*?)<\/code><\/pre>/g;
      let match;
      let modifiedHtml = html;

      while ((match = regex.exec(html)) !== null) {
        const ciphertext = match[1].trim();
        console.log("Ciphertext block found:", ciphertext);
        
        // Add key and lock emoji buttons to trigger passphrase input and encryption status
        const keyButton = `<span class="decrypt-key" style="cursor: pointer;">🔑</span>`;
        const lockButton = `<span class="decrypt-toggle" style="cursor: pointer;">🔒</span>`;
        const placeholder = `<pre><code class="lang-ciphertext" data-decrypted="false">${ciphertext}</code></pre>`;
        modifiedHtml = modifiedHtml.replace(match[0], keyButton + lockButton + placeholder);
      }

      next(modifiedHtml);
    });

    // Hook to handle the click event on the key and lock/unlock buttons
    hook.doneEach(function() {
      document.querySelectorAll('.decrypt-key').forEach(keyButton => {
        keyButton.addEventListener('click', function() {
          const ciphertextElement = keyButton.nextElementSibling.nextElementSibling.querySelector('code');
          const ciphertext = ciphertextElement.textContent.trim();
          requestPassphrase(ciphertextElement, ciphertext, keyButton.nextElementSibling); // Pass both the lock button and ciphertext element
        });
      });

      document.querySelectorAll('.decrypt-toggle').forEach(lockButton => {
        lockButton.addEventListener('click', function() {
          const ciphertextElement = lockButton.nextElementSibling.querySelector('code');
          const ciphertext = ciphertextElement.textContent.trim();
          const passphrase = getPassphrase(); // Fetch passphrase from localStorage every time
          
          if (ciphertextElement.getAttribute('data-decrypted') === 'true') {
            toggleDecryptedContent(ciphertextElement, null, ciphertext, lockButton); // Revert to encrypted text
          } else if (passphrase) {
            decrypt(ciphertext, passphrase).then(decryptedText => {
              if (decryptedText) {
                toggleDecryptedContent(ciphertextElement, decryptedText, ciphertext, lockButton); // Decrypt and toggle
              } else {
                console.error("Failed to decrypt content.");
                alert("Decryption failed. Please enter the correct key.");
              }
            });
          } else {
            console.log("No passphrase found. Please click the key icon to enter a passphrase.");
          }
        });
      });
    });
  }

  // Expose the plugin to global scope
  window.decryptContentPlugin = decryptContent;
})();
