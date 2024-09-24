# docsify-ciphertext

This Docsify plugin allows you to encrypt and decrypt sections of your markdown content using a passphrase. Users can click a key icon to input a passphrase and decrypt all encrypted fields on the page. The encrypted content is protected using AES-256-GCM encryption, ensuring that only users with the correct passphrase can view the decrypted content.
the passphase is
```
myPassphrase
```


```ciphertext
KLLKb4dGZep+Clqf5OsUqPo1LDy48g+Jn8idWEmre4ThlQwgjdYnHufB4FIDXyZ70Dsnbp5VbhuHbto4ZfR1
```



```ciphertext
QKqpNLtiPDxzEeZFgP4Z34jiwWYQeUlumsrNXYCMfRZoZohQD07cy6WH0IDB2QsnBvko
```

## Encoder / Decoder 

[Example](./cipher.html ':include :type=iframe width=100% height=900px')


## Features

- **Encrypt and Decrypt Content:** Use this plugin to display encrypted content in your Docsify site. Content is hidden until the correct passphrase is entered.
- **Lock/Unlock Toggle:** Once decrypted, users can toggle between the encrypted and decrypted content by clicking the lock/unlock icon.
- **Persistent Passphrase:** The passphrase is stored in `localStorage`, so users don't need to re-enter it every time they navigate between pages.
- **Multiple Fields:** Decrypt multiple fields on the same page with a single passphrase. If a field fails to decrypt, users can re-enter the correct key for that field.
- **Customizable Icons:** The plugin uses intuitive key 🔑 and lock 🔒/unlock 🔓 icons for user interaction.

## Installation

1. **Include the Plugin Script:**

   First, add the plugin JavaScript file to your Docsify site. Either download the script or link it directly in your `index.html` file.

   ```html
   <script src="decrypt-plugin.js"></script>
   ```

2. **Initialize the Plugin:**

   After including the script, add the following configuration in your Docsify settings (usually in the `index.html`):

   ```html
   <script>
     window.$docsify = {
       name: 'Docsify Ciphertext Decryption Plugin',
       plugins: [
         window.decryptContentPlugin,
         // Other plugins...
       ]
     };
   </script>
   ```

3. **Encrypt Your Content:**

   To encrypt content, you can use a Node.js script that generates AES-256-GCM encrypted ciphertext from plaintext data (see [Usage](#usage) below). Insert the encrypted content into your markdown like this:

   ```markdown
   ```ciphertext
   KLLKb4dGZep+Clqf5OsUqPo1LDy48g+Jn8idWEmre4ThlQwgjdYnHufB4FIDXyZ70Dsnbp5VbhuHbto4ZfR1
   ```
   ```

## Usage

1. **Encrypting Content (Node.js):**

   You can encrypt content using the following Node.js script to produce AES-256-GCM ciphertext:

   ```javascript
   const crypto = require('crypto');

   function encrypt(data, passphrase) {
     const salt = crypto.randomBytes(16);
     const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
     const iv = crypto.randomBytes(12);
     const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
     const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
     const authTag = cipher.getAuthTag();
     return Buffer.concat([salt, iv, authTag, encrypted]).toString('base64');
   }

   const passphrase = 'myPassphrase';
   const data = 'https://example.com';

   console.log(encrypt(data, passphrase));
   ```

   Use this script to encrypt your content and include the ciphertext in your markdown files.

2. **Decryption Flow:**

   - **🔑 Key Icon:** Clicking this icon prompts the user to input the passphrase. The key is stored in `localStorage` and used to decrypt any encrypted fields on the page.
   - **🔒 Lock Icon:** Clicking this icon decrypts the content if the correct key has been entered. It then changes to an unlock icon.
   - **🔓 Unlock Icon:** Clicking this icon reverts the content back to its encrypted state.

3. **Toggling Content:**

   Users can toggle between the encrypted and decrypted versions of the content by interacting with the lock and unlock icons. All encrypted content is protected by AES-256-GCM encryption.

## API

The plugin adds two user interaction icons:

- **🔑 Key Icon:** Prompts the user to enter a passphrase. The passphrase is stored in `localStorage` for convenience.
- **🔒/🔓 Lock/Unlock Icon:** Used to toggle between the encrypted and decrypted content.

## Example

Here’s an example of how encrypted content would look in your markdown:

```markdown
# My Secret Links

Here are my secret links. Decrypt them using the 🔑 key icon. Remove the backslash "\" to make it work

\```ciphertext
KLLKb4dGZep+Clqf5OsUqPo1LDy48g+Jn8idWEmre4ThlQwgjdYnHufB4FIDXyZ70Dsnbp5VbhuHbto4ZfR1
\```

```

After entering the passphrase, users will be able to see the decrypted content, which may look like a URL, text, or any other data you encrypted.

## Security

- **AES-256-GCM Encryption:** The plugin uses strong AES-256-GCM encryption, which provides confidentiality and integrity verification through authentication tags. Only users with the correct passphrase can decrypt the content.
- **Passphrase Management:** The passphrase is stored in `localStorage`, so the user doesn't need to re-enter it as they navigate between pages. You can clear the passphrase using the `clearPassphrase` function if needed.

## Limitations

- **Client-Side Encryption:** The encryption and decryption happen entirely on the client side. Ensure that your use case aligns with this approach.
- **No Password Recovery:** If a user forgets the passphrase, there is no way to recover the encrypted content without knowing the correct key.
