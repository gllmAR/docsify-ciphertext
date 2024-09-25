# docsify-ciphertext

This Docsify plugin allows you to encrypt and decrypt sections of your markdown content using a passphrase. Users can click a key icon to input a passphrase and decrypt all encrypted fields on the page. The encrypted content is protected using AES-256-GCM encryption, ensuring that only users with the correct passphrase can view the decrypted content.
the passphase is

## Exemple


```passphrase
myPassphrase
```


```ciphertext
KLLKb4dGZep+Clqf5OsUqPo1LDy48g+Jn8idWEmre4ThlQwgjdYnHufB4FIDXyZ70Dsnbp5VbhuHbto4ZfR1
```



## Encoder / Decoder 

[ciphertext](./cipher.html ':include :type=iframe width=100% height=800px')

* [ciphertext encrypt/decrypt ](/cipher.html)


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


## Tests 

### Lorem ipsum

```markdown
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum accumsan accumsan lectus vitae fermentum. Etiam dapibus ligula blandit, finibus neque et, feugiat nisi. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris condimentum massa sit amet neque aliquam, ac commodo lorem euismod. Praesent tristique pellentesque venenatis. Cras libero ex, feugiat quis neque at, dictum sagittis ex. Phasellus id aliquet felis. Aenean porta erat ac accumsan efficitur. Donec quis vehicula lorem, at efficitur nibh. 
```

```ciphertext
Gwb7NfJa2J8HLJ2UtVs7ft7xz0IzP1fBH1N27XCM4SJPzg1aGD/m8q9Cni+wkeUbJC3rqf5/s7i3QD6CrjVtlrY+mpK25Amx4Hw6a5J4djUlBf+ov6FB5QhFAdfPnj9WMD3MV25rO/9SLVIx7pf8IhDv6S2Vh+UWz6vgHx3z9b7yrwoi2hZZH4+cSVQv8JrBrcZV+MYl5xWGYA+mF575fNsxlcOR8BRwWzicHDDRIzWkP26v0MLgpKtwSqttn7v9Q/CWf8FEFcX2osV7keAozUrASqnoSwyKD7E3pyjlEQ5VEtKNr7PCRtlHDHCi0uAazwycrgtSJfzmtbKTmtHMXk+r8mKHoUkvK++soq2uJwfVajlOYhf1nHAIo5FsmQmlY7YFcg63oMbJCKA39/U5bcNJ+cZ0ztMEY3PWEs5obOYs4PrVPYQtylP/yNx+6bOmuG/V1W9idXsqByRBKZP7Rxa1ogrLcThU2yiS9R5TA5ubq1MpAK2+MV3tHieuRXsWltKsX3A4EOw8x52wWVNq3Bx6z7gnqNI74g4FYTnerbSI5UTLkcrynG0OTKKgzYSO54/f5S6HONChXVxwz0IJnfupw7pESYDVLDlklA2IiemjgKJCZNWihVOuS0g+HffbSRyDm60WJFjKjC8Xg2QMML12Nu48o7M1xl90nfvwTyi0mFNn9la3Ev3E+R0RM8tOfiDdOyfka4BrAbi5GBjlB1nnfYsG0uUt8xAxq4ILKvb5+ZpL
```

### ASCII

```markdown
Hello, this is an ASCII test.
Characters: A-Z, a-z, 0-9
Symbols: ! @ # $ % ^ & * ( ) _ + - = [ ] { } ; : ' " , . < > / ? | \ ~
```

```ciphertext
u4V96t9L6mugvpliWleLa40kNqw2l4HzLlnCBKrP+9tMnIe/I5IIa70MzVCZihvnXwkhCrA1UXLrkts63J3ZWK//qcRibzXK3i+dpgfD1RlDMb3StNHT2IDufQ0hjwi4oXUTCsrvZe5RMVWJ7HLRowgQzblCbeI85Rnyh2Isrsc5yhWb7Yt9v5CWHlC/amIaFIoB2DH8ll8j1JuA246EsCEKfYL11rYM5/U=
```

### UTF-8

```markdown
This is a UTF-8 test.
Accented characters: é, à, ö, ç, ñ, ü, ø, å
Greek letters: α, β, γ, δ, ε, ζ, η, θ, λ, μ, π, σ, τ, φ, ω
Currency symbols: €, ¥, £, ₹
Math symbols: ∑, ∞, √, ∫, ≠, ≤, ≥
```

```ciphertext
Gaua0/pwJBP8oJ2Csjd86AIVXHRc3Vn1Mn4rtcaepCJXe7HTZyGJnHEuQQuLEg/Othol4U7e+1OuQFHhZ17/WEfEJNiZRx5AJtV0pberkTN/lB8PLP/K/uo8MdJfShz3aUlMOSwZOr8GTTn3gTfNiLc7rJyiAILwMU/P7weztGFH1JBkphhae0bk8t9nJa3YIPtWlojI/jhn0iVcx5X9w5zATd1vZd4VxTUlzo6bTnwtq/g3QsD795AdWMQdNrAgQ0Tp0IZW/iWymoKn49ScLoQzbSvTjgwsHmyAgifML4Vw0vx6IdTR6D+Btsw/g/gxF1FYEonLQNUqDIKDRMCFxvZN7PShelFN6nWdb/Jl58tfTQ==
```

### Emoji


```markdown
This is an Emoji test.
Faces: 😀 😁 😂 🤣 😍
Animals: 🐶 🐱 🦊 🐻 🦁
Nature: 🌳 🌻 🌞 🌈 🌊
Objects: 🚗 ✈️ 🖥️ 📱 🎧

```

```ciphertext
nnzLYcp6LTlZEM5glRsUdb7bHzzB3e1hoA8EkDk/UMClPnX/0DgmBmY2u/A8TAHZTsE035/yxqCs8omXqyAJfMVTlc1IjiN92mGVJq9XRyeRPTU/vSi8zYr+Mf5iuE/e2vzDsYYqpsS2ayKy/7sE5Sw3k7XTp/pa7JNZGA9ATJpZqq+5sjko1q2tX20r7baccVFHxEt0Q4CHZ4XJLITbSdhXy28zCc4pqGhelx9J8X2QkdizNVoQ/e2WFSpY/L8i9FLKyOCMhM6wiKf8
```

### JSON


```markdown
{
  "name": "Alice",
  "age": 30,
  "email": "alice@example.com",
  "interests": ["coding", "encryption", "reading"]
}

```

```ciphertext
/hSKMVdgtBLN++f7gnMyDJlO6koBh2Gvt5n20NNdViEtE0cVwiwcEkiW3+kfYezP8W2i1oqQZFJ5g8bABlIpl0cKcC29DcVAE0iyFz7yAFVKTF3D21qIDZjUQLeiWz10dIptGcuRmI4yJmt9+f5O6xSEQbyj070uVSTiwg5KjV1FSyQvLRnA2iLX2LCz37DAU+DGqfSQG+SBow0PC4BkK2aZ

```

