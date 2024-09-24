#!/usr/bin/env node

const crypto = require('crypto');
const child_process = require('child_process');
const os = require('os');

// Function to display help
function displayHelp() {
    console.log('Usage: node crypto-cli.js [options]');
    console.log('');
    console.log('Options:');
    console.log('  -h, --help          Display help information');
    console.log('  -e, --encrypt       Encrypt mode');
    console.log('  -d, --decrypt       Decrypt mode');
    console.log('  -i, --input <data>  Input data (URL or ciphertext)');
    console.log('  -p, --passphrase    Passphrase for encryption/decryption');
    console.log('  -c, --copy          Copy output to clipboard');
    console.log('');
    console.log('Examples:');
    console.log('  node crypto-cli.js -e -i "https://example.com" -p "myPassphrase" -c');
    console.log('  node crypto-cli.js -d -i "<ciphertext>" -p "myPassphrase" -c');
}

// Function to encrypt data
function encrypt(url, passphrase) {
    // Derive a key from the passphrase
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

    // Encrypt the URL
    const iv = crypto.randomBytes(12); // AES-GCM requires a 12-byte IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(url, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    // Combine salt, iv, authTag, and encrypted data
    const encryptedData = Buffer.concat([
        salt,
        iv,
        authTag,
        Buffer.from(encrypted, 'base64')
    ]).toString('base64');

    return encryptedData;
}

// Function to decrypt data
function decrypt(encryptedDataBase64, passphrase) {
    try {
        const encryptedData = Buffer.from(encryptedDataBase64, 'base64');

        // Extract salt, iv, authTag, and encrypted content
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const authTag = encryptedData.slice(28, 44);
        const encryptedContent = encryptedData.slice(44);

        // Derive the key using PBKDF2
        const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

        // Decrypt the data
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedContent, undefined, 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        // Decryption failed
        return null;
    }
}

// Function to copy text to clipboard
function copyToClipboard(text) {
    const platform = os.platform();

    try {
        if (platform === 'win32') {
            // Windows
            const proc = child_process.spawn('clip');
            proc.stdin.write(text);
            proc.stdin.end();
        } else if (platform === 'darwin') {
            // macOS
            const proc = child_process.spawn('pbcopy');
            proc.stdin.write(text);
            proc.stdin.end();
        } else if (platform === 'linux') {
            // Linux
            // Try xclip first
            const proc = child_process.spawn('xclip', ['-selection', 'clipboard']);
            proc.stdin.on('error', function(err) {
                // If xclip is not installed, try xsel
                const procXsel = child_process.spawn('xsel', ['--clipboard', '--input']);
                procXsel.stdin.write(text);
                procXsel.stdin.end();
                procXsel.stdin.on('error', function(err) {
                    console.error('Error: xclip or xsel is required to copy to clipboard on Linux.');
                });
            });
            proc.stdin.write(text);
            proc.stdin.end();
        } else {
            console.error('Error: Unsupported platform. Clipboard copy is not available.');
        }
    } catch (err) {
        console.error('Error copying to clipboard:', err.message);
    }
}

// Parse command-line arguments
const args = process.argv.slice(2);

if (args.includes('-h') || args.includes('--help') || args.length === 0) {
    displayHelp();
    process.exit(0);
}

let mode = null;
let input = null;
let passphrase = null;
let copyOutput = false;

for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
        case '-e':
        case '--encrypt':
            mode = 'encrypt';
            break;
        case '-d':
        case '--decrypt':
            mode = 'decrypt';
            break;
        case '-p':
        case '--passphrase':
            passphrase = args[i + 1];
            i++;
            break;
        case '-i':
        case '--input':
            input = args[i + 1];
            i++;
            break;
        case '-c':
        case '--copy':
            copyOutput = true;
            break;
        default:
            console.log(`Unknown argument: ${arg}`);
            displayHelp();
            process.exit(1);
    }
}

if (!mode || !input || !passphrase) {
    console.log('Error: Missing required arguments.');
    displayHelp();
    process.exit(1);
}

if (mode === 'encrypt') {
    const encrypted = encrypt(input, passphrase);
    console.log('Encrypted Data:');
    console.log(encrypted);
    if (copyOutput) {
        copyToClipboard(encrypted);
        console.log('Encrypted data copied to clipboard.');
    }
} else if (mode === 'decrypt') {
    const decrypted = decrypt(input, passphrase);
    if (decrypted) {
        console.log('Decrypted Data:');
        console.log(decrypted);
        if (copyOutput) {
            copyToClipboard(decrypted);
            console.log('Decrypted data copied to clipboard.');
        }
    } else {
        console.log('Decryption failed. Incorrect passphrase or corrupted data.');
    }
} else {
    console.log('Error: Unknown mode.');
    displayHelp();
    process.exit(1);
}
