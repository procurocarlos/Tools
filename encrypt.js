#!/usr/bin/env node
/**
 * OpsBee page encryptor
 * Usage: node encrypt.js <password>
 *
 * Reads:  opsbee-version-checker-source.html  (plain app)
 * Writes: opsbee-version-checker.html         (AES-256-GCM encrypted, PBKDF2 key)
 *
 * The deployed file is an unreadable blob — source code, URLs, and logic are
 * only accessible after the correct password is entered in the browser.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const password = process.argv[2];
if (!password) { console.error('Usage: node encrypt.js <password>'); process.exit(1); }

const SRC  = path.join(__dirname, 'opsbee-version-checker-source.html');
const DEST = path.join(__dirname, 'opsbee-version-checker.html');
const ITERATIONS = 200000;

const plaintext = fs.readFileSync(SRC, 'utf8');
const salt      = crypto.randomBytes(32);
const iv        = crypto.randomBytes(12);
const key       = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');

const cipher    = crypto.createCipheriv('aes-256-gcm', key, iv);
const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
const authTag   = cipher.getAuthTag();

// Payload: salt(32) + iv(12) + ciphertext + authTag(16)
const payload = Buffer.concat([salt, iv, encrypted, authTag]).toString('base64');

const wrapper = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpsBee · Version Report</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Helvetica Neue',Arial,sans-serif;background:#2C2C2D;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .box{background:#1e1e1f;border:1px solid #333;border-radius:12px;padding:40px 32px;width:100%;max-width:340px;text-align:center}
  .logo{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:26px}
  .logo-text{color:#fff;font-size:17px;font-weight:600;letter-spacing:-.3px}
  .logo-text span{color:#FCB816}
  h2{color:#fff;font-size:14px;font-weight:600;margin-bottom:6px}
  p{color:#6B6B6C;font-size:12px;margin-bottom:22px}
  input{width:100%;padding:10px 12px;background:#2a2a2b;border:1px solid #444;border-radius:8px;color:#fff;font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
  input:focus{border-color:#FCB816}
  input.err{border-color:#993C1D;animation:shake .3s}
  button{margin-top:12px;width:100%;background:#FCB816;color:#2C2C2D;border:none;border-radius:8px;padding:10px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;transition:opacity .15s}
  button:hover{opacity:.88}
  .msg{margin-top:10px;font-size:11px;color:#993C1D;min-height:16px}
  .hint{margin-top:8px;font-size:11px;color:#4A4A4B}
  @keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none">
      <path d="M13 2L23 7.5V18.5L13 24L3 18.5V7.5L13 2Z" fill="#FCB816"/>
      <text x="13" y="17" text-anchor="middle" font-size="10" font-weight="700" fill="#2C2C2D" font-family="Arial">OB</text>
    </svg>
    <span class="logo-text">Ops<span>Bee</span></span>
  </div>
  <h2>Version Report</h2>
  <p>Enter the password to continue</p>
  <input id="pwd" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')unlock()">
  <button onclick="unlock()">Unlock</button>
  <div class="msg" id="msg"></div>
  <div class="hint" id="hint"></div>
</div>
<script>
const PAYLOAD    = '${payload}';
const ITERATIONS = ${ITERATIONS};

function b64ToBytes(b64) {
  const bin = atob(b64); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let attempts = 0;

async function unlock() {
  const pwd = document.getElementById('pwd').value;
  if (!pwd) return;

  const inp  = document.getElementById('pwd');
  const msg  = document.getElementById('msg');
  const hint = document.getElementById('hint');
  inp.disabled = true;
  msg.textContent = '';
  hint.textContent = 'Verifying…';

  try {
    const bytes      = b64ToBytes(PAYLOAD);
    const salt       = bytes.slice(0, 32);
    const iv         = bytes.slice(32, 44);
    const ciphertext = bytes.slice(44); // includes 16-byte GCM auth tag at end

    const keyMat = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pwd), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      keyMat,
      { name: 'AES-GCM', length: 256 },
      false, ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    const html      = new TextDecoder().decode(decrypted);

    document.open('text/html');
    document.write(html);
    document.close();

  } catch {
    attempts++;
    inp.disabled = false;
    inp.value = '';
    inp.classList.add('err');
    setTimeout(() => inp.classList.remove('err'), 400);
    hint.textContent = '';
    msg.textContent  = attempts >= 3
      ? \`Incorrect password (\${attempts} attempts)\`
      : 'Incorrect password';
    inp.focus();
  }
}
</script>
</body>
</html>`;

fs.writeFileSync(DEST, wrapper, 'utf8');
console.log(`✓ Encrypted → ${path.basename(DEST)}`);
console.log(`  Salt:       ${salt.toString('hex').slice(0, 16)}…`);
console.log(`  IV:         ${iv.toString('hex')}`);
console.log(`  PBKDF2:     ${ITERATIONS.toLocaleString()} iterations (SHA-256)`);
console.log(`  Cipher:     AES-256-GCM`);
