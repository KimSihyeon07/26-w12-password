export function checkStrength(pw) {
  if (!pw) {
    return { level: 'none', label: '대기', score: 0, checks: [] };
  }

  let score = 0;
  const checks = [
    { label: '8자 이상', ok: pw.length >= 8 },
    { label: '12자 이상', ok: pw.length >= 12 },
    { label: '소문자 포함', ok: /[a-z]/.test(pw) },
    { label: '대문자 포함', ok: /[A-Z]/.test(pw) },
    { label: '숫자 포함', ok: /[0-9]/.test(pw) },
    { label: '특수문자 포함', ok: /[^A-Za-z0-9]/.test(pw) },
  ];

  if (pw.length >= 8) score += 20;
  if (pw.length >= 12) score += 20;
  if (/[a-z]/.test(pw)) score += 12;
  if (/[A-Z]/.test(pw)) score += 13;
  if (/[0-9]/.test(pw)) score += 15;
  if (/[^A-Za-z0-9]/.test(pw)) score += 20;

  const weakPattern = /(1234|qwer|asdf|password|admin)/i.test(pw) || /(.)\1{2,}/.test(pw);
  if (weakPattern) score -= 25;

  score = Math.max(5, Math.min(100, score));
  if (score < 45) return { level: 'weak', label: '약함', score, checks, weakPattern };
  if (score < 75) return { level: 'medium', label: '보통', score, checks, weakPattern };
  return { level: 'strong', label: '강함', score, checks, weakPattern };
}

function pickRandomChar(pool) {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return pool[bytes[0] % pool.length];
}

export function generatePassword({ length = 16, upper = true, lower = true, number = true, symbol = true }) {
  const groups = [];
  if (upper) groups.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (lower) groups.push('abcdefghijklmnopqrstuvwxyz');
  if (number) groups.push('0123456789');
  if (symbol) groups.push('!@#$%^&*()-_=+[]{}?');

  const activeGroups = groups.length ? groups : ['abcdefghijklmnopqrstuvwxyz0123456789'];
  const allChars = activeGroups.join('');
  const len = Math.max(6, Math.min(64, Number(length) || 16));

  const bytes = new Uint32Array(len);
  crypto.getRandomValues(bytes);
  const chars = Array.from({ length: len }, (_, i) => allChars[bytes[i] % allChars.length]);

  // 선택한 문자 종류가 최소 1글자씩 포함되도록 보장
  const indices = Array.from({ length: len }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const rand = new Uint32Array(1);
    crypto.getRandomValues(rand);
    const j = rand[0] % (i + 1);
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }

  const slotsToForce = Math.min(len, activeGroups.length);
  for (let i = 0; i < slotsToForce; i++) {
    chars[indices[i]] = pickRandomChar(activeGroups[i]);
  }

  return chars.join('');
}

async function toSha1Upper(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

export async function checkBreach(pw) {
  const hash = await toSha1Upper(pw);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;

  const res = await fetch(url, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const text = await res.text();
  for (const line of text.split('\n')) {
    const [hSuffix, countStr] = line.trim().split(':');
    const count = Number(countStr);
    if (hSuffix === suffix && count > 0) {
      return { breached: true, count, prefix, suffix, url };
    }
  }
  return { breached: false, count: 0, prefix, suffix, url };
}

async function deriveAesKey(passphrase, saltBytes) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function encryptNote(passphrase, plainText) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plainText)
  );
  return JSON.stringify({
    s: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(cipherBuf)),
  });
}

export async function decryptNote(passphrase, payloadJson) {
  const parsed = JSON.parse(payloadJson);
  const salt = base64ToBytes(parsed.s);
  const iv = base64ToBytes(parsed.iv);
  const ct = base64ToBytes(parsed.ct);
  const key = await deriveAesKey(passphrase, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(plainBuf);
}