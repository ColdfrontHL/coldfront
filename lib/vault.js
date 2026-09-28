// Encrypted vault, same construction as MetaMask's browser-passworder:
// PBKDF2-HMAC-SHA256 (600k iterations) -> AES-256-GCM. A random 32-byte vault key
// encrypts the secret; the vault key is wrapped once per unlock method
// (passphrase, and optionally a passkey via the WebAuthn PRF extension + HKDF).
// Internal identifiers ('agent-login-for-hyperliquid/...' HKDF info, 'agent-login/v1' AAD) predate the Coldfront name
// and are kept for compatibility: changing them would invalidate every existing vault and passkey.
// The plaintext header fields (id, master, agentAddress, name) are authenticated as
// AES-GCM additional data, so editing them on disk makes the vault refuse to open.

const enc = new TextEncoder();
const dec = new TextDecoder();
export const PBKDF2_ITERATIONS = 600000;
export const MIN_PASSPHRASE = 12;
const ITER_MIN = 100000, ITER_MAX = 5000000;

export const b64u = {
  enc: (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0)),
};
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const isB64u = (s, min, max) => typeof s === 'string' && /^[A-Za-z0-9_-]*$/.test(s) && s.length >= min && s.length <= max;
const isAddr = (s) => typeof s === 'string' && /^0x[0-9a-f]{40}$/.test(s);

// Bounded, versioned schema check. Run before rendering or any cryptography.
export function validateVault(v) {
  const bad = (m) => { throw new Error('Vault unreadable: ' + m); };
  if (!v || typeof v !== 'object') bad('not an object');
  if (v.v !== 1) bad('unsupported version');
  // The id goes into the authenticated header next to free text (the name), so its alphabet is closed: with a '|' in it,
  // two different headers could serialise to the same bytes. Setup writes a UUID.
  if (typeof v.id !== 'string' || !/^[A-Za-z0-9-]{8,64}$/.test(v.id)) bad('missing or malformed id');
  if (!isAddr(v.master) || !isAddr(v.agentAddress)) bad('malformed address');
  if (typeof v.name !== 'string' || v.name.length > 64) bad('malformed name');
  const box = (b, ctMin, ctMax) => { if (!b || !isB64u(b.iv, 16, 16) || !isB64u(b.ct, ctMin, ctMax)) bad('malformed ciphertext'); };
  box(v.secret, 60, 400);
  const p = v.wraps?.passphrase;
  if (!p || !isB64u(p.salt, 22, 22) || !Number.isInteger(p.iterations) || p.iterations < ITER_MIN || p.iterations > ITER_MAX) bad('malformed passphrase wrap');
  box(p, 60, 80);
  const k = v.wraps?.passkey;
  if (k !== undefined) {
    if (!isB64u(k.credentialId, 16, 2048) || !isB64u(k.hkdfSalt, 43, 43) || !isB64u(k.prfSalt, 43, 43)) bad('malformed passkey wrap');
    if (k.transports !== undefined && !(Array.isArray(k.transports) && k.transports.length <= 8 && k.transports.every((t) => typeof t === 'string' && t.length <= 16))) bad('malformed passkey transports');
    box(k, 60, 80);
  }
  return v;
}

const vaultAad = (v) => 'agent-login/v1|' + v.id + '|' + v.master + '|' + v.agentAddress + '|' + v.name;

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function passKey(passphrase, salt, iterations) {
  const km = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function prfKey(prfOutput, salt) {
  const km = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('agent-login-for-hyperliquid/passkey-wrap/v1') }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, bytes, aad) {
  const iv = rand(12);
  const params = { name: 'AES-GCM', iv, ...(aad ? { additionalData: enc.encode(aad) } : {}) };
  const ct = await crypto.subtle.encrypt(params, key, bytes);
  return { iv: b64u.enc(iv), ct: b64u.enc(ct) };
}
async function open(key, box, aad) {
  const params = { name: 'AES-GCM', iv: b64u.dec(box.iv), ...(aad ? { additionalData: enc.encode(aad) } : {}) };
  return new Uint8Array(await crypto.subtle.decrypt(params, key, b64u.dec(box.ct)));
}

export function checkPassphrase(passphrase) {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE) throw new Error('Passphrase must be at least ' + MIN_PASSPHRASE + ' characters.');
}

export async function createVault({ master, name, agentAddress, privateKey, passphrase }) {
  checkPassphrase(passphrase);
  const vaultKey = rand(32);
  const salt = rand(16);
  const header = { id: crypto.randomUUID(), master, agentAddress, name: (name || '').slice(0, 64) };
  const payload = enc.encode(JSON.stringify({ key: privateKey }));
  return validateVault({
    v: 1,
    createdAt: Date.now(),
    ...header,
    secret: await seal(await aesKey(vaultKey), payload, vaultAad(header)),
    wraps: {
      passphrase: { salt: b64u.enc(salt), iterations: PBKDF2_ITERATIONS, ...(await seal(await passKey(passphrase, salt, PBKDF2_ITERATIONS), vaultKey)) },
    },
  });
}

async function openSecret(vault, vaultKey) {
  let bytes;
  try { bytes = await open(await aesKey(vaultKey), vault.secret, vaultAad(vault)); }
  catch { throw new Error('Vault integrity check failed: the stored account fields were altered.'); }
  const payload = JSON.parse(dec.decode(bytes));
  if (typeof payload.key !== 'string' || !/^0x[0-9a-f]{64}$/.test(payload.key)) throw new Error('Vault payload is malformed.');
  return { key: payload.key, vaultKey };
}

export async function unlockWithPassphrase(vault, passphrase) {
  validateVault(vault);
  const w = vault.wraps.passphrase;
  let vaultKey;
  try {
    vaultKey = await open(await passKey(passphrase, b64u.dec(w.salt), w.iterations), w);
  } catch {
    throw new Error('Wrong passphrase.');
  }
  return openSecret(vault, vaultKey);
}

export async function addPasskeyWrap(vault, vaultKey, { credentialId, prfOutput, prfSalt }) {
  const salt = rand(32);
  const wrap = await seal(await prfKey(prfOutput, salt), vaultKey);
  return validateVault({ ...vault, wraps: { ...vault.wraps, passkey: { credentialId, hkdfSalt: b64u.enc(salt), prfSalt: b64u.enc(prfSalt), ...wrap } } });
}

export async function unlockWithPasskey(vault, prfOutput) {
  validateVault(vault);
  const w = vault.wraps.passkey;
  if (!w) throw new Error('No passkey registered.');
  let vaultKey;
  try {
    vaultKey = await open(await prfKey(prfOutput, b64u.dec(w.hkdfSalt)), w);
  } catch {
    throw new Error('Passkey did not unlock the vault.');
  }
  return openSecret(vault, vaultKey);
}

export function removePasskeyWrap(vault) {
  const { passkey, ...rest } = vault.wraps;
  return { ...vault, wraps: rest };
}
