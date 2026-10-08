// Minimal, dependency-free secp256k1 + keccak-256: derives the API wallet address, and signs ONE kind of message,
// the referral-code request that setup sends when the user presses "Apply code" (lib/referral.js). Nothing else is signed.

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = [
  0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
];

const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) {
  // extended Euclid: returns a^-1 mod m
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}
function add(p, q) {
  if (!p) return q;
  if (!q) return p;
  const [x1, y1] = p, [x2, y2] = q;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  let l;
  if (x1 === x2 && y1 === y2) l = mod(3n * x1 * x1 * inv(2n * y1));
  else l = mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}
function mul(k, p) {
  let r = null, a = p;
  while (k > 0n) {
    if (k & 1n) r = add(r, a);
    a = add(a, a);
    k >>= 1n;
  }
  return r;
}

// keccak-256 (original padding 0x01, not SHA-3's 0x06)
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
  0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
  0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => (n === 0n ? x : ((x << n) | (x >> (64n - n))) & M64);
function keccakF(A) {
  for (let r = 0; r < 24; r++) {
    const C = [], D = [];
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
    for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], BigInt(ROT[x][y]));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & M64) & B[((x + 2) % 5) + 5 * y]);
    A[0] ^= RC[r];
  }
}
export function keccak256(bytes) {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
      A[i] ^= lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) { let lane = A[i]; for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xFFn); lane >>= 8n; } }
  return out;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export function normalizePrivateKey(input) {
  let k = String(input || '').trim();
  if (k.startsWith('0x') || k.startsWith('0X')) k = k.slice(2);
  if (!/^[0-9a-fA-F]{64}$/.test(k)) throw new Error('Private key must be 64 hex characters, with or without 0x.');
  const n = BigInt('0x' + k);
  if (n === 0n || n >= N) throw new Error('Private key is out of range.');
  return '0x' + k.toLowerCase();
}

export function privateKeyToAddress(privKey) {
  const k = BigInt(normalizePrivateKey(privKey));
  const [x, y] = mul(k, G);
  const pub = new Uint8Array(64);
  const xh = x.toString(16).padStart(64, '0'), yh = y.toString(16).padStart(64, '0');
  for (let i = 0; i < 32; i++) { pub[i] = parseInt(xh.slice(i * 2, i * 2 + 2), 16); pub[32 + i] = parseInt(yh.slice(i * 2, i * 2 + 2), 16); }
  return '0x' + hex(keccak256(pub)).slice(24);
}

export function normalizeAddress(input) {
  const a = String(input || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error('Address must be 0x followed by 40 hex characters.');
  return a.toLowerCase();
}

export function checksumAddress(addr) {
  const a = normalizeAddress(addr).slice(2);
  const h = hex(keccak256(new TextEncoder().encode(a)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

// ECDSA over secp256k1 with a deterministic nonce (RFC 6979, HMAC-SHA256), low-s, Ethereum recovery value.
// `digest` is the 32-byte hash to sign. Returns { r, s, v } as Hyperliquid's API takes them (0x hex, v = 27 or 28).
const toBytes32 = (n) => { const h = n.toString(16).padStart(64, '0'); const o = new Uint8Array(32); for (let i = 0; i < 32; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return o; };
const toBig = (bytes) => BigInt('0x' + hex(bytes));
async function hmac(key, ...parts) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const len = parts.reduce((n, p) => n + p.length, 0); const msg = new Uint8Array(len); let o = 0;
  for (const p of parts) { msg.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}
export async function signDigest(privKey, digest) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error('A 32-byte digest is required.');
  const d = BigInt(normalizePrivateKey(privKey));
  const z = toBig(digest);
  const x = toBytes32(d), h1 = toBytes32(mod(z, N));
  let V = new Uint8Array(32).fill(1), K = new Uint8Array(32);
  K = await hmac(K, V, Uint8Array.of(0), x, h1); V = await hmac(K, V);
  K = await hmac(K, V, Uint8Array.of(1), x, h1); V = await hmac(K, V);
  for (let i = 0; i < 64; i++) {
    V = await hmac(K, V);
    const k = toBig(V);
    if (k > 0n && k < N) {
      const R = mul(k, G);
      const r = mod(R[0], N);
      let s = mod(inv(k, N) * (z + r * d), N);
      if (r !== 0n && s !== 0n && R[0] < N) {
        let rec = Number(R[1] & 1n);
        if (s > N / 2n) { s = N - s; rec ^= 1; }
        return { r: '0x' + r.toString(16).padStart(64, '0'), s: '0x' + s.toString(16).padStart(64, '0'), v: 27 + rec };
      }
    }
    K = await hmac(K, V, Uint8Array.of(0)); V = await hmac(K, V);
  }
  throw new Error('Could not sign.');
}

export const shortAddress = (a) => (a ? a.slice(0, 6) + '…' + a.slice(-4) : '');
