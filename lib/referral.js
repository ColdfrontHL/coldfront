// The one request Coldfront ever signs: "set referral code COLDFRONT on this account", sent to Hyperliquid's exchange
// endpoint when the user presses "Apply code" in setup. It is the request Hyperliquid's own app sends when a user
// presses "Join with code" (an ordinary action signed by the API wallet); verified byte for byte against the official
// SDK (test/sign.test.mjs). It can only set a referral code: this module builds no other action.
// Chrome's affiliate policy: the code is applied only by that click, never on its own.
import { keccak256, signDigest } from './eth.js';
import { REF_CODE } from './hl.js';

const EXCHANGE = 'https://api.hyperliquid.xyz/exchange';
const enc = new TextEncoder();
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const str = (s) => { const b = enc.encode(s); if (b.length > 31) throw new Error('String too long.'); return cat(Uint8Array.of(0xa0 | b.length), b); }; // msgpack fixstr
const word = (n) => { const o = new Uint8Array(32); let v = BigInt(n); for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };

// keccak256(msgpack({type, code}) + nonce as 8 bytes big-endian + 0x00 for "no vault"), as Hyperliquid hashes an action.
function actionHash(code, nonce) {
  const packed = cat(Uint8Array.of(0x82), str('type'), str('setReferrer'), str('code'), str(code));
  return keccak256(cat(packed, word(nonce).slice(24), Uint8Array.of(0)));
}
// EIP-712: domain { name "Exchange", version "1", chainId 1337, verifyingContract 0x0 }, struct Agent { source "a" (mainnet), connectionId }.
const DOMAIN = keccak256(cat(keccak256(enc.encode('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')), keccak256(enc.encode('Exchange')), keccak256(enc.encode('1')), word(1337), word(0)));
const AGENT_TYPE = keccak256(enc.encode('Agent(string source,bytes32 connectionId)'));
export function referralDigest(code, nonce) {
  const struct = keccak256(cat(AGENT_TYPE, keccak256(enc.encode('a')), actionHash(code, nonce)));
  return keccak256(cat(Uint8Array.of(0x19, 0x01), DOMAIN, struct));
}
export async function signReferral(privateKey, nonce, code = REF_CODE) {
  if (!Number.isSafeInteger(nonce) || nonce <= 0) throw new Error('Bad nonce.');
  if (typeof code !== 'string' || !/^[A-Z0-9]{1,20}$/.test(code)) throw new Error('Bad referral code.');
  return { action: { type: 'setReferrer', code }, nonce, signature: await signDigest(privateKey, referralDigest(code, nonce)), vaultAddress: null };
}

// Sends it. Resolves { ok: true } or { ok: false, reason } with Hyperliquid's own words; rejects only when the request did not reach Hyperliquid (or it did not answer in 15 seconds).
export async function applyReferral(privateKey) {
  const body = await signReferral(privateKey, Date.now());
  const r = await fetch(EXCHANGE, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  if (!r.ok) return { ok: false, reason: 'error ' + r.status + '. Try again in a minute.' };
  const j = await r.json();
  if (j?.status === 'ok') return { ok: true };
  return { ok: false, reason: String(typeof j?.response === 'string' ? j.response : 'Hyperliquid refused the request.').slice(0, 200) };
}
