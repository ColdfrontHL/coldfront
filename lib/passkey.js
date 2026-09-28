// WebAuthn PRF ceremonies shared by the popup and the fallback window.
import { unlockWithPasskey, addPasskeyWrap, validateVault, b64u } from './vault.js';

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
export const NO_PRF = 'This passkey provider does not support the PRF extension, so it cannot protect the vault. Use the passphrase, or try Chrome\'s own passkeys (Google Password Manager) or a security key.';

async function getVault() { const v = (await chrome.storage.local.get('vault')).vault; return v ? validateVault(v) : null; }

// Passing the credential's transports lets Chrome route straight to the provider that holds it
// (Touch ID, Google Password Manager, a security key) instead of asking which kind of passkey.
async function prfFromGet(credentialId, prfSalt, transports) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      rpId: chrome.runtime.id,
      allowCredentials: [{ type: 'public-key', id: b64u.dec(credentialId), ...(transports?.length ? { transports } : {}) }],
      userVerification: 'required',
      hints: transports?.includes('internal') ? ['client-device'] : undefined,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const out = assertion.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error(NO_PRF);
  return new Uint8Array(out);
}

// Runs ONE device prompt and returns the decrypted key; checks the vault did not change meanwhile.
// A cancelled prompt and "this provider does not hold the credential" are the same NotAllowedError by
// design, so this never starts a second prompt on its own: cancelling must not open Chrome's
// device chooser. For a passkey registered before transports were stored, the error carries
// `legacyRouting` so the caller can offer an unrouted attempt on the user's NEXT press.
export async function passkeyUnlock({ unrouted = false } = {}) {
  const vault = await getVault();
  const w = vault?.wraps?.passkey;
  if (!w) throw new Error('No passkey registered for this vault.');
  const known = Array.isArray(w.transports) && w.transports.length > 0;
  const transports = unrouted ? [] : (known ? w.transports : ['internal']);
  let prfOutput;
  try { prfOutput = await prfFromGet(w.credentialId, b64u.dec(w.prfSalt), transports); }
  catch (e) { if (!known && !unrouted) { try { e.legacyRouting = true; } catch {} } throw e; }
  const { key } = await unlockWithPasskey(vault, prfOutput);
  const current = await getVault();
  if (!current || current.id !== vault.id || current.wraps.passkey?.credentialId !== w.credentialId) throw new Error('The vault or passkey changed while the prompt was open. Nothing was unlocked.');
  return { key, vault, credentialId: w.credentialId };
}

// Creates a device passkey and binds its PRF secret to the vault. Needs the vault key from a passphrase unlock.
export async function passkeyRegister(vault, vaultKey) {
  const prfSalt = rand(32);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: rand(32),
      rp: { id: chrome.runtime.id, name: 'Coldfront' },
      user: { id: rand(16), name: 'Coldfront vault', displayName: 'Coldfront vault' }, // no account data: passkey lists can be synced and shown elsewhere
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      hints: ['client-device'],
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const ext = cred.getClientExtensionResults();
  if (!ext.prf?.enabled) throw new Error(NO_PRF);
  let transports = [];
  try { transports = cred.response.getTransports ? cred.response.getTransports() : []; } catch {}
  const credentialId = b64u.enc(cred.rawId);
  let prfOutput = ext.prf.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  if (!prfOutput) prfOutput = await prfFromGet(credentialId, prfSalt, transports);
  const current = await getVault();
  if (!current || current.id !== vault.id) throw new Error('The vault was deleted or replaced while the passkey was being created. Nothing was saved.');
  const updated = await addPasskeyWrap(current, vaultKey, { credentialId, prfOutput, prfSalt });
  updated.wraps.passkey.transports = transports;
  // Commit through the worker queue against the vault on disk; a deletion during the wrap cannot be undone by this write.
  const r = await chrome.runtime.sendMessage({ type: 'vaultWrite', expectId: vault.id, vault: updated });
  if (!r || r.error) throw new Error(r?.error || 'Could not save the passkey.');
  return updated;
}

export function friendlyPasskeyError(e) {
  if (e?.name === 'NotAllowedError') return e.legacyRouting ? 'The passkey prompt was cancelled, or this passkey lives on another device. Press again to choose from all your devices.' : 'The passkey prompt was cancelled or timed out.';
  if (e?.name === 'SecurityError') return 'This browser does not allow passkeys from extension pages: ' + e.message;
  return e?.message || String(e);
}
