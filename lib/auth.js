// Every unlock presents an attempt token that the worker issued BEFORE the authentication began (before the
// passphrase derivation, before the passkey prompt). A lock, or another unlock, starts a new epoch in the worker,
// so an authentication that was already under way when the user locked cannot open a session afterwards.
export async function beginAuth() {
  const r = await chrome.runtime.sendMessage({ type: 'authBegin' });
  if (r && r.error === 'unknown message') throw new Error('Coldfront was updated on disk but the running copy is older. Reload it on chrome://extensions, then try again.');
  if (!r || r.error || typeof r.attempt !== 'string') throw new Error((r && r.error) || 'Could not start the unlock.');
  return r.attempt;
}
