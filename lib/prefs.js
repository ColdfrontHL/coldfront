// User preferences (chrome.storage.local 'prefs'). Applied at page load for theme and motion.
export const DEFAULT_PREFS = {
  autoLock: 30,            // minutes; 0 = until the browser closes
  idleLock: 0,             // minutes of system idle before locking; 0 = off
  lockOnTabsClosed: false, // lock when the last Hyperliquid tab closes
  approvalCheck: true,     // ask Hyperliquid's public info endpoint whether the agent is approved
  motion: 'calm',          // 'full' | 'calm' | 'off'
  passkeyHost: 'popup',    // 'popup' | 'window' (auto-set to window if the popup gets closed by the OS prompt)
  wipeAfterBoot: true,     // remove the key from page storage once the app has read it (it reads once, at boot)
};
export const AUTOLOCK_OPTIONS = [5, 15, 30, 60, 240, 0];
export const IDLE_OPTIONS = [0, 2, 5, 15, 30];

export async function getPrefs() {
  const { prefs } = await chrome.storage.local.get('prefs');
  return sanitize({ ...DEFAULT_PREFS, ...(prefs || {}) });
}
// Saves go through the worker's queue. A queue inside this module would only order the writes of ONE page: the popup,
// the setup tab and the passkey window each import their own copy, and their read-modify-writes could still cross.
export async function setPrefs(patch) {
  const r = await chrome.runtime.sendMessage({ type: 'prefsPatch', patch });
  if (!r || r.error) throw new Error((r && r.error) || 'Could not save the setting.');
  return r.prefs;
}
export function sanitize(p) {
  return {
    autoLock: AUTOLOCK_OPTIONS.includes(Number(p.autoLock)) ? Number(p.autoLock) : 30,
    idleLock: IDLE_OPTIONS.includes(Number(p.idleLock)) ? Number(p.idleLock) : 0,
    lockOnTabsClosed: !!p.lockOnTabsClosed,
    approvalCheck: p.approvalCheck !== false,
    motion: ['full', 'calm', 'off'].includes(p.motion) ? p.motion : 'calm',
    passkeyHost: ['popup', 'window'].includes(p.passkeyHost) ? p.passkeyHost : 'popup',
    wipeAfterBoot: p.wipeAfterBoot !== false,
  };
}
// Stamp motion on <html>; returns the prefs.
export async function applyPrefs() {
  const p = await getPrefs();
  document.documentElement.dataset.motion = p.motion;
  return p;
}
