// Decides whether a tab's old document is really gone after the worker asked for a reload. chrome.tabs.reload
// resolves when a reload is INITIATED, and a message that finds no receiver proves nothing: the old document may
// simply have lost its content script (after an extension reload, say) while it keeps running. So only positive
// evidence counts: the tab was closed, the tab now shows another site, or a newer document of ours answers (a
// different document id when the old one acknowledged the lock, otherwise one born after the lock began).
// After the normal deadline the check waits on only while Chrome shows the tab as loading its new document (a slow
// connection keeps the old document on screen until the new one arrives; so does a page too busy to let its reload
// through), up to a hard cap. A tab that is not loading, because it sits on its old document, counts as "not replaced"
// at the normal deadline, one still loading at the cap counts the same, and the popup says to close it.
// Dependencies are passed in so the rule can be unit-tested with a fake clock (test/evict.test.mjs).
export async function confirmReplaced(io, tabId, since, oldDoc, { timeoutMs = 4000, loadingTimeoutMs = 12000, probeMs = 600, pauseMs = 200 } = {}) {
  const start = io.now();
  while (io.now() < start + loadingTimeoutMs) {
    // Ask the tab first: when a load finishes, the new document is already there to answer.
    const r = await Promise.race([
      io.whoami(tabId).then((x) => (x && typeof x === 'object' ? x : 'silent'), () => 'no receiver'),
      io.sleep(probeMs).then(() => 'silent'),
    ]);
    if (typeof r === 'object' && (oldDoc ? r.doc !== oldDoc : r.born >= since)) return true;
    const pastDeadline = io.now() >= start + timeoutMs;
    if (r === 'no receiver' || pastDeadline) {
      let tab;
      try { tab = await io.getTab(tabId); } catch { return true; } // closed
      if (!tab || !io.isHl(tab.url)) return true; // shows another site: the old document is not the one displayed
      if (pastDeadline && tab.status !== 'loading') return false; // not on its way to a new document
    }
    await io.sleep(pauseMs);
  }
  return false;
}
