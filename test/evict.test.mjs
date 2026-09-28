// Unit test for lib/evict.js: when may the worker count a tab as locked? Run: node test/evict.test.mjs
import { confirmReplaced } from '../lib/evict.js';

let failures = 0;
const check = (cond, label, extra = '') => { console.log((cond ? 'ok   ' : 'FAIL ') + label + (extra ? '  ' + extra : '')); if (!cond) failures++; };

// A fake clock: sleep() advances virtual time and resolves on a later macrotask, so an immediate whoami answer or
// rejection always settles first, the way a real message reply beats a 600 ms timer.
// `tab` is the tab Chrome reports: an object, or a function of the virtual time.
function io({ answers, tab = { url: 'https://app.hyperliquid.xyz/trade', status: 'complete' }, closed = false }) {
  let t = 0, calls = 0;
  return {
    now: () => t,
    sleep: (ms) => new Promise((r) => setTimeout(() => { t += ms; r(); }, 0)),
    whoami: () => { const a = answers(calls++, t); if (a === 'hang') return new Promise(() => {}); if (a === 'none') return Promise.reject(new Error('Receiving end does not exist.')); return Promise.resolve(a); },
    getTab: () => (closed ? Promise.reject(new Error('No tab with id')) : Promise.resolve(typeof tab === 'function' ? tab(t) : tab)),
    isHl: (u) => typeof u === 'string' && u.startsWith('https://app.hyperliquid.xyz/'),
    elapsed: () => t,
    calls: () => calls,
  };
}
const SINCE = 1000;

{ const x = io({ answers: () => 'none' });
  const r = await confirmReplaced(x, 1, SINCE, 'old');
  check(r === false, 'no receiver while the tab still shows Hyperliquid is NOT proof of eviction', 'virtual ms ' + x.elapsed()); }
{ const x = io({ answers: () => 'none', closed: true });
  check((await confirmReplaced(x, 1, SINCE, 'old')) === true, 'no receiver and the tab is closed: gone'); }
{ const x = io({ answers: () => 'none', tab: { url: undefined } });
  check((await confirmReplaced(x, 1, SINCE, 'old')) === true, 'no receiver and the tab shows another site: the old document is not displayed'); }
{ const x = io({ answers: () => ({ doc: 'old', born: 5 }) });
  check((await confirmReplaced(x, 1, SINCE, 'old')) === false, 'the old document keeps answering: not replaced'); }
{ const x = io({ answers: () => ({ doc: 'new', born: 5 }) });
  check((await confirmReplaced(x, 1, SINCE, 'old')) === true, 'a different document answers (old one had acknowledged the lock): replaced, whatever the clocks say'); }
{ const x = io({ answers: () => ({ doc: 'z', born: SINCE - 1 }) });
  check((await confirmReplaced(x, 1, SINCE, null)) === false, 'no acknowledgement and only a document born before the lock answers: not replaced'); }
{ const x = io({ answers: () => ({ doc: 'z', born: SINCE + 1 }) });
  check((await confirmReplaced(x, 1, SINCE, null)) === true, 'no acknowledgement and a document born after the lock answers: replaced'); }
{ const x = io({ answers: (n) => (n < 3 ? 'none' : { doc: 'new', born: SINCE + 50 }) });
  check((await confirmReplaced(x, 1, SINCE, 'old')) === true, 'no receiver during the reload, then the new document answers: replaced'); }
{ const x = io({ answers: () => 'hang' });
  const r = await confirmReplaced(x, 1, SINCE, 'old');
  check(r === false && x.elapsed() <= 4000 + 600 + 200, 'a silent tab: not replaced, and the check ends at its deadline (not 10 slow rounds)', 'virtual ms ' + x.elapsed()); }

// A slow connection: the old document stays on screen (and answers) while the tab loads the new one.
const LOADING = { url: 'https://app.hyperliquid.xyz/trade', status: 'loading' };
{ const x = io({ answers: (n, t) => (t < 7000 ? { doc: 'old', born: 5 } : { doc: 'new', born: SINCE + 7000 }), tab: (t) => (t < 7000 ? LOADING : { url: LOADING.url, status: 'complete' }) });
  const r = await confirmReplaced(x, 1, SINCE, 'old');
  check(r === true, 'a reload that is still loading after 4 s is waited for, and confirmed when the new document answers', 'virtual ms ' + x.elapsed()); }
{ const x = io({ answers: () => ({ doc: 'old', born: 5 }), tab: LOADING });
  const r = await confirmReplaced(x, 1, SINCE, 'old');
  check(r === false && x.elapsed() >= 12000 && x.elapsed() <= 12000 + 600 + 200, 'a tab that stays "loading" is still given up at the hard cap (12 s)', 'virtual ms ' + x.elapsed()); }
{ const x = io({ answers: () => ({ doc: 'old', born: 5 }) });
  const r = await confirmReplaced(x, 1, SINCE, 'old');
  check(r === false && x.elapsed() < 4000 + 600 + 200 + 1, 'a tab that sits on its old document (not loading) gets no extra time', 'virtual ms ' + x.elapsed()); }

console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
process.exit(failures ? 1 : 0);
