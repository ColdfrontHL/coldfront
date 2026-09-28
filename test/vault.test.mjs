// Vault round trip and tamper checks for lib/vault.js. Run: node test/vault.test.mjs (Node 20+, WebCrypto built in)
import { createVault, unlockWithPassphrase, validateVault, PBKDF2_ITERATIONS } from '../lib/vault.js';

let failures = 0;
const check = (cond, label) => { console.log((cond ? 'ok   ' : 'FAIL ') + label); if (!cond) failures++; };
const rejects = async (p) => { try { await p; return false; } catch { return true; } };

const master = '0x' + '11'.repeat(20), agentAddress = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';
const privateKey = '0x' + '1'.padStart(64, '0'), passphrase = 'correct horse battery staple';
const v = await createVault({ master, name: 'desk', agentAddress, privateKey, passphrase });

check(v.wraps.passphrase.iterations === PBKDF2_ITERATIONS && PBKDF2_ITERATIONS === 600000, 'passphrase wrap uses PBKDF2-SHA256 with 600,000 rounds');
check(!JSON.stringify(v).includes(privateKey.slice(2)), 'the stored vault does not contain the API key in plain text');
check((await unlockWithPassphrase(v, passphrase)).key === privateKey, 'the right passphrase opens the vault');
check(await rejects(unlockWithPassphrase(v, 'wrong passphrase!!')), 'a wrong passphrase is refused');
check(await rejects(unlockWithPassphrase({ ...v, master: '0x' + '22'.repeat(20) }, passphrase)), 'an edited account address makes the vault refuse to open (authenticated header)');
check(await rejects(unlockWithPassphrase({ ...v, name: 'other' }, passphrase)), 'an edited wallet name makes the vault refuse to open');
check(await rejects(createVault({ master, name: '', agentAddress, privateKey, passphrase: 'short' })), 'a passphrase under 12 characters is refused');
let threw = false; try { validateVault({ ...v, wraps: { passphrase: { ...v.wraps.passphrase, iterations: 1000 } } }); } catch { threw = true; }
check(threw, 'a vault with too few PBKDF2 rounds is rejected before any cryptography');
const v2 = await createVault({ master, name: 'desk', agentAddress, privateKey, passphrase });
check(v2.secret.iv !== v.secret.iv && v2.wraps.passphrase.salt !== v.wraps.passphrase.salt, 'every vault gets a fresh salt and IV');

console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
process.exit(failures ? 1 : 0);
