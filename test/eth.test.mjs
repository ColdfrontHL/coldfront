import { privateKeyToAddress, checksumAddress, keccak256 } from '../lib/eth.js';
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const cases = [
  ['0x' + '1'.padStart(64, '0'), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'],
  ['0x' + '2'.padStart(64, '0'), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf'],
  ['0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318', '0x2c7536e3605d9c16a7a3d7b1898e529396a65c23'],
];
let ok = true;
for (const [k, want] of cases) { const got = privateKeyToAddress(k); console.log(got === want ? 'ok ' : 'FAIL', k.slice(0, 10), got); ok &&= got === want; }
const kh = hex(keccak256(new TextEncoder().encode('')));
console.log(kh === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' ? 'ok ' : 'FAIL', 'keccak("")');
ok &&= kh === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const cs = checksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
console.log(cs === '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed' ? 'ok ' : 'FAIL', 'EIP-55', cs);
ok &&= cs === '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
process.exit(ok ? 0 : 1);
