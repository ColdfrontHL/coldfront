# Coldfront: published source

Coldfront is a Chrome extension for trading on Hyperliquid from the account your cold wallet holds, without connecting the wallet every time. Your cold wallet signs once to authorize an API key; Coldfront keeps that API key encrypted on your computer and gives it to the official Hyperliquid app while unlocked. Website: https://cold-front.xyz. X: https://x.com/ColdfrontHL.

This repository publishes the parts of Coldfront that protect your API key, so anyone can check how it is stored and unlocked. It follows the approach hardware-wallet makers such as Ledger use: the security-critical code is public; some product components are not.

## What is here

| File | What it does |
|---|---|
| `lib/vault.js` | The encrypted vault: PBKDF2-SHA256 (600,000 rounds) → AES-256-GCM, a random vault key wrapped once per unlock method, the account fields authenticated as additional data, and a bounded schema check before any cryptography |
| `lib/passkey.js` | Touch ID (passkey) and security-key unlock through the WebAuthn PRF extension; the PRF output wraps the vault key through HKDF |
| `lib/eth.js` | Address derivation (secp256k1, keccak-256) used to show and check the API wallet address. It never signs anything |
| `lib/evict.js` | The rule that decides whether a Hyperliquid tab was really reloaded after a lock |
| `lib/auth.js` | The authentication epoch: an unlock that started before a lock cannot complete after it |
| `lib/prefs.js` | Settings and their allowed values |
| `test/` | Unit tests for the above |

## What is not here, and why

Two components are not published:

- **The referral check**, which limits Coldfront to accounts that joined Hyperliquid with code COLDFRONT. It is how a free tool made by a small independent team is paid for; it has no effect on how your API key is protected.
- **The handoff to the Hyperliquid app**: how the extension gives the API key to the app while unlocked, removes it from the page and reloads the tabs on lock. Its behaviour, and what it does not protect against, is described on https://cold-front.xyz/security/ and was part of every security review.

The extension installed from the Chrome Web Store contains both components. Like any Chrome extension, its installed package can be inspected.

## Verify

```
node test/eth.test.mjs
node test/evict.test.mjs
node test/vault.test.mjs
```

Node 20 or newer. The files here are copied unchanged from the extension's source for each release.

## Releases

| Version | SHA-256 of the package uploaded to the Chrome Web Store |
|---|---|
| 1.0.0 | `e5de31968ea18bd501923730327192de55db507e633be8c9da21328acea0b4e8` |

## Security reviews

Six internal review rounds and 157 automated checks, including checks against the live Hyperliquid app. Coldfront has not had an independent audit yet. A summary of the latest review is in `SECURITY.md`. To report a problem: security@cold-front.xyz.

## Licence

PolyForm Shield 1.0.0 (see `LICENSE.md`). You may read, run, change and share this code, including in your own products, except to build a product that competes with Coldfront. `NOTICE` contains the required notice that must travel with any copy.
