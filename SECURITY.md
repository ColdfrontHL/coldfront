# Security

## How your API key is kept

1. **Stored.** Encrypted with your passphrase (PBKDF2-SHA256, 600,000 rounds, AES-256-GCM) in the extension's own storage, which web pages cannot read. The passphrase is at least 12 characters and is never stored.
2. **Unlocked.** With the passphrase, or with Touch ID (passkey) or a security key (WebAuthn PRF). The decrypted API key is kept in the extension's session memory, with the auto-lock deadline set first.
3. **Used.** Handed to the official Hyperliquid app while unlocked, then removed from the page's storage.
4. **Locked.** Every Hyperliquid tab reloads so the app forgets the API key, and each tab is checked. Coldfront locks after the time you choose, when the computer is idle or locked, or when the last Hyperliquid tab closes.

An API key can place, change and cancel orders. It cannot withdraw, send, transfer between accounts or approve other wallets; Hyperliquid enforces this. Withdrawals always need your cold wallet.

## What Coldfront does not protect against

- Malware on your computer while Coldfront is unlocked.
- A compromised Hyperliquid website, or another extension allowed to run on it, while unlocked.
- Trades you did not mean to make: the API key can trade.
- A fake copy of Coldfront. Install only from the link on https://cold-front.xyz.

## Latest internal review (round 6, 28 September 2026)

This is our own review, not an independent audit. No outside security firm has reviewed Coldfront yet.

No critical findings. No finding lets a website, another extension's messages or a network attacker take the API key from the vault, or unlock Coldfront without the passphrase or passkey.

| Severity | Finding | Status |
|---|---|---|
| Major | Whoever controls the publisher account could ship a harmful update | Controls in progress: hardware-key login for the publisher account, and a SHA-256 hash of every uploaded package in the README |
| Medium | While unlocked, code running on the Hyperliquid site can use the API key to trade | Inherent to how the official app accepts API wallets; limited by locking |
| Minor | The API key is briefly in the page's storage on disk while the app starts | Removed as soon as the app has read it |
| Minor | The referral check runs on the user's machine | Accepted; it does not affect key safety |
| Minor | Passphrases are checked for length only | A common-password check is planned |
| Info | Seven smaller items (wording, tests, disclosures) | Fixed or accepted |

## Reporting

Email security@cold-front.xyz. Please include the steps to reproduce and the extension version.
