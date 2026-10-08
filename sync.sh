#!/bin/bash
# Copies the published parts of the Coldfront extension from the private repository and refuses to finish if any
# withheld component leaks in. Usage: bash sync.sh [path to the private repo]
set -euo pipefail
cd "$(dirname "$0")"
SRC="${1:-../hl-agent-login}"
PUBLIC_LIB=(vault.js passkey.js eth.js auth.js prefs.js evict.js referral.js)
PUBLIC_TEST=(eth.test.mjs evict.test.mjs vault.test.mjs)
for f in "${PUBLIC_LIB[@]}"; do cp "$SRC/lib/$f" "lib/$f"; done
for f in "${PUBLIC_TEST[@]}"; do cp "$SRC/test/$f" "test/$f"; done
# withheld: the referral gate and the component that hands the API key to the Hyperliquid app
# lib/referral.js is published although it names REF_CODE: it is the one request the extension signs, so it must be readable
if grep -rIl --exclude=referral.js -e "hyperliquid.api_wallet" -e "REF_CODE" -e "referralOf" -e "slotValue" -e "getSlot" lib test; then
  echo "A withheld component appeared in the public files above. Nothing is safe to publish."; exit 1
fi
for t in test/*.mjs; do node "$t" > /dev/null || { echo "FAIL $t"; exit 1; }; done
echo "synced ${#PUBLIC_LIB[@]} modules, tests pass, no withheld code"
