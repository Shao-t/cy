# Third-party notices

## hash-wasm 4.12.0

- Project: https://github.com/Daninet/hash-wasm
- Package: `hash-wasm@4.12.0`
- Bundled file: `vendor/argon2.umd.min.js`
- SHA-256: `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094`
- License: MIT; see `vendor/hash-wasm-LICENSE`

The dependency is bundled locally so CIPHER does not fetch executable code
from a CDN at runtime. Updates must be pinned to an exact version and reviewed
before replacing the bundled file or its recorded checksum.

## BIP-39 English wordlist

- Specification: https://github.com/bitcoin/bips/tree/master/bip-0039
- Bundled file: `vendor/bip39-en.js`
- Upstream source SHA-256: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
- Bundled JavaScript SHA-256: `66901446773bb5189de77637e033e7a13780b549da86864f0e2fce9b77b0029a`
- License: MIT, as declared by BIP-39

CIPHER uses only the fixed 2,048-entry English wordlist. Its
8+1 recovery phrase is a CIPHER-specific 88-bit format and is not a BIP-39
wallet mnemonic. Wordlist changes require a new format version and review.
