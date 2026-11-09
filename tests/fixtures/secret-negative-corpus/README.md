# Secret-scanner negative corpus

Ordinary prompt content for `tests/secret_precision.rs`: source code (Rust,
Python, TypeScript, Go, SQL), web and JSON logs, stack traces, API responses,
transaction and block hashes, mixed-case public addresses, Git SHAs, Substrate
development URIs, the public development phrase, BIP32 public vectors, Bitcoin
addresses, local development account keys, RNG seeds, and documentation
placeholders. It also includes prose with BIP39 wordlist words and an invalid
checksum, base64 data URIs, Bittensor SS58 addresses, lockfile integrity values,
and Kubernetes YAML. `secret-precision-regressions.txt` records prior false
positives from image digests, SRI, type annotations, code expressions, and
lockfiles.

Everything here is synthetic or a public-by-design development/test vector.
The Hardhat and Anvil account values are the documented local-only defaults and
must not be used on a public network. The precision test requires zero findings
outside the original format-specific vendor rules.
