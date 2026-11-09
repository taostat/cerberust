# Secret-scanner negative corpus

Ordinary prompt content for `tests/secret_precision.rs`: source code (Rust,
Python, TypeScript, Go, SQL), web and JSON logs, stack traces, API responses,
prose (including a run of BIP39 wordlist words with an invalid checksum),
hashes and digests, base64 data URIs and code samples, Bittensor SS58 addresses
and hashes, lockfile integrity/checksum lines, Kubernetes YAML, and docs with
placeholder keys. `secret-precision-regressions.txt` records confirmed false
positives from git and image digests, SRI, type annotations, code expressions,
and lockfiles.

Everything here is synthetic. Identifiers, hashes and checksummed public
addresses use deterministic test data; no credential is included. The precision
test requires zero findings outside the original format-specific vendor rules.
