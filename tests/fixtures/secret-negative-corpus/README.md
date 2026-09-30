# Secret-scanner negative corpus

Ordinary prompt content for `tests/secret_precision.rs`: source code (Rust,
Python, TypeScript, Go, SQL), web and JSON logs, stack traces, API responses,
prose (including a run of BIP39 wordlist words with an invalid checksum),
hashes and digests, base64 data URIs, Bittensor SS58 addresses and hashes,
Kubernetes YAML, and docs with placeholder keys.

Everything here is synthetic. Identifiers, hashes and addresses were generated
from a fixed random seed; none is a credential, and none belongs to a real
account. The ported vendor rules, the Taostats key patterns and the seed-phrase
detector must find nothing in these files.
