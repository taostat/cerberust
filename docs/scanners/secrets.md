# SecretScanner — API keys & credentials

## What it protects you from

Secrets end up in prompts constantly, and almost always by accident. A developer
pastes a stack trace with an API key in it. Someone drops a config file into a
"what's wrong with this?" prompt. A `.env` line sneaks into a code snippet. Every
one of those sends a live credential to a model provider — and worse, a model asked
to "repeat the config above" will happily **echo the secret straight back** to the
user.

`SecretScanner` catches credentials in both directions: API keys, tokens, private
keys, and labelled secrets. It masks them on the way to the model so the provider
never sees them, and — by default — **never** restores them, so they're never
echoed back either.

## Why you'd use it

- **Secrets never reach the provider.** They're replaced with a placeholder before
  the model call.
- **One-way by default.** Unlike PII, a secret is never put back in the reply. Once
  masked, it stays masked — for the model, the provider, and the user.
- **It catches the bespoke ones too.** Beyond known vendor formats, a high-entropy
  backstop flags opaque tokens that match no known pattern, so your internal
  service token doesn't slip through just because it isn't an AWS key.

## Quick example

```rust
use cerberust::{ScanCtx, Scanner, SecretScanner};

let scanner = SecretScanner::new();
let mut ctx = ScanCtx::new();

let verdict = scanner.scan("deploy with AKIAIOSFODNN7EXAMPLE", &mut ctx)?;
assert!(verdict.text.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
assert!(!verdict.text.contains("AKIAIOSFODNN7EXAMPLE"));
# Ok::<(), cerberust::ScanError>(())
```

Drop it into a stack alongside `PiiScanner` and `RestoreScanner::for_pii()` — the
PII round-trips, the secret stays redacted, because the PII restorer only owns the
PII entity types.

## How it works

Four layers of detection, all emitting spans into the shared redact path:

1. **Known vendor formats** — exact patterns for credentials with a recognizable
   shape:
   - the original set: AWS access keys (`AKIA…`), GitHub tokens (`ghp_…`), Stripe
     live keys (`sk_live_…`), OpenAI keys (`sk-…`), Google API keys (`AIza…`),
     Slack webhook URLs and PEM private-key blocks (full block, and the lone
     header for truncated keys);
   - **200 rules ported from [gitleaks](https://github.com/gitleaks/gitleaks)
     v8.30.1** — GitHub fine-grained and app tokens, GitLab, Anthropic, Slack
     `xox*`, JWTs, npm, PyPI, Hugging Face, Datadog, Twilio, SendGrid, Vault,
     cloud providers and many more. The table is generated from the vendored
     upstream config (`data/gitleaks/`), not copied by hand, and matched with
     gitleaks' own semantics: a rule's regex runs only when one of its keywords
     occurs, the redacted span is the rule's secret capture group, an entropy
     minimum drops placeholder-like values, and gitleaks' allowlists and
     stopwords apply;
   - Taostats API keys: `gm_live_…`, `bm_live_…`, `ts_live_…` and
     `tao-<uuid>:<signature>`.

   Not ported, because a one-way redactor must not damage prompts: gitleaks'
   `generic-api-key` (a keyword-plus-assignment rule that flags too much ordinary
   code; the entropy backstop below covers opaque tokens), OAuth client IDs and
   other identifiers, publishable/public keys meant to be embedded in clients,
   and rules gitleaks scopes to file paths (a prompt has no path). The full list,
   with reasons, is `EXCLUDED` in `src/scanner/gitleaks_rules.rs`.

   Known limits of the ported rules: `heroku-api-key` matches any UUID assigned
   near the word "heroku" (Heroku keys are UUIDs), and `twilio-api-key` matches
   any `SK` followed by 32 hex characters. gitleaks' detection of secrets
   inside base64- or hex-encoded text is not ported; encoded secrets are left to
   the entropy backstop. `sourcegraph-access-token` stays keyword-gated even
   though its keyword can sit outside the token (its bare 40-hex form would
   match every git SHA), so on a stream a Sourcegraph token whose keyword was
   flushed in an earlier chunk is missed.

   When an original pattern and a ported rule match the same span, the original
   type name wins (`AWS_ACCESS_KEY`, `GITHUB_TOKEN`, …), so existing
   placeholders keep their names. Ported rules name their placeholders after
   the gitleaks rule id (`github-fine-grained-pat` → `GITHUB_FINE_GRAINED_PAT`).

2. **Labelled secrets** — `password=…`, `api_key: …`, `token = …`, prefixed
   labels such as `db_password: …` or `DB_PASSWORD=…`, the `passphrase`,
   `credentials`, `private_key`, `secret_key`, `signing_key` and
   `encryption_key` labels, and
   `scheme://user:password@host` URL credentials. Here it redacts **just the
   value**, not the label, so `password=hunter2` becomes `password=[REDACTED…]`.
   Unquoted type annotations, function calls and attribute references, plus
   complete environment/template references and exact common placeholders,
   are left intact. Quoted literals are still scanned even when their contents
   resemble code. Typed assignments and literal defaults in `os.getenv` and
   `os.environ.get` redact the value while preserving the surrounding code.
   For example, `password: Optional[str] = None`,
   `token = self.tokenizer(text)`, `password=${DB_PASSWORD}` and
   `token=YOUR_TOKEN` do not produce labelled-secret redactions.
   A double-quoted JSON key ending in a credential label, such as
   `{"password": "…"}` or `"db_password": "…"`, also produces value-only spans
   when its decoded value is a single-token string. `null`, booleans, numbers,
   objects, masked or bracketed placeholders, references, schema/type hints,
   common display labels, and pagination keys such as `next_token` and
   `previous_token` are left intact by this rule.

3. **Seed phrases** — runs of words from the BIP39 English wordlist, redacted as
   `SEED_PHRASE`. Words may be separated by whitespace, commas, semicolons,
   hyphens, quotes, backticks or brackets (JSON arrays and code lists match) and
   optionally numbered. A run of exactly 12, 15, 18, 21 or 24 list words is
   redacted even if its checksum fails, since one mistyped word leaves a phrase
   brute-forceable. Inside a longer run, the checksum picks out the phrase; this
   is what keeps ordinary prose, where many list words are common English, from
   matching. On a stream, a trailing run of list words is held back until a
   non-list word ends it, so a phrase is never split across flushes.

4. **High-entropy backstop** — for the credential that matches no known pattern.
   Each whitespace-delimited token that *looks* like an opaque secret (long, and
   either hex or base64-ish) must contain at least three of lowercase letters,
   uppercase letters, digits and symbols before its Shannon entropy is measured.
   This keeps pure-hex hashes and lowercase/alphanumeric identifiers out of the
   generic `SECRET` path; pure-hex credentials need a format-specific rule.
   Checksum-valid SS58 account indices and 32/33-byte public-key addresses,
   Bitcoin P2PKH/P2SH Base58Check addresses, and syntactically valid SRI digests
   are also left intact. The
   character-class and identifier checks run before the entropy calculation.

## Structural crypto formats

These detections require an exact key shape, a checksum, or a named field. A
transaction hash, block hash, wallet address, Git SHA, or public development
identifier does not become a secret just because it is long or hexadecimal.

- **GM, Blockmachine, and Taostats** retain their existing entity types and
  accept both `*_live_` and `*_test_` prefixes followed by exactly 64 lowercase
  hexadecimal characters.
- **Bittensor** reports `BITTENSOR_SEED` for a `0x` value with exactly 64 hex
  characters after a `seed` flag/label or the keyfile's `secretSeed` field.
  `BITTENSOR_PRIVATE_KEY` covers 64 or 128 hex characters in the keyfile's
  `privateKey` field, with an optional `0x`. `BITTENSOR_SECRET_PHRASE` redacts
  the quoted value of `secretPhrase`. These field names follow the
  [btwallet keyfile source][btwallet-keyfile].
- **Substrate secret URIs** match a 32-byte hex seed with a hard or soft
  derivation path, or a valid BIP39 phrase followed by a path. The mnemonic
  checksum is required. The public `//Alice`-style development URIs and the
  public Substrate development phrase remain untouched. See the
  [sp-core SecretUri format](https://docs.rs/sp-core/latest/sp_core/crypto/struct.SecretUri.html).
- **Ethereum private keys** are exactly 64 hex characters, optionally with
  `0x`, and must follow a named assignment such as `PRIVATE_KEY`,
  `DEPLOYER_PRIVATE_KEY`, or `secret_key`. Bare transaction and block hashes
  are not candidates. The 20 public local development keys from Hardhat's
  documented test mnemonic are allowlisted; they are intended only for local
  development. See [Ethereum account documentation](https://ethereum.org/developers/docs/accounts)
  and [Hardhat network reference](https://v2.hardhat.org/hardhat-network/docs/reference).
- **Bitcoin WIF** values are Base58Check-decoded and checked for the mainnet or
  testnet version, 32-byte payload, optional compression marker, and
  double-SHA-256 checksum. **BIP32 extended private keys** validate the 78-byte
  payload, private version bytes, private key marker, and checksum for xprv,
  tprv, and the verified SLIP-132 private prefixes. See the
  [WIF format](https://en.bitcoin.it/wiki/Wallet_import_format),
  [BIP32](https://bitcoin.org/bip/32/), and
  [SLIP-0132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md).
  Public extended keys such as xpub and tpub and Bitcoin addresses remain
  unflagged.
- **Solana keypairs** require a `secretKey`, `keypair`, or `solana` assignment
  and either a JSON array of exactly 64 byte values or a Base58 value that
  decodes to exactly 64 bytes. This checks the documented keypair shape without
  attempting curve validation. See the
  [Solana restore-keypair guide](https://solana.com/developers/cookbook/wallets/restore-keypair).

Plain 0x transaction and block hashes, 20-byte 0x addresses, SS58 addresses,
Git SHAs, Substrate development URIs, the public development phrase, xpub/tpub
values, Bitcoin addresses, and documentation placeholders stay unflagged.
Provider keys receive a dedicated rule only when a primary source defines the
complete prefix, length, and character set.

[btwallet-keyfile]: https://raw.githubusercontent.com/opentensor/btwallet/main/src/keyfile.rs

All hits are interned into the vault under a **one-way** policy: redacted on input,
never restored. Even if you pair the stack with a PII restorer, secrets stay masked,
because restore is enforced per placeholder and the restorer only owns PII types.

## Options / config

| Method | Effect |
|---|---|
| `SecretScanner::new()` | input scanner, `OneWay` (the default — never restored) |
| `.with_direction(dir)` | run on `Input` or `Output` (mask secrets the model emits) |
| `.with_policy(policy)` | override the restore policy (rarely — one-way is the safe default) |

Running it on `Direction::Output` masks secrets the **model** emits — useful when a
model might echo a credential it was shown or fabricate a plausible one.

### Structured field values

A caller that scans structured data one value at a time (JSON object values,
tool-call arguments) loses the key that labels each value. Pass it with
`ScannerStack::run_input_field(field, value)` or `run_output_field(field, value)`:
the field name is set on `ScanCtx::field` for that run, and the secret scanner
treats it as the value's label, the same way it reads `field: "value"` or
`"field": "value"` in running text. The labelled-secret rules and their
exemptions apply unchanged.

```rust
let redacted = stack.run_input_field("privateKey", value)?;
```

**Opt-in**, like every scanner — nothing runs until you add it to a `ScannerStack`.
Ships in the default build (no extra cargo feature).

## Performance

On the benchmark corpus, the secret scanner runs at **~570k samples/sec** with
**perfect precision and recall (1.00 / 1.00)**, a little under half the throughput
before the gitleaks port (1.31M samples/sec). The ratio was measured on one
machine, before and after, and applied to the published figure. On detection,
`llm-guard`'s detect-secrets recalls only 0.45 on the same corpus — it doesn't
recognize several of the OpenAI / Stripe / labelled `key=value` forms cerberust
catches. See [benchmarks](../benchmarks.md) for the full table and methodology.

Unary scan latency, release build, one machine (0.1.1 → this version):

| Input | 0.1.1 | now |
|---|---|---|
| 2 KB of ordinary prompt text | 6 µs | 12 µs |
| 51 KB negative corpus | 172 µs | 379 µs |
| 51 KB with every rule keyword repeated throughout | 192 µs | 1.5 ms |

A ported rule's regex runs only when one of its keywords occurs, and then only
over windows around the keyword hits, widened by the rule's longest possible
match. The last row is the worst case for that: every rule runs.

The streaming hold-back DFA over all secret patterns is compiled once per pattern
set and reused across streams, and keeps its state cache across pushes.

`tests/secret_precision.rs` checks the ported rules, Taostats key patterns,
seed-phrase detector and generic `SECRET` findings against ordinary prompt
content. Its corpus includes code in several languages, logs, stack traces,
JSON, prose, hashes, lockfile checksums and integrity values, code data, and
checksum-valid public addresses; it requires zero detections outside the
original format-specific vendor rules.
