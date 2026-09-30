# Vendored gitleaks rules

`gitleaks.toml` is the default configuration of
[gitleaks](https://github.com/gitleaks/gitleaks) **v8.30.1**, unmodified:

- Source: `https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml`
- SHA-256: `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`
- Licence: MIT, Copyright (c) 2019 Zachary Rice — see [`LICENSE`](LICENSE)

cerberust does not read this file at runtime. `tests/gitleaks_rules.rs`
generates `src/scanner/gitleaks_rules.rs` from it and fails if the checked-in
table drifts. Which rules are left out, and why, is listed in that table's
`EXCLUDED`.

To update: replace `gitleaks.toml` with a newer release's file, update the
version and SHA-256 here and in `tests/gitleaks_rules.rs`, then run

```sh
CERBERUST_REGENERATE_GITLEAKS=1 cargo test --test gitleaks_rules
cargo test
```
