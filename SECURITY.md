# Security Policy

`cerberust` sits on the security boundary between an application and a language
model: it handles secrets and PII, and — with the `wasm` feature — executes
untrusted third-party guard components. A vulnerability here can leak the very
data the library exists to protect, so we take reports seriously.

## Supported versions

`cerberust` is pre-1.0. Security fixes land on the latest released `0.x` line;
there is no backporting to earlier versions. Upgrade to the newest release to
receive fixes.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private security advisories](https://github.com/taostat/cerberust/security/advisories/new).
This keeps the report confidential until a fix is available and gives us a
private channel to coordinate.

Please include:

- the affected version (or commit) and feature flags in use,
- a description of the issue and its impact,
- steps to reproduce or a proof-of-concept, and
- any suggested remediation, if you have one.

## What to expect

- We aim to acknowledge a report within a few business days.
- We will confirm the issue, determine affected versions, and keep you updated
  on remediation progress.
- Once a fix is released we will publish an advisory and credit the reporter,
  unless you prefer to remain anonymous.

## Scope

Reports of particular interest:

- redaction bypasses that let PII or secrets reach a model or a model's
  response unmasked,
- vault sentinel pre-imaging or cross-request value splicing,
- sandbox escapes in the WASM guard runner (`wasm` feature) — any path by which
  a guest component gains ambient authority (filesystem, network, clock) or
  exfiltrates text it was handed, and
- ReDoS or other denial-of-service via caller-supplied or built-in patterns.

The ML prompt-injection scanner (`prompt-injection` feature) is a probabilistic
classifier; missed or over-eager classifications are accuracy limitations, not
vulnerabilities, unless they stem from a memory-safety or input-handling defect.
