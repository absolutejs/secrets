# @absolutejs/secrets changelog

## 0.0.1 — 2026-05-29

Initial release.

- `createSecretBroker({ adapter, audit, cacheTtlMs, redactionMinLength, clock })`
  factory.
- `resolve(name)` → `{ value, fingerprint }`. Pulls from cache if fresh,
  otherwise asks the adapter. `fingerprint` is the sha256 prefix of the
  value, safe to log.
- `rotate(name)` calls `adapter.rotate?` and invalidates the cache.
- `invalidate(name?)` clears one entry or the whole cache.
- `redact(text)` walks every known secret value in the cache and replaces
  it with `[REDACTED:name]` in any string. Use this on text destined for a
  log sink before it leaves the host. Skips matches shorter than
  `redactionMinLength` (default 8) to avoid blanking out coincidental
  short-string matches.
- `audit` hook fires on every `resolve` / `rotate` / cache miss with
  `{ event, name, fingerprint?, ok, at }`.
- Bundled adapters:
  - `inMemoryAdapter({ initial?, rotate? })` — pure in-process map. Great
    for tests and dev.
  - `envAdapter({ prefix?, env? })` — reads `process.env`, optionally
    prefix-scoped. `rotate` is unsupported.
  - `compositeAdapter([adapter, ...])` — tries each adapter in order;
    the first non-null value wins. `rotate` and `put` are forwarded to
    the first adapter that supports them.
- Pure host-side, single-process v0.0.1. AWS Secrets Manager / Vault /
  Doppler / Infisical adapters ship in later versions as their own
  subpaths or sibling packages.
