# @absolutejs/secrets changelog

## 0.4.0 — 2026-05-31

Durable adapter — closes the "where do my secrets actually live"
question. `envAdapter` is dev-only, `inMemoryAdapter` is for tests,
neither survives a process restart. `encryptedFileAdapter` is the
production-ready durable surface — committable to a private repo
with the master key kept separately.

### Added — `encryptedFileAdapter`

- AES-256-GCM via Web Crypto. Zero runtime deps; works in Bun and
  Node 20+ without extra packages.
- Per-value random 12-byte IV. Same plaintext encrypted twice
  produces different ciphertext.
- Two master-key shapes:
  - `{ type: 'passphrase', passphrase }` — PBKDF2-SHA256, default
    600k iterations (OWASP 2025 recommendation for SHA-256). Salt
    stored in the file.
  - `{ type: 'raw', bytes }` — 32 raw bytes. No KDF. Useful when
    the key comes from a vendor secret manager.
- Atomic file writes via temp + `rename`. Concurrent reader sees
  either old or new, never half-written.
- Cross-mode mismatch caught loudly (passphrase ↔ raw).
- AES-GCM's auth tag means wrong key surfaces as a clear "wrong
  master key or corrupted file" error, not silent garbage.
- Lazy init: KDF + file read on first `fetch`/`put`.
- `io` override for tests so suites don't touch disk.
- `rotate` override matching `inMemoryAdapter` for structured tokens.

### File format

```json
{
  "version": 1,
  "kdf": { "type": "pbkdf2-sha256", "iterations": 600000, "salt": "<base64>" },
  "values": { "STRIPE_KEY": { "iv": "<base64>", "ct": "<base64>" } }
}
```

`kdf` omitted when master key is raw bytes. Safe to commit (it's all
base64 ciphertext) as long as the master key stays out of the repo.

### Composition with `@absolutejs/deploy/env`

```ts
const adapter = encryptedFileAdapter({
  path: './.secrets.enc.json',
  key: { type: 'passphrase', passphrase: process.env.SECRETS_MASTER! },
});
const broker = createSecretBroker({ adapter });

await broker.rotate('STRIPE_KEY');                        // re-encrypts the file
await syncSecretsToDeployments(broker, deployments);      // pushes to every target
```

### Tests

17 new tests (`tests/encryptedFile.test.ts`) — passphrase + raw key
round-trips, wrong-passphrase failure, per-value IV uniqueness, salt
stability, cross-mode mismatch detection, SecretAdapter contract
(list/remove/rotate), broker composition, real filesystem
round-trip, atomic-write guarantee.

Test count: 53 → 70.

## 0.3.0 — 2026-05-30

### Added — OpenTelemetry tracing via @absolutejs/telemetry

Closes G2 (deep-research audit) for the secret broker.

- **`SecretBrokerOptions.tracerProvider?: TracerProvider`** — any
  `@opentelemetry/api`-compatible `TracerProvider`. Structural type
  via `@absolutejs/telemetry`; no peer-dep on `@opentelemetry/api`.
- **`secrets.resolve` span** wraps every `resolve()` call with
  `abs.secret.name` attribute. On cache hit and on adapter
  fulfillment, `abs.secret.fingerprint` is set (sha256-derived;
  safe-for-log). `secrets.cache = "hit" | "miss"` distinguishes the
  paths. `secrets.found = false` when the adapter returned null.
- **`secrets.rotate` span** wraps every `rotate()` call with the same
  attributes (new fingerprint after the rotation succeeds).
- **`redact()` is NOT traced** — it's called per log line, which
  would explode span volume. Use the existing audit hook for
  per-redaction signals if you need them.
- Status mapping: ERROR + `recordException` on adapter throw; OK
  otherwise (including null-not-found resolves).
- `@absolutejs/telemetry` added as a regular dep.
- Zero-cost when `tracerProvider` is omitted.

5 new tests in `tests/tracing.test.ts`: cache hit / miss / not-found
/ adapter error / rotate. Plus noop fallback.

Test count: 48 → 53.

## 0.2.0 — 2026-05-29

Substrate-pattern uniformity. Backwards-compatible — new surface is additive.

### Added

- **`broker.metrics()`** returns `SecretBrokerMetrics` — cumulative
  counters since `createSecretBroker()`: `resolves`, `resolveHits`,
  `resolveMisses`, `resolveErrors`, `rotates`, `rotateErrors`,
  `invalidations`, `redactCalls`, `redactionsApplied`,
  `redactionsBase64`. Survives `drain()` and `dispose()` so the
  operator can read final state post-shutdown.

- **`broker.drain()`** flips the broker into draining state — new
  `resolve()` / `rotate()` calls reject with `BrokerDrainedError`
  (new export). In-flight adapter calls keep running to completion.
  Symmetric with `runtime.drain()` / `queue.drain()` /
  `HibernatingIsolatePool.drain()`. Use this during graceful
  shutdown so a tenant whose process is about to stop doesn't issue
  a fresh fetch against the secret store mid-teardown.

11 new tests in `tests/metrics.test.ts`. Test count: 37 → 48.

## 0.1.0 — 2026-05-29

Substrate-deepening pass. Backwards-compatible — new surface is additive.

### Added

- **`broker.redactStream()`** — returns a `TransformStream<string, string>`.
  Streaming variant of `redact()` that catches secrets even when they
  straddle a chunk boundary. The transform keeps a lookback buffer the size
  of the longest cached secret, redacts the WHOLE buffer per chunk (so
  in-flight secrets become labels), then holds back the tail until the next
  chunk arrives. Drop-in for any log forwarder so plaintext secrets never
  reach the sink — `tenantStdout.pipe(broker.redactStream()).pipe(loki)`.
- **`broker.onRotate(name, listener)`** — subscribe to rotation events for
  a specific name. Listener fires AFTER the new value lands in the cache,
  with `{ name, value, fingerprint, at }`. Returns an unsubscribe handle.
  Use this for long-lived connections (DB clients, AI SDKs, WebSocket
  servers) that need to swap credentials in-place. Multiple listeners on
  the same name all fire; a throwing listener doesn't crash `rotate`.
- **`cacheTtlOverrides: Record<string, number>`** — per-name TTL override.
  High-blast-radius secrets (admin tokens, signing keys) can refresh more
  often than the global default; rarely-changing ones can refresh less.
- **`redactionEncodings: ('plain' | 'base64')[]`** — by default `redact`
  looks for the raw value. Add `'base64'` and the broker also looks for
  the base64-encoded form of every cached secret — useful when secrets
  end up inside JWTs, cookies, or any payload that base64-wraps a
  credential. Labels distinguish: `[REDACTED:NAME]` vs `[REDACTED:NAME:b64]`.

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
