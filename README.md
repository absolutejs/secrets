# @absolutejs/secrets

Host-side secret broker for multi-tenant Bun runtimes. Three jobs, kept narrow:

1. **Resolve** secrets through a pluggable adapter. The broker caches the
   value, returns a `{ value, fingerprint }` pair where the fingerprint is
   a sha256 prefix safe to log, and fires an audit event per call.
2. **Redact** known cached secrets out of arbitrary strings (an error
   message, a stdout line, a stack trace) before the text lands in any
   log sink. Replacement: `[REDACTED:NAME]`.
3. **Rotate** through the adapter, invalidate the cache, return the new
   value.

Pure logic, zero Bun / Elysia surface. The intended consumers inside the
SB-6 substrate are `@absolutejs/sync`'s `bridgeFetch.authorization()` hook
(host-side credential injection for sandboxed mutations) and `unsafeHost`
declarations (per-customer host functions like Stripe charge, Slack ping,
queue push).

## Agent credential operations

Agents should not call `resolve()` and should never receive a bearer token.
`createCredentialOperationBroker()` instead gives them bounded capabilities:
an exact agent and user, provider, operation scopes, URL origins, expiry, and
maximum use count. The host resolves the secret only after the grant is
atomically consumed, then passes it directly to an allowlisted provider
operation. Results and audit events contain digests and identifiers, never the
credential.

Agency is a required host peer (`>=0.7.1 <0.8.0`) and is externalized from the
Secrets build. The credential broker therefore uses the host's one approval
ledger instead of embedding a second enforcement runtime. This package tests
against exactly `0.7.1`; a new Agency minor requires an explicit compatibility
release.

```ts
import {
  createCredentialOperationBroker,
  createMemoryCredentialGrantStore,
} from "@absolutejs/secrets/agent";

const grants = createMemoryCredentialGrantStore();
await grants.put({
  agentId: "research-agent",
  allowedOrigins: ["https://api.example.com"],
  createdAt: Date.now(),
  expiresAt: Date.now() + 60_000,
  grantId: "grant_123",
  maximumUses: 1,
  provider: "example",
  scopes: ["create-report"],
  secretName: "EXAMPLE_API_KEY",
  used: 0,
  userId: "user_123",
});

const operations = createCredentialOperationBroker({
  agency,
  providers: [
    {
      provider: "example",
      operations: {
        "create-report": ({ credential, destination, input, signal }) =>
          fetch(new URL("/reports", destination), {
            body: JSON.stringify(input),
            headers: { authorization: `Bearer ${credential}` },
            method: "POST",
            signal,
          }).then((response) => response.json()),
      },
    },
  ],
  secrets: broker,
  store: grants,
});
```

Use a durable `CredentialGrantStore` in production. Passing an `agency` adds
policy, approval, single-use execution lease, and receipt enforcement.
Requestable denials can be resumed after approval with
`operations.resume(actionId)`.

```ts
import {
  createSecretBroker,
  envAdapter,
  inMemoryAdapter,
  compositeAdapter,
} from "@absolutejs/secrets/broker";

const broker = createSecretBroker({
  adapter: compositeAdapter([
    inMemoryAdapter({ initial: { TEST_KEY: "sk_test_local_value" } }),
    envAdapter({ prefix: "ABS_SECRET_" }),
  ]),
  audit: (event) => observabilitySink.write(event),
  cacheTtlMs: 60_000,
});

// In bridgeFetch.authorization():
const { value, fingerprint } = (await broker.resolve("STRIPE_KEY"))!;
logger.info("charging", { tenant, fingerprint }); // safe — no plaintext
return { Authorization: `Bearer ${value}` };

// In a log sink, before text leaves the host:
const sanitized = broker.redact(line); // [REDACTED:STRIPE_KEY] replaces plaintext
sinkToCustomerVisibleLog(sanitized);

// Rotate:
const next = await broker.rotate("STRIPE_KEY");
notifyDependents(next.fingerprint); // tell consumers a new key is in cache
```

## v0.0.1 surface

| API                           | Purpose                                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `createSecretBroker(options)` | Factory. Returns a `SecretBroker`.                                                                                                          |
| `broker.resolve(name)`        | Returns `{ value, fingerprint }                                                                                                             | null`. Uses cache within `cacheTtlMs`. |
| `broker.fingerprint(value)`   | Pure helper — sha256 prefix of any string. No adapter call.                                                                                 |
| `broker.redact(text)`         | Rewrite arbitrary text, replacing every cached value (longer-first) with `[REDACTED:NAME]`. Skips values shorter than `redactionMinLength`. |
| `broker.rotate(name)`         | Calls `adapter.rotate?`, caches the result, returns it. Throws if the adapter doesn't support rotation.                                     |
| `broker.invalidate(name?)`    | Clear one entry or the whole cache.                                                                                                         |
| `broker.dispose()`            | Tear down — clears cache; subsequent resolves return `null`.                                                                                |

### Bundled adapters

| Adapter                                  | Use                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `inMemoryAdapter({ initial?, rotate? })` | Tests, dev, and starter templates. Supports every operation. Default rotate = random base36.                              |
| `envAdapter({ prefix?, env? })`          | Reads `process.env` (or any injected `env` map). Prefix-scoped to avoid leaking unrelated env vars via `list`. Read-only. |
| `compositeAdapter([...])`                | Fan-out / fallback. `fetch` falls through; writes go to the first writeable adapter.                                      |

AWS Secrets Manager / HashiCorp Vault / Doppler / Infisical / GCP Secret
Manager / Azure Key Vault adapters ship later as siblings — they're the
ones with real auth surface, so they don't belong in v0.0.1.

### Versioned overlap rotation

`defineSecretOverlapRotation`, `secretOverlapCandidateVersions`,
`verifySecretOverlapVersion`, and `secretOverlapDisposition` provide the pure
host-side state machine for zero-downtime credential changes. The current
version is always tried first, proof from the retained version cannot verify
the replacement, a proven replacement retires the old version at the deadline,
and an unproven replacement restores the known-good version. Storage adapters
retain and remove the encrypted material; these helpers keep that policy
consistent without handling plaintext.

### Audit

Every `resolve`, `rotate`, and `invalidate` fires the `audit` hook with
one of:

- `{ event: 'resolve.hit', name, fingerprint, at }`
- `{ event: 'resolve.miss', name, fingerprint?, at }` — fingerprint present when the miss turned into a cache write
- `{ event: 'resolve.error', name, error, at }` — adapter threw
- `{ event: 'rotate', name, fingerprint, at }`
- `{ event: 'invalidate', name, at }` — `name` is `null` for a full clear

A throwing or rejecting hook is logged + discarded. The broker is on the
hot path for every credential lookup — one broken audit sink must not
take everything down.

### Why fingerprints

`broker.fingerprint(value)` is a deterministic sha256 prefix. Two purposes:

- **Logs.** Trace records can say "served credentials/abc12345" without
  leaking the secret; if the same fingerprint shows up across two requests
  you know they used the same key.
- **Webhook verification.** Compare an inbound HMAC hex against
  `fingerprint(expectedSecret)` to confirm rotation propagation without
  ever putting the secret next to the comparison.

It is NOT a security construct — 8 hex chars has only 32 bits of entropy.
Treat it as a tag, not a token.

## What v0.0.1 does NOT include

- Vendored AWS / Vault / Doppler / Infisical adapters (siblings, later).
- Encrypted on-disk cache.
- Cross-process secret sharing.
- Streaming key-rotation propagation to downstream sandboxes (caller wires that on top of `rotate`'s return).

## Architectural role

- **`@absolutejs/sync`** — `bridgeFetch.authorization()` and `unsafeHost` host functions ask the broker for credentials per call. The plaintext never crosses the sandbox boundary.
- **`@absolutejs/runtime`** — passes the broker into the per-tenant process via the `env` it injects (or via a side-channel; the broker doesn't care).
- **`@absolutejs/router`** — no direct relationship; runs upstream of the broker.
- **`@absolutejs/metering`** — `audit` can sink directly into the metering pipeline so credential lookups are billable observability events.

## License

BSL 1.1 with a named carveout for the hosted secrets-management / credential-broker / runtime-secrets-injection category (AWS Secrets Manager, HashiCorp Vault Cloud, Doppler, 1Password Secrets, Infisical, GCP Secret Manager, Azure Key Vault, Akeyless, Cloudflare Workers Secrets, Vercel Environment Variables as a product). See [LICENSE](./LICENSE). Change Date: 4 years from first release; Change License: Apache 2.0.
