/**
 * @absolutejs/secrets — host-side secret broker for multi-tenant Bun
 * runtimes.
 *
 * Three responsibilities, kept narrow on purpose:
 *
 * 1. **Resolve.** A pluggable adapter fetches a secret by name. The broker
 *    caches the answer, hands the caller back a `{ value, fingerprint }`
 *    pair (fingerprint is a sha256 prefix safe to put in logs), and fires
 *    an audit event for every lookup.
 * 2. **Redact.** Walks every known cached secret out of an arbitrary string
 *    before it leaves the host (e.g. an error message that contains the
 *    leaked API key the host call just made). The replacement is
 *    `[REDACTED:name]`; matches shorter than `redactionMinLength` are
 *    skipped to avoid blanking coincidental short tokens.
 * 3. **Rotate.** Delegates to `adapter.rotate?(name)` if the adapter
 *    supports it, invalidates the cache entry. Caller is expected to
 *    re-distribute to dependent surfaces.
 *
 * v0.0.1 ships three adapters: `inMemoryAdapter`, `envAdapter`,
 * `compositeAdapter`. AWS Secrets Manager / Vault / Doppler / Infisical
 * adapters ship later as siblings.
 *
 * The broker is bun/elysia-agnostic — same posture as router + meter.
 */

export type SecretValue = {
	/** The plaintext secret. Treat as poison: never log, never serialize. */
	value: string;
	/**
	 * Short sha256-derived id (first 8 hex chars). Stable across calls for
	 * the same value; safe to print in logs and traces. Useful for "which
	 * version of the key did this request use?" diagnostics without leaking.
	 */
	fingerprint: string;
};

export type SecretAdapter = {
	/** Return the plaintext value for a name, or `null` if not stored here. */
	fetch: (name: string) => Promise<string | null>;
	/** Write a value. Optional — adapters may be read-only. */
	put?: (name: string, value: string) => Promise<void>;
	/** Delete a value. Optional. */
	remove?: (name: string) => Promise<void>;
	/** Rotate a value; return the NEW plaintext. Optional. */
	rotate?: (name: string) => Promise<string>;
	/** Enumerate names. Optional; default omitted to avoid leaking the index. */
	list?: () => Promise<string[]>;
};

export type AuditEvent =
	| { event: 'resolve.hit'; name: string; fingerprint: string; at: number }
	| { event: 'resolve.miss'; name: string; fingerprint?: string; at: number }
	| { event: 'resolve.error'; name: string; error: string; at: number }
	| { event: 'rotate'; name: string; fingerprint: string; at: number }
	| { event: 'invalidate'; name: string | null; at: number };

export type AuditHook = (event: AuditEvent) => void | Promise<void>;

export type RedactionEncoding = 'plain' | 'base64';

export type SecretBrokerOptions = {
	/** The adapter the broker delegates fetch / rotate / put to. */
	adapter: SecretAdapter;
	/** Audit hook fired on every resolve / rotate / invalidate. */
	audit?: AuditHook;
	/**
	 * How long a cached secret stays fresh, in ms. After this, the next
	 * resolve re-hits the adapter. Default 60_000 (1 minute). Set to
	 * `Infinity` to disable TTL — only `rotate` / `invalidate` evict.
	 */
	cacheTtlMs?: number;
	/**
	 * Per-name TTL overrides. The override wins over `cacheTtlMs`. Use
	 * a short TTL for high-blast-radius secrets (admin tokens, signing
	 * keys) so a compromised value's lifetime is bounded by the override,
	 * not the global default.
	 */
	cacheTtlOverrides?: Record<string, number>;
	/**
	 * Minimum length a cached value must have before `redact` will rewrite
	 * occurrences of it in arbitrary text. Default 8 — short values risk
	 * blanking out coincidental matches (e.g. a short password "abc1"
	 * appearing as a substring of unrelated text).
	 */
	redactionMinLength?: number;
	/**
	 * Encodings to redact alongside the plaintext value. Default `['plain']`.
	 * Add `'base64'` to also catch base64-encoded forms — useful when
	 * secrets end up inside JWTs, cookies, or any payload that base64-wraps
	 * a credential.
	 */
	redactionEncodings?: RedactionEncoding[];
	/** Override `Date.now` for tests. */
	clock?: () => number;
};

/** Listener registered via {@link SecretBroker.onRotate}. */
export type RotationListener = (event: {
	name: string;
	value: string;
	fingerprint: string;
	at: number;
}) => void | Promise<void>;

export type SecretBroker = {
	/**
	 * Resolve a secret by name. Returns `null` if the adapter reports
	 * no value. Caches the answer for `cacheTtlMs`.
	 */
	resolve: (name: string) => Promise<SecretValue | null>;
	/**
	 * Returns the fingerprint of a value WITHOUT touching the adapter.
	 * Useful for hashing a value the caller already has — e.g. a webhook
	 * payload — to compare against an audit log.
	 */
	fingerprint: (value: string) => string;
	/**
	 * Replace every cached secret value found in `text` with
	 * `[REDACTED:name]`. Returns the rewritten text. Subjects shorter than
	 * `redactionMinLength` are skipped.
	 */
	redact: (text: string) => string;
	/**
	 * Streaming variant of {@link redact}. Returns a `TransformStream`
	 * that catches secrets even when they're split across chunks (a chunk
	 * boundary in the middle of `sk_live_abc...` would otherwise miss). The
	 * stream keeps a lookback buffer the size of the longest cached secret;
	 * once the buffer outgrows that, the safe-region prefix is emitted.
	 *
	 * Use this on `process.stdout` / `process.stderr` / a tenant log forwarder
	 * so plaintext secrets never reach the sink.
	 */
	redactStream: () => TransformStream<string, string>;
	/**
	 * Rotate a secret. Calls `adapter.rotate(name)`, invalidates the cache,
	 * returns the new `{ value, fingerprint }`. Throws if the adapter does
	 * not support rotation. Fires every `onRotate` listener registered for
	 * this name.
	 */
	rotate: (name: string) => Promise<SecretValue>;
	/**
	 * Subscribe to rotation events for a specific name. Listener fires
	 * AFTER the new value is in the cache. Returns an unsubscribe handle.
	 * Use this for long-lived connections (DB clients, AI provider SDKs)
	 * that need to swap credentials in-place when rotation lands.
	 */
	onRotate: (name: string, listener: RotationListener) => () => void;
	/**
	 * Invalidate one cache entry, or the whole cache when `name` is omitted.
	 */
	invalidate: (name?: string) => void;
	/** Tear down the broker — clears the cache; further resolves still hit the adapter. */
	dispose: () => void;
	/**
	 * Operator-shaped cumulative counters since `createSecretBroker()`.
	 * Scrape on a 30s interval for tier monitoring + rotation cadence.
	 * Added in 0.2.0.
	 */
	metrics: () => SecretBrokerMetrics;
	/**
	 * Refuse new `resolve()` / `rotate()` calls (they reject with
	 * `BrokerDrainedError`); in-flight adapter calls keep running. Use
	 * during graceful shutdown so a tenant whose process is about to
	 * stop doesn't issue a fresh fetch against the secret store mid-
	 * teardown. Symmetric with `runtime.drain()` / `queue.drain()`.
	 * Added in 0.2.0.
	 */
	drain: () => void;
};

/**
 * Returned by {@link SecretBroker.metrics}. All counters cumulative
 * since `createSecretBroker()`; cleared by neither `dispose()` nor
 * `drain()` (so the operator can see what happened pre-shutdown).
 * Added in 0.2.0.
 */
export type SecretBrokerMetrics = {
	/** `resolve()` calls — including cached hits, misses, and errors. */
	resolves: number;
	/** `resolve()` calls served from cache (no adapter hit). */
	resolveHits: number;
	/** `resolve()` calls that hit the adapter (cache miss OR expired). */
	resolveMisses: number;
	/** `resolve()` calls where the adapter threw. */
	resolveErrors: number;
	/** Successful `rotate()` calls. */
	rotates: number;
	/** `rotate()` calls where the adapter threw. */
	rotateErrors: number;
	/** `invalidate()` calls (per call, regardless of cache size). */
	invalidations: number;
	/** `redact()` calls (whether anything was rewritten or not). */
	redactCalls: number;
	/**
	 * Distinct (secret, encoding) pairs that triggered a replacement —
	 * NOT total occurrences. A `redact()` call that rewrites the same
	 * key three times in one string bumps this by 1. Useful for
	 * "is anything ever actually getting redacted, or are we configured
	 * for nothing."
	 */
	redactionsApplied: number;
	/** Subset of `redactionsApplied` for base64 encoding. */
	redactionsBase64: number;
};

/**
 * Thrown by `resolve()` / `rotate()` after `drain()` has been called.
 * Added in 0.2.0.
 */
export class BrokerDrainedError extends Error {
	constructor() {
		super(
			'[secrets] Broker is draining — resolve/rotate refused. ' +
				'Use the broker before the shutdown handler fires.'
		);
		this.name = 'BrokerDrainedError';
	}
}

// -----------------------------------------------------------------------------
// Fingerprint
// -----------------------------------------------------------------------------

const HEX = '0123456789abcdef';

const sha256Hex = (input: string): string => {
	// 2026-era Bun: `crypto.subtle.digest` is the portable path. Synchronous
	// path via `Bun.CryptoHasher` is faster but requires Bun globals; we use
	// subtle to keep the broker runtime-agnostic at the cost of being async.
	// For the `fingerprint(value)` *public* method we want a synchronous
	// answer — so we use a tiny in-house sha256. It's slower than the native
	// digest but only runs on the secret value (small, ~ < 1KB), once per
	// distinct value over the broker's lifetime (memoized in the cache entry).
	return sha256(input);
};

// Pure JS sha256, NIST FIPS 180-4. Small + dependency-free. Returns lowercase hex.
const ROUND_CONSTANTS = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const sha256 = (input: string): string => {
	const bytes = new TextEncoder().encode(input);
	const bitLength = bytes.length * 8;
	const padLength = ((bytes.length + 9 + 63) & ~63) - bytes.length;
	const padded = new Uint8Array(bytes.length + padLength);
	padded.set(bytes);
	padded[bytes.length] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(padded.length - 4, bitLength >>> 0);
	view.setUint32(padded.length - 8, Math.floor(bitLength / 0x1_0000_0000));

	let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
	let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
	const w = new Uint32Array(64);
	for (let i = 0; i < padded.length; i += 64) {
		for (let t = 0; t < 16; t++) {
			w[t] = view.getUint32(i + t * 4);
		}
		for (let t = 16; t < 64; t++) {
			const w15 = w[t - 15]!;
			const w2 = w[t - 2]!;
			const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
			const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
			w[t] = (w[t - 16]! + s0 + w[t - 7]! + s1) >>> 0;
		}
		let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
		for (let t = 0; t < 64; t++) {
			const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
			const ch = (e & f) ^ (~e & g);
			const T1 = (h + S1 + ch + ROUND_CONSTANTS[t]! + w[t]!) >>> 0;
			const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const T2 = (S0 + maj) >>> 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) >>> 0;
		}
		h0 = (h0 + a) >>> 0;
		h1 = (h1 + b) >>> 0;
		h2 = (h2 + c) >>> 0;
		h3 = (h3 + d) >>> 0;
		h4 = (h4 + e) >>> 0;
		h5 = (h5 + f) >>> 0;
		h6 = (h6 + g) >>> 0;
		h7 = (h7 + h) >>> 0;
	}
	const toHex = (n: number): string => {
		let result = '';
		for (let i = 7; i >= 0; i--) {
			result += HEX[(n >>> (i * 4)) & 0xf];
		}
		return result;
	};
	return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4) + toHex(h5) + toHex(h6) + toHex(h7);
};

const fingerprintOf = (value: string): string => sha256Hex(value).slice(0, 8);

// -----------------------------------------------------------------------------
// Bundled adapters
// -----------------------------------------------------------------------------

export type InMemoryAdapterOptions = {
	initial?: Record<string, string>;
	/** Override the rotation strategy. Default = random 32-char base36 string. */
	rotate?: (name: string, previous: string | null) => string;
};

const randomBase36 = (length: number): string => {
	let out = '';
	while (out.length < length) {
		out += Math.random().toString(36).slice(2);
	}
	return out.slice(0, length);
};

export const inMemoryAdapter = (
	options: InMemoryAdapterOptions = {},
): SecretAdapter => {
	const store = new Map<string, string>();
	for (const [k, v] of Object.entries(options.initial ?? {})) store.set(k, v);
	const rotate = options.rotate ?? (() => randomBase36(32));
	return {
		fetch: async (name) => store.get(name) ?? null,
		list: async () => Array.from(store.keys()),
		put: async (name, value) => { store.set(name, value); },
		remove: async (name) => { store.delete(name); },
		rotate: async (name) => {
			const next = rotate(name, store.get(name) ?? null);
			store.set(name, next);
			return next;
		},
	};
};

export type EnvAdapterOptions = {
	/**
	 * If set, lookups are prefixed before reading from env. e.g.
	 * `prefix: 'ABS_SECRET_'` and `resolve('STRIPE_KEY')` reads `ABS_SECRET_STRIPE_KEY`.
	 * Default `''` (no prefix).
	 */
	prefix?: string;
	/** The env object to read from. Default `process.env`. */
	env?: Record<string, string | undefined>;
};

export const envAdapter = (options: EnvAdapterOptions = {}): SecretAdapter => {
	const prefix = options.prefix ?? '';
	const env = options.env ?? (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {};
	return {
		fetch: async (name) => {
			const key = `${prefix}${name}`;
			const value = env[key];
			return value === undefined ? null : value;
		},
		list: async () => {
			if (!prefix) return Object.keys(env);
			const matches: string[] = [];
			for (const key of Object.keys(env)) {
				if (key.startsWith(prefix)) matches.push(key.slice(prefix.length));
			}
			return matches;
		},
	};
};

/**
 * Compose adapters: `fetch` falls through to the first non-null result;
 * `put` / `rotate` / `remove` go to the first adapter that implements them.
 */
export const compositeAdapter = (adapters: SecretAdapter[]): SecretAdapter => {
	const firstWith = <K extends keyof SecretAdapter>(method: K) =>
		adapters.find((adapter) => adapter[method] !== undefined);
	return {
		fetch: async (name) => {
			for (const adapter of adapters) {
				const value = await adapter.fetch(name);
				if (value !== null) return value;
			}
			return null;
		},
		list: async () => {
			const seen = new Set<string>();
			for (const adapter of adapters) {
				if (!adapter.list) continue;
				for (const name of await adapter.list()) seen.add(name);
			}
			return Array.from(seen);
		},
		put: async (name, value) => {
			const target = firstWith('put');
			if (!target?.put) throw new Error('No adapter in the composite supports put()');
			await target.put(name, value);
		},
		remove: async (name) => {
			const target = firstWith('remove');
			if (!target?.remove) throw new Error('No adapter in the composite supports remove()');
			await target.remove(name);
		},
		rotate: async (name) => {
			const target = firstWith('rotate');
			if (!target?.rotate) throw new Error('No adapter in the composite supports rotate()');
			return target.rotate(name);
		},
	};
};

// -----------------------------------------------------------------------------
// Broker
// -----------------------------------------------------------------------------

type CacheEntry = {
	value: string;
	fingerprint: string;
	storedAt: number;
};

export const createSecretBroker = (options: SecretBrokerOptions): SecretBroker => {
	const clock = options.clock ?? Date.now;
	const defaultTtl = options.cacheTtlMs ?? 60_000;
	const ttlOverrides = options.cacheTtlOverrides ?? {};
	const minLen = options.redactionMinLength ?? 8;
	const encodings = options.redactionEncodings ?? ['plain'];
	const audit = options.audit;
	const cache = new Map<string, CacheEntry>();
	const rotationListeners = new Map<string, Set<RotationListener>>();
	let disposed = false;
	let draining = false;
	// 0.2.0: cumulative operator counters. Survive `drain()` and
	// `dispose()` so the operator can read final state post-shutdown.
	const counters: SecretBrokerMetrics = {
		invalidations: 0,
		redactCalls: 0,
		redactionsApplied: 0,
		redactionsBase64: 0,
		resolveErrors: 0,
		resolveHits: 0,
		resolveMisses: 0,
		resolves: 0,
		rotateErrors: 0,
		rotates: 0
	};

	const ttlFor = (name: string): number => ttlOverrides[name] ?? defaultTtl;

	const fireRotation = (name: string, value: string, fingerprint: string, at: number) => {
		const set = rotationListeners.get(name);
		if (!set || set.size === 0) return;
		for (const listener of set) {
			try {
				const ret = listener({ at, fingerprint, name, value });
				if (ret && typeof (ret as Promise<void>).then === 'function') {
					(ret as Promise<void>).catch((error) => {
						console.error('[secrets] rotation listener rejected:', error);
					});
				}
			} catch (error) {
				console.error('[secrets] rotation listener threw:', error);
			}
		}
	};

	const fireAudit = (event: AuditEvent) => {
		if (!audit) return;
		try {
			const result = audit(event);
			if (result && typeof (result as Promise<void>).then === 'function') {
				(result as Promise<void>).catch((error) => {
					console.error('[secrets] audit hook rejected:', error);
				});
			}
		} catch (error) {
			console.error('[secrets] audit hook threw:', error);
		}
	};

	const cacheEntry = (name: string, value: string, now: number): CacheEntry => {
		const entry: CacheEntry = {
			fingerprint: fingerprintOf(value),
			storedAt: now,
			value,
		};
		cache.set(name, entry);
		return entry;
	};

	const resolve: SecretBroker['resolve'] = async (name) => {
		if (disposed) return null;
		if (draining) throw new BrokerDrainedError();
		counters.resolves += 1;
		const now = clock();
		const cached = cache.get(name);
		if (cached && now - cached.storedAt < ttlFor(name)) {
			counters.resolveHits += 1;
			fireAudit({ at: now, event: 'resolve.hit', fingerprint: cached.fingerprint, name });
			return { fingerprint: cached.fingerprint, value: cached.value };
		}
		counters.resolveMisses += 1;
		try {
			const value = await options.adapter.fetch(name);
			if (value === null) {
				fireAudit({ at: now, event: 'resolve.miss', name });
				cache.delete(name);
				return null;
			}
			const entry = cacheEntry(name, value, now);
			fireAudit({ at: now, event: 'resolve.miss', fingerprint: entry.fingerprint, name });
			return { fingerprint: entry.fingerprint, value: entry.value };
		} catch (error) {
			counters.resolveErrors += 1;
			fireAudit({
				at: now,
				error: error instanceof Error ? error.message : String(error),
				event: 'resolve.error',
				name,
			});
			throw error;
		}
	};

	const rotate: SecretBroker['rotate'] = async (name) => {
		if (disposed) throw new Error('Broker is disposed');
		if (draining) throw new BrokerDrainedError();
		if (!options.adapter.rotate) {
			throw new Error('Adapter does not support rotate()');
		}
		try {
			const next = await options.adapter.rotate(name);
			const now = clock();
			const entry = cacheEntry(name, next, now);
			counters.rotates += 1;
			fireAudit({ at: now, event: 'rotate', fingerprint: entry.fingerprint, name });
			fireRotation(name, entry.value, entry.fingerprint, now);
			return { fingerprint: entry.fingerprint, value: entry.value };
		} catch (error) {
			counters.rotateErrors += 1;
			throw error;
		}
	};

	const invalidate: SecretBroker['invalidate'] = (name) => {
		if (name === undefined) {
			cache.clear();
		} else {
			cache.delete(name);
		}
		counters.invalidations += 1;
		fireAudit({ at: clock(), event: 'invalidate', name: name ?? null });
	};

	// Returns every (representation, replacementLabel) pair currently in
	// the cache that's worth searching for. Longest-first so a longer
	// secret blanks BEFORE one of its substrings would.
	const redactionPairs = (): Array<[string, string]> => {
		const pairs: Array<[string, string]> = [];
		for (const [name, entry] of cache) {
			if (entry.value.length < minLen) continue;
			for (const enc of encodings) {
				if (enc === 'plain') {
					pairs.push([entry.value, `[REDACTED:${name}]`]);
				} else if (enc === 'base64') {
					try {
						const encoded = btoa(entry.value);
						// Skip if encoding produces a too-short token to be safe.
						if (encoded.length >= minLen) {
							pairs.push([encoded, `[REDACTED:${name}:b64]`]);
						}
					} catch {
						// btoa rejects non-Latin-1; skip silently.
					}
				}
			}
		}
		pairs.sort((a, b) => b[0].length - a[0].length);
		return pairs;
	};

	const redact: SecretBroker['redact'] = (text) => {
		counters.redactCalls += 1;
		if (text.length === 0 || cache.size === 0) return text;
		let out = text;
		for (const [needle, replacement] of redactionPairs()) {
			if (!out.includes(needle)) continue;
			out = out.split(needle).join(replacement);
			counters.redactionsApplied += 1;
			if (replacement.endsWith(':b64]')) counters.redactionsBase64 += 1;
		}
		return out;
	};

	const redactStream: SecretBroker['redactStream'] = () => {
		// Per-chunk algorithm:
		//   1. Append chunk to buffer.
		//   2. Redact the WHOLE buffer (complete secrets → labels).
		//   3. Hold back the last `lookback` chars — they might contain a
		//      partial secret that completes on the next chunk. The next
		//      chunk's redact() will catch it once the full secret arrives.
		//   4. Emit the safe prefix.
		// Without step 2 happening BEFORE the split, a secret straddling the
		// boundary would have its prefix emitted un-redacted before the suffix
		// even shows up.
		let buffer = '';
		const maxLen = () =>
			redactionPairs().reduce((max, [needle]) => Math.max(max, needle.length), 0);
		return new TransformStream<string, string>({
			transform: (chunk, controller) => {
				buffer += chunk;
				const lookback = maxLen();
				const reduced = redact(buffer);
				if (reduced.length <= lookback) {
					buffer = reduced;
					return;
				}
				const safe = reduced.slice(0, reduced.length - lookback);
				buffer = reduced.slice(reduced.length - lookback);
				if (safe.length > 0) controller.enqueue(safe);
			},
			flush: (controller) => {
				if (buffer.length === 0) return;
				controller.enqueue(redact(buffer));
				buffer = '';
			},
		});
	};

	const onRotate: SecretBroker['onRotate'] = (name, listener) => {
		let set = rotationListeners.get(name);
		if (!set) {
			set = new Set();
			rotationListeners.set(name, set);
		}
		set.add(listener);
		return () => {
			const current = rotationListeners.get(name);
			if (!current) return;
			current.delete(listener);
			if (current.size === 0) rotationListeners.delete(name);
		};
	};

	return {
		dispose: () => {
			disposed = true;
			cache.clear();
			rotationListeners.clear();
		},
		drain: () => {
			draining = true;
		},
		fingerprint: fingerprintOf,
		invalidate,
		metrics: () => ({ ...counters }),
		onRotate,
		redact,
		redactStream,
		resolve,
		rotate,
	};
};
