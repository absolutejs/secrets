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

import {
	ABS_ATTRS,
	tracerOrNoop,
	type TracerProvider
} from '@absolutejs/telemetry';

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
	/**
	 * Optional OpenTelemetry tracer provider. When set, `broker.resolve`
	 * and `broker.rotate` are wrapped in `secrets.resolve` /
	 * `secrets.rotate` spans with `abs.secret.name` +
	 * `abs.secret.fingerprint` attributes. `broker.redact` is NOT
	 * traced — it's called per log line, which would explode span
	 * volume. When omitted, all tracing is a zero-allocation noop.
	 * Added in 0.3.0.
	 */
	tracerProvider?: TracerProvider;
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
// encryptedFileAdapter — durable, AES-256-GCM, committable to private repo
// -----------------------------------------------------------------------------

const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const ENC_FILE_VERSION = 1;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32;

const bytesToBase64 = (bytes: Uint8Array): string => {
	let bin = '';
	for (const byte of bytes) bin += String.fromCharCode(byte);
	return btoa(bin);
};

const base64ToBytes = (b64: string): Uint8Array => {
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
	return out;
};

type EncryptedEntry = {
	/** Base64 12-byte IV. */
	iv: string;
	/** Base64 AES-GCM ciphertext (includes 16-byte tag at end). */
	ct: string;
};

type EncryptedFile = {
	version: 1;
	/** Salt is omitted when the master key is supplied as raw bytes. */
	kdf?: {
		type: 'pbkdf2-sha256';
		iterations: number;
		salt: string;
	};
	values: Record<string, EncryptedEntry>;
};

/** Override for tests; defaults touch disk via `node:fs/promises`. */
export type EncryptedFileIO = {
	readFile: (path: string) => Promise<string | undefined>;
	writeFileAtomic: (path: string, contents: string) => Promise<void>;
};

export type EncryptedFileAdapterMasterKey =
	| { type: 'passphrase'; passphrase: string }
	| { type: 'raw'; bytes: Uint8Array };

export type EncryptedFileAdapterOptions = {
	/** Absolute or relative path to the encrypted JSON file. */
	path: string;
	/**
	 * Master key. Either a `passphrase` (KDF'd via PBKDF2-SHA256 with the
	 * salt stored in the file) or `raw` 32 bytes (no KDF — pass the key
	 * directly, useful when sourced from a vendor secret manager).
	 */
	key: EncryptedFileAdapterMasterKey;
	/**
	 * PBKDF2 iterations when `key.type === 'passphrase'`. Default 600_000
	 * (OWASP 2025 recommendation for SHA-256). The chosen value is stored
	 * in the file so future opens use it.
	 */
	pbkdf2Iterations?: number;
	/** Override the rotation strategy (matches `inMemoryAdapter`). */
	rotate?: (name: string, previous: string | null) => string;
	/** Override file IO (tests). */
	io?: EncryptedFileIO;
};

const defaultIo = (): EncryptedFileIO => ({
	readFile: async (path) => {
		try {
			const text = await (await import('node:fs/promises')).readFile(
				path,
				'utf8'
			);
			return text;
		} catch (error) {
			if ((error as { code?: string }).code === 'ENOENT') return undefined;
			throw error;
		}
	},
	writeFileAtomic: async (path, contents) => {
		const fs = await import('node:fs/promises');
		const tempPath = `${path}.tmp.${process.pid}`;
		await fs.writeFile(tempPath, contents, { mode: 0o600 });
		await fs.rename(tempPath, path);
	}
});

const deriveKeyFromPassphrase = async (
	passphrase: string,
	salt: Uint8Array,
	iterations: number
): Promise<CryptoKey> => {
	const base = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(passphrase) as BufferSource,
		'PBKDF2',
		false,
		['deriveKey']
	);
	return crypto.subtle.deriveKey(
		{
			hash: 'SHA-256',
			iterations,
			name: 'PBKDF2',
			salt: salt as BufferSource
		},
		base,
		{ length: 256, name: 'AES-GCM' },
		false,
		['encrypt', 'decrypt']
	);
};

const importRawKey = async (bytes: Uint8Array): Promise<CryptoKey> => {
	if (bytes.length !== KEY_BYTES) {
		throw new Error(
			`[secrets/encrypted-file] raw key must be ${KEY_BYTES} bytes (got ${bytes.length})`
		);
	}
	return crypto.subtle.importKey(
		'raw',
		bytes as BufferSource,
		{ name: 'AES-GCM' },
		false,
		['encrypt', 'decrypt']
	);
};

/**
 * Durable secret adapter that stores `name → value` in an encrypted
 * JSON file (AES-256-GCM, per-value random IV). File is safe to commit
 * to a private repo as long as the master key is kept separately
 * (1Password, env var, hardware key, etc.).
 *
 * Two master-key shapes:
 *
 *   - `{ type: 'passphrase', passphrase }` — PBKDF2-SHA256 from the
 *     passphrase, salt stored in the file. OWASP 2025 default (600k
 *     iterations); add a stronger one via `pbkdf2Iterations`.
 *   - `{ type: 'raw', bytes }` — 32 raw bytes. No KDF. Useful when the
 *     key comes from a vendor secret manager that already gave you
 *     random bytes.
 *
 * Caches decrypted values in memory after first read (consistent with
 * the broker's caching layer above it).
 */
export const encryptedFileAdapter = (
	options: EncryptedFileAdapterOptions
): SecretAdapter => {
	const io = options.io ?? defaultIo();
	const iterations = options.pbkdf2Iterations ?? DEFAULT_PBKDF2_ITERATIONS;
	const rotate = options.rotate ?? (() => randomBase36(32));

	let cache: Map<string, string> | undefined;
	let derivedKey: CryptoKey | undefined;
	let salt: Uint8Array | undefined;

	const ensureKey = async (): Promise<CryptoKey> => {
		if (derivedKey !== undefined) return derivedKey;
		if (options.key.type === 'raw') {
			derivedKey = await importRawKey(options.key.bytes);
			return derivedKey;
		}
		if (salt === undefined) {
			salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
		}
		derivedKey = await deriveKeyFromPassphrase(
			options.key.passphrase,
			salt,
			iterations
		);
		return derivedKey;
	};

	const load = async (): Promise<Map<string, string>> => {
		if (cache !== undefined) return cache;
		const fileText = await io.readFile(options.path);
		if (fileText === undefined) {
			cache = new Map();
			return cache;
		}
		let parsed: EncryptedFile;
		try {
			parsed = JSON.parse(fileText) as EncryptedFile;
		} catch (error) {
			throw new Error(
				`[secrets/encrypted-file] could not parse ${options.path}: ${
					(error as Error).message
				}`
			);
		}
		if (parsed.version !== ENC_FILE_VERSION) {
			throw new Error(
				`[secrets/encrypted-file] unsupported file version ${parsed.version} in ${options.path}`
			);
		}
		if (parsed.kdf !== undefined) {
			if (options.key.type !== 'passphrase') {
				throw new Error(
					`[secrets/encrypted-file] file was written with a passphrase but raw key was supplied`
				);
			}
			salt = base64ToBytes(parsed.kdf.salt);
		} else if (options.key.type === 'passphrase') {
			throw new Error(
				`[secrets/encrypted-file] file was written with a raw key but passphrase was supplied`
			);
		}
		const key = await ensureKey();
		const decoded = new Map<string, string>();
		for (const [name, entry] of Object.entries(parsed.values)) {
			try {
				const iv = base64ToBytes(entry.iv) as BufferSource;
				const ct = base64ToBytes(entry.ct) as BufferSource;
				const pt = await crypto.subtle.decrypt(
					{ iv, name: 'AES-GCM' },
					key,
					ct
				);
				decoded.set(name, new TextDecoder().decode(pt));
			} catch {
				throw new Error(
					`[secrets/encrypted-file] failed to decrypt "${name}" in ${options.path} — wrong master key or corrupted file`
				);
			}
		}
		cache = decoded;
		return cache;
	};

	const save = async (): Promise<void> => {
		const data = cache ?? new Map<string, string>();
		const key = await ensureKey();
		const values: Record<string, EncryptedEntry> = {};
		for (const [name, value] of data) {
			const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
			const ct = await crypto.subtle.encrypt(
				{ iv: iv as BufferSource, name: 'AES-GCM' },
				key,
				new TextEncoder().encode(value) as BufferSource
			);
			values[name] = {
				ct: bytesToBase64(new Uint8Array(ct)),
				iv: bytesToBase64(iv)
			};
		}
		const file: EncryptedFile = {
			values,
			version: ENC_FILE_VERSION,
			...(options.key.type === 'passphrase' && salt !== undefined
				? {
						kdf: {
							iterations,
							salt: bytesToBase64(salt),
							type: 'pbkdf2-sha256'
						}
					}
				: {})
		};
		await io.writeFileAtomic(options.path, JSON.stringify(file, null, 2));
	};

	return {
		fetch: async (name) => {
			const data = await load();
			return data.get(name) ?? null;
		},
		list: async () => {
			const data = await load();
			return Array.from(data.keys());
		},
		put: async (name, value) => {
			const data = await load();
			data.set(name, value);
			await save();
		},
		remove: async (name) => {
			const data = await load();
			data.delete(name);
			await save();
		},
		rotate: async (name) => {
			const data = await load();
			const previous = data.get(name) ?? null;
			const next = rotate(name, previous);
			data.set(name, next);
			await save();
			return next;
		}
	};
};

// -----------------------------------------------------------------------------
// rotateMasterKey — re-encrypt the file under a new master key
// -----------------------------------------------------------------------------

export type RotateMasterKeyOptions = {
	/** Path to the encrypted JSON file (must exist). */
	path: string;
	/** Master key the file was written with. */
	oldKey: EncryptedFileAdapterMasterKey;
	/** Master key to re-encrypt under. */
	newKey: EncryptedFileAdapterMasterKey;
	/**
	 * PBKDF2 iterations for the new passphrase (when `newKey.type ===
	 * 'passphrase'`). Default 600_000. Stored in the rewritten file.
	 */
	newPbkdf2Iterations?: number;
	/** Override file IO (tests). */
	io?: EncryptedFileIO;
};

/**
 * Re-encrypt the entire secrets file under a new master key. Reads
 * every value with `oldKey`, writes them back encrypted under
 * `newKey`. Atomic at the file layer (temp + rename); the old file
 * remains intact if any step fails before the final write.
 *
 * Use cases:
 *   - master passphrase leak: rotate to a new passphrase
 *   - moving from passphrase to raw-bytes (or vice versa) — e.g.
 *     graduating from "operator-typed passphrase" to "key sourced
 *     from a vendor secret manager"
 *   - periodic master-key rotation as a compliance hygiene measure
 *
 * After this returns, any process still holding the old key
 * will fail to decrypt on next access. Rotate the consumers'
 * master-key references at the same time you call this.
 */
export const rotateMasterKey = async (
	options: RotateMasterKeyOptions
): Promise<void> => {
	const io = options.io ?? defaultIo();
	const newIterations =
		options.newPbkdf2Iterations ?? DEFAULT_PBKDF2_ITERATIONS;

	const fileText = await io.readFile(options.path);
	if (fileText === undefined) {
		throw new Error(
			`[secrets/encrypted-file] file ${options.path} does not exist`
		);
	}

	let parsed: EncryptedFile;
	try {
		parsed = JSON.parse(fileText) as EncryptedFile;
	} catch (error) {
		throw new Error(
			`[secrets/encrypted-file] could not parse ${options.path}: ${(error as Error).message}`
		);
	}
	if (parsed.version !== ENC_FILE_VERSION) {
		throw new Error(
			`[secrets/encrypted-file] unsupported file version ${parsed.version} in ${options.path}`
		);
	}

	let oldDerivedKey: CryptoKey;
	if (options.oldKey.type === 'raw') {
		if (parsed.kdf !== undefined) {
			throw new Error(
				`[secrets/encrypted-file] file was written with a passphrase but old key was supplied as raw`
			);
		}
		oldDerivedKey = await importRawKey(options.oldKey.bytes);
	} else {
		if (parsed.kdf === undefined) {
			throw new Error(
				`[secrets/encrypted-file] file was written with a raw key but old key was supplied as passphrase`
			);
		}
		const oldSalt = base64ToBytes(parsed.kdf.salt);
		oldDerivedKey = await deriveKeyFromPassphrase(
			options.oldKey.passphrase,
			oldSalt,
			parsed.kdf.iterations
		);
	}

	const decrypted = new Map<string, string>();
	for (const [name, entry] of Object.entries(parsed.values)) {
		try {
			const iv = base64ToBytes(entry.iv) as BufferSource;
			const ct = base64ToBytes(entry.ct) as BufferSource;
			const pt = await crypto.subtle.decrypt(
				{ iv, name: 'AES-GCM' },
				oldDerivedKey,
				ct
			);
			decrypted.set(name, new TextDecoder().decode(pt));
		} catch {
			throw new Error(
				`[secrets/encrypted-file] failed to decrypt "${name}" with old master key — wrong key or corrupted file`
			);
		}
	}

	let newDerivedKey: CryptoKey;
	let newSalt: Uint8Array | undefined;
	if (options.newKey.type === 'raw') {
		newDerivedKey = await importRawKey(options.newKey.bytes);
	} else {
		newSalt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
		newDerivedKey = await deriveKeyFromPassphrase(
			options.newKey.passphrase,
			newSalt,
			newIterations
		);
	}

	const newValues: Record<string, EncryptedEntry> = {};
	for (const [name, value] of decrypted) {
		const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
		const ct = await crypto.subtle.encrypt(
			{ iv: iv as BufferSource, name: 'AES-GCM' },
			newDerivedKey,
			new TextEncoder().encode(value) as BufferSource
		);
		newValues[name] = {
			ct: bytesToBase64(new Uint8Array(ct)),
			iv: bytesToBase64(iv)
		};
	}

	const newFile: EncryptedFile = {
		values: newValues,
		version: ENC_FILE_VERSION,
		...(options.newKey.type === 'passphrase' && newSalt !== undefined
			? {
					kdf: {
						iterations: newIterations,
						salt: bytesToBase64(newSalt),
						type: 'pbkdf2-sha256'
					}
				}
			: {})
	};

	await io.writeFileAtomic(options.path, JSON.stringify(newFile, null, 2));
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
	// 0.3.0: OTel tracer (noop when options.tracerProvider unset).
	const tracer = tracerOrNoop(options.tracerProvider, '@absolutejs/secrets');
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
		// 0.3.0: span the resolve. Attribute carries the secret NAME
		// (safe) and on cache hit also the FINGERPRINT (also safe —
		// it's sha256-derived, never the value).
		const span = tracer.startSpan('secrets.resolve', {
			attributes: { [ABS_ATTRS.secretName]: name }
		});
		counters.resolves += 1;
		const now = clock();
		try {
			const cached = cache.get(name);
			if (cached && now - cached.storedAt < ttlFor(name)) {
				counters.resolveHits += 1;
				span.setAttribute(ABS_ATTRS.secretFingerprint, cached.fingerprint);
				span.setAttribute('secrets.cache', 'hit');
				fireAudit({ at: now, event: 'resolve.hit', fingerprint: cached.fingerprint, name });
				span.setStatus({ code: 1 /* OK */ });
				return { fingerprint: cached.fingerprint, value: cached.value };
			}
			counters.resolveMisses += 1;
			span.setAttribute('secrets.cache', 'miss');
			const value = await options.adapter.fetch(name);
			if (value === null) {
				fireAudit({ at: now, event: 'resolve.miss', name });
				cache.delete(name);
				span.setAttribute('secrets.found', false);
				span.setStatus({ code: 1 /* OK */ });
				return null;
			}
			const entry = cacheEntry(name, value, now);
			span.setAttribute(ABS_ATTRS.secretFingerprint, entry.fingerprint);
			fireAudit({ at: now, event: 'resolve.miss', fingerprint: entry.fingerprint, name });
			span.setStatus({ code: 1 /* OK */ });
			return { fingerprint: entry.fingerprint, value: entry.value };
		} catch (error) {
			counters.resolveErrors += 1;
			fireAudit({
				at: now,
				error: error instanceof Error ? error.message : String(error),
				event: 'resolve.error',
				name,
			});
			span.recordException(error);
			span.setStatus({
				code: 2 /* ERROR */,
				message: error instanceof Error ? error.message : String(error)
			});
			throw error;
		} finally {
			span.end();
		}
	};

	const rotate: SecretBroker['rotate'] = async (name) => {
		if (disposed) throw new Error('Broker is disposed');
		if (draining) throw new BrokerDrainedError();
		if (!options.adapter.rotate) {
			throw new Error('Adapter does not support rotate()');
		}
		// 0.3.0: span the rotation. The pre-rotation fingerprint isn't
		// known until after the cache lookup is done; attach the new
		// fingerprint on success.
		const span = tracer.startSpan('secrets.rotate', {
			attributes: { [ABS_ATTRS.secretName]: name }
		});
		try {
			const next = await options.adapter.rotate(name);
			const now = clock();
			const entry = cacheEntry(name, next, now);
			counters.rotates += 1;
			span.setAttribute(ABS_ATTRS.secretFingerprint, entry.fingerprint);
			span.setStatus({ code: 1 /* OK */ });
			fireAudit({ at: now, event: 'rotate', fingerprint: entry.fingerprint, name });
			fireRotation(name, entry.value, entry.fingerprint, now);
			return { fingerprint: entry.fingerprint, value: entry.value };
		} catch (error) {
			counters.rotateErrors += 1;
			span.recordException(error);
			span.setStatus({
				code: 2 /* ERROR */,
				message: error instanceof Error ? error.message : String(error)
			});
			throw error;
		} finally {
			span.end();
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
