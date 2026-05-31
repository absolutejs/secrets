/**
 * Tests for encryptedFileAdapter. Uses an in-memory IO override so
 * tests don't touch disk, plus one real-FS round-trip test to verify
 * the default IO path works.
 */
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
	createSecretBroker,
	encryptedFileAdapter,
	type EncryptedFileIO
} from '../src/index';

const memoryIo = (
	initial: Record<string, string> = {}
): EncryptedFileIO & { snapshot: () => Record<string, string> } => {
	const files = new Map(Object.entries(initial));
	return {
		readFile: async (path) => files.get(path),
		snapshot: () => Object.fromEntries(files),
		writeFileAtomic: async (path, contents) => {
			files.set(path, contents);
		}
	};
};

const FILE_PATH = '/test/secrets.enc.json';
const PASSPHRASE = 'correct horse battery staple';
const RAW_KEY = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) RAW_KEY[i] = i;

// =============================================================================
// passphrase mode
// =============================================================================

describe('encryptedFileAdapter — passphrase mode', () => {
	test('creates the file on first put + round-trips through fetch', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000 // fast for tests
		});
		await adapter.put?.('STRIPE_KEY', 'sk_live_xyz');
		const fetched = await adapter.fetch('STRIPE_KEY');
		expect(fetched).toBe('sk_live_xyz');
		// File exists in our memory FS.
		expect(io.snapshot()[FILE_PATH]).toBeDefined();
		// And it's JSON with the expected shape.
		const parsed = JSON.parse(io.snapshot()[FILE_PATH] as string);
		expect(parsed.version).toBe(1);
		expect(parsed.kdf?.type).toBe('pbkdf2-sha256');
		expect(parsed.kdf?.iterations).toBe(1000);
		expect(parsed.values.STRIPE_KEY).toBeDefined();
		// Ciphertext is NOT plaintext.
		expect(JSON.stringify(parsed)).not.toContain('sk_live_xyz');
	});

	test('a fresh adapter instance can decrypt the same file', async () => {
		const io = memoryIo();
		const a = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await a.put?.('KEY1', 'value1');
		await a.put?.('KEY2', 'value2');

		// Fresh instance, same passphrase, same file.
		const b = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		expect(await b.fetch('KEY1')).toBe('value1');
		expect(await b.fetch('KEY2')).toBe('value2');
	});

	test('wrong passphrase fails to decrypt loudly', async () => {
		const io = memoryIo();
		const a = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await a.put?.('KEY1', 'value1');

		const b = encryptedFileAdapter({
			io,
			key: { passphrase: 'wrong', type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await expect(b.fetch('KEY1')).rejects.toThrow(
			'wrong master key or corrupted file'
		);
	});

	test('per-value IVs are unique — same value encrypted twice produces different ciphertext', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await adapter.put?.('A', 'same-value');
		await adapter.put?.('B', 'same-value');
		const parsed = JSON.parse(io.snapshot()[FILE_PATH] as string);
		// Same plaintext → different ciphertext (because random IV).
		expect(parsed.values.A.ct).not.toBe(parsed.values.B.ct);
		expect(parsed.values.A.iv).not.toBe(parsed.values.B.iv);
	});

	test('salt is stable across writes (so subsequent decrypts still work)', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await adapter.put?.('KEY1', 'value1');
		const salt1 = JSON.parse(io.snapshot()[FILE_PATH] as string).kdf.salt;
		await adapter.put?.('KEY2', 'value2');
		const salt2 = JSON.parse(io.snapshot()[FILE_PATH] as string).kdf.salt;
		expect(salt1).toBe(salt2);
	});
});

// =============================================================================
// raw-key mode
// =============================================================================

describe('encryptedFileAdapter — raw key mode', () => {
	test('round-trips with a 32-byte raw key', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('STRIPE_KEY', 'sk_live_xyz');
		expect(await adapter.fetch('STRIPE_KEY')).toBe('sk_live_xyz');

		// File should NOT have a kdf section.
		const parsed = JSON.parse(io.snapshot()[FILE_PATH] as string);
		expect(parsed.kdf).toBeUndefined();
	});

	test('rejects raw keys of wrong length', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: new Uint8Array(16), type: 'raw' },
			path: FILE_PATH
		});
		await expect(adapter.put?.('K', 'v')).rejects.toThrow('32 bytes');
	});

	test('cross-mode mismatch throws (raw key + passphrase-written file)', async () => {
		const io = memoryIo();
		// Write with passphrase.
		const a = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await a.put?.('K', 'v');
		// Try to read with raw key.
		const b = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await expect(b.fetch('K')).rejects.toThrow(
			'written with a passphrase but raw key was supplied'
		);
	});

	test('cross-mode mismatch throws (passphrase + raw-written file)', async () => {
		const io = memoryIo();
		const a = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await a.put?.('K', 'v');
		const b = encryptedFileAdapter({
			io,
			key: { passphrase: PASSPHRASE, type: 'passphrase' },
			path: FILE_PATH,
			pbkdf2Iterations: 1000
		});
		await expect(b.fetch('K')).rejects.toThrow(
			'written with a raw key but passphrase was supplied'
		);
	});
});

// =============================================================================
// SecretAdapter contract — list / remove / rotate
// =============================================================================

describe('encryptedFileAdapter — SecretAdapter contract', () => {
	test('list returns the names of stored secrets', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('A', '1');
		await adapter.put?.('B', '2');
		const names = await adapter.list?.();
		expect(names?.sort()).toEqual(['A', 'B']);
	});

	test('remove deletes a secret + persists', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('A', '1');
		await adapter.put?.('B', '2');
		await adapter.remove?.('A');
		expect(await adapter.fetch('A')).toBeNull();
		expect(await adapter.fetch('B')).toBe('2');
		// A fresh instance sees the same state.
		const fresh = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		expect(await fresh.fetch('A')).toBeNull();
		expect(await fresh.fetch('B')).toBe('2');
	});

	test('rotate generates a new value with the default strategy', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('K', 'old');
		const next = await adapter.rotate?.('K');
		expect(next).toBeDefined();
		expect(next).not.toBe('old');
		expect(next!.length).toBeGreaterThanOrEqual(32);
		expect(await adapter.fetch('K')).toBe(next!);
	});

	test('rotate honors a custom strategy', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH,
			rotate: (name, previous) =>
				`${name}-from-${previous ?? 'init'}-counter`
		});
		await adapter.put?.('STRIPE_KEY', 'sk_live_old');
		const next = await adapter.rotate?.('STRIPE_KEY');
		expect(next).toBe('STRIPE_KEY-from-sk_live_old-counter');
	});
});

// =============================================================================
// Broker composition
// =============================================================================

describe('encryptedFileAdapter — composed with SecretBroker', () => {
	test('broker.resolve + broker.rotate work through the encrypted adapter', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('STRIPE_KEY', 'sk_live_old');

		const broker = createSecretBroker({ adapter, cacheTtlMs: 60_000 });
		const first = await broker.resolve('STRIPE_KEY');
		expect(first?.value).toBe('sk_live_old');

		const rotated = await broker.rotate('STRIPE_KEY');
		expect(rotated.value).not.toBe('sk_live_old');
		expect(rotated.fingerprint).toBe(broker.fingerprint(rotated.value));

		// Re-resolve should now get the new value (broker invalidates on rotate).
		const after = await broker.resolve('STRIPE_KEY');
		expect(after?.value).toBe(rotated.value);
	});

	test('rotation listener fires when broker.rotate is called against the file', async () => {
		const io = memoryIo();
		const adapter = encryptedFileAdapter({
			io,
			key: { bytes: RAW_KEY, type: 'raw' },
			path: FILE_PATH
		});
		await adapter.put?.('DB_PASSWORD', 'initial');
		const broker = createSecretBroker({ adapter });
		const events: string[] = [];
		broker.onRotate('DB_PASSWORD', (event) => {
			events.push(event.value);
		});
		await broker.rotate('DB_PASSWORD');
		expect(events).toHaveLength(1);
		expect(events[0]).not.toBe('initial');
	});
});

// =============================================================================
// Real filesystem round-trip
// =============================================================================

describe('encryptedFileAdapter — real filesystem round-trip', () => {
	let tmpDir: string;

	beforeAll(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), 'abssecrets-'));
	});

	afterAll(async () => {
		await rm(tmpDir, { force: true, recursive: true });
	});

	test('default IO writes a real file that re-decrypts on a fresh adapter', async () => {
		const path = join(tmpDir, 'secrets.enc.json');
		const a = encryptedFileAdapter({
			key: { bytes: RAW_KEY, type: 'raw' },
			path
		});
		await a.put?.('STRIPE_KEY', 'sk_live_xyz');
		// File exists on disk and is JSON.
		const onDisk = await readFile(path, 'utf8');
		expect(onDisk).toContain('"version"');
		expect(onDisk).not.toContain('sk_live_xyz');

		const b = encryptedFileAdapter({
			key: { bytes: RAW_KEY, type: 'raw' },
			path
		});
		expect(await b.fetch('STRIPE_KEY')).toBe('sk_live_xyz');
	});

	test('default IO writes atomically: tmp file disappears after rename', async () => {
		const path = join(tmpDir, 'atomic.enc.json');
		const adapter = encryptedFileAdapter({
			key: { bytes: RAW_KEY, type: 'raw' },
			path
		});
		await adapter.put?.('K', 'v');
		// No leftover .tmp.<pid> file.
		const { readdir } = await import('node:fs/promises');
		const dirEntries = await readdir(tmpDir);
		expect(dirEntries.some((e) => e.includes('atomic.enc.json.tmp'))).toBe(
			false
		);
	});
});
