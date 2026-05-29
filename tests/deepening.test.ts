import { describe, expect, test } from 'bun:test';
import { createSecretBroker, inMemoryAdapter, type RotationListener, type SecretAdapter } from '../src';

const tick = () => {
	let t = 1_000_000;
	return () => {
		t += 1;
		return t;
	};
};

describe('per-name TTL overrides', () => {
	test('a per-name override beats the global default', async () => {
		let fetches = 0;
		const adapter: SecretAdapter = {
			fetch: async (name) => {
				fetches += 1;
				return name === 'FAST' ? 'value-of-fast' : 'value-of-slow';
			},
		};
		let now = 1_000_000;
		const broker = createSecretBroker({
			adapter,
			cacheTtlMs: 60_000,
			cacheTtlOverrides: { FAST: 100 },
			clock: () => now,
		});

		await broker.resolve('FAST');
		await broker.resolve('SLOW');
		expect(fetches).toBe(2);

		now += 200; // past FAST's TTL but within SLOW's default.
		await broker.resolve('FAST');
		await broker.resolve('SLOW');
		// FAST refetched; SLOW still cached.
		expect(fetches).toBe(3);
	});
});

describe('onRotate listeners', () => {
	test('listener fires after rotate() with the new value', async () => {
		const events: Array<{ name: string; value: string; fingerprint: string }> = [];
		const adapter = inMemoryAdapter({ initial: { K: 'old-value-1234567' } });
		const broker = createSecretBroker({ adapter });

		broker.onRotate('K', (event) => {
			events.push({ fingerprint: event.fingerprint, name: event.name, value: event.value });
		});

		await broker.resolve('K');
		const next = await broker.rotate('K');
		expect(events).toHaveLength(1);
		expect(events[0]!.name).toBe('K');
		expect(events[0]!.value).toBe(next.value);
		expect(events[0]!.fingerprint).toBe(next.fingerprint);
	});

	test('multiple listeners on the same name all fire', async () => {
		const calls: string[] = [];
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'v0-padded-out-to-min' } }),
		});
		broker.onRotate('K', () => { calls.push('a'); });
		broker.onRotate('K', () => { calls.push('b'); });
		await broker.rotate('K');
		expect(calls.sort()).toEqual(['a', 'b']);
	});

	test('unsubscribe handle removes the listener', async () => {
		const calls: string[] = [];
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'v0-padded-out-to-min' } }),
		});
		const off = broker.onRotate('K', () => { calls.push('hit'); });
		await broker.rotate('K');
		off();
		await broker.rotate('K');
		expect(calls).toEqual(['hit']);
	});

	test('listener on a different name does not fire', async () => {
		const calls: string[] = [];
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { A: 'aaaa-padded-out', B: 'bbbb-padded-out' } }),
		});
		broker.onRotate('A', () => { calls.push('a'); });
		await broker.rotate('B');
		expect(calls).toEqual([]);
	});

	test('a throwing listener does not crash rotate', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'value-1234567890' } }),
		});
		broker.onRotate('K', () => { throw new Error('boom'); });
		const next = await broker.rotate('K');
		expect(next.value).not.toBe('value-1234567890');
	});

	test('an async-rejected listener does not crash rotate', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'value-1234567890' } }),
		});
		const listener: RotationListener = () => Promise.reject(new Error('async boom'));
		broker.onRotate('K', listener);
		const next = await broker.rotate('K');
		expect(next.value).not.toBe('value-1234567890');
	});
});

describe('base64 encoding redaction', () => {
	test('catches a base64-encoded form of a cached secret', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { JWT_SIG: 'super-secret-jwt-signing-key' } }),
			redactionEncodings: ['plain', 'base64'],
		});
		await broker.resolve('JWT_SIG');
		const encoded = btoa('super-secret-jwt-signing-key');
		const text = `payload: header.${encoded}.body something`;
		const redacted = broker.redact(text);
		expect(redacted).toContain('[REDACTED:JWT_SIG:b64]');
		expect(redacted).not.toContain(encoded);
	});

	test('plain redaction still works alongside base64', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'plain-secret-12345' } }),
			redactionEncodings: ['plain', 'base64'],
		});
		await broker.resolve('K');
		const text = `here it is: plain-secret-12345 done`;
		expect(broker.redact(text)).toContain('[REDACTED:K]');
	});

	test('omitting base64 from encodings leaves base64 forms untouched', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'plain-secret-12345' } }),
		});
		await broker.resolve('K');
		const encoded = btoa('plain-secret-12345');
		const text = `b64: ${encoded}`;
		expect(broker.redact(text)).toBe(text); // unchanged
	});
});

describe('redactStream', () => {
	test('redacts a secret that does NOT cross a chunk boundary', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'sk-test-abcdefgh12345' } }),
		});
		await broker.resolve('K');
		const stream = broker.redactStream();
		const writer = stream.writable.getWriter();
		const reader = stream.readable.getReader();
		const decoder: string[] = [];
		const drain = (async () => {
			while (true) {
				const { value, done } = await reader.read();
				if (done) break;
				decoder.push(value);
			}
		})();
		await writer.write('header sk-test-abcdefgh12345 footer\n');
		await writer.close();
		await drain;
		const joined = decoder.join('');
		expect(joined).toContain('[REDACTED:K]');
		expect(joined).not.toContain('sk-test-abcdefgh12345');
	});

	test('catches a secret split across two chunks via the lookback buffer', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'sk-test-abcdefgh12345' } }),
		});
		await broker.resolve('K');
		const stream = broker.redactStream();
		const writer = stream.writable.getWriter();
		const reader = stream.readable.getReader();
		const out: string[] = [];
		const drain = (async () => {
			while (true) {
				const { value, done } = await reader.read();
				if (done) break;
				out.push(value);
			}
		})();
		// Split the secret in the middle.
		await writer.write('PREFIX sk-test-');
		await writer.write('abcdefgh12345 SUFFIX\n');
		await writer.close();
		await drain;
		const joined = out.join('');
		expect(joined).toContain('[REDACTED:K]');
		expect(joined).not.toContain('sk-test-abcdefgh12345');
	});

	test('empty stream produces empty output', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'sk-test-abcdefgh12345' } }),
		});
		await broker.resolve('K');
		const stream = broker.redactStream();
		const writer = stream.writable.getWriter();
		const reader = stream.readable.getReader();
		const out: string[] = [];
		const drain = (async () => {
			while (true) {
				const { value, done } = await reader.read();
				if (done) break;
				out.push(value);
			}
		})();
		await writer.close();
		await drain;
		expect(out.join('')).toBe('');
	});

	test('streamed output never holds longer than buffer beyond final flush', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'longishsecretvalue1234' } }),
		});
		await broker.resolve('K');
		const stream = broker.redactStream();
		const writer = stream.writable.getWriter();
		const reader = stream.readable.getReader();
		const chunks: string[] = [];
		const drain = (async () => {
			while (true) {
				const { value, done } = await reader.read();
				if (done) break;
				chunks.push(value);
			}
		})();
		// Many short chunks; nothing matches; everything should still emit.
		for (let i = 0; i < 50; i++) {
			await writer.write(`chunk-${i} `);
		}
		await writer.close();
		await drain;
		const joined = chunks.join('');
		for (let i = 0; i < 50; i++) {
			expect(joined).toContain(`chunk-${i}`);
		}
	});
});
