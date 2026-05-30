import { describe, expect, test } from 'bun:test';
import {
	ABS_ATTRS,
	createNoopSpan,
	type Span,
	type Tracer,
	type TracerProvider
} from '@absolutejs/telemetry';
import {
	createSecretBroker,
	inMemoryAdapter,
	type SecretAdapter
} from '../src';

type CapturedSpan = {
	name: string;
	attrs: Record<string, unknown>;
	status?: { code: number; message?: string };
	exception?: unknown;
	ended: boolean;
};

const makeCapturingTracerProvider = (): {
	provider: TracerProvider;
	spans: CapturedSpan[];
} => {
	const spans: CapturedSpan[] = [];
	const makeSpan = (record: CapturedSpan): Span => {
		const noop = createNoopSpan();
		return {
			...noop,
			end: () => {
				record.ended = true;
			},
			isRecording: () => !record.ended,
			recordException: (exception) => {
				record.exception = exception;
			},
			setAttribute: ((key: string, value: unknown) => {
				record.attrs[key] = value;
				return makeSpan(record);
			}) as Span['setAttribute'],
			setStatus: ((status) => {
				record.status = status;
				return makeSpan(record);
			}) as Span['setStatus']
		};
	};
	const tracer: Tracer = {
		startActiveSpan: ((name, optionsOrFn, maybeFn) => {
			const fn =
				typeof optionsOrFn === 'function' ? optionsOrFn : maybeFn;
			const record: CapturedSpan = { attrs: {}, ended: false, name };
			spans.push(record);
			return (fn as (s: Span) => unknown)(makeSpan(record));
		}) as Tracer['startActiveSpan'],
		startSpan: (name, options) => {
			const record: CapturedSpan = {
				attrs: { ...(options?.attributes ?? {}) },
				ended: false,
				name
			};
			spans.push(record);
			return makeSpan(record);
		}
	};
	return {
		provider: { getTracer: () => tracer },
		spans
	};
};

describe('secrets 0.3.0 — OTel via @absolutejs/telemetry', () => {
	test('resolve hit emits secrets.resolve span with name + fingerprint + cache=hit', async () => {
		const { provider, spans } = makeCapturingTracerProvider();
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { API_KEY: 'sk_live_abc' } }),
			tracerProvider: provider
		});
		await broker.resolve('API_KEY'); // miss → cache
		await broker.resolve('API_KEY'); // hit
		const resolveSpans = spans.filter(
			(s) => s.name === 'secrets.resolve'
		);
		expect(resolveSpans).toHaveLength(2);
		// All resolves: name attr set, fingerprint set (on the value
		// path), status OK.
		expect(resolveSpans[0]!.attrs[ABS_ATTRS.secretName]).toBe('API_KEY');
		expect(resolveSpans[0]!.attrs['secrets.cache']).toBe('miss');
		expect(resolveSpans[1]!.attrs['secrets.cache']).toBe('hit');
		expect(resolveSpans[0]!.attrs[ABS_ATTRS.secretFingerprint]).toBeDefined();
		expect(resolveSpans[0]!.status?.code).toBe(1);
		expect(resolveSpans[0]!.ended).toBe(true);
	});

	test('resolve missing key emits span with secrets.found=false', async () => {
		const { provider, spans } = makeCapturingTracerProvider();
		const broker = createSecretBroker({
			adapter: inMemoryAdapter(),
			tracerProvider: provider
		});
		const result = await broker.resolve('NOT_PRESENT');
		expect(result).toBeNull();
		const span = spans.find((s) => s.name === 'secrets.resolve');
		expect(span!.attrs['secrets.found']).toBe(false);
		expect(span!.status?.code).toBe(1);
	});

	test('resolve adapter error records exception + ERROR status', async () => {
		const { provider, spans } = makeCapturingTracerProvider();
		const broken: SecretAdapter = {
			fetch: async () => {
				throw new Error('adapter timeout');
			}
		};
		const broker = createSecretBroker({
			adapter: broken,
			tracerProvider: provider
		});
		await expect(broker.resolve('any')).rejects.toThrow('adapter timeout');
		const span = spans.find((s) => s.name === 'secrets.resolve');
		expect(span!.status?.code).toBe(2);
		expect(span!.exception).toBeInstanceOf(Error);
		expect(span!.ended).toBe(true);
	});

	test('rotate emits secrets.rotate span with new fingerprint', async () => {
		const { provider, spans } = makeCapturingTracerProvider();
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({
				initial: { DB_PASS: 'old' },
				rotate: () => 'new-value-rotated'
			}),
			tracerProvider: provider
		});
		const result = await broker.rotate('DB_PASS');
		const span = spans.find((s) => s.name === 'secrets.rotate');
		expect(span).toBeDefined();
		expect(span!.attrs[ABS_ATTRS.secretName]).toBe('DB_PASS');
		expect(span!.attrs[ABS_ATTRS.secretFingerprint]).toBe(
			result.fingerprint
		);
		expect(span!.status?.code).toBe(1);
	});

	test('without tracerProvider, broker still works (noop)', async () => {
		const broker = createSecretBroker({
			adapter: inMemoryAdapter({ initial: { K: 'v' } })
		});
		const result = await broker.resolve('K');
		expect(result?.value).toBe('v');
	});
});
