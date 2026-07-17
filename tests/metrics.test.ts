import { describe, expect, test } from "bun:test";
import {
  BrokerDrainedError,
  createSecretBroker,
  inMemoryAdapter,
  type SecretAdapter,
} from "../src";

const failingAdapter = (): SecretAdapter => ({
  fetch: async () => {
    throw new Error("adapter boom");
  },
});

const rotatingAdapter = (initial: string, next: string): SecretAdapter => {
  let value = initial;
  return {
    fetch: async () => value,
    rotate: async () => {
      value = next;
      return next;
    },
  };
};

describe("broker.metrics() — 0.2.0", () => {
  test("starts with zeroed counters", () => {
    const broker = createSecretBroker({ adapter: inMemoryAdapter() });
    expect(broker.metrics()).toEqual({
      invalidations: 0,
      redactCalls: 0,
      redactionsApplied: 0,
      redactionsBase64: 0,
      resolveErrors: 0,
      resolveHits: 0,
      resolveMisses: 0,
      resolves: 0,
      rotateErrors: 0,
      rotates: 0,
    });
  });

  test("resolveMisses bumps on adapter hit, resolveHits on cache hit", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({ initial: { API_KEY: "sk_live_123" } }),
    });
    await broker.resolve("API_KEY"); // miss → fetch
    await broker.resolve("API_KEY"); // cached hit
    await broker.resolve("API_KEY"); // cached hit
    const m = broker.metrics();
    expect(m.resolves).toBe(3);
    expect(m.resolveMisses).toBe(1);
    expect(m.resolveHits).toBe(2);
    expect(m.resolveErrors).toBe(0);
  });

  test("resolveErrors bumps when the adapter throws", async () => {
    const broker = createSecretBroker({ adapter: failingAdapter() });
    await expect(broker.resolve("any")).rejects.toThrow(/adapter boom/);
    const m = broker.metrics();
    expect(m.resolves).toBe(1);
    expect(m.resolveMisses).toBe(1);
    expect(m.resolveErrors).toBe(1);
  });

  test("rotates and rotateErrors are independent counters", async () => {
    const ok = createSecretBroker({
      adapter: rotatingAdapter("old", "new"),
    });
    await ok.resolve("K");
    await ok.rotate("K");
    expect(ok.metrics().rotates).toBe(1);
    expect(ok.metrics().rotateErrors).toBe(0);

    const broken = createSecretBroker({
      adapter: {
        fetch: async () => "v",
        rotate: async () => {
          throw new Error("rotate boom");
        },
      },
    });
    await expect(broken.rotate("K")).rejects.toThrow(/rotate boom/);
    expect(broken.metrics().rotates).toBe(0);
    expect(broken.metrics().rotateErrors).toBe(1);
  });

  test("redact counters track calls + per-replacement triggers", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({
        initial: {
          API_KEY: "sk_live_long_value",
          DB_PASS: "p@ssw0rd_long",
        },
      }),
    });
    await broker.resolve("API_KEY");
    await broker.resolve("DB_PASS");
    // Single redact call with two distinct secrets replaced.
    broker.redact("use sk_live_long_value and p@ssw0rd_long");
    const m = broker.metrics();
    expect(m.redactCalls).toBe(1);
    expect(m.redactionsApplied).toBe(2);
    expect(m.redactionsBase64).toBe(0);
    // Empty redact still counts the call.
    broker.redact("nothing here");
    expect(broker.metrics().redactCalls).toBe(2);
    expect(broker.metrics().redactionsApplied).toBe(2);
  });

  test("base64 redaction bumps redactionsBase64 separately", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({
        initial: { JWT_SECRET: "this_is_a_long_secret" },
      }),
      redactionEncodings: ["plain", "base64"],
    });
    await broker.resolve("JWT_SECRET");
    const encoded = btoa("this_is_a_long_secret");
    broker.redact(`raw: this_is_a_long_secret; b64: ${encoded}`);
    const m = broker.metrics();
    expect(m.redactionsApplied).toBe(2);
    expect(m.redactionsBase64).toBe(1);
  });

  test("invalidations counter bumps regardless of cache contents", () => {
    const broker = createSecretBroker({ adapter: inMemoryAdapter() });
    broker.invalidate();
    broker.invalidate("nonexistent");
    expect(broker.metrics().invalidations).toBe(2);
  });
});

describe("broker.drain() — 0.2.0", () => {
  test("refuses new resolve() with BrokerDrainedError", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({ initial: { K: "v" } }),
    });
    broker.drain();
    await expect(broker.resolve("K")).rejects.toBeInstanceOf(
      BrokerDrainedError,
    );
  });

  test("refuses new rotate() with BrokerDrainedError", async () => {
    const broker = createSecretBroker({
      adapter: rotatingAdapter("a", "b"),
    });
    broker.drain();
    await expect(broker.rotate("K")).rejects.toBeInstanceOf(BrokerDrainedError);
  });

  test("in-flight resolves complete normally; drain only gates future calls", async () => {
    let release!: (v: string) => void;
    const adapter: SecretAdapter = {
      fetch: () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    };
    const broker = createSecretBroker({ adapter });
    const pending = broker.resolve("SLOW");
    // drain AFTER the resolve has started but BEFORE the adapter resolves.
    broker.drain();
    release("the-value");
    const value = await pending;
    expect(value?.value).toBe("the-value");
  });

  test("metrics() still readable after drain", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({ initial: { K: "v" } }),
    });
    await broker.resolve("K");
    broker.drain();
    const m = broker.metrics();
    expect(m.resolves).toBe(1);
    expect(m.resolveMisses).toBe(1);
  });
});
