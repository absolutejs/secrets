import { describe, expect, test } from "bun:test";
import {
  compositeAdapter,
  createSecretBroker,
  envAdapter,
  inMemoryAdapter,
  type AuditEvent,
  type SecretAdapter,
} from "../src/broker";

const clockFrom = (start = 1_000_000) => {
  let now = start;
  return {
    advance: (ms: number) => {
      now += ms;
    },
    now: () => now,
  };
};

describe("createSecretBroker", () => {
  test("resolve hits the adapter and caches the answer", async () => {
    const fetches: string[] = [];
    const adapter: SecretAdapter = {
      fetch: async (name) => {
        fetches.push(name);
        return name === "STRIPE_KEY" ? "sk_live_abcdef0123456789" : null;
      },
    };
    const broker = createSecretBroker({ adapter });

    const first = await broker.resolve("STRIPE_KEY");
    expect(first?.value).toBe("sk_live_abcdef0123456789");
    expect(first?.fingerprint).toHaveLength(8);

    const second = await broker.resolve("STRIPE_KEY");
    expect(second?.value).toBe("sk_live_abcdef0123456789");
    expect(fetches).toEqual(["STRIPE_KEY"]);
  });

  test("cache TTL expires; next resolve re-hits the adapter", async () => {
    const clock = clockFrom();
    const fetches: string[] = [];
    const adapter: SecretAdapter = {
      fetch: async (name) => {
        fetches.push(name);
        return "v1";
      },
    };
    const broker = createSecretBroker({
      adapter,
      cacheTtlMs: 1000,
      clock: clock.now,
    });

    await broker.resolve("K");
    clock.advance(500);
    await broker.resolve("K");
    expect(fetches).toHaveLength(1);

    clock.advance(600);
    await broker.resolve("K");
    expect(fetches).toHaveLength(2);
  });

  test("missing secret returns null, audit records miss", async () => {
    const events: AuditEvent[] = [];
    const broker = createSecretBroker({
      adapter: { fetch: async () => null },
      audit: (event) => {
        events.push(event);
      },
    });
    const result = await broker.resolve("NOPE");
    expect(result).toBeNull();
    expect(events).toHaveLength(1);
    expect(events[0]!.event).toBe("resolve.miss");
  });

  test("audit fires for hit, miss, rotate, invalidate", async () => {
    const events: AuditEvent[] = [];
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({ initial: { K: "value-12345678" } }),
      audit: (event) => {
        events.push(event);
      },
    });
    await broker.resolve("K"); // miss (first)
    await broker.resolve("K"); // hit
    await broker.rotate("K"); // rotate
    broker.invalidate("K");

    expect(events.map((event) => event.event)).toEqual([
      "resolve.miss",
      "resolve.hit",
      "rotate",
      "invalidate",
    ]);
  });

  test("fingerprint is deterministic and a sha256 prefix (hex 0-9 a-f)", async () => {
    const broker = createSecretBroker({ adapter: { fetch: async () => null } });
    const first = broker.fingerprint("hello");
    const second = broker.fingerprint("hello");
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{8}$/);

    // Different inputs produce different fingerprints (overwhelmingly).
    expect(broker.fingerprint("world")).not.toBe(first);
  });

  test("redact replaces every cached value in arbitrary text", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({
        initial: {
          API_KEY: "apikeyvalue1234567890",
          DB_PASSWORD: "verysecretpassword",
        },
      }),
    });
    await broker.resolve("API_KEY");
    await broker.resolve("DB_PASSWORD");

    const log =
      "GET /v1 failed with apikeyvalue1234567890 then DB error verysecretpassword end";
    const redacted = broker.redact(log);
    expect(redacted).toBe(
      "GET /v1 failed with [REDACTED:API_KEY] then DB error [REDACTED:DB_PASSWORD] end",
    );
  });

  test("redact prefers longer values when one is a substring of another", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({
        initial: {
          LONG_KEY: "partialvalue_extended_suffix",
          SHORT_KEY: "partialvalue",
        },
      }),
    });
    await broker.resolve("LONG_KEY");
    await broker.resolve("SHORT_KEY");

    const text = "leak: partialvalue_extended_suffix here";
    const result = broker.redact(text);
    // LONG_KEY must redact first; SHORT_KEY must NOT then double-process the placeholder.
    expect(result).toBe("leak: [REDACTED:LONG_KEY] here");
  });

  test("redact skips values shorter than redactionMinLength", async () => {
    const broker = createSecretBroker({
      adapter: inMemoryAdapter({ initial: { TINY: "abc" } }),
      redactionMinLength: 8,
    });
    await broker.resolve("TINY");
    const text = "this abc is too short to safely redact";
    expect(broker.redact(text)).toBe(text);
  });

  test("rotate calls adapter.rotate, invalidates, returns the new value", async () => {
    let rotated = 0;
    const adapter: SecretAdapter = {
      fetch: async () => "old",
      rotate: async () => {
        rotated += 1;
        return "new-rotated-value-12345";
      },
    };
    const broker = createSecretBroker({ adapter });
    await broker.resolve("K");
    const next = await broker.rotate("K");
    expect(rotated).toBe(1);
    expect(next.value).toBe("new-rotated-value-12345");

    // A subsequent resolve sees the new value WITHOUT re-fetching (it was cached on rotate).
    let postFetches = 0;
    (adapter as { fetch: SecretAdapter["fetch"] }).fetch = async () => {
      postFetches += 1;
      return "old-again";
    };
    const after = await broker.resolve("K");
    expect(after?.value).toBe("new-rotated-value-12345");
    expect(postFetches).toBe(0);
  });

  test("rotate throws when adapter does not support it", async () => {
    const broker = createSecretBroker({ adapter: { fetch: async () => "v" } });
    await expect(broker.rotate("K")).rejects.toThrow(/rotate/i);
  });

  test("invalidate(name) clears one entry; invalidate() clears all", async () => {
    let fetches = 0;
    const broker = createSecretBroker({
      adapter: {
        fetch: async (name) => {
          fetches += 1;
          return `value-of-${name}-padded`;
        },
      },
    });
    await broker.resolve("A");
    await broker.resolve("B");
    expect(fetches).toBe(2);

    broker.invalidate("A");
    await broker.resolve("A"); // re-fetches
    await broker.resolve("B"); // still cached
    expect(fetches).toBe(3);

    broker.invalidate();
    await broker.resolve("A");
    await broker.resolve("B");
    expect(fetches).toBe(5);
  });

  test("dispose makes subsequent resolves return null", async () => {
    const broker = createSecretBroker({ adapter: { fetch: async () => "x" } });
    await broker.resolve("K");
    broker.dispose();
    const result = await broker.resolve("K");
    expect(result).toBeNull();
  });

  test("adapter fetch error surfaces; audit records the error", async () => {
    const events: AuditEvent[] = [];
    const broker = createSecretBroker({
      adapter: {
        fetch: async () => {
          throw new Error("vault unreachable");
        },
      },
      audit: (event) => {
        events.push(event);
      },
    });
    await expect(broker.resolve("K")).rejects.toThrow("vault unreachable");
    expect(events).toHaveLength(1);
    expect(events[0]!.event).toBe("resolve.error");
  });

  test("async audit hook rejection does not crash resolve", async () => {
    const broker = createSecretBroker({
      adapter: { fetch: async () => "value-1234567890" },
      audit: () => Promise.reject(new Error("audit boom")),
    });
    const result = await broker.resolve("K");
    expect(result?.value).toBe("value-1234567890");
  });
});

describe("inMemoryAdapter", () => {
  test("roundtrips initial data, supports put / remove / list", async () => {
    const adapter = inMemoryAdapter({ initial: { A: "1", B: "2" } });
    expect(await adapter.fetch("A")).toBe("1");
    expect(await adapter.list?.()).toEqual(["A", "B"]);

    await adapter.put?.("C", "3");
    expect(await adapter.fetch("C")).toBe("3");

    await adapter.remove?.("A");
    expect(await adapter.fetch("A")).toBeNull();
  });

  test("default rotate returns a long random string", async () => {
    const adapter = inMemoryAdapter({ initial: { K: "old" } });
    const next = await adapter.rotate!("K");
    expect(next.length).toBeGreaterThanOrEqual(16);
    expect(next).not.toBe("old");
    expect(await adapter.fetch("K")).toBe(next);
  });

  test("custom rotate strategy is used", async () => {
    const adapter = inMemoryAdapter({
      initial: { K: "v1" },
      rotate: (name, previous) => `${previous}-rotated-${name}`,
    });
    const next = await adapter.rotate!("K");
    expect(next).toBe("v1-rotated-K");
  });
});

describe("envAdapter", () => {
  test("reads from a scoped prefix", async () => {
    const adapter = envAdapter({
      env: { ABS_STRIPE_KEY: "sk-test", OTHER: "ignored" },
      prefix: "ABS_",
    });
    expect(await adapter.fetch("STRIPE_KEY")).toBe("sk-test");
    expect(await adapter.fetch("OTHER")).toBeNull();
    expect(await adapter.list?.()).toEqual(["STRIPE_KEY"]);
  });

  test("with no prefix exposes every env entry", async () => {
    const adapter = envAdapter({ env: { A: "1", B: "2" } });
    expect(await adapter.fetch("A")).toBe("1");
    expect(await adapter.list?.()).toEqual(["A", "B"]);
  });
});

describe("compositeAdapter", () => {
  test("fetch falls through until one returns non-null", async () => {
    const composite = compositeAdapter([
      { fetch: async (name) => (name === "A" ? "first" : null) },
      { fetch: async (name) => (name === "B" ? "second" : null) },
    ]);
    expect(await composite.fetch("A")).toBe("first");
    expect(await composite.fetch("B")).toBe("second");
    expect(await composite.fetch("C")).toBeNull();
  });

  test("put / rotate go to the first adapter that supports them", async () => {
    const putTarget: string[] = [];
    const readonly: SecretAdapter = { fetch: async () => null };
    const writeable: SecretAdapter = {
      fetch: async () => null,
      put: async (name) => {
        putTarget.push(name);
      },
      rotate: async () => "rotated",
    };
    const composite = compositeAdapter([readonly, writeable]);
    await composite.put!("K", "v");
    expect(putTarget).toEqual(["K"]);
    expect(await composite.rotate!("K")).toBe("rotated");
  });

  test("put throws when no adapter supports it", async () => {
    const composite = compositeAdapter([{ fetch: async () => null }]);
    await expect(composite.put!("K", "v")).rejects.toThrow(/put/);
  });

  test("list deduplicates across adapters", async () => {
    const a: SecretAdapter = {
      fetch: async () => null,
      list: async () => ["A", "B"],
    };
    const b: SecretAdapter = {
      fetch: async () => null,
      list: async () => ["B", "C"],
    };
    const composite = compositeAdapter([a, b]);
    expect(new Set((await composite.list?.()) ?? [])).toEqual(
      new Set(["A", "B", "C"]),
    );
  });
});
