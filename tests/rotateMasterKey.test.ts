/**
 * Tests for rotateMasterKey — the "leaked passphrase, re-encrypt under
 * a new master key" helper.
 */
import { describe, expect, test } from "bun:test";
import {
  encryptedFileAdapter,
  rotateMasterKey,
  type EncryptedFileIO,
} from "../src/index";

const memoryIo = (
  initial: Record<string, string> = {},
): EncryptedFileIO & { snapshot: () => Record<string, string> } => {
  const files = new Map(Object.entries(initial));
  return {
    readFile: async (path) => files.get(path),
    snapshot: () => Object.fromEntries(files),
    writeFileAtomic: async (path, contents) => {
      files.set(path, contents);
    },
  };
};

const FILE_PATH = "/test/secrets.enc.json";
const RAW_KEY_A = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) RAW_KEY_A[i] = i;
const RAW_KEY_B = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) RAW_KEY_B[i] = i + 100;

const SAMPLE = {
  DATABASE_URL: "postgres://prod",
  OPENAI_KEY: "sk-openai-xyz",
  STRIPE_KEY: "sk_live_xyz",
};

const seedFile = async (
  io: EncryptedFileIO,
  key:
    | { type: "passphrase"; passphrase: string }
    | { type: "raw"; bytes: Uint8Array },
): Promise<void> => {
  const adapter = encryptedFileAdapter({
    io,
    key,
    path: FILE_PATH,
    pbkdf2Iterations: 1000,
  });
  for (const [name, value] of Object.entries(SAMPLE)) {
    await adapter.put?.(name, value);
  }
};

const expectAllValuesReadable = async (
  io: EncryptedFileIO,
  key:
    | { type: "passphrase"; passphrase: string }
    | { type: "raw"; bytes: Uint8Array },
): Promise<void> => {
  const adapter = encryptedFileAdapter({
    io,
    key,
    path: FILE_PATH,
    pbkdf2Iterations: 1000,
  });
  for (const [name, value] of Object.entries(SAMPLE)) {
    expect(await adapter.fetch(name)).toBe(value);
  }
};

describe("rotateMasterKey — passphrase → passphrase", () => {
  test("re-encrypts so the new passphrase reads + the old fails", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });

    await rotateMasterKey({
      io,
      newKey: { passphrase: "new-pass", type: "passphrase" },
      newPbkdf2Iterations: 1000,
      oldKey: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
    });

    await expectAllValuesReadable(io, {
      passphrase: "new-pass",
      type: "passphrase",
    });

    // The old passphrase fails to decrypt.
    const oldReader = encryptedFileAdapter({
      io,
      key: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
      pbkdf2Iterations: 1000,
    });
    await expect(oldReader.fetch("STRIPE_KEY")).rejects.toThrow(
      "wrong master key",
    );
  });

  test("uses a fresh salt + IVs after rotation", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });
    const before = JSON.parse(io.snapshot()[FILE_PATH] as string);
    await rotateMasterKey({
      io,
      newKey: { passphrase: "new-pass", type: "passphrase" },
      newPbkdf2Iterations: 1000,
      oldKey: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
    });
    const after = JSON.parse(io.snapshot()[FILE_PATH] as string);
    // Salt is new.
    expect(after.kdf.salt).not.toBe(before.kdf.salt);
    // IVs are new.
    for (const name of Object.keys(SAMPLE)) {
      expect(after.values[name].iv).not.toBe(before.values[name].iv);
      expect(after.values[name].ct).not.toBe(before.values[name].ct);
    }
  });
});

describe("rotateMasterKey — cross-mode transitions", () => {
  test("passphrase → raw key", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });
    await rotateMasterKey({
      io,
      newKey: { bytes: RAW_KEY_A, type: "raw" },
      oldKey: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
    });
    await expectAllValuesReadable(io, { bytes: RAW_KEY_A, type: "raw" });
    // File should no longer have a kdf section.
    const parsed = JSON.parse(io.snapshot()[FILE_PATH] as string);
    expect(parsed.kdf).toBeUndefined();
  });

  test("raw key → passphrase", async () => {
    const io = memoryIo();
    await seedFile(io, { bytes: RAW_KEY_A, type: "raw" });
    await rotateMasterKey({
      io,
      newKey: { passphrase: "new-pass", type: "passphrase" },
      newPbkdf2Iterations: 1000,
      oldKey: { bytes: RAW_KEY_A, type: "raw" },
      path: FILE_PATH,
    });
    await expectAllValuesReadable(io, {
      passphrase: "new-pass",
      type: "passphrase",
    });
    const parsed = JSON.parse(io.snapshot()[FILE_PATH] as string);
    expect(parsed.kdf.type).toBe("pbkdf2-sha256");
  });

  test("raw key → raw key", async () => {
    const io = memoryIo();
    await seedFile(io, { bytes: RAW_KEY_A, type: "raw" });
    await rotateMasterKey({
      io,
      newKey: { bytes: RAW_KEY_B, type: "raw" },
      oldKey: { bytes: RAW_KEY_A, type: "raw" },
      path: FILE_PATH,
    });
    await expectAllValuesReadable(io, { bytes: RAW_KEY_B, type: "raw" });
  });
});

describe("rotateMasterKey — guards", () => {
  test("wrong old passphrase fails loudly", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });
    await expect(
      rotateMasterKey({
        io,
        newKey: { passphrase: "new-pass", type: "passphrase" },
        oldKey: { passphrase: "WRONG", type: "passphrase" },
        path: FILE_PATH,
      }),
    ).rejects.toThrow("wrong key or corrupted file");
  });

  test("missing file throws", async () => {
    const io = memoryIo();
    await expect(
      rotateMasterKey({
        io,
        newKey: { passphrase: "new", type: "passphrase" },
        oldKey: { passphrase: "old", type: "passphrase" },
        path: FILE_PATH,
      }),
    ).rejects.toThrow("does not exist");
  });

  test("cross-mode mismatch on oldKey throws", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });
    await expect(
      rotateMasterKey({
        io,
        newKey: { passphrase: "new", type: "passphrase" },
        oldKey: { bytes: RAW_KEY_A, type: "raw" },
        path: FILE_PATH,
      }),
    ).rejects.toThrow(
      "written with a passphrase but old key was supplied as raw",
    );
  });

  test("cross-mode mismatch on raw-written file with passphrase oldKey throws", async () => {
    const io = memoryIo();
    await seedFile(io, { bytes: RAW_KEY_A, type: "raw" });
    await expect(
      rotateMasterKey({
        io,
        newKey: { passphrase: "new", type: "passphrase" },
        oldKey: { passphrase: "old", type: "passphrase" },
        path: FILE_PATH,
      }),
    ).rejects.toThrow(
      "written with a raw key but old key was supplied as passphrase",
    );
  });

  test("file remains intact if decryption fails (no partial write)", async () => {
    const io = memoryIo();
    await seedFile(io, { passphrase: "old-pass", type: "passphrase" });
    const before = io.snapshot()[FILE_PATH];
    await expect(
      rotateMasterKey({
        io,
        newKey: { passphrase: "new-pass", type: "passphrase" },
        oldKey: { passphrase: "WRONG", type: "passphrase" },
        path: FILE_PATH,
      }),
    ).rejects.toThrow();
    const after = io.snapshot()[FILE_PATH];
    expect(after).toBe(before);
  });
});

describe("rotateMasterKey — value preservation", () => {
  test("all values round-trip exactly through rotation", async () => {
    const io = memoryIo();
    const interesting: Record<string, string> = {
      DOLLAR_SIGNS: "a$b$c",
      LONG_VALUE: "x".repeat(2000),
      QUOTES: "a\"b'c",
      SPECIAL: "éñü",
      WITH_SPACES: "value with spaces",
    };
    const setupAdapter = encryptedFileAdapter({
      io,
      key: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
      pbkdf2Iterations: 1000,
    });
    for (const [name, value] of Object.entries(interesting)) {
      await setupAdapter.put?.(name, value);
    }

    await rotateMasterKey({
      io,
      newKey: { bytes: RAW_KEY_A, type: "raw" },
      oldKey: { passphrase: "old-pass", type: "passphrase" },
      path: FILE_PATH,
    });

    const reader = encryptedFileAdapter({
      io,
      key: { bytes: RAW_KEY_A, type: "raw" },
      path: FILE_PATH,
    });
    for (const [name, value] of Object.entries(interesting)) {
      expect(await reader.fetch(name)).toBe(value);
    }
  });
});
