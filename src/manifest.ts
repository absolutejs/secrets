import {
  defineImplementation,
  defineManifest,
  toolFactory,
} from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";
import type {
  EncryptedFileAdapterOptions,
  EnvAdapterOptions,
  InMemoryAdapterOptions,
  SecretBroker,
  SecretBrokerOptions,
} from "./broker";

const tool = toolFactory<SecretBroker>();

/* Serializable subset of SecretBrokerOptions: cache + redaction knobs only.
 * `adapter` is instance-valued → the `adapter` slot; `audit` / `clock` /
 * `tracerProvider` are function-or-instance-valued → wiring concerns, never
 * settings. Tools NEVER return secret values — names, fingerprints, and
 * counters only. */
const settings = Type.Object({
  cacheTtlMs: Type.Optional(
    Type.Number({
      description:
        "How long a fetched secret is reused before asking the store again, in milliseconds. Default is 1 minute.",
      minimum: 0,
      title: "Secret cache lifetime",
      "x-group": "caching",
    }),
  ),
  cacheTtlOverrides: Type.Optional(
    Type.Record(Type.String(), Type.Number({ minimum: 0 }), {
      description:
        "Per-secret cache lifetimes (milliseconds) that override the default. Use a short lifetime for high-impact keys like admin tokens.",
      title: "Per-secret cache lifetimes",
      "x-group": "caching",
    }),
  ),
  redactionEncodings: Type.Optional(
    Type.Array(Type.Union([Type.Literal("plain"), Type.Literal("base64")]), {
      description:
        "Which forms of a secret get scrubbed from logs. Add 'base64' to also catch secrets hidden inside tokens and cookies.",
      title: "Scrubbed encodings",
      "x-group": "redaction",
    }),
  ),
  redactionMinLength: Type.Optional(
    Type.Integer({
      description:
        "Secrets shorter than this are not scrubbed from logs, to avoid blanking coincidental short matches. Default 8.",
      minimum: 1,
      title: "Minimum length to scrub",
      "x-group": "redaction",
    }),
  ),
});

export const manifest = defineManifest<SecretBrokerOptions, SecretBroker>()({
  contract: 2,
  identity: {
    accent: "#0d9488",
    category: "infrastructure",
    description:
      "One `createSecretBroker()` for resolving, caching, rotating, and log-scrubbing credentials. Pluggable adapters (env vars, encrypted file, in-memory, composite), sha256 fingerprints safe for logs, an audit hook on every lookup, and `redact()` / `redactStream()` that strip known secrets out of anything headed for a log sink.",
    docsUrl: "https://github.com/absolutejs/secrets",
    name: "@absolutejs/secrets",
    tagline: "Keep API keys and passwords out of your code and logs.",
  },
  implements: [
    defineImplementation<EnvAdapterOptions>()({
      contract: "secrets/adapter",
      factory: "envAdapter",
      from: "@absolutejs/secrets",
      settings: Type.Object({
        prefix: Type.Optional(
          Type.String({
            description:
              "Only environment variables starting with this prefix are treated as secrets, looked up without it (prefix 'ABS_SECRET_' makes STRIPE_KEY read ABS_SECRET_STRIPE_KEY).",
            examples: ["ABS_SECRET_"],
            title: "Variable prefix",
          }),
        ),
      }),
      title: "Environment variables (simplest — reads process.env)",
      wiring: {
        code: "envAdapter(${settings})",
        imports: [{ from: "@absolutejs/secrets", names: ["envAdapter"] }],
      },
    }),
    defineImplementation<InMemoryAdapterOptions>()({
      contract: "secrets/adapter",
      factory: "inMemoryAdapter",
      from: "@absolutejs/secrets",
      settings: Type.Object({}),
      title: "In memory (development only — values reset on restart)",
      wiring: {
        code: "inMemoryAdapter()",
        imports: [{ from: "@absolutejs/secrets", names: ["inMemoryAdapter"] }],
      },
    }),
    defineImplementation<EncryptedFileAdapterOptions>()({
      contract: "secrets/adapter",
      factory: "encryptedFileAdapter",
      from: "@absolutejs/secrets",
      requires: {
        env: [
          {
            description:
              "Master passphrase that unlocks the encrypted secrets file. Keep it out of the repo (password manager, host env).",
            key: "SECRETS_MASTER_PASSPHRASE",
            secret: true,
          },
        ],
      },
      settings: Type.Object({
        path: Type.String({
          default: "./var/secrets.enc.json",
          description:
            "Where the encrypted file lives. Safe to commit to a private repo — values are AES-256-GCM encrypted; only the master passphrase unlocks them.",
          title: "Encrypted file location",
        }),
      }),
      title: "Encrypted file (durable — unlocked by a master passphrase)",
      wiring: {
        code: "encryptedFileAdapter({ key: { passphrase: ${env.SECRETS_MASTER_PASSPHRASE} ?? '', type: 'passphrase' }, ...${settings} })",
        imports: [
          {
            from: "@absolutejs/secrets",
            names: ["encryptedFileAdapter"],
          },
        ],
      },
    }),
  ],
  settings,
  slots: {
    adapter: {
      configPath: "adapter",
      contract: "secrets/adapter",
      description: "Where your secret values live",
      known: [
        "@absolutejs/secrets#env",
        "@absolutejs/secrets#memory",
        "@absolutejs/secrets#encrypted-file",
      ],
      required: true,
    },
  },
  tools: {
    check_secret: tool.runtime({
      annotations: { readOnlyHint: true },
      authorization: {
        approval: "never",
        audience: "admin",
        effects: ["read"],
        requiredScopes: ["secrets:inspect"],
      },
      description:
        "Check whether a named secret is configured. Reports presence and a log-safe sha256 fingerprint — never the value.",
      handler: async ({ name }, broker) => {
        const secret = await broker.resolve(name);

        return secret === null
          ? `"${name}" is not configured`
          : `"${name}" is configured (fingerprint ${secret.fingerprint})`;
      },
      input: Type.Object({ name: Type.String({ minLength: 1 }) }),
    }),
    redact_text: tool.runtime({
      annotations: { readOnlyHint: true },
      authorization: {
        approval: "never",
        audience: "admin",
        effects: ["read"],
        requiredScopes: ["secrets:redact"],
      },
      description:
        "Preview redaction: returns the given text with every known (cached) secret replaced by [REDACTED:name]. Useful to check a log line or error message is safe to share. Only secrets the broker has already resolved are scrubbed.",
      handler: ({ text }, broker) => broker.redact(text),
      input: Type.Object({ text: Type.String() }),
    }),
    secret_stats: tool.runtime({
      annotations: { readOnlyHint: true },
      authorization: {
        approval: "never",
        audience: "admin",
        effects: ["read"],
        requiredScopes: ["secrets:inspect"],
      },
      description:
        "Cumulative broker counters since the server started: resolves (hits/misses/errors), rotations, and how often redaction actually fired.",
      handler: (_input, broker) => JSON.stringify(broker.metrics()),
      input: Type.Object({}),
    }),
  },
  wiring: [
    {
      id: "default",
      server: {
        code: "const secrets = createSecretBroker({ adapter: ${slot.adapter}, ...${settings} });",
        imports: [
          {
            from: "@absolutejs/secrets",
            names: ["createSecretBroker"],
          },
        ],
        placement: "module-scope",
      },
      title: "Create the secret broker",
    },
  ],
});
