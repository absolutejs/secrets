import { describe, expect, test } from "bun:test";
import {
  allowAllPolicy,
  createAgency,
  createMemoryAgencyStore,
} from "@absolutejs/agency";
import {
  createCredentialOperationBroker,
  createMemoryCredentialGrantStore,
  createSecretBroker,
  inMemoryAdapter,
  type CredentialGrant,
} from "../src";

const actor = {
  agentId: "agent_1",
  scopes: ["mail:send"],
  userId: "user_1",
};

const setup = async ({
  agency,
}: { agency?: ReturnType<typeof createAgency> } = {}) => {
  const adapter = inMemoryAdapter();
  await adapter.put?.("mail-token", "never-enter-model-context");
  const secrets = createSecretBroker({ adapter });
  const store = createMemoryCredentialGrantStore();
  const grant: CredentialGrant = {
    agentId: actor.agentId,
    allowedOrigins: ["https://api.mail.test"],
    createdAt: 1,
    expiresAt: 10_000,
    grantId: "grant_1",
    maximumUses: 1,
    provider: "mail",
    scopes: ["send"],
    secretName: "mail-token",
    used: 0,
    userId: actor.userId,
  };
  await store.put(grant);
  const seen: string[] = [];
  const broker = createCredentialOperationBroker({
    agency,
    now: () => 100,
    providers: [
      {
        operations: {
          send: ({ credential, destination }) => {
            seen.push(credential, destination.origin);
            return { messageId: "msg_1" };
          },
        },
        provider: "mail",
      },
    ],
    secrets,
    store,
  });

  return { broker, grant, seen, store };
};

describe("credential operation broker", () => {
  test("keeps the credential host-side and consumes a single-use grant", async () => {
    const { broker, seen } = await setup();
    const result = await broker.request({
      actor,
      destination: "https://api.mail.test/v1/messages",
      grantId: "grant_1",
      input: { subject: "hello" },
      operation: "send",
    });
    expect(result.kind).toBe("completed");
    expect(JSON.stringify(result)).not.toContain("never-enter-model-context");
    expect(seen).toEqual([
      "never-enter-model-context",
      "https://api.mail.test",
    ]);
    await expect(
      broker.request({
        actor,
        destination: "https://api.mail.test/v1/messages",
        grantId: "grant_1",
        operation: "send",
      }),
    ).rejects.toThrow("exhausted");
  });

  test("rejects confused deputies, scope escalation, and lookalike origins", async () => {
    const { broker } = await setup();
    await expect(
      broker.request({
        actor: { ...actor, agentId: "agent_2" },
        destination: "https://api.mail.test",
        grantId: "grant_1",
        operation: "send",
      }),
    ).rejects.toThrow("actor mismatch");
    await expect(
      broker.request({
        actor,
        destination: "https://api.mail.test",
        grantId: "grant_1",
        operation: "delete-account",
      }),
    ).rejects.toThrow("outside grant scope");
    await expect(
      broker.request({
        actor,
        destination: "https://api.mail.test.evil.example",
        grantId: "grant_1",
        operation: "send",
      }),
    ).rejects.toThrow("destination");
  });

  test("runs an allowed operation through a single-use agency lease", async () => {
    const agency = createAgency({
      now: () => 100,
      policy: allowAllPolicy(),
      store: createMemoryAgencyStore(),
    });
    const { broker } = await setup({ agency });
    const result = await broker.request({
      actor,
      destination: "https://api.mail.test",
      grantId: "grant_1",
      operation: "send",
    });
    expect(result.kind).toBe("completed");
    expect(result.actionId).toStartWith("act_");
  });

  test("persists requestable denials for approval and resume", async () => {
    let approved = false;
    const agency = createAgency({
      now: () => 100,
      policy: {
        evaluate: ({ approval }) =>
          approval || approved
            ? {
                decisionId: "allow",
                evaluatedAt: 100,
                kind: "allow" as const,
              }
            : {
                decisionId: "deny",
                evaluatedAt: 100,
                kind: "deny" as const,
                reason: "Approval required",
                requestable: true,
              },
      },
      store: createMemoryAgencyStore(),
    });
    const { broker } = await setup({ agency });
    const pending = await broker.request({
      actor,
      destination: "https://api.mail.test",
      grantId: "grant_1",
      operation: "send",
    });
    expect(pending.kind).toBe("pending");
    if (pending.kind !== "pending") throw new Error("Expected pending");
    approved = true;
    await agency.approve({
      actionId: pending.actionId,
      approvedBy: "user_1",
      approvedUntil: 1_000,
    });
    const result = await broker.resume(pending.actionId);
    expect(result.kind).toBe("completed");
  });
});
