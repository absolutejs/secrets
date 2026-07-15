import {
  type ActionDecision,
  type Agency,
  type AgentActor,
  digest,
} from "@absolutejs/agency";
import type { SecretBroker } from "./index";

export type CredentialGrant = {
  agentId: string;
  allowedOrigins: ReadonlyArray<string>;
  createdAt: number;
  expiresAt: number;
  grantId: string;
  maximumUses: number;
  provider: string;
  scopes: ReadonlyArray<string>;
  secretName: string;
  used: number;
  userId: string;
};

export type CredentialOperationInput = {
  actor: AgentActor;
  destination: string;
  grantId: string;
  idempotencyKey?: string;
  input?: unknown;
  operation: string;
};

export type CredentialOperationContext = {
  credential: string;
  destination: URL;
  input: unknown;
  signal?: AbortSignal;
};

export type CredentialProvider = {
  operations: Record<
    string,
    (context: CredentialOperationContext) => Promise<unknown> | unknown
  >;
  provider: string;
};

export type PendingCredentialOperation = {
  actionId: string;
  input: CredentialOperationInput;
};

export type CredentialGrantStore = {
  consume: (
    grantId: string,
    now: number,
  ) => Promise<CredentialGrant | undefined>;
  get: (grantId: string) => Promise<CredentialGrant | undefined>;
  getPending: (
    actionId: string,
  ) => Promise<PendingCredentialOperation | undefined>;
  put: (grant: CredentialGrant) => Promise<void>;
  putPending: (pending: PendingCredentialOperation) => Promise<void>;
  revoke: (grantId: string) => Promise<boolean>;
};

export type CredentialOperationEvent =
  | {
      actionId?: string;
      destinationOrigin: string;
      grantId: string;
      operation: string;
      provider: string;
      type: "credential.operation.requested";
    }
  | {
      actionId?: string;
      destinationOrigin: string;
      grantId: string;
      operation: string;
      provider: string;
      resultDigest?: string;
      status: "failed" | "succeeded";
      type: "credential.operation.completed";
    };

export type CredentialOperationResult =
  | {
      actionId: string;
      decision: ActionDecision;
      kind: "pending";
    }
  | {
      actionId?: string;
      kind: "completed";
      result: unknown;
      resultDigest: string;
    };

export type CredentialOperationBrokerOptions = {
  agency?: Agency;
  emit?: (event: CredentialOperationEvent) => Promise<void> | void;
  now?: () => number;
  providers: ReadonlyArray<CredentialProvider>;
  secrets: SecretBroker;
  store: CredentialGrantStore;
};

const normalizeOrigin = (destination: string) => new URL(destination).origin;

const validateGrant = (
  grant: CredentialGrant,
  input: CredentialOperationInput,
  now: number,
) => {
  if (
    grant.agentId !== input.actor.agentId ||
    grant.userId !== input.actor.userId
  )
    throw new Error("Credential grant actor mismatch");
  if (grant.expiresAt <= now) throw new Error("Credential grant has expired");
  if (!grant.scopes.includes(input.operation))
    throw new Error("Credential operation is outside grant scope");
  const origin = normalizeOrigin(input.destination);
  if (!grant.allowedOrigins.map(normalizeOrigin).includes(origin))
    throw new Error("Credential destination is outside grant scope");
  if (grant.used >= grant.maximumUses)
    throw new Error("Credential grant has been exhausted");

  return origin;
};

export const createMemoryCredentialGrantStore = (): CredentialGrantStore => {
  const grants = new Map<string, CredentialGrant>();
  const pending = new Map<string, PendingCredentialOperation>();
  let lock = Promise.resolve();

  const exclusive = async <Result>(run: () => Result | Promise<Result>) => {
    const previous = lock;
    let release = () => {};
    lock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await run();
    } finally {
      release();
    }
  };

  return {
    consume: (grantId, now) =>
      exclusive(() => {
        const grant = grants.get(grantId);
        if (
          grant === undefined ||
          grant.expiresAt <= now ||
          grant.used >= grant.maximumUses
        )
          return undefined;
        const consumed = { ...grant, used: grant.used + 1 };
        grants.set(grantId, consumed);
        return { ...consumed };
      }),
    get: async (grantId) => {
      const grant = grants.get(grantId);
      return grant === undefined ? undefined : { ...grant };
    },
    getPending: async (actionId) => pending.get(actionId),
    put: async (grant) => {
      if (grant.maximumUses < 1)
        throw new Error("maximumUses must be positive");
      if (grant.used < 0 || grant.used > grant.maximumUses)
        throw new Error("Invalid credential grant usage");
      grants.set(grant.grantId, { ...grant });
    },
    putPending: async (operation) => {
      pending.set(operation.actionId, operation);
    },
    revoke: async (grantId) => grants.delete(grantId),
  };
};

export const createCredentialOperationBroker = ({
  agency,
  emit,
  now = Date.now,
  providers,
  secrets,
  store,
}: CredentialOperationBrokerOptions) => {
  const providerMap = new Map(
    providers.map((provider) => [provider.provider, provider]),
  );

  const perform = async (
    input: CredentialOperationInput,
    actionId?: string,
    signal?: AbortSignal,
  ): Promise<CredentialOperationResult> => {
    const preview = await store.get(input.grantId);
    if (preview === undefined) throw new Error("Unknown credential grant");
    const origin = validateGrant(preview, input, now());
    const provider = providerMap.get(preview.provider);
    const operation = provider?.operations[input.operation];
    if (provider === undefined || operation === undefined)
      throw new Error("Credential provider operation is not registered");
    await emit?.({
      actionId,
      destinationOrigin: origin,
      grantId: preview.grantId,
      operation: input.operation,
      provider: preview.provider,
      type: "credential.operation.requested",
    });
    const consumed = await store.consume(input.grantId, now());
    if (consumed === undefined)
      throw new Error("Credential grant has been exhausted");
    validateGrant({ ...consumed, used: consumed.used - 1 }, input, now());
    const secret = await secrets.resolve(consumed.secretName);
    if (secret === null) throw new Error("Credential is not configured");
    try {
      const result = await operation({
        credential: secret.value,
        destination: new URL(input.destination),
        input: input.input,
        signal,
      });
      const resultDigest = await digest(result);
      await emit?.({
        actionId,
        destinationOrigin: origin,
        grantId: consumed.grantId,
        operation: input.operation,
        provider: consumed.provider,
        resultDigest,
        status: "succeeded",
        type: "credential.operation.completed",
      });
      return { actionId, kind: "completed", result, resultDigest };
    } catch (error) {
      await emit?.({
        actionId,
        destinationOrigin: origin,
        grantId: consumed.grantId,
        operation: input.operation,
        provider: consumed.provider,
        status: "failed",
        type: "credential.operation.completed",
      });
      throw error;
    }
  };

  const request = async (
    input: CredentialOperationInput,
    signal?: AbortSignal,
  ): Promise<CredentialOperationResult> => {
    const grant = await store.get(input.grantId);
    if (grant === undefined) throw new Error("Unknown credential grant");
    const origin = validateGrant(grant, input, now());
    if (agency === undefined) return perform(input, undefined, signal);
    const { action, decision } = await agency.request({
      action: `credential.${grant.provider}.${input.operation}`,
      actor: input.actor,
      context: { destinationOrigin: origin, grantId: grant.grantId },
      effects: ["external-network"],
      expiresAt: grant.expiresAt,
      idempotencyKey: input.idempotencyKey,
      input: { destination: input.destination, input: input.input },
      resource: { id: grant.grantId, type: "credential-grant" },
    });
    if (decision.kind !== "allow") {
      await store.putPending({ actionId: action.actionId, input });
      return { actionId: action.actionId, decision, kind: "pending" };
    }
    const lease = await agency.issueLease(action.actionId);
    const execution = await agency.execute({
      executor: `credential-provider:${grant.provider}`,
      leaseId: lease.leaseId,
      run: () => perform(input, action.actionId, signal),
    });
    return execution.result;
  };

  const resume = async (actionId: string, signal?: AbortSignal) => {
    if (agency === undefined) throw new Error("Agency is not configured");
    const pending = await store.getPending(actionId);
    if (pending === undefined)
      throw new Error("Unknown pending credential operation");
    const lease = await agency.issueLease(actionId);
    const execution = await agency.execute({
      executor: "credential-provider",
      leaseId: lease.leaseId,
      run: () => perform(pending.input, actionId, signal),
    });
    return execution.result;
  };

  return { request, resume, revoke: store.revoke };
};

export type CredentialOperationBroker = ReturnType<
  typeof createCredentialOperationBroker
>;
