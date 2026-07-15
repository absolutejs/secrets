import type { CredentialGrant, CredentialGrantStore, PendingCredentialOperation } from "./operations";

export type SecretsSqlResult<Row> = { rowCount: number; rows: ReadonlyArray<Row> };
export type SecretsSqlClient = {
  query: <Row = Record<string, unknown>>(sql: string, parameters?: ReadonlyArray<unknown>) => Promise<SecretsSqlResult<Row>>;
};

const namespaceOf = (namespace: string) => {
  if (!/^[a-z_][a-z0-9_]*$/.test(namespace))
    throw new Error("Secrets PostgreSQL namespace must be a simple identifier");
  return namespace;
};

export const credentialGrantsPostgresSchemaSql = (namespace = "secrets") => {
  const ns = namespaceOf(namespace);
  return `CREATE SCHEMA IF NOT EXISTS ${ns};
CREATE TABLE IF NOT EXISTS ${ns}.credential_grants (
  grant_id text PRIMARY KEY, agent_id text NOT NULL, user_id text NOT NULL,
  provider text NOT NULL, expires_at bigint NOT NULL, maximum_uses integer NOT NULL CHECK (maximum_uses > 0),
  used integer NOT NULL DEFAULT 0 CHECK (used >= 0 AND used <= maximum_uses), data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS credential_grants_agent_idx ON ${ns}.credential_grants (agent_id, expires_at);
CREATE TABLE IF NOT EXISTS ${ns}.pending_operations (
  action_id text PRIMARY KEY, grant_id text NOT NULL REFERENCES ${ns}.credential_grants(grant_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(), data jsonb NOT NULL
);`;
};

type DataRow<Value> = { data: Value };

export const createPostgresCredentialGrantStore = ({ client, namespace = "secrets" }: { client: SecretsSqlClient; namespace?: string }): CredentialGrantStore => {
  const ns = namespaceOf(namespace);
  return {
    consume: async (grantId, now) => {
      const result = await client.query<DataRow<CredentialGrant>>(
        `UPDATE ${ns}.credential_grants SET used = used + 1, data = jsonb_set(data, '{used}', to_jsonb(used + 1), true) WHERE grant_id = $1 AND expires_at > $2 AND used < maximum_uses RETURNING data`,
        [grantId, now],
      );
      return result.rows[0]?.data;
    },
    get: async (grantId) =>
      (await client.query<DataRow<CredentialGrant>>(`SELECT data FROM ${ns}.credential_grants WHERE grant_id = $1`, [grantId])).rows[0]?.data,
    getPending: async (actionId) =>
      (await client.query<DataRow<PendingCredentialOperation>>(`SELECT data FROM ${ns}.pending_operations WHERE action_id = $1`, [actionId])).rows[0]?.data,
    put: async (grant) => {
      if (grant.maximumUses < 1 || grant.used < 0 || grant.used > grant.maximumUses)
        throw new Error("Invalid credential grant usage");
      await client.query(
        `INSERT INTO ${ns}.credential_grants (grant_id, agent_id, user_id, provider, expires_at, maximum_uses, used, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT (grant_id) DO UPDATE SET expires_at=EXCLUDED.expires_at, maximum_uses=EXCLUDED.maximum_uses, used=EXCLUDED.used, data=EXCLUDED.data`,
        [grant.grantId, grant.agentId, grant.userId, grant.provider, grant.expiresAt, grant.maximumUses, grant.used, JSON.stringify(grant)],
      );
    },
    putPending: async (pending) => {
      await client.query(
        `INSERT INTO ${ns}.pending_operations (action_id, grant_id, data) VALUES ($1,$2,$3::jsonb) ON CONFLICT (action_id) DO UPDATE SET data=EXCLUDED.data`,
        [pending.actionId, pending.input.grantId, JSON.stringify(pending)],
      );
    },
    revoke: async (grantId) =>
      (await client.query(`DELETE FROM ${ns}.credential_grants WHERE grant_id = $1`, [grantId])).rowCount === 1,
  };
};
