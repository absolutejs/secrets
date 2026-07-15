import { describe, expect, test } from 'bun:test';
import { createPostgresCredentialGrantStore, credentialGrantsPostgresSchemaSql, type SecretsSqlClient } from '../src';

describe('PostgreSQL credential grants', () => {
	test('consumes with one bounded update', async () => {
		const calls: string[] = [];
		const client: SecretsSqlClient = { query: async (sql) => {
			calls.push(sql);
			return { rowCount: 0, rows: [] };
		} };
		const store = createPostgresCredentialGrantStore({ client });
		expect(await store.consume('grant-1', 100)).toBeUndefined();
		expect(calls[0]).toContain('used < maximum_uses');
		expect(calls[0]).toContain('expires_at >');
	});

	test('rejects unsafe schema identifiers', () => {
		expect(credentialGrantsPostgresSchemaSql()).toContain('secrets.credential_grants');
		expect(() => credentialGrantsPostgresSchemaSql('bad;drop')).toThrow('simple identifier');
	});
});
