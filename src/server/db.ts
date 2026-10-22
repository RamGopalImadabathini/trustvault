import { Pool, type PoolClient } from "pg";
import type { AppConfig } from "./config.js";

export function createPool(config: AppConfig): Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: "trustvault-api"
  });
}

export async function inTransaction<T>(
  client: PoolClient,
  work: () => Promise<T>
): Promise<T> {
  await client.query("BEGIN");
  try {
    const result = await work();
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}
