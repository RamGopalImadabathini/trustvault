import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "pg";

const MIGRATION_NAME_PATTERN = /^\d{3,}_[a-z0-9_]+\.sql$/;
const MIGRATION_LOCK_ID = 73190421;

async function migrate(): Promise<void> {
  const connectionString = process.env.DB_MIGRATION_URL;

  if (!connectionString) {
    throw new Error("DB_MIGRATION_URL is required to apply migrations.");
  }

  const migrationsPath = fileURLToPath(
    new URL("../db/migrations/", import.meta.url)
  );
  const names = (await readdir(migrationsPath))
    .filter((name) => name.endsWith(".sql"))
    .sort();

  for (const name of names) {
    if (!MIGRATION_NAME_PATTERN.test(name)) {
      throw new Error(`Invalid migration filename: ${name}`);
    }
  }

  const client = new Client({ connectionString });
  await client.connect();

  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_ID]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const appliedResult = await client.query<{ name: string }>(
      "SELECT name FROM schema_migrations"
    );
    const applied = new Set(appliedResult.rows.map((row) => row.name));

    for (const name of names) {
      if (applied.has(name)) {
        continue;
      }

      const sql = await readFile(path.join(migrationsPath, name), "utf8");
      await client.query("BEGIN");

      try {
        await client.query(sql);
        await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [
          name
        ]);
        await client.query("COMMIT");
        console.info(`Applied migration ${name}`);
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
  } finally {
    try {
      await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_ID]);
    } finally {
      await client.end();
    }
  }
}

void migrate().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown migration error.";
  console.error(`Migration failed: ${message}`);
  process.exitCode = 1;
});
