import "dotenv/config";
import { loadConfig } from "../src/server/config.js";
import { createPool } from "../src/server/db.js";
import { verifyAuditChain } from "../src/server/audit.js";

async function verify(): Promise<void> {
  const config = loadConfig(process.env);
  const pool = createPool(config);
  try {
    const client = await pool.connect();
    try {
      const result = await verifyAuditChain(client, config.auditHmacSecret);
      if (!result.valid) {
        console.error(`Audit chain invalid at row ${result.firstInvalidId}.`);
        process.exitCode = 1;
        return;
      }
      console.info(`Audit chain valid (${result.checked} rows).`);
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

void verify().catch((error: unknown) => {
  console.error(
    "Audit chain verification failed:",
    error instanceof Error ? error.message : "Unknown verification error."
  );
  process.exitCode = 1;
});
