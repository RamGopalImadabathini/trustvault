import "dotenv/config";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createPool } from "./db.js";

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const portValue = process.env.PORT ?? "3000";
  const port = Number(portValue);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Invalid PORT; expected an integer from 1 to 65535.");
  }

  const pool = createPool(config);
  try {
    await pool.query("SELECT 1");
    const app = createApp({
      pool,
      config,
      storageDirectory: path.resolve(process.env.STORAGE_DIRECTORY ?? "storage")
    });
    await app.listen({ host: "0.0.0.0", port });
    console.info(`TrustVault API listening on port ${port}`);
  } catch (error) {
    await pool.end();
    throw error;
  }
}

void main().catch((error: unknown) => {
  console.error(
    "TrustVault server failed to start:",
    error instanceof Error ? error.message : "Unknown error."
  );
  process.exitCode = 1;
});
