import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

async function main(): Promise<void> {
  try {
    loadConfig(process.env);
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error("Invalid environment configuration.");
    }
    process.exitCode = 1;
    return;
  }

  const app = createApp();
  const portValue = process.env.PORT ?? "3000";
  const port = Number(portValue);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("Invalid PORT; expected an integer from 1 to 65535.");
    process.exitCode = 1;
    return;
  }

  try {
    await app.listen({ host: "0.0.0.0", port });
  } catch (error) {
    console.error(
      "TrustVault server failed to start:",
      error instanceof Error ? error.message : "Unknown error."
    );
    process.exitCode = 1;
  }
}

void main();
