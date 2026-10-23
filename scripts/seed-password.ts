const LOCAL_DEMO_PASSWORD = "TrustVault-Local-Demo-2026!";

export function getSeedDemoPassword(environment: NodeJS.ProcessEnv): string {
  const configuredPassword = environment.SEED_DEMO_PASSWORD;
  if (environment.NODE_ENV === "production") {
    if (!configuredPassword?.trim()) {
      throw new Error("SEED_DEMO_PASSWORD is required to seed in production.");
    }
    return configuredPassword;
  }
  return configuredPassword?.trim() ? configuredPassword : LOCAL_DEMO_PASSWORD;
}
