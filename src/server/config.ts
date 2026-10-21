const REQUIRED_SECRET_NAMES = [
  "MASTER_KEY",
  "AUDIT_HMAC_SECRET",
  "SESSION_SECRET"
] as const;

const REQUIRED_ENV_NAMES = ["DATABASE_URL", ...REQUIRED_SECRET_NAMES] as const;
const MIN_SECRET_BYTES = 32;

export interface AppConfig {
  databaseUrl: string;
  masterKey: string;
  auditHmacSecret: string;
  sessionSecret: string;
}

export class EnvironmentConfigurationError extends Error {
  constructor(invalidNames: readonly string[]) {
    super(
      `Invalid environment configuration. Missing or invalid (required secrets must be at least ${MIN_SECRET_BYTES} bytes): ${invalidNames.join(", ")}`
    );
    this.name = "EnvironmentConfigurationError";
  }
}

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const invalidNames = REQUIRED_ENV_NAMES.filter((name) => {
    const value = env[name];
    return (
      value === undefined ||
      Buffer.byteLength(value, "utf8") < MIN_SECRET_BYTES ||
      (name === "DATABASE_URL" && !isPostgresUrl(value))
    );
  });

  if (invalidNames.length > 0) {
    throw new EnvironmentConfigurationError(invalidNames);
  }

  return {
    databaseUrl: env.DATABASE_URL!,
    masterKey: env.MASTER_KEY!,
    auditHmacSecret: env.AUDIT_HMAC_SECRET!,
    sessionSecret: env.SESSION_SECRET!
  };
}

function isPostgresUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:") &&
      parsed.hostname.length > 0 &&
      parsed.pathname.length > 1
    );
  } catch {
    return false;
  }
}
