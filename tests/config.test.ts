import { describe, expect, it } from "vitest";
import {
  EnvironmentConfigurationError,
  loadConfig
} from "../src/server/config.js";

const validEnv: NodeJS.ProcessEnv = {
  DATABASE_URL: "postgresql://user:password@localhost:5432/trustvault",
  MASTER_KEY: "m".repeat(32),
  AUDIT_HMAC_SECRET: "a".repeat(32),
  SESSION_SECRET: "s".repeat(32)
};

describe("loadConfig", () => {
  it("loads all required environment values", () => {
    expect(loadConfig(validEnv)).toEqual({
      databaseUrl: validEnv.DATABASE_URL,
      masterKey: validEnv.MASTER_KEY,
      auditHmacSecret: validEnv.AUDIT_HMAC_SECRET,
      sessionSecret: validEnv.SESSION_SECRET
    });
  });

  it("reports all missing and undersized variables together", () => {
    expect(() => loadConfig({})).toThrowError(
      "DATABASE_URL, MASTER_KEY, AUDIT_HMAC_SECRET, SESSION_SECRET"
    );
  });

  it("measures secrets in UTF-8 bytes", () => {
    const env = {
      ...validEnv,
      MASTER_KEY: "é".repeat(16)
    };

    expect(() => loadConfig(env)).not.toThrow();
    expect(() =>
      loadConfig({ ...env, MASTER_KEY: "é".repeat(15) })
    ).toThrowError("MASTER_KEY");
  });

  it("does not include secret values in configuration errors", () => {
    const secret = "do-not-disclose-" + "x".repeat(32);

    try {
      loadConfig({ ...validEnv, AUDIT_HMAC_SECRET: secret.slice(0, 8) });
      throw new Error("Expected invalid configuration to throw.");
    } catch (error) {
      expect(error).toBeInstanceOf(EnvironmentConfigurationError);
      expect((error as Error).message).not.toContain(secret);
      expect((error as Error).message).toContain("AUDIT_HMAC_SECRET");
    }
  });

  it.each(["http://localhost/db", "postgresql://", "not-a-url"])(
    "rejects unsupported or malformed database URLs: %s",
    (databaseUrl) => {
      expect(() => loadConfig({ ...validEnv, DATABASE_URL: databaseUrl }))
        .toThrowError("DATABASE_URL");
    }
  );
});
