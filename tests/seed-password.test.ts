import { describe, expect, it } from "vitest";
import { getSeedDemoPassword } from "../scripts/seed-password.js";

describe("seed demo password configuration", () => {
  it("uses the public demo password only for non-production environments without an override", () => {
    expect(getSeedDemoPassword({ NODE_ENV: "development" })).toBe(
      "TrustVault-Local-Demo-2026!"
    );
  });

  it("allows a local seed password override", () => {
    expect(
      getSeedDemoPassword({
        NODE_ENV: "development",
        SEED_DEMO_PASSWORD: "local-custom-password"
      })
    ).toBe("local-custom-password");
  });

  it("refuses production seeding when SEED_DEMO_PASSWORD is missing or blank", () => {
    expect(() => getSeedDemoPassword({ NODE_ENV: "production" })).toThrow(
      "SEED_DEMO_PASSWORD is required to seed in production."
    );
    expect(() =>
      getSeedDemoPassword({
        NODE_ENV: "production",
        SEED_DEMO_PASSWORD: "   "
      })
    ).toThrow("SEED_DEMO_PASSWORD is required to seed in production.");
  });

  it("uses the configured password in production without exposing it in errors", () => {
    expect(
      getSeedDemoPassword({
        NODE_ENV: "production",
        SEED_DEMO_PASSWORD: "unique-production-demo-password"
      })
    ).toBe("unique-production-demo-password");
  });
});
