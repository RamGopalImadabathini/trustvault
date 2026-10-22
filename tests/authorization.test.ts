import { describe, expect, it, vi } from "vitest";
import { authorize, validateRouteRegistry, type Actor } from "../src/server/authorization.js";
import type { PoolClient } from "pg";
import { issueCsrfToken, hasValidCsrfToken } from "../src/server/sessions.js";

const actor: Actor = {
  id: "00000000-0000-4000-8000-000000000001",
  role: "viewer",
  sessionId: "00000000-0000-4000-8000-000000000010",
  csrfSecret: Buffer.alloc(32, 7)
};

describe("authorization entry point", () => {
  it("delegates every authorization decision to the database policy function", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ allowed: true }] });
    const client = { query } as unknown as PoolClient;

    await expect(
      authorize(
        client,
        actor,
        "00000000-0000-4000-8000-000000000002",
        "document.read_metadata"
      )
    ).resolves.toBe(true);
    expect(query).toHaveBeenCalledWith(
      "SELECT trustvault_authorize($1::uuid, $2::uuid, $3::text) AS allowed",
      [actor.id, "00000000-0000-4000-8000-000000000002", "document.read_metadata"]
    );
  });

  it("denies by default when the policy function returns no allowed row", async () => {
    const client = {
      query: vi.fn().mockResolvedValue({ rows: [] })
    } as unknown as PoolClient;
    await expect(
      authorize(client, null, "00000000-0000-4000-8000-000000000002", "document.download")
    ).resolves.toBe(false);
  });
});

describe("route authorization registry", () => {
  it("accepts routes only when each has a known authorization action", () => {
    expect(() =>
      validateRouteRegistry([
        {
          method: "GET",
          url: "/api/documents/:id",
          config: { authzAction: "document.read_metadata" }
        }
      ])
    ).not.toThrow();
  });

  it("refuses to start with a missing or unknown route action", () => {
    expect(() =>
      validateRouteRegistry([
        { method: "GET", url: "/forgotten" },
        {
          method: "POST",
          url: "/unknown",
          config: { authzAction: "document.bypass" }
        }
      ])
    ).toThrowError("GET /forgotten, POST /unknown");
  });
});

describe("CSRF token", () => {
  it("validates only the token bound to the active session and secret", () => {
    const token = issueCsrfToken(actor.sessionId, actor.csrfSecret, "s".repeat(40));
    expect(hasValidCsrfToken(token, actor, "s".repeat(40))).toBe(true);
    expect(hasValidCsrfToken(token, actor, "x".repeat(40))).toBe(false);
    expect(hasValidCsrfToken(undefined, actor, "s".repeat(40))).toBe(false);
  });
});
