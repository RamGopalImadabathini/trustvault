import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApp, type AppDependencies } from "../src/server/app.js";
import { resolveBuildFilePath } from "../src/server/static-files.js";
import type { FastifyInstance } from "fastify";
import type { Pool, PoolClient } from "pg";

const config = {
  databaseUrl: "postgresql://user:password@localhost:5432/trustvault",
  masterKey: "m".repeat(40),
  auditHmacSecret: "a".repeat(40),
  sessionSecret: "s".repeat(40)
};

function createMockDependencies(
  failAuditWrite = false,
  clientBuildDirectory?: string
): AppDependencies {
  const client = {
    query: async (sql: string, values?: unknown[]) => {
      if (sql.includes("trustvault_authorize")) {
        const action = values?.[2];
        return {
          rows: [
            {
              allowed:
                action !== "system.not_found" &&
                (action !== "auth.me" || values?.[0] !== null)
            }
          ]
        };
      }
      if (sql.includes("SELECT row_hash")) return { rows: [] };
      if (sql.includes("nextval")) return { rows: [{ id: "1" }] };
      if (failAuditWrite && sql.includes("INSERT INTO audit_log")) {
        throw new Error("simulated audit persistence failure");
      }
      return { rows: [], rowCount: 1 };
    },
    release: () => undefined
  } as unknown as PoolClient;
  const pool = {
    connect: async () => client
  } as unknown as Pool;
  return { pool, config, storageDirectory: "storage", clientBuildDirectory };
}

describe("health endpoint", () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it("returns a minimal health response", async () => {
    app = createApp(createMockDependencies());
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();

    if (!address || typeof address === "string") {
      throw new Error("Fastify did not bind to a TCP port.");
    }

    const response = await request(`http://127.0.0.1:${address.port}`)
      .get("/healthz")
      .expect(200);

    expect(response.body).toEqual({ status: "ok" });
  });

  it("fails closed when the audit write cannot be persisted", async () => {
    app = createApp(createMockDependencies(true));
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Fastify did not bind to a TCP port.");
    }

    const response = await request(`http://127.0.0.1:${address.port}`)
      .get("/healthz")
      .expect(500);
    expect(response.body).toEqual({ error: "Internal server error" });
  });

  it("requires authorization for API routes", async () => {
    app = createApp(createMockDependencies());
    const response = await app.inject({ method: "GET", url: "/api/auth/me" });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "Invalid email or password" });
  });

  it("returns the normal not-found response for unknown API routes", async () => {
    app = createApp(createMockDependencies());
    const response = await app.inject({ method: "GET", url: "/api/not-a-route" });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "Not found" });
    expect(response.headers["content-type"]).not.toContain("text/html");
  });

  it("serves the built SPA with security headers and falls back to index.html", async () => {
    const buildDirectory = await mkdtemp(path.join(os.tmpdir(), "trustvault-client-"));
    await mkdir(path.join(buildDirectory, "assets"));
    await writeFile(path.join(buildDirectory, "index.html"), "<main>TrustVault</main>");
    await writeFile(path.join(buildDirectory, "assets", "app.js"), "export {};");
    app = createApp(createMockDependencies(false, buildDirectory));

    const page = await app.inject({ method: "GET", url: "/documents/123" });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("<main>TrustVault</main>");
    expect(page.headers["content-security-policy"]).toContain("default-src 'self'");

    const asset = await app.inject({ method: "GET", url: "/assets/app.js" });
    expect(asset.statusCode).toBe(200);
    expect(asset.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(asset.headers["content-type"]).toContain("text/javascript");
    await app.close();
    app = undefined;
    await rm(buildDirectory, { recursive: true, force: true });
  });

  it("rejects paths that traverse outside the client build directory", async () => {
    const buildDirectory = await mkdtemp(path.join(os.tmpdir(), "trustvault-client-"));
    await writeFile(path.join(buildDirectory, "index.html"), "<main>TrustVault</main>");
    app = createApp(createMockDependencies(false, buildDirectory));

    expect(resolveBuildFilePath(buildDirectory, "/../.env")).toBeNull();
    expect(resolveBuildFilePath(buildDirectory, "/%2e%2e/.env")).toBeNull();
    const response = await app.inject({
      method: "GET",
      url: "/%2e%2e/.env"
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("<main>TrustVault</main>");
    expect(response.body).not.toContain("DATABASE_URL");
    await app.close();
    app = undefined;
    await rm(buildDirectory, { recursive: true, force: true });
  });
});
