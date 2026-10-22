import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp, type AppDependencies } from "../src/server/app.js";
import type { FastifyInstance } from "fastify";
import type { Pool, PoolClient } from "pg";

const config = {
  databaseUrl: "postgresql://user:password@localhost:5432/trustvault",
  masterKey: "m".repeat(40),
  auditHmacSecret: "a".repeat(40),
  sessionSecret: "s".repeat(40)
};

function createMockDependencies(failAuditWrite = false): AppDependencies {
  const client = {
    query: async (sql: string) => {
      if (sql.includes("trustvault_authorize")) return { rows: [{ allowed: true }] };
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
  return { pool, config, storageDirectory: "storage" };
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
});
