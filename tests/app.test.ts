import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import type { FastifyInstance } from "fastify";

describe("health endpoint", () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it("returns a minimal health response", async () => {
    app = createApp();
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
});
