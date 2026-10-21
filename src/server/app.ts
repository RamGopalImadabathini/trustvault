import Fastify, { type FastifyInstance } from "fastify";

export function createApp(): FastifyInstance {
  const app = Fastify({ logger: false });

  app.get("/healthz", async () => ({ status: "ok" }));

  return app;
}
