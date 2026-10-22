import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyRequest } from "fastify";
import type { PoolClient } from "pg";
import type { Actor } from "./authorization.js";

export const SESSION_COOKIE = "tv_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function createSessionSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function hashSessionSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

export async function createSession(
  client: PoolClient,
  userId: string,
  sessionSecret: string
): Promise<{ id: string; cookieValue: string; csrfSecret: Buffer }> {
  const idResult = await client.query<{ id: string }>(
    `INSERT INTO sessions (user_id, secret_hash, expires_at, csrf_secret)
     VALUES ($1, $2, $3, $4)
     RETURNING id::text`,
    [
      userId,
      hashSessionSecret(sessionSecret),
      new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      randomBytes(32)
    ]
  );
  const id = idResult.rows[0]?.id;
  if (!id) {
    throw new Error("Could not create session.");
  }
  const session = await client.query<{ csrf_secret: Buffer }>(
    "SELECT csrf_secret FROM sessions WHERE id = $1",
    [id]
  );
  const csrfSecret = session.rows[0]?.csrf_secret;
  if (!csrfSecret) {
    throw new Error("Could not load newly created session.");
  }
  return { id, cookieValue: `${id}.${sessionSecret}`, csrfSecret };
}

export function issueCsrfToken(
  sessionId: string,
  csrfSecret: Buffer,
  sessionSigningSecret: string
): string {
  return createHmac("sha256", sessionSigningSecret)
    .update(`${sessionId}.${csrfSecret.toString("base64url")}`)
    .digest("base64url");
}

export function hasValidCsrfToken(
  supplied: string | undefined,
  actor: Actor,
  sessionSigningSecret: string
): boolean {
  if (!supplied || !/^[A-Za-z0-9_-]{43}$/.test(supplied)) {
    return false;
  }
  const expected = Buffer.from(
    issueCsrfToken(actor.sessionId, actor.csrfSecret, sessionSigningSecret),
    "utf8"
  );
  const actual = Buffer.from(supplied, "utf8");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function readSessionCookie(request: FastifyRequest): string | undefined {
  const cookie = request.headers.cookie;
  if (!cookie) {
    return undefined;
  }
  for (const part of cookie.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === SESSION_COOKIE) {
      return valueParts.join("=");
    }
  }
  return undefined;
}

export async function loadActor(
  client: PoolClient,
  request: FastifyRequest
): Promise<Actor | null> {
  const cookie = readSessionCookie(request);
  if (!cookie) {
    return null;
  }
  const separator = cookie.indexOf(".");
  if (separator < 1) {
    return null;
  }
  const sessionId = cookie.slice(0, separator);
  const secret = cookie.slice(separator + 1);
  if (!/^[0-9a-f-]{36}$/i.test(sessionId) || !/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    return null;
  }

  const result = await client.query<{
    id: string;
    user_id: string;
    role: "admin" | "owner" | "viewer";
    csrf_secret: Buffer;
  }>(
    `SELECT s.id::text, s.user_id::text, u.role, s.csrf_secret
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1
       AND s.secret_hash = $2
       AND s.revoked_at IS NULL
       AND s.expires_at > transaction_timestamp()
       AND u.is_active = true`,
    [sessionId, hashSessionSecret(secret)]
  );
  const row = result.rows[0];
  if (!row) {
    return null;
  }
  return {
    id: row.user_id,
    role: row.role,
    csrfSecret: row.csrf_secret,
    sessionId: row.id
  };
}

export function setSessionCookie(cookieValue: string): string {
  return `${SESSION_COOKIE}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
