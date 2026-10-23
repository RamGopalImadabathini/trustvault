import cookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import argon2 from "argon2";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import type {
  FastifyError,
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteOptions
} from "fastify";
import Fastify from "fastify";
import { resolveBuildFilePath, serveClientFile } from "./static-files.js";
import type { Pool, PoolClient } from "pg";
import { appendAudit, verifyAuditChain } from "./audit.js";
import { countOffHoursAccess } from "./anomalies.js";
import {
  deterministicSuggestions,
  validateSuggestions,
  type AiSuggestionProvider,
  type SuggestionCandidate,
  type SuggestionMetadata
} from "./ai.js";
import {
  authorize,
  validateRouteRegistry,
  type Actor,
  type AuthzAction
} from "./authorization.js";
import type { AppConfig } from "./config.js";
import { loadActor, setSessionCookie, clearSessionCookie, createSession, createSessionSecret, issueCsrfToken, hasValidCsrfToken } from "./sessions.js";
import { decryptFromStorage, encryptAndStore, safeDownloadHeaders, validateUpload, type EncryptedFile } from "./storage.js";

declare module "fastify" {
  interface FastifyContextConfig {
    authzAction?: AuthzAction;
  }
}

const DUMMY_PASSWORD_HASH = argon2.hash("trustvault-dummy-password-not-a-login");
const DOCUMENT_NOT_FOUND = { error: "Not found" };
const LOGIN_FAILURE = { error: "Invalid email or password" };
const DOC_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL_PATTERN = /^[^\s@]{1,128}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface AppDependencies {
  pool: Pool;
  config: AppConfig;
  storageDirectory: string;
  clientBuildDirectory?: string;
  malwareScanner?: (upload: ReturnType<typeof validateUpload>) => Promise<"clean" | "rejected">;
  aiSuggestionProvider?: AiSuggestionProvider;
  auditVerifier?: typeof verifyAuditChain;
}

interface RouteResult {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  stream?: Buffer;
  afterResponse?: () => Promise<void>;
  auditOutcome?: "allowed" | "denied";
  auditReason?: string;
}

interface RouteContext {
  client: PoolClient;
  actor: Actor | null;
  request: FastifyRequest;
  reply: FastifyReply;
  documentId: string | null;
  trackStorageKey: (key: string | null) => void;
}

interface RouteDefinition extends Omit<RouteOptions, "handler" | "config"> {
  url: string;
  action: AuthzAction;
  config?: RouteOptions["config"];
  documentId?: (client: PoolClient, request: FastifyRequest) => Promise<string | null>;
  handle: (context: RouteContext) => Promise<RouteResult>;
}

export function createApp(dependencies: AppDependencies): FastifyInstance {
  const app = Fastify({ logger: false, trustProxy: false, bodyLimit: 11 * 1024 * 1024 });
  const registeredRoutes: Array<{
    method: string;
    url: string;
    config?: { authzAction?: string };
  }> = [];
  registeredRoutes.push(
    {
      method: "*",
      url: "<not-found>",
      config: { authzAction: "system.not_found" }
    },
    {
      method: "*",
      url: "<request-error>",
      config: { authzAction: "system.request_error" }
    }
  );

  app.addHook("onRoute", (routeOptions) => {
    registeredRoutes.push({
      method: Array.isArray(routeOptions.method)
        ? routeOptions.method.join(",")
        : routeOptions.method,
      url: routeOptions.url,
      config: routeOptions.config
    });
  });
  app.addHook("onReady", async () => {
    validateRouteRegistry(registeredRoutes);
  });

  app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"]
      }
    },
    crossOriginResourcePolicy: { policy: "same-origin" }
  });
  app.register(cookie);
  app.register(multipart, {
    limits: { fileSize: 10 * 1024 * 1024, files: 1, fields: 5, parts: 6 },
    throwFileSizeLimit: false
  });
  app.register(rateLimit, { global: false });

  const register = (definition: RouteDefinition): void => {
    const {
      action,
      documentId: resolveDocumentId,
      handle,
      config,
      ...routeOptions
    } = definition;

    app.route({
      ...routeOptions,
      attachValidation: true,
      config: {
        ...config,
        authzAction: action
      },
      handler: async (request, reply) => {
        const client = await dependencies.pool.connect();
        let transactionOpen = false;
        let keepClientForStream = false;
        let downloadLockId: string | null = null;
        let clientReleased = false;
        let actor: Actor | null = null;
        let documentId: string | null = null;
        let uncommittedStorageKey: string | null = null;
        let destroyClient = false;
        const releaseClient = (destroy = false): void => {
          if (!clientReleased) {
            clientReleased = true;
            client.release(destroy);
          }
        };

        const finishDownload = async (): Promise<void> => {
          if (!keepClientForStream) {
            return;
          }
          keepClientForStream = false;
          if (downloadLockId) {
            try {
              await client.query("SELECT pg_advisory_unlock(hashtext($1))", [
                downloadLockId
              ]);
            } catch (error) {
              request.log.error({ err: error }, "Could not release download lock");
              releaseClient(true);
              return;
            }
            try {
              releaseClient();
            } catch (error) {
              request.log.error({ err: error }, "Could not release download connection");
            }
          } else {
            releaseClient();
          }
        };

        try {
          await client.query("BEGIN");
          transactionOpen = true;
          documentId = resolveDocumentId
            ? await resolveDocumentId(client, request)
            : resolveParamDocumentId(request);

          if (action === "document.download" && documentId) {
            await client.query("SELECT pg_advisory_lock(hashtext($1))", [
              documentId
            ]);
            downloadLockId = documentId;
          }
          if (documentId) {
            await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
              documentId
            ]);
          }

          actor = await loadActor(client, request);
          const allowed = await authorize(client, actor, documentId, action);
          if (!allowed) {
            const deniedStatus = action.startsWith("document.")
              ? 404
              : actor
                ? 403
                : 401;
            await appendAudit(
              client,
              dependencies.config.auditHmacSecret,
              createAuditEvent(request, actor, documentId, action, "denied", "not_permitted")
            );
            await client.query("COMMIT");
            transactionOpen = false;
            uncommittedStorageKey = null;
            return reply.code(deniedStatus).send(
              deniedStatus === 404
                ? DOCUMENT_NOT_FOUND
                : action.startsWith("auth.")
                  ? LOGIN_FAILURE
                  : { error: "Forbidden" }
            );
          }

          if (
            actor &&
            MUTATING_METHODS.has(request.method) &&
            action !== "auth.login" &&
            !hasValidCsrfToken(
              request.headers["x-csrf-token"] as string | undefined,
              actor,
              dependencies.config.sessionSecret
            )
          ) {
            await appendAudit(
              client,
              dependencies.config.auditHmacSecret,
              createAuditEvent(request, actor, documentId, action, "denied", "csrf_invalid")
            );
            await client.query("COMMIT");
            transactionOpen = false;
            return reply.code(403).send({ error: "Request could not be verified" });
          }

          if (request.validationError) {
            await appendAudit(
              client,
              dependencies.config.auditHmacSecret,
              createAuditEvent(
                request,
                actor,
                documentId,
                action,
                "denied",
                "validation_failed"
              )
            );
            await client.query("COMMIT");
            transactionOpen = false;
            return reply.code(400).send({ error: "Invalid request" });
          }

          const result = await handle({
            client,
            actor,
            request,
            reply,
            documentId,
            trackStorageKey: (key) => {
              uncommittedStorageKey = key;
            }
          });
          const status = result.status ?? 200;
          await appendAudit(
            client,
            dependencies.config.auditHmacSecret,
            createAuditEvent(
              request,
              actor,
              documentId,
              action,
              result.auditOutcome ?? (status >= 400 ? "denied" : "allowed"),
              result.auditReason ?? (status >= 400 ? "request_rejected" : "allowed")
            )
          );
          await client.query("COMMIT");
          transactionOpen = false;

          for (const [name, value] of Object.entries(result.headers ?? {})) {
            reply.header(name, value);
          }
          if (result.stream) {
            if (downloadLockId) {
              keepClientForStream = true;
              reply.raw.once("finish", () => void finishDownload());
              reply.raw.once("close", () => void finishDownload());
            }
            reply.code(status).send(Readable.from(result.stream));
            return reply;
          }
          return reply.code(status).send(result.body);
        } catch (error) {
          if (transactionOpen) {
            try {
              await client.query("ROLLBACK");
              transactionOpen = false;
            } catch (rollbackError) {
              request.log.error({ err: rollbackError }, "Could not roll back failed request");
              destroyClient = true;
            }
          }
          if (uncommittedStorageKey) {
            try {
              await removeStorageQuietly(
                dependencies.storageDirectory,
                uncommittedStorageKey
              );
              uncommittedStorageKey = null;
            } catch (cleanupError) {
              request.log.error(
                { err: cleanupError },
                "Could not remove an uncommitted upload"
              );
            }
          }
          if (!destroyClient) {
            try {
              await client.query("BEGIN");
              transactionOpen = true;
              await appendAudit(
                client,
                dependencies.config.auditHmacSecret,
                createAuditEvent(request, actor, documentId, action, "denied", "request_failed")
              );
              await client.query("COMMIT");
              transactionOpen = false;
            } catch (auditError) {
              request.log.error({ err: auditError }, "Could not audit failed request");
              if (transactionOpen) {
                try {
                  await client.query("ROLLBACK");
                  transactionOpen = false;
                } catch (rollbackError) {
                  request.log.error(
                    { err: rollbackError },
                    "Could not roll back failed-request audit"
                  );
                  destroyClient = true;
                }
              }
            }
          }
          request.log.error({ err: error }, "TrustVault request failed");
          if (destroyClient) {
            releaseClient(true);
          }
          return reply.code(500).send({ error: "Internal server error" });
        } finally {
          if (!keepClientForStream) {
            if (downloadLockId) {
              try {
                await client.query("SELECT pg_advisory_unlock(hashtext($1))", [
                  downloadLockId
                ]);
              } catch {
                releaseClient(true);
              }
            }
            releaseClient();
          }
        }
      }
    });

  };

  app.setNotFoundHandler(async (request, reply) => {
    const pathname = request.url.split("?")[0] ?? request.url;
    if (
      dependencies.clientBuildDirectory &&
      (request.method === "GET" || request.method === "HEAD") &&
      pathname !== "/api" &&
      !pathname.startsWith("/api/")
    ) {
      const served = await serveClientFile(
        dependencies.clientBuildDirectory,
        pathname,
        reply
      );
      if (served) {
        return reply;
      }
      if (resolveBuildFilePath(dependencies.clientBuildDirectory, pathname)) {
        const fallbackServed = await serveClientFile(
          dependencies.clientBuildDirectory,
          "/",
          reply
        );
        if (fallbackServed) {
          return reply;
        }
      }
    }

    try {
      await auditFrameworkFailure(
        dependencies,
        request,
        "system.not_found",
        "route_not_found"
      );
      return reply.code(404).send(DOCUMENT_NOT_FOUND);
    } catch (error) {
      request.log.error({ err: error }, "Could not audit unmatched request");
      return reply.code(500).send({ error: "Internal server error" });
    }
  });

  app.setErrorHandler(async (error: FastifyError, request, reply) => {
    const statusCode =
      typeof error.statusCode === "number" &&
      error.statusCode >= 400 &&
      error.statusCode <= 599
        ? error.statusCode
        : 500;
    try {
      await auditFrameworkFailure(
        dependencies,
        request,
        "system.request_error",
        `request_error_${statusCode}`
      );
      return reply.code(statusCode).send({
        error: statusCode >= 500 ? "Internal server error" : "Request rejected"
      });
    } catch (auditError) {
      request.log.error(
        { err: auditError, originalError: error },
        "Could not audit request error"
      );
      return reply.code(500).send({ error: "Internal server error" });
    }
  });

  register({
    method: "GET",
    url: "/healthz",
    action: "system.health",
    handle: async ({ client }) => {
      await client.query("SELECT 1");
      return { body: { status: "ok" } };
    }
  });

  register({
    method: "POST",
    url: "/api/auth/login",
    action: "auth.login",
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["email", "password"],
        properties: {
          email: { type: "string", maxLength: 320 },
          password: { type: "string", minLength: 1, maxLength: 1024 }
        }
      }
    },
    handle: async ({ client, request }) => {
      const body = request.body as { email: string; password: string };
      const normalizedEmail = body.email.trim().toLowerCase();
      const rowResult = EMAIL_PATTERN.test(normalizedEmail)
        ? await client.query<{
            id: string;
            role: Actor["role"];
            password_hash: string;
            is_active: boolean;
            locked_until: Date | null;
          }>(
            `SELECT id::text, role, password_hash, is_active, locked_until
             FROM users WHERE email = $1`,
            [normalizedEmail]
          )
        : { rows: [] };
      const user = rowResult.rows[0];
      const hash = user?.password_hash ?? (await DUMMY_PASSWORD_HASH);
      let passwordMatches = false;
      try {
        passwordMatches = await argon2.verify(hash, body.password);
      } catch {
        passwordMatches = false;
      }

      const locked =
        user?.locked_until !== null &&
        user?.locked_until !== undefined &&
        user.locked_until.getTime() > Date.now();
      if (!user || !user.is_active || !passwordMatches || locked) {
        if (user && user.is_active && !locked) {
          await client.query(
            `UPDATE users
             SET failed_login_count = failed_login_count + 1,
                 locked_until = CASE WHEN failed_login_count + 1 >= 5
                   THEN now() + interval '15 minutes' ELSE locked_until END,
                 updated_at = now()
             WHERE id = $1`,
            [user.id]
          );
        }
        return { status: 401, body: LOGIN_FAILURE };
      }

      await client.query(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1",
        [user.id]
      );
      const secret = createSessionSecret();
      const session = await createSession(client, user.id, secret);
      return {
        headers: { "Set-Cookie": setSessionCookie(session.cookieValue) },
        body: { authenticated: true }
      };
    }
  });

  register({
    method: "POST",
    url: "/api/auth/logout",
    action: "auth.logout",
    handle: async ({ client, actor }) => {
      if (actor) {
        await client.query(
          "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
          [actor.sessionId]
        );
      }
      return {
        headers: { "Set-Cookie": clearSessionCookie() },
        body: { authenticated: false }
      };
    }
  });

  register({
    method: "GET",
    url: "/api/auth/me",
    action: "auth.me",
    handle: async ({ actor }) => {
      if (!actor) {
        return { status: 401, body: LOGIN_FAILURE };
      }
      return {
        body: {
          id: actor.id,
          role: actor.role,
          csrfToken: issueCsrfToken(
            actor.sessionId,
            actor.csrfSecret,
            dependencies.config.sessionSecret
          )
        }
      };
    }
  });

  register({
    method: "POST",
    url: "/api/documents",
    action: "document.create",
    handle: async ({ client, actor, request, trackStorageKey }) => {
      const part = await request.file();
      if (!part) {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      const bytes = await part.toBuffer();
      if (part.file.truncated) {
        return { status: 413, body: { error: "File exceeds upload limit" } };
      }
      const titleField = part.fields.title;
      const title =
        titleField && "value" in titleField && typeof titleField.value === "string"
          ? titleField.value.trim()
          : "";
      const categoryField = part.fields.category;
      const category =
        categoryField &&
        "value" in categoryField &&
        typeof categoryField.value === "string"
          ? categoryField.value.trim()
          : null;
      const folderField = part.fields.folderId;
      const folderId =
        folderField && "value" in folderField && typeof folderField.value === "string"
          ? folderField.value
          : null;
      if (!actor || title.length < 1 || title.length > 500) {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      if (
        (category !== null && category.length > 100) ||
        (folderId !== null && !DOC_ID_PATTERN.test(folderId))
      ) {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      if (folderId) {
        const folder = await client.query(
          `SELECT 1 FROM folders
           WHERE id = $1 AND deleted_at IS NULL`,
          [folderId]
        );
        if (folder.rowCount !== 1) {
          return { status: 400, body: { error: "Invalid upload" } };
        }
      }
      let upload;
      try {
        upload = validateUpload(part.filename, part.mimetype, bytes);
      } catch {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      if (!dependencies.malwareScanner) {
        return { status: 503, body: { error: "Uploads temporarily unavailable" } };
      }
      const scanResult = await dependencies.malwareScanner(upload);
      if (scanResult !== "clean") {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      const encrypted = await encryptAndStore(
        dependencies.storageDirectory,
        dependencies.config.masterKey,
        upload
      );
      trackStorageKey(encrypted.storageKey);
      try {
        const doc = await client.query<{ id: string }>(
          `INSERT INTO documents
            (owner_id, title, category, folder_id, declared_mime_type, original_filename)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
          [
            actor.id,
            title,
            category || null,
            folderId,
            upload.mimeType,
            upload.filename
          ]
        );
        const documentId = doc.rows[0]?.id;
        if (!documentId) {
          throw new Error("Document insert did not return an identifier.");
        }
        const versionId = await insertVersion(
          client,
          actor.id,
          documentId,
          encrypted,
          upload.mimeType,
          scanResult,
          1
        );
        await client.query(
          "UPDATE documents SET current_version_id = $2, updated_at = now() WHERE id = $1",
          [documentId, versionId]
        );
        return {
          status: 201,
          body: { id: documentId, title, versionId }
        };
      } catch (error) {
        await removeStorageQuietly(dependencies.storageDirectory, encrypted.storageKey);
        trackStorageKey(null);
        throw error;
      }
    }
  });

  register({
    method: "GET",
    url: "/api/folders",
    action: "folder.list",
    documentId: async () => null,
    handle: async ({ client, actor }) => {
      if (!actor) {
        return { status: 401, body: LOGIN_FAILURE };
      }
      const folders = await client.query(
        `SELECT id::text, name, parent_id::text, created_at
         FROM folders
         WHERE deleted_at IS NULL
         ORDER BY name`,
        []
      );
      return { body: { folders: folders.rows } };
    }
  });

  register({
    method: "POST",
    url: "/api/folders",
    action: "folder.create",
    documentId: async () => null,
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["name"],
        properties: {
          name: { type: "string", minLength: 1, maxLength: 200 }
        }
      }
    },
    handle: async ({ client, actor, request }) => {
      if (!actor) {
        return { status: 401, body: LOGIN_FAILURE };
      }
      const name = (request.body as { name: string }).name.trim();
      if (name.length === 0) {
        return { status: 400, body: { error: "Invalid folder" } };
      }
      const result = await client.query<{ id: string }>(
        `INSERT INTO folders (name, created_by)
         VALUES ($1, $2) RETURNING id::text`,
        [name, actor.id]
      );
      return { status: 201, body: { id: result.rows[0]?.id, name } };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/ai-suggestions",
    action: "document.ai.suggest",
    handle: async ({ client, actor, documentId, request }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const documentResult = await client.query<{
        title: string;
        description: string | null;
        category: string | null;
        owner_name: string;
      }>(
        `SELECT d.title, d.description, d.category, u.display_name AS owner_name
         FROM documents d JOIN users u ON u.id = d.owner_id
         WHERE d.id = $1 AND d.deleted_at IS NULL`,
        [documentId]
      );
      const metadata = documentResult.rows[0];
      if (!metadata) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const candidateResult = await client.query<{
        user_id: string;
        display_name: string;
        role: SuggestionCandidate["role"];
      }>(
        `SELECT u.id::text AS user_id, u.display_name, u.role
         FROM users u
         WHERE u.is_active = true AND u.id <> $2
           AND u.role IN ('owner', 'viewer')
           AND NOT EXISTS (
             SELECT 1 FROM document_grants g
             WHERE g.document_id = $1 AND g.user_id = u.id
               AND g.revoked_at IS NULL
               AND (g.expires_at IS NULL OR g.expires_at > now())
           )
         ORDER BY u.role, u.display_name
         LIMIT 100`,
        [documentId, actor.id]
      );
      const candidates: SuggestionCandidate[] = candidateResult.rows.map((row) => ({
        userId: row.user_id,
        displayName: row.display_name,
        role: row.role
      }));
      const suggestionMetadata: SuggestionMetadata = {
        title: metadata.title,
        description: metadata.description,
        category: metadata.category,
        ownerName: metadata.owner_name
      };
      const provider = dependencies.aiSuggestionProvider;
      let providerName = "deterministic-fallback";
      let validated;
      if (provider) {
        providerName = provider.name.slice(0, 100);
        try {
          const output = await provider.suggest({
            metadata: suggestionMetadata,
            candidates
          });
          validated = validateSuggestions(output, candidates);
        } catch (error) {
          request.log.error({ err: error }, "AI suggestion provider failed");
          return { status: 503, body: { error: "Suggestions temporarily unavailable" } };
        }
      } else {
        validated = deterministicSuggestions(candidates);
      }
      const metadataHash = createHash("sha256")
        .update(JSON.stringify(suggestionMetadata))
        .digest();
      const result = await client.query<{ id: string }>(
        `INSERT INTO ai_suggestions
          (document_id, requested_by, provider, input_metadata_hash, suggestions)
         VALUES ($1, $2, $3, $4, $5::jsonb)
         RETURNING id::text`,
        [
          documentId,
          actor.id,
          providerName || "provider",
          metadataHash,
          JSON.stringify(validated)
        ]
      );
      const suggestionsWithNames = validated.map((suggestion) => ({
        ...suggestion,
        displayName:
          candidates.find((candidate) => candidate.userId === suggestion.userId)
            ?.displayName ?? ""
      }));
      return {
        status: 201,
        body: {
          id: result.rows[0]?.id,
          provider: providerName,
          suggestions: suggestionsWithNames
        }
      };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/ai-suggestions/:suggestionId/decision",
    action: "document.ai.decide",
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["decision"],
        properties: {
          decision: { type: "string", enum: ["accepted", "rejected", "modified"] }
        }
      }
    },
    handle: async ({ client, actor, documentId, request }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const suggestionId = (request.params as { suggestionId: string }).suggestionId;
      if (!DOC_ID_PATTERN.test(suggestionId)) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const decision = (request.body as {
        decision: "accepted" | "rejected" | "modified";
      }).decision;
      const updated = await client.query(
        `UPDATE ai_suggestions
         SET decision = $3, decided_by = $4, decided_at = now()
         WHERE id = $1 AND document_id = $2 AND decision IS NULL
         RETURNING id`,
        [suggestionId, documentId, decision, actor.id]
      );
      return updated.rowCount === 1
        ? {
            body: {
              decided: true,
              decision,
              grantCreated: false,
              nextStep: "Create any approved grant separately."
            }
          }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "GET",
    url: "/api/admin/audit",
    action: "admin.audit.read",
    documentId: async () => null,
    schema: {
      querystring: {
        type: "object",
        additionalProperties: false,
        properties: {
          limit: { type: "string", pattern: "^[0-9]{1,3}$" }
        }
      }
    },
    handle: async ({ client, actor, request }) => {
      const requestedLimit = Number(
        (request.query as { limit?: string }).limit ?? "50"
      );
      const limit = Math.min(Math.max(requestedLimit, 1), 100);
      const result = await client.query(
        `SELECT a.id::text, a.occurred_at, a.actor_role, u.display_name AS actor_name,
                a.action, a.outcome, a.reason, a.request_id,
                CASE WHEN a.document_id IS NOT NULL
                          AND trustvault_authorize($2::uuid, a.document_id, 'document.read_metadata')
                     THEN a.document_id::text ELSE NULL END AS document_id,
                CASE WHEN a.document_id IS NOT NULL
                          AND trustvault_authorize($2::uuid, a.document_id, 'document.read_metadata')
                     THEN d.title ELSE NULL END AS document_title
         FROM audit_log a
         LEFT JOIN users u ON u.id = a.actor_id
         LEFT JOIN documents d ON d.id = a.document_id
         ORDER BY a.id DESC LIMIT $1`,
        [limit, actor?.id ?? null]
      );
      return { body: { events: result.rows } };
    }
  });

  register({
    method: "GET",
    url: "/api/admin/audit/verify",
    action: "admin.audit.verify",
    documentId: async () => null,
    handle: async ({ client }) => {
      const verifier = dependencies.auditVerifier ?? verifyAuditChain;
      const result = await verifier(client, dependencies.config.auditHmacSecret);
      return { body: result };
    }
  });

  register({
    method: "GET",
    url: "/api/admin/anomalies",
    action: "admin.anomalies.read",
    documentId: async () => null,
    handle: async ({ client }) => {
      const denials = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM (
           SELECT actor_id FROM audit_log
           WHERE outcome = 'denied' AND occurred_at > now() - interval '1 hour'
           GROUP BY actor_id HAVING count(*) >= 5
         ) repeated`
      );
      const downloads = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM (
           SELECT actor_id FROM audit_log
           WHERE action = 'document.download' AND outcome = 'allowed'
             AND occurred_at > now() - interval '1 hour'
           GROUP BY actor_id HAVING count(*) >= 20
         ) bulk`
      );
      const grants = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM (
           SELECT actor_id FROM audit_log
           WHERE action = 'document.grant' AND outcome = 'allowed'
             AND occurred_at > now() - interval '10 minutes'
           GROUP BY actor_id HAVING count(*) >= 10
         ) bursts`
      );
      const offHours = await client.query<{ hour: number; count: string }>(
        `SELECT EXTRACT(HOUR FROM occurred_at AT TIME ZONE 'UTC')::int AS hour,
                count(*)::text AS count
         FROM audit_log
         WHERE action LIKE 'document.%' AND outcome = 'allowed'
           AND occurred_at > now() - interval '24 hours'
         GROUP BY hour`
      );
      const offHoursCount = countOffHoursAccess(
        offHours.rows.map((row) => ({ hour: row.hour, count: Number(row.count) }))
      );
      const verifier = dependencies.auditVerifier ?? verifyAuditChain;
      const chain = await verifier(client, dependencies.config.auditHmacSecret);
      const anomalies = [
        {
          type: "repeated_denials",
          count: Number(denials.rows[0]?.count ?? 0)
        },
        {
          type: "bulk_downloads",
          count: Number(downloads.rows[0]?.count ?? 0)
        },
        {
          type: "grant_bursts",
          count: Number(grants.rows[0]?.count ?? 0)
        },
        {
          type: "off_hours_access",
          count: offHoursCount
        },
        {
          type: "failed_chain_verification",
          count: chain.valid ? 0 : 1
        }
      ].filter((item) => item.count > 0);
      return { body: { anomalies } };
    }
  });

  register({
    method: "PATCH",
    url: "/api/folders/:id",
    action: "folder.manage",
    documentId: async () => null,
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["name"],
        properties: {
          name: { type: "string", minLength: 1, maxLength: 200 }
        }
      }
    },
    handle: async ({ client, actor, request }) => {
      if (!actor) {
        return { status: 401, body: LOGIN_FAILURE };
      }
      const id = (request.params as { id: string }).id;
      if (!DOC_ID_PATTERN.test(id)) {
        return { status: 404, body: { error: "Not found" } };
      }
      const name = (request.body as { name: string }).name.trim();
      if (!name) {
        return { status: 400, body: { error: "Invalid folder" } };
      }
      const result = await client.query(
        `UPDATE folders SET name = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id::text, name`,
        [id, name]
      );
      return result.rowCount === 1
        ? { body: result.rows[0] }
        : { status: 404, body: { error: "Not found" } };
    }
  });

  register({
    method: "DELETE",
    url: "/api/folders/:id",
    action: "folder.manage",
    documentId: async () => null,
    handle: async ({ client, actor, request }) => {
      if (!actor) {
        return { status: 401, body: LOGIN_FAILURE };
      }
      const id = (request.params as { id: string }).id;
      if (!DOC_ID_PATTERN.test(id)) {
        return { status: 404, body: { error: "Not found" } };
      }
      const result = await client.query(
        `UPDATE folders SET deleted_at = now(), updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id`,
        [id]
      );
      return result.rowCount === 1
        ? { body: { deleted: true } }
        : { status: 404, body: { error: "Not found" } };
    }
  });

  for (const [url, resultKey] of [
    ["/api/documents", "documents"],
    ["/api/search", "results"]
  ] as const) {
    register({
      method: "GET",
      url,
      action: "document.search",
      documentId: async () => null,
      schema: {
        querystring: {
          type: "object",
          additionalProperties: false,
          properties: {
            q: { type: "string", maxLength: 200 },
            name: { type: "string", maxLength: 200 },
            owner: { type: "string", maxLength: 200 },
            category: { type: "string", maxLength: 100 },
            from: { type: "string", maxLength: 10 },
            to: { type: "string", maxLength: 10 },
            includeDeleted: { type: "string", enum: ["true", "false"] }
          }
        }
      },
      handle: async ({ client, actor, request }) => {
        if (!actor) {
          return { status: 401, body: LOGIN_FAILURE };
        }
        const filters = request.query as {
          q?: string;
          name?: string;
          owner?: string;
          category?: string;
          from?: string;
          to?: string;
          includeDeleted?: string;
        };
        if (
          (filters.from && !isCalendarDate(filters.from)) ||
          (filters.to && !isCalendarDate(filters.to))
        ) {
          return { status: 400, body: { error: "Invalid search" } };
        }
        const documents = await searchAuthorizedDocuments(
          client,
          actor.id,
          filters
        );
        return { body: { [resultKey]: documents } };
      }
    });
  }

  register({
    method: "GET",
    url: "/api/documents/:id",
    action: "document.read_metadata",
    handle: async ({ client, documentId }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `SELECT id::text, title, description, category, folder_id::text,
                declared_mime_type,
                original_filename, created_at, updated_at
         FROM documents WHERE id = $1 AND deleted_at IS NULL`,
        [documentId]
      );
      return result.rows.length === 1
        ? { body: result.rows[0] }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/grants",
    action: "document.grants.read",
    handle: async ({ client, documentId }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `SELECT g.user_id::text, u.display_name, u.email::text,
                g.level, g.created_at, g.expires_at
         FROM document_grants g
         JOIN users u ON u.id = g.user_id
         WHERE g.document_id = $1 AND g.revoked_at IS NULL
           AND (g.expires_at IS NULL OR g.expires_at > now())
         ORDER BY g.created_at`,
        [documentId]
      );
      return { body: { grants: result.rows } };
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/grant-targets",
    action: "document.grant.targets",
    handle: async ({ client, actor, documentId }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const users = await client.query(
        `SELECT u.id::text, u.display_name, u.email::text, u.role
         FROM users u
         WHERE u.is_active = true AND u.id <> $2
           AND NOT EXISTS (
             SELECT 1 FROM document_grants g
             WHERE g.document_id = $1 AND g.user_id = u.id
               AND g.revoked_at IS NULL
               AND (g.expires_at IS NULL OR g.expires_at > now())
           )
         ORDER BY u.display_name
         LIMIT 100`,
        [documentId, actor.id]
      );
      return { body: { users: users.rows } };
    }
  });

  register({
    method: "PATCH",
    url: "/api/documents/:id",
    action: "document.edit_metadata",
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        minProperties: 1,
        properties: {
          title: { type: "string", minLength: 1, maxLength: 500 },
          description: { type: "string", maxLength: 10000 },
          category: { type: ["string", "null"], maxLength: 100 }
        }
      }
    },
    handle: async ({ client, documentId, request }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const body = request.body as {
        title?: string;
        description?: string;
        category?: string | null;
      };
      const result = await client.query(
        `UPDATE documents
         SET title = COALESCE($2, title),
             description = CASE WHEN $3::boolean THEN $4 ELSE description END,
             category = CASE WHEN $5::boolean THEN $6 ELSE category END,
             updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id::text, title, description, category`,
        [
          documentId,
          body.title ?? null,
          Object.hasOwn(body, "description"),
          body.description ?? null,
          Object.hasOwn(body, "category"),
          body.category ?? null
        ]
      );
      return result.rows.length === 1
        ? { body: result.rows[0] }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "DELETE",
    url: "/api/documents/:id",
    action: "document.delete",
    handle: async ({ client, documentId }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `UPDATE documents SET deleted_at = now(), updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL RETURNING id`,
        [documentId]
      );
      return result.rowCount === 1
        ? { body: { deleted: true } }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/restore",
    action: "document.restore",
    handle: async ({ client, documentId }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `UPDATE documents SET deleted_at = NULL, updated_at = now()
         WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
        [documentId]
      );
      return result.rowCount === 1
        ? { body: { restored: true } }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/grants",
    action: "document.grant",
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        required: ["userId", "level"],
        properties: {
          userId: { type: "string", format: "uuid" },
          level: { type: "string", enum: ["read", "edit", "manage"] },
          expiresAt: { type: "string", format: "date-time" }
        }
      }
    },
    handle: async ({ client, actor, documentId, request }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const body = request.body as { userId: string; level: string; expiresAt?: string };
      const user = await client.query(
        "SELECT id FROM users WHERE id = $1 AND is_active = true",
        [body.userId]
      );
      if (user.rowCount !== 1 || body.userId === actor.id) {
        return { status: 400, body: { error: "Grant request is invalid" } };
      }
      if (body.expiresAt && new Date(body.expiresAt).getTime() <= Date.now()) {
        return { status: 400, body: { error: "Grant request is invalid" } };
      }
      const result = await client.query<{ id: string }>(
        `INSERT INTO document_grants
          (document_id, user_id, level, granted_by, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id::text`,
        [documentId, body.userId, body.level, actor.id, body.expiresAt ?? null]
      );
      return { status: 201, body: { grantId: result.rows[0]?.id } };
    }
  });

  register({
    method: "DELETE",
    url: "/api/documents/:id/grants/:userId",
    action: "document.revoke",
    handle: async ({ client, actor, documentId, request }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const userId = (request.params as { userId: string }).userId;
      const result = await client.query(
        `UPDATE document_grants
         SET revoked_at = now(), revoked_by = $3
         WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
        [documentId, userId, actor.id]
      );
      return result.rowCount === 1
        ? { body: { revoked: true } }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/versions",
    action: "document.versions.read",
    handle: async ({ client, documentId }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `SELECT id::text, version_number, size_bytes, detected_mime_type, created_at
         FROM document_versions WHERE document_id = $1 ORDER BY version_number DESC`,
        [documentId]
      );
      return { body: { versions: result.rows } };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/versions",
    action: "document.version.create",
    handle: async ({ client, actor, documentId, request, trackStorageKey }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const part = await request.file();
      if (!part || part.fieldname !== "file") {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      const bytes = await part.toBuffer();
      if (part.file.truncated) {
        return { status: 413, body: { error: "File exceeds upload limit" } };
      }
      let upload;
      try {
        upload = validateUpload(part.filename, part.mimetype, bytes);
      } catch {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      if (!dependencies.malwareScanner) {
        return { status: 503, body: { error: "Uploads temporarily unavailable" } };
      }
      const scanResult = await dependencies.malwareScanner(upload);
      if (scanResult !== "clean") {
        return { status: 400, body: { error: "Invalid upload" } };
      }
      const current = await client.query<{ next_version: number }>(
        `SELECT COALESCE(max(version_number), 0) + 1 AS next_version
         FROM document_versions WHERE document_id = $1`,
        [documentId]
      );
      const versionNumber = current.rows[0]?.next_version;
      if (!versionNumber) {
        throw new Error("Could not allocate a document version number.");
      }
      const encrypted = await encryptAndStore(
        dependencies.storageDirectory,
        dependencies.config.masterKey,
        upload
      );
      trackStorageKey(encrypted.storageKey);
      try {
        const versionId = await insertVersion(
          client,
          actor.id,
          documentId,
          encrypted,
          upload.mimeType,
          scanResult,
          versionNumber
        );
        await client.query(
          `UPDATE documents
           SET current_version_id = $2, original_filename = $3,
               declared_mime_type = $4, updated_at = now()
           WHERE id = $1`,
          [documentId, versionId, upload.filename, upload.mimeType]
        );
        return { status: 201, body: { id: versionId, versionNumber } };
      } catch (error) {
        await removeStorageQuietly(dependencies.storageDirectory, encrypted.storageKey);
        trackStorageKey(null);
        throw error;
      }
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/versions/:versionId",
    action: "document.version.read",
    handle: async ({ client, documentId, request }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const versionId = (request.params as { versionId: string }).versionId;
      if (!DOC_ID_PATTERN.test(versionId)) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const result = await client.query(
        `SELECT id::text, version_number, size_bytes, detected_mime_type, created_at
         FROM document_versions
         WHERE document_id = $1 AND id = $2`,
        [documentId, versionId]
      );
      return result.rows[0]
        ? { body: result.rows[0] }
        : { status: 404, body: DOCUMENT_NOT_FOUND };
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/versions/:versionId/download",
    action: "document.download",
    handle: async ({ client, documentId, request }) => {
      if (!documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const versionId = (request.params as { versionId: string }).versionId;
      if (!DOC_ID_PATTERN.test(versionId)) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const file = await loadEncryptedVersion(client, documentId, versionId);
      if (!file) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const plaintext = await decryptFromStorage(
        dependencies.storageDirectory,
        dependencies.config.masterKey,
        file.encrypted
      );
      return {
        stream: plaintext,
        headers: safeDownloadHeaders(file.filename, file.mimeType)
      };
    }
  });

  register({
    method: "POST",
    url: "/api/documents/:id/download-tokens",
    action: "document.download.issue",
    handle: async ({ client, actor, documentId }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const version = await client.query<{ id: string }>(
        "SELECT current_version_id::text AS id FROM documents WHERE id = $1 AND deleted_at IS NULL",
        [documentId]
      );
      if (!version.rows[0]?.id) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const token = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256").update(token).digest();
      await client.query(
        `INSERT INTO download_tokens
          (token_hash, user_id, document_id, version_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '60 seconds')`,
        [tokenHash, actor.id, documentId, version.rows[0].id]
      );
      return { status: 201, body: { token, expiresInSeconds: 60 } };
    }
  });

  register({
    method: "GET",
    url: "/api/downloads/:token",
    action: "document.download",
    documentId: async (client, request) => {
      const token = (request.params as { token: string }).token;
      if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
        return null;
      }
      const result = await client.query<{ document_id: string }>(
        "SELECT document_id::text FROM download_tokens WHERE token_hash = $1",
        [createHash("sha256").update(token).digest()]
      );
      return result.rows[0]?.document_id ?? null;
    },
    handle: async ({ client, actor, documentId, request }) => {
      if (!actor || !documentId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const token = (request.params as { token: string }).token;
      const tokenRow = await client.query<{
        user_id: string;
        version_id: string;
        redeemed_at: Date | null;
        revoked_at: Date | null;
      }>(
        `SELECT user_id::text, version_id::text, redeemed_at, revoked_at
         FROM download_tokens
         WHERE token_hash = $1 AND document_id = $2 AND expires_at > now()
         FOR UPDATE`,
        [createHash("sha256").update(token).digest(), documentId]
      );
      const record = tokenRow.rows[0];
      if (
        !record ||
        record.user_id !== actor.id ||
        record.redeemed_at ||
        record.revoked_at
      ) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const file = await loadEncryptedVersion(client, documentId, record.version_id);
      if (!file) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const plaintext = await decryptFromStorage(
        dependencies.storageDirectory,
        dependencies.config.masterKey,
        file.encrypted
      );
      await client.query(
        "UPDATE download_tokens SET redeemed_at = now() WHERE token_hash = $1",
        [createHash("sha256").update(token).digest()]
      );
      return {
        stream: plaintext,
        headers: safeDownloadHeaders(file.filename, file.mimeType)
      };
    }
  });

  register({
    method: "GET",
    url: "/api/documents/:id/download",
    action: "document.download",
    handle: async ({ client, documentId, actor }) => {
      if (!documentId || !actor) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const version = await client.query<{ id: string }>(
        "SELECT current_version_id::text AS id FROM documents WHERE id = $1 AND deleted_at IS NULL",
        [documentId]
      );
      const versionId = version.rows[0]?.id;
      if (!versionId) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const file = await loadEncryptedVersion(client, documentId, versionId);
      if (!file) {
        return { status: 404, body: DOCUMENT_NOT_FOUND };
      }
      const plaintext = await decryptFromStorage(
        dependencies.storageDirectory,
        dependencies.config.masterKey,
        file.encrypted
      );
      return {
        stream: plaintext,
        headers: safeDownloadHeaders(file.filename, file.mimeType)
      };
    }
  });

  register({
    method: "PATCH",
    url: "/api/admin/users/:id",
    action: "admin.users.manage",
    schema: {
      body: {
        type: "object",
        additionalProperties: false,
        minProperties: 1,
        properties: {
          role: { type: "string", enum: ["admin", "owner", "viewer"] },
          isActive: { type: "boolean" }
        }
      }
    },
    handle: async ({ client, request }) => {
      const id = (request.params as { id: string }).id;
      if (!DOC_ID_PATTERN.test(id)) {
        return { status: 404, body: { error: "Not found" } };
      }
      const body = request.body as { role?: Actor["role"]; isActive?: boolean };
      const changed = await client.query(
        `UPDATE users SET
           role = COALESCE($2, role),
           is_active = COALESCE($3, is_active),
           deactivated_at = CASE WHEN $3 = false THEN now()
             WHEN $3 = true THEN NULL ELSE deactivated_at END,
           updated_at = now()
         WHERE id = $1 RETURNING id`,
        [id, body.role ?? null, body.isActive ?? null]
      );
      if (changed.rowCount !== 1) {
        return { status: 404, body: { error: "Not found" } };
      }
      if (body.role !== undefined || body.isActive === false) {
        await client.query(
          "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
          [id]
        );
      }
      return { body: { updated: true } };
    }
  });

  return app;
}

function resolveParamDocumentId(request: FastifyRequest): string | null {
  const params = request.params as { id?: string };
  if (!params?.id) {
    return null;
  }
  return DOC_ID_PATTERN.test(params.id) ? params.id : null;
}

function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

async function searchAuthorizedDocuments(
  client: PoolClient,
  actorId: string,
  filters: {
    q?: string;
    name?: string;
    owner?: string;
    category?: string;
    from?: string;
    to?: string;
    includeDeleted?: string;
  }
): Promise<unknown[]> {
  const result = await client.query(
    `SELECT d.id::text, d.title, d.description, d.category,
            d.folder_id::text, d.deleted_at, d.created_at,
            owner.display_name AS owner_name,
            CASE WHEN d.deleted_at IS NULL
              THEN trustvault_authorize($1::uuid, d.id, 'document.edit_metadata')
              ELSE false
            END AS can_edit,
            CASE WHEN d.deleted_at IS NULL
              THEN trustvault_authorize($1::uuid, d.id, 'document.grants.read')
              ELSE false
            END AS can_manage,
            CASE WHEN d.deleted_at IS NOT NULL
              THEN trustvault_authorize($1::uuid, d.id, 'document.restore')
              ELSE false
            END AS can_restore
     FROM documents d
     JOIN users owner ON owner.id = d.owner_id
     JOIN LATERAL (
       SELECT CASE
         WHEN d.deleted_at IS NULL THEN
           trustvault_authorize($1::uuid, d.id, 'document.read_metadata')
         ELSE
           $6::boolean AND
             trustvault_authorize($1::uuid, d.id, 'document.restore')
       END AS allowed
     ) permission_filter ON permission_filter.allowed
     WHERE ($2 = '' OR d.title ILIKE '%' || $2 || '%'
                       OR d.description ILIKE '%' || $2 || '%')
       AND ($3 = '' OR d.title ILIKE '%' || $3 || '%')
       AND ($4 = '' OR owner.display_name ILIKE '%' || $4 || '%')
       AND ($5 = '' OR d.category ILIKE '%' || $5 || '%')
       AND ($7::date IS NULL OR d.created_at >= $7::date)
       AND ($8::date IS NULL OR d.created_at < ($8::date + interval '1 day'))
     ORDER BY d.created_at DESC
     LIMIT 100`,
    [
      actorId,
      filters.q?.trim() ?? "",
      filters.name?.trim() ?? "",
      filters.owner?.trim() ?? "",
      filters.category?.trim() ?? "",
      filters.includeDeleted === "true",
      filters.from ?? null,
      filters.to ?? null
    ]
  );
  return result.rows;
}

async function auditFrameworkFailure(
  dependencies: AppDependencies,
  request: FastifyRequest,
  action: "system.not_found" | "system.request_error",
  reason: string
): Promise<void> {
  const client = await dependencies.pool.connect();
  let transactionOpen = false;
  let destroyClient = false;
  try {
    await client.query("BEGIN");
    transactionOpen = true;
    const actor = await loadActor(client, request);
    const allowed = await authorize(client, actor, null, action);
    if (allowed) {
      throw new Error("Framework-level failure actions must remain denied.");
    }
    await appendAudit(
      client,
      dependencies.config.auditHmacSecret,
      createAuditEvent(
        request,
        actor,
        resolveParamDocumentId(request),
        action,
        "denied",
        reason
      )
    );
    await client.query("COMMIT");
    transactionOpen = false;
  } catch (error) {
    if (transactionOpen) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        request.log.error({ err: rollbackError }, "Could not roll back request audit");
        destroyClient = true;
      }
    }
    throw error;
  } finally {
    client.release(destroyClient);
  }
}

function createAuditEvent(
  request: FastifyRequest,
  actor: Actor | null,
  documentId: string | null,
  action: AuthzAction,
  outcome: "allowed" | "denied",
  reason: string
) {
  return {
    actorId: actor?.id ?? null,
    actorRole: actor?.role ?? null,
    ipAddress: request.ip || null,
    userAgent: request.headers["user-agent"]?.slice(0, 1024) ?? null,
    documentId,
    action,
    outcome,
    reason,
    requestId:
      request.id.length <= 200
        ? request.id || randomUUID()
        : createHash("sha256").update(request.id).digest("hex")
  };
}

async function insertVersion(
  client: PoolClient,
  actorId: string,
  documentId: string,
  encrypted: EncryptedFile,
  mimeType: string,
  scanStatus: "clean" | "rejected",
  versionNumber: number
): Promise<string> {
  const result = await client.query<{ id: string }>(
    `INSERT INTO document_versions
      (document_id, version_number, storage_key, wrapped_data_key,
       key_wrap_nonce, key_wrap_auth_tag, file_nonce, file_auth_tag,
       sha256, size_bytes, detected_mime_type, created_by, scan_status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
     RETURNING id::text`,
    [
      documentId,
      versionNumber,
      encrypted.storageKey,
      encrypted.wrappedDataKey,
      encrypted.keyWrapNonce,
      encrypted.keyWrapAuthTag,
      encrypted.fileNonce,
      encrypted.fileAuthTag,
      encrypted.sha256,
      encrypted.sizeBytes,
      mimeType,
      actorId,
      scanStatus
    ]
  );
  const id = result.rows[0]?.id;
  if (!id) {
    throw new Error("Version insert did not return an identifier.");
  }
  return id;
}

async function loadEncryptedVersion(
  client: PoolClient,
  documentId: string,
  versionId: string
): Promise<{ encrypted: EncryptedFile; filename: string; mimeType: string } | null> {
  const result = await client.query<{
    storage_key: string;
    wrapped_data_key: Buffer;
    key_wrap_nonce: Buffer;
    key_wrap_auth_tag: Buffer;
    file_nonce: Buffer;
    file_auth_tag: Buffer;
    sha256: Buffer;
    size_bytes: string;
    detected_mime_type: string;
    original_filename: string;
  }>(
    `SELECT v.storage_key, v.wrapped_data_key, v.key_wrap_nonce,
            v.key_wrap_auth_tag, v.file_nonce, v.file_auth_tag, v.sha256,
            v.size_bytes::text, v.detected_mime_type, d.original_filename
     FROM document_versions v
     JOIN documents d ON d.id = v.document_id
     WHERE v.document_id = $1 AND v.id = $2 AND d.deleted_at IS NULL
       AND v.scan_status = 'clean'`,
    [documentId, versionId]
  );
  const row = result.rows[0];
  if (!row) {
    return null;
  }
  return {
    encrypted: {
      storageKey: row.storage_key,
      wrappedDataKey: row.wrapped_data_key,
      keyWrapNonce: row.key_wrap_nonce,
      keyWrapAuthTag: row.key_wrap_auth_tag,
      fileNonce: row.file_nonce,
      fileAuthTag: row.file_auth_tag,
      sha256: row.sha256,
      sizeBytes: Number(row.size_bytes)
    },
    filename: row.original_filename,
    mimeType: row.detected_mime_type
  };
}

async function removeStorageQuietly(directory: string, storageKey: string): Promise<void> {
  try {
    const { removeStoredFile } = await import("./storage.js");
    await removeStoredFile(directory, storageKey);
  } catch (error) {
    throw new Error("Could not remove uncommitted encrypted upload.", { cause: error });
  }
}
