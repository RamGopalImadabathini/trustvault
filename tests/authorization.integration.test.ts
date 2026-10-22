import "dotenv/config";
import { randomUUID } from "node:crypto";
import { rename, rm } from "node:fs/promises";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { Pool } from "pg";
import { createApp } from "../src/server/app.js";
import { verifyAuditChain } from "../src/server/audit.js";
import { loadConfig } from "../src/server/config.js";
import { createPool } from "../src/server/db.js";

const enabled =
  Boolean(process.env.DATABASE_URL) &&
  process.env.TRUSTVAULT_INTEGRATION !== "false";

describe.skipIf(!enabled)("PostgreSQL authorization and revocation integration", () => {
  let app: FastifyInstance;
  let pool: Pool;
  let cleanupPool: Pool;
  let documentId: string;
  let folderId: string;
  let uploadStorageKey: string;
  let testTitle: string;
  let baseUrl: string;
  const generatedUserIds: string[] = [];

  beforeAll(async () => {
    const config = loadConfig(process.env);
    pool = createPool(config);
    if (!process.env.DB_MIGRATION_URL) {
      throw new Error("DB_MIGRATION_URL is required for test fixture cleanup.");
    }
    cleanupPool = new Pool({ connectionString: process.env.DB_MIGRATION_URL });
    await pool.query("SELECT 1");
    app = createApp({
      pool,
      config,
      storageDirectory: path.resolve(process.env.STORAGE_DIRECTORY ?? "storage"),
      malwareScanner: async () => "clean"
    });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Could not bind integration-test API.");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
    testTitle = `integration-${randomUUID()}`;
  }, 30_000);

  afterAll(async () => {
    if (documentId) {
      const fileResult = await cleanupPool.query<{ storage_key: string }>(
        "SELECT storage_key FROM document_versions WHERE document_id = $1",
        [documentId]
      );
      await cleanupPool.query("DELETE FROM download_tokens WHERE document_id = $1", [
        documentId
      ]);
      await cleanupPool.query("DELETE FROM document_grants WHERE document_id = $1", [
        documentId
      ]);
      await cleanupPool.query("DELETE FROM ai_suggestions WHERE document_id = $1", [
        documentId
      ]);
      await cleanupPool.query(
        "UPDATE documents SET current_version_id = NULL WHERE id = $1",
        [documentId]
      );
      await cleanupPool.query("DELETE FROM document_versions WHERE document_id = $1", [
        documentId
      ]);
      await cleanupPool.query("DELETE FROM documents WHERE id = $1", [documentId]);
      await Promise.all(
        fileResult.rows.map((row) =>
          rm(
            path.resolve(process.env.STORAGE_DIRECTORY ?? "storage", row.storage_key),
            { force: true }
          )
        )
      );
    }
    if (folderId) {
      await cleanupPool.query(
        "UPDATE documents SET folder_id = NULL WHERE folder_id = $1",
        [folderId]
      );
      await cleanupPool.query("DELETE FROM folders WHERE id = $1", [folderId]);
    }
    if (generatedUserIds.length > 0) {
      await cleanupPool.query("DELETE FROM users WHERE id = ANY($1::uuid[])", [
        generatedUserIds
      ]);
    }
    await app?.close();
    await pool?.end();
    await cleanupPool?.end();
  });

  it("enforces cross-user access, download, audit, and immediate revocation", async () => {
    const owner = await login("owner.one@trustvault.local");
    const viewer = await login("viewer.one@trustvault.local");
    const otherViewer = await login("viewer.two@trustvault.local");
    const otherOwner = await login("owner.two@trustvault.local");
    const admin = await login("admin@trustvault.local");

    const form = new FormData();
    form.set("title", testTitle);
    form.set("category", "integration-category");
    form.set(
      "file",
      new Blob(["%PDF-1.7 trusted demo document\n"], {
        type: "application/pdf"
      }),
      "test.pdf"
    );
    const uploadResponse = await fetch(`${baseUrl}/api/documents`, {
      method: "POST",
      headers: {
        Cookie: owner.cookie,
        "x-csrf-token": owner.csrf
      },
      body: form
    });
    expect(uploadResponse.status).toBe(201);
    const uploadBody = (await uploadResponse.json()) as { id: string };
    documentId = uploadBody.id;
    const storedFile = await pool.query<{ storage_key: string }>(
      "SELECT storage_key FROM document_versions WHERE document_id = $1",
      [documentId]
    );
    uploadStorageKey = storedFile.rows[0]?.storage_key ?? "";

    const ownerGrant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: {
        userId: viewer.id,
        level: "read"
      }
    });
    expect(ownerGrant.statusCode).toBe(201);

    const viewerSearch = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: viewer.cookie }
    });
    expect(viewerSearch.json().documents.map((item: { id: string }) => item.id)).toContain(
      documentId
    );
    const viewerSearchRoute = await app.inject({
      method: "GET",
      url: `/api/search?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: viewer.cookie }
    });
    expect(viewerSearchRoute.json().results.map((item: { id: string }) => item.id)).toContain(
      documentId
    );
    const deniedSearch = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: otherViewer.cookie }
    });
    expect(deniedSearch.json().documents).toEqual([]);
    const deniedSearchRoute = await app.inject({
      method: "GET",
      url: `/api/search?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: otherViewer.cookie }
    });
    expect(deniedSearchRoute.json().results).toEqual([]);
    const editGrant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { userId: otherViewer.id, level: "edit" }
    });
    expect(editGrant.statusCode).toBe(201);
    const escalation = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: otherViewer.cookie, "x-csrf-token": otherViewer.csrf },
      payload: { userId: viewer.id, level: "read" }
    });
    expect(escalation.statusCode).toBe(404);
    await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}/grants/${otherViewer.id}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    const adminDocumentRead = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}`,
      headers: { cookie: admin.cookie }
    });
    expect(adminDocumentRead.statusCode).toBe(404);
    expect(adminDocumentRead.json()).toEqual({ error: "Not found" });

    const allowed = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}`,
      headers: { cookie: viewer.cookie }
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().title).toBe(testTitle);

    const deniedResults = await Promise.all([
      app.inject({
        method: "GET",
        url: `/api/documents/${documentId}`,
        headers: { cookie: otherViewer.cookie }
      }),
      app.inject({
        method: "GET",
        url: `/api/documents/${documentId}`,
        headers: { cookie: otherOwner.cookie }
      }),
      app.inject({
        method: "PATCH",
        url: `/api/documents/${documentId}`,
        headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf },
        payload: { title: "forged" }
      }),
      app.inject({
        method: "DELETE",
        url: `/api/documents/${documentId}`,
        headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf }
      }),
      app.inject({
        method: "GET",
        url: `/api/documents/${documentId}/download`,
        headers: { cookie: otherViewer.cookie }
      }),
      app.inject({
        method: "GET",
        url: `/api/documents/${documentId}/download`,
        headers: { cookie: "tv_session=not-a-valid-session" }
      }),
      app.inject({
        method: "GET",
        url: `/api/documents/${documentId}`,
        headers: { cookie: "tv_session=not-a-valid-session" }
      })
    ]);
    for (const response of deniedResults) {
      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: "Not found" });
    }

    const csrfDenied = await app.inject({
      method: "PATCH",
      url: `/api/documents/${documentId}`,
      headers: { cookie: owner.cookie },
      payload: { description: "must not be changed" }
    });
    expect(csrfDenied.statusCode).toBe(403);
    expect(csrfDenied.json()).toEqual({
      error: "Request could not be verified"
    });

    const deniedTokenIssue = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/download-tokens`,
      headers: { cookie: otherViewer.cookie, "x-csrf-token": otherViewer.csrf }
    });
    expect(deniedTokenIssue.statusCode).toBe(404);
    expect(deniedTokenIssue.json()).toEqual({ error: "Not found" });

    const tokenResponse = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/download-tokens`,
      headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf }
    });
    expect(tokenResponse.statusCode).toBe(201);
    const token = tokenResponse.json().token as string;
    const shareGrant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { userId: otherViewer.id, level: "read" }
    });
    expect(shareGrant.statusCode).toBe(201);
    const sharedToken = await app.inject({
      method: "GET",
      url: `/api/downloads/${token}`,
      headers: { cookie: otherViewer.cookie }
    });
    expect(sharedToken.statusCode).toBe(404);
    expect(sharedToken.json()).toEqual({ error: "Not found" });
    await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}/grants/${otherViewer.id}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    const downloaded = await app.inject({
      method: "GET",
      url: `/api/downloads/${token}`,
      headers: { cookie: viewer.cookie }
    });
    expect(downloaded.statusCode).toBe(200);
    expect(downloaded.headers["content-disposition"]).toContain("attachment");
    expect(downloaded.headers["x-content-type-options"]).toBe("nosniff");
    expect(downloaded.body).toContain("trusted demo document");

    const replay = await app.inject({
      method: "GET",
      url: `/api/downloads/${token}`,
      headers: { cookie: viewer.cookie }
    });
    expect(replay.statusCode).toBe(404);
    expect(replay.json()).toEqual({ error: "Not found" });

    const futureTokenResponse = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/download-tokens`,
      headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf }
    });
    const futureToken = futureTokenResponse.json().token as string;
    const revoke = await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}/grants/${viewer.id}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(revoke.statusCode).toBe(200);
    const afterRevoke = await app.inject({
      method: "GET",
      url: `/api/downloads/${futureToken}`,
      headers: { cookie: viewer.cookie }
    });
    expect(afterRevoke.statusCode).toBe(404);
    expect(afterRevoke.json()).toEqual({ error: "Not found" });
    const searchAfterRevoke = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: viewer.cookie }
    });
    expect(searchAfterRevoke.json().documents).toEqual([]);
    const searchRouteAfterRevoke = await app.inject({
      method: "GET",
      url: `/api/search?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: viewer.cookie }
    });
    expect(searchRouteAfterRevoke.json().results).toEqual([]);

    const concurrentGrant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { userId: viewer.id, level: "read" }
    });
    expect(concurrentGrant.statusCode).toBe(201);
    const concurrentTokenResponse = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/download-tokens`,
      headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf }
    });
    const concurrentToken = concurrentTokenResponse.json().token as string;
    const [racingDownload, racingRevoke] = await Promise.all([
      app.inject({
        method: "GET",
        url: `/api/downloads/${concurrentToken}`,
        headers: { cookie: viewer.cookie }
      }),
      app.inject({
        method: "DELETE",
        url: `/api/documents/${documentId}/grants/${viewer.id}`,
        headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
      })
    ]);
    expect(racingRevoke.statusCode).toBe(200);
    expect([200, 404]).toContain(racingDownload.statusCode);
    expect(
      (
        await app.inject({
          method: "GET",
          url: `/api/documents/${documentId}`,
          headers: { cookie: viewer.cookie }
        })
      ).statusCode
    ).toBe(404);

    const softDelete = await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(softDelete.statusCode).toBe(200);
    const deletedMetadata = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}`,
      headers: { cookie: owner.cookie }
    });
    expect(deletedMetadata.statusCode).toBe(404);
    const restore = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/restore`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(restore.statusCode).toBe(200);

    const storageDirectory = path.resolve(process.env.STORAGE_DIRECTORY ?? "storage");
    const originalPath = path.join(storageDirectory, uploadStorageKey);
    const unavailablePath = `${originalPath}.temporary`;
    await rename(originalPath, unavailablePath);
    try {
      const failedRead = await app.inject({
        method: "GET",
        url: `/api/documents/${documentId}/download`,
        headers: { cookie: owner.cookie }
      });
      expect(failedRead.statusCode).toBe(500);
    } finally {
      await rename(unavailablePath, originalPath);
    }
    const failureAudit = await pool.query(
      `SELECT 1 FROM audit_log
       WHERE document_id = $1 AND action = 'document.download'
         AND outcome = 'denied' AND reason = 'request_failed'`,
      [documentId]
    );
    expect(failureAudit.rowCount).toBeGreaterThan(0);

    const noScannerApp = createApp({
      pool,
      config: loadConfig(process.env),
      storageDirectory
    });
    await noScannerApp.listen({ host: "127.0.0.1", port: 0 });
    try {
      const address = noScannerApp.server.address();
      if (!address || typeof address === "string") {
        throw new Error("Could not bind API without a malware scanner.");
      }
      const form = new FormData();
      form.set("title", `unscanned-${randomUUID()}`);
      form.set(
        "file",
        new Blob(["%PDF-1.7 upload that requires scanning\n"], {
          type: "application/pdf"
        }),
        "unscanned.pdf"
      );
      const noScannerResponse = await fetch(
        `http://127.0.0.1:${address.port}/api/documents`,
        {
          method: "POST",
          headers: {
            Cookie: owner.cookie,
            "x-csrf-token": owner.csrf
          },
          body: form
        }
      );
      expect(noScannerResponse.status).toBe(503);
      expect(await noScannerResponse.json()).toEqual({
        error: "Uploads temporarily unavailable"
      });
      const scannerAudit = await pool.query<{ action: string; outcome: string }>(
        `SELECT action, outcome FROM audit_log
         ORDER BY audit_log.id DESC LIMIT 1`
      );
      expect(scannerAudit.rows[0]).toEqual({
        action: "document.create",
        outcome: "denied"
      });
    } finally {
      await noScannerApp.close();
    }

    const missing = await app.inject({
      method: "GET",
      url: `/api/documents/${randomUUID()}`,
      headers: { cookie: otherViewer.cookie }
    });
    const forbidden = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}`,
      headers: { cookie: otherViewer.cookie }
    });
    expect(missing.statusCode).toBe(404);
    expect(forbidden.statusCode).toBe(404);
    expect(missing.body).toBe(forbidden.body);

    const audit = await pool.query<{ outcome: string; action: string }>(
      `SELECT outcome, action FROM audit_log
       WHERE document_id = $1 AND request_id <> 'seed-demo'
       ORDER BY id`,
      [documentId]
    );
    expect(audit.rows.some((row) => row.outcome === "denied")).toBe(true);
    expect(audit.rows.some((row) => row.action === "document.download")).toBe(true);
    expect(uploadStorageKey).toBeTruthy();
  }, 60_000);

  it("keeps search, folders, versions, AI decisions, and admin metadata scoped", async () => {
    const owner = await login("owner.one@trustvault.local");
    const viewer = await login("viewer.one@trustvault.local");
    const otherViewer = await login("viewer.two@trustvault.local");
    const admin = await login("admin@trustvault.local");
    const today = new Date().toISOString().slice(0, 10);

    const ownerSearch = await app.inject({
      method: "GET",
      url: `/api/documents?name=${encodeURIComponent(testTitle)}&owner=Owner%20One&category=integration-category&from=${today}&to=${today}`,
      headers: { cookie: owner.cookie }
    });
    expect(ownerSearch.statusCode).toBe(200);
    expect(ownerSearch.json().documents.map((item: { id: string }) => item.id)).toContain(
      documentId
    );

    const folder = await app.inject({
      method: "POST",
      url: "/api/folders",
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { name: `integration-folder-${randomUUID()}` }
    });
    expect(folder.statusCode).toBe(201);
    folderId = folder.json().id as string;
    await cleanupPool.query(
      "UPDATE documents SET folder_id = $2 WHERE id = $1",
      [documentId, folderId]
    );
    const visibleFolder = await app.inject({
      method: "GET",
      url: "/api/folders",
      headers: { cookie: otherViewer.cookie }
    });
    expect(visibleFolder.json().folders.map((item: { id: string }) => item.id)).toContain(
      folderId
    );
    const deniedThroughFolder = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: otherViewer.cookie }
    });
    expect(deniedThroughFolder.json().documents).toEqual([]);
    const viewerFolderMutation = await app.inject({
      method: "PATCH",
      url: `/api/folders/${folderId}`,
      headers: { cookie: otherViewer.cookie, "x-csrf-token": otherViewer.csrf },
      payload: { name: "unauthorized folder change" }
    });
    expect(viewerFolderMutation.statusCode).toBe(403);

    const grant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { userId: viewer.id, level: "read" }
    });
    expect(grant.statusCode).toBe(201);
    const filterSearch = await app.inject({
      method: "GET",
      url: `/api/search?category=integration-category&owner=Owner%20One`,
      headers: { cookie: viewer.cookie }
    });
    expect(filterSearch.json().results.map((item: { id: string }) => item.id)).toContain(
      documentId
    );

    const versions = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}/versions`,
      headers: { cookie: viewer.cookie }
    });
    expect(versions.statusCode).toBe(200);
    const versionId = versions.json().versions[0]?.id as string;
    const versionMetadata = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}/versions/${versionId}`,
      headers: { cookie: viewer.cookie }
    });
    expect(versionMetadata.statusCode).toBe(200);
    const versionDownload = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}/versions/${versionId}/download`,
      headers: { cookie: viewer.cookie }
    });
    expect(versionDownload.statusCode).toBe(200);
    expect(versionDownload.body).toContain("trusted demo document");

    const deniedVersionForm = new FormData();
    deniedVersionForm.set(
      "file",
      new Blob(["%PDF-1.7 unauthorized version\n"], {
        type: "application/pdf"
      }),
      "unauthorized-version.pdf"
    );
    const deniedVersionCreate = await fetch(
      `${baseUrl}/api/documents/${documentId}/versions`,
      {
        method: "POST",
        headers: { Cookie: viewer.cookie, "x-csrf-token": viewer.csrf },
        body: deniedVersionForm
      }
    );
    expect(deniedVersionCreate.status).toBe(404);

    const editGrant = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/grants`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { userId: otherViewer.id, level: "edit" }
    });
    expect(editGrant.statusCode).toBe(201);
    const versionForm = new FormData();
    versionForm.set(
      "file",
      new Blob(["%PDF-1.7 second authorized version\n"], {
        type: "application/pdf"
      }),
      "second-version.pdf"
    );
    const createdVersion = await fetch(
      `${baseUrl}/api/documents/${documentId}/versions`,
      {
        method: "POST",
        headers: {
          Cookie: otherViewer.cookie,
          "x-csrf-token": otherViewer.csrf
        },
        body: versionForm
      }
    );
    expect(createdVersion.status).toBe(201);
    const secondVersion = (await createdVersion.json()) as {
      id: string;
      versionNumber: number;
    };
    expect(secondVersion.versionNumber).toBe(2);
    const secondVersionDownload = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}/versions/${secondVersion.id}/download`,
      headers: { cookie: viewer.cookie }
    });
    expect(secondVersionDownload.statusCode).toBe(200);
    expect(secondVersionDownload.body).toContain("second authorized version");

    const suggestions = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/ai-suggestions`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(suggestions.statusCode).toBe(201);
    const suggestionBody = suggestions.json() as {
      id: string;
      suggestions: { userId: string; reason: string }[];
    };
    expect(suggestionBody.suggestions.length).toBeGreaterThan(0);
    const candidateId = suggestionBody.suggestions[0]?.userId;
    const grantCountBeforeDecision = await pool.query(
      `SELECT count(*)::int AS count FROM document_grants
       WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [documentId, candidateId]
    );
    const decision = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/ai-suggestions/${suggestionBody.id}/decision`,
      headers: { cookie: viewer.cookie, "x-csrf-token": viewer.csrf },
      payload: { decision: "accepted" }
    });
    expect(decision.statusCode).toBe(404);
    const ownerDecision = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/ai-suggestions/${suggestionBody.id}/decision`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
      payload: { decision: "accepted" }
    });
    expect(ownerDecision.statusCode).toBe(200);
    expect(ownerDecision.json().grantCreated).toBe(false);
    const grantCountAfterDecision = await pool.query(
      `SELECT count(*)::int AS count FROM document_grants
       WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [documentId, candidateId]
    );
    expect(grantCountAfterDecision.rows[0]?.count).toBe(
      grantCountBeforeDecision.rows[0]?.count
    );

    const softDelete = await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(softDelete.statusCode).toBe(200);
    const unauthorizedDeletedSearch = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}&includeDeleted=true`,
      headers: { cookie: viewer.cookie }
    });
    expect(unauthorizedDeletedSearch.json().documents).toEqual([]);
    const hiddenDeleted = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}`,
      headers: { cookie: owner.cookie }
    });
    expect(hiddenDeleted.json().documents).toEqual([]);
    const recoveredSearch = await app.inject({
      method: "GET",
      url: `/api/documents?q=${encodeURIComponent(testTitle)}&includeDeleted=true`,
      headers: { cookie: owner.cookie }
    });
    expect(recoveredSearch.json().documents.map((item: { id: string }) => item.id)).toContain(
      documentId
    );
    const restore = await app.inject({
      method: "POST",
      url: `/api/documents/${documentId}/restore`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(restore.statusCode).toBe(200);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const denied = await app.inject({
        method: "GET",
        url: `/api/documents/${randomUUID()}`,
        headers: { cookie: otherViewer.cookie }
      });
      expect(denied.statusCode).toBe(404);
    }
    for (let download = 0; download < 20; download += 1) {
      const response = await app.inject({
        method: "GET",
        url: `/api/documents/${documentId}/download`,
        headers: { cookie: viewer.cookie }
      });
      expect(response.statusCode).toBe(200);
    }
    for (let index = 0; index < 10; index += 1) {
      const user = await cleanupPool.query<{ id: string }>(
        `INSERT INTO users (email, display_name, password_hash, role)
         SELECT $1, $2, password_hash, 'viewer'
         FROM users WHERE id = $3
         RETURNING id::text`,
        [
          `phase-test-${randomUUID()}@trustvault.local`,
          `Phase Test Viewer ${index}`,
          owner.id
        ]
      );
      const userId = user.rows[0]?.id;
      if (!userId) {
        throw new Error("Could not create anomaly test user.");
      }
      generatedUserIds.push(userId);
      const createdGrant = await app.inject({
        method: "POST",
        url: `/api/documents/${documentId}/grants`,
        headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf },
        payload: { userId, level: "read" }
      });
      expect(createdGrant.statusCode).toBe(201);
    }

    const adminAudit = await app.inject({
      method: "GET",
      url: "/api/admin/audit?limit=100",
      headers: { cookie: admin.cookie }
    });
    expect(adminAudit.statusCode).toBe(200);
    const hiddenDocumentEvents = adminAudit
      .json()
      .events.filter((event: { action: string }) =>
        ["document.read_metadata", "document.download"].includes(event.action)
      );
    expect(hiddenDocumentEvents.length).toBeGreaterThan(0);
    expect(
      hiddenDocumentEvents.every(
        (event: { document_id: string | null; document_title: string | null }) =>
          event.document_id === null && event.document_title === null
      )
    ).toBe(true);
    const adminAnomalies = await app.inject({
      method: "GET",
      url: "/api/admin/anomalies",
      headers: { cookie: admin.cookie }
    });
    const currentFlags = adminAnomalies.json().anomalies as {
      type: string;
      count: number;
    }[];
    expect(currentFlags.map((item) => item.type)).toEqual(
      expect.arrayContaining(["repeated_denials", "bulk_downloads", "grant_bursts"])
    );
    expect(JSON.stringify(adminAnomalies.json())).not.toContain(testTitle);

    const invalidChainApp = createApp({
      pool,
      config: loadConfig(process.env),
      storageDirectory: path.resolve(process.env.STORAGE_DIRECTORY ?? "storage"),
      aiSuggestionProvider: {
        name: "test-provider",
        suggest: async ({ metadata }) => {
          expect(Object.keys(metadata).sort()).toEqual([
            "category",
            "description",
            "ownerName",
            "title"
          ]);
          return [{ userId: randomUUID(), reason: "Not an eligible candidate." }];
        }
      },
      auditVerifier: async () => ({
        valid: false,
        checked: 10,
        firstInvalidId: "7"
      })
    });
    await invalidChainApp.ready();
    const providerSuggestion = await invalidChainApp.inject({
      method: "POST",
      url: `/api/documents/${documentId}/ai-suggestions`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    expect(providerSuggestion.statusCode).toBe(201);
    expect(providerSuggestion.json().suggestions).toEqual([]);
    const invalidAnomalies = await invalidChainApp.inject({
      method: "GET",
      url: "/api/admin/anomalies",
      headers: { cookie: admin.cookie }
    });
    expect(invalidAnomalies.json().anomalies).toContainEqual({
      type: "failed_chain_verification",
      count: 1
    });
    await invalidChainApp.close();

    await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}/grants/${viewer.id}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    await app.inject({
      method: "DELETE",
      url: `/api/documents/${documentId}/grants/${otherViewer.id}`,
      headers: { cookie: owner.cookie, "x-csrf-token": owner.csrf }
    });
    const deniedVersionDownload = await app.inject({
      method: "GET",
      url: `/api/documents/${documentId}/versions/${secondVersion.id}/download`,
      headers: { cookie: viewer.cookie }
    });
    expect(deniedVersionDownload.statusCode).toBe(404);
    expect(deniedVersionDownload.json()).toEqual({ error: "Not found" });
  }, 30_000);

  it("revokes sessions after a role change or deactivation", async () => {
    const admin = await login("admin@trustvault.local");
    const viewer = await login("viewer.three@trustvault.local");
    const roleChange = await app.inject({
      method: "PATCH",
      url: `/api/admin/users/${viewer.id}`,
      headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf },
      payload: { role: "owner" }
    });
    expect(roleChange.statusCode).toBe(200);
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/api/auth/me",
          headers: { cookie: viewer.cookie }
        })
      ).statusCode
    ).toBe(401);

    const newSession = await login("viewer.three@trustvault.local");
    const deactivate = await app.inject({
      method: "PATCH",
      url: `/api/admin/users/${viewer.id}`,
      headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf },
      payload: { isActive: false }
    });
    expect(deactivate.statusCode).toBe(200);
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/api/auth/me",
          headers: { cookie: newSession.cookie }
        })
      ).statusCode
    ).toBe(401);

    const restore = await app.inject({
      method: "PATCH",
      url: `/api/admin/users/${viewer.id}`,
      headers: { cookie: admin.cookie, "x-csrf-token": admin.csrf },
      payload: { isActive: true, role: "viewer" }
    });
    expect(restore.statusCode).toBe(200);
  });

  it("keeps login errors uniform and locks accounts after repeated failures", async () => {
    const nonexistent = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: {
        email: "nobody@trustvault.local",
        password: "incorrect-password"
      }
    });
    const wrongPassword = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: {
        email: "viewer.three@trustvault.local",
        password: "incorrect-password"
      }
    });
    expect(nonexistent.statusCode).toBe(401);
    expect(wrongPassword.statusCode).toBe(401);
    expect(nonexistent.body).toBe(wrongPassword.body);

    try {
      const attempts = await Promise.all(
        Array.from({ length: 5 }, () =>
          app.inject({
            method: "POST",
            url: "/api/auth/login",
            payload: {
              email: "viewer.three@trustvault.local",
              password: "incorrect-password"
            }
          })
        )
      );
      for (const response of attempts) {
        expect(response.statusCode).toBe(401);
      }
      const locked = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: {
          email: "viewer.three@trustvault.local",
          password: "TrustVault-Local-Demo-2026!"
        }
      });
      expect(locked.statusCode).toBe(401);
      expect(locked.body).toBe(nonexistent.body);
    } finally {
      await cleanupPool.query(
        `UPDATE users SET failed_login_count = 0, locked_until = NULL
         WHERE email = 'viewer.three@trustvault.local'`
      );
    }
  });

  it("verifies the live audit chain and blocks row mutation", async () => {
    const result = await pool.query(
      `SELECT id::text FROM audit_log ORDER BY audit_log.id DESC LIMIT 1`
    );
    const latestId = result.rows[0]?.id as string | undefined;
    expect(latestId).toBeTruthy();

    const client = await pool.connect();
    try {
      await expect(verifyAuditChain(client, loadConfig(process.env).auditHmacSecret))
        .resolves.toMatchObject({ valid: true, firstInvalidId: null });
    } finally {
      client.release();
    }

    const cleanupClient = await cleanupPool.connect();
    const mutations = [
      () => cleanupClient.query("UPDATE audit_log SET reason = reason WHERE id = $1", [latestId]),
      () => cleanupClient.query("DELETE FROM audit_log WHERE id = $1", [latestId]),
      () => cleanupClient.query("TRUNCATE audit_log")
    ];
    try {
      for (const mutation of mutations) {
        await cleanupClient.query("BEGIN");
        try {
          await expect(mutation()).rejects.toThrow("audit_log is append-only");
        } finally {
          await cleanupClient.query("ROLLBACK");
        }
      }
    } finally {
      cleanupClient.release();
    }
  });

  it("audits unmatched routes and malformed requests", async () => {
    const unmatched = await app.inject({
      method: "GET",
      url: "/api/not-a-route"
    });
    expect(unmatched.statusCode).toBe(404);
    expect(unmatched.json()).toEqual({ error: "Not found" });

    const malformed = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: { "content-type": "application/json" },
      payload: "{"
    });
    expect(malformed.statusCode).toBe(400);
    expect(malformed.json()).toEqual({ error: "Request rejected" });

    const events = await pool.query<{ action: string; outcome: string }>(
      `SELECT action, outcome FROM audit_log
       WHERE reason IN ('route_not_found', 'request_error_400')
       ORDER BY audit_log.id DESC LIMIT 2`
    );
    expect(events.rows).toEqual(
      expect.arrayContaining([
        { action: "system.not_found", outcome: "denied" },
        { action: "system.request_error", outcome: "denied" }
      ])
    );
  });

  async function login(email: string): Promise<{
    id: string;
    cookie: string;
    csrf: string;
  }> {
    const response = await app.inject({
      method: "POST",
      url: "/api/auth/login",
      payload: { email, password: "TrustVault-Local-Demo-2026!" }
    });
    expect(response.statusCode).toBe(200);
    const setCookie = response.headers["set-cookie"];
    if (!setCookie) {
      throw new Error("Login did not set a session cookie.");
    }
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0]! : setCookie;
    expect(cookieHeader).toContain("HttpOnly");
    expect(cookieHeader).toContain("Secure");
    expect(cookieHeader).toContain("SameSite=Strict");
    const cookie = cookieHeader.split(";")[0]!;
    const me = await app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie }
    });
    expect(me.statusCode).toBe(200);
    const meBody = me.json() as { id: string; csrfToken: string };
    const user = await pool.query<{ id: string }>(
      "SELECT id::text FROM users WHERE email = $1",
      [email]
    );
    return {
      id: user.rows[0]?.id ?? meBody.id,
      cookie,
      csrf: meBody.csrfToken
    };
  }
});
