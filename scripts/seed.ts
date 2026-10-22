import "dotenv/config";
import argon2 from "argon2";
import path from "node:path";
import { PoolClient } from "pg";
import { loadConfig } from "../src/server/config.js";
import { appendAudit } from "../src/server/audit.js";
import { createPool } from "../src/server/db.js";
import { encryptAndStore, removeStoredFile, validateUpload } from "../src/server/storage.js";

const DEMO_PASSWORD = "TrustVault-Local-Demo-2026!";
const DEMO_USERS = [
  { email: "admin@trustvault.local", name: "Demo Admin", role: "admin" },
  { email: "owner.one@trustvault.local", name: "Owner One", role: "owner" },
  { email: "owner.two@trustvault.local", name: "Owner Two", role: "owner" },
  { email: "viewer.one@trustvault.local", name: "Viewer One", role: "viewer" },
  { email: "viewer.two@trustvault.local", name: "Viewer Two", role: "viewer" },
  { email: "viewer.three@trustvault.local", name: "Viewer Three", role: "viewer" }
] as const;
const STORAGE_DIRECTORY = path.resolve(process.env.STORAGE_DIRECTORY ?? "storage");

async function seed(): Promise<void> {
  if (process.env.NODE_ENV === "production" && process.env.ALLOW_DEMO_SEED !== "true") {
    throw new Error("Refusing demo seed in production without ALLOW_DEMO_SEED=true.");
  }
  const config = loadConfig(process.env);
  const pool = createPool(config);
  const client = await pool.connect();
  const createdStorageKeys: string[] = [];
  const passwordHash = await argon2.hash(DEMO_PASSWORD, {
    type: argon2.argon2id,
    memoryCost: 65_536,
    timeCost: 3,
    parallelism: 1
  });

  try {
    await client.query("BEGIN");
    const users = new Map<string, string>();
    for (const user of DEMO_USERS) {
      await client.query(
        `INSERT INTO users (email, display_name, password_hash, role)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO NOTHING`,
        [user.email, user.name, passwordHash, user.role]
      );
      const row = await client.query<{ id: string }>(
        "SELECT id::text FROM users WHERE email = $1 AND is_active = true",
        [user.email]
      );
      if (!row.rows[0]?.id) {
        throw new Error(`Demo account could not be loaded: ${user.email}`);
      }
      users.set(user.email, row.rows[0].id);
    }

    const ownerOne = requireUser(users, "owner.one@trustvault.local");
    const ownerTwo = requireUser(users, "owner.two@trustvault.local");
    const viewerOne = requireUser(users, "viewer.one@trustvault.local");
    const viewerTwo = requireUser(users, "viewer.two@trustvault.local");
    const documentOne = await ensureSampleDocument(
      client,
      ownerOne,
      "Demo document: owner one",
      "Owner One demo document.\n",
      config.masterKey,
      createdStorageKeys
    );
    const documentTwo = await ensureSampleDocument(
      client,
      ownerTwo,
      "Demo document: owner two",
      "Owner Two private demo document.\n",
      config.masterKey,
      createdStorageKeys
    );
    await client.query(
      `INSERT INTO document_grants (document_id, user_id, level, granted_by)
       VALUES ($1, $2, 'read', $3)
       ON CONFLICT (document_id, user_id) WHERE revoked_at IS NULL DO NOTHING`,
      [documentOne, viewerOne, ownerOne]
    );
    const priorRevokedGrant = await client.query(
      `SELECT 1 FROM document_grants
       WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NOT NULL LIMIT 1`,
      [documentTwo, viewerTwo]
    );
    if (priorRevokedGrant.rowCount === 0) {
      await client.query(
        `INSERT INTO document_grants
          (document_id, user_id, level, granted_by, revoked_at, revoked_by)
         VALUES ($1, $2, 'read', $3, now(), $3)`,
        [documentTwo, viewerTwo, ownerTwo]
      );
    }

    await appendSeedAuditOnce(client, config.auditHmacSecret, {
      actorId: ownerOne,
      actorRole: "owner",
      ipAddress: "127.0.0.1",
      userAgent: "trustvault-seed",
      documentId: documentOne,
      action: "document.grant",
      outcome: "allowed",
      reason: "seed_demo_grant",
      requestId: "seed-demo-grant"
    });
    await appendSeedAuditOnce(client, config.auditHmacSecret, {
      actorId: viewerTwo,
      actorRole: "viewer",
      ipAddress: "127.0.0.1",
      userAgent: "trustvault-seed",
      documentId: documentTwo,
      action: "document.read_metadata",
      outcome: "denied",
      reason: "seed_demo_denied_attempt",
      requestId: "seed-demo-denied"
    });
    await client.query("COMMIT");
    console.info(`Seeded ${DEMO_USERS.length} demo users and two sample documents.`);
  } catch (error) {
    await client.query("ROLLBACK");
    await Promise.all(
      createdStorageKeys.map((key) => removeStoredFile(STORAGE_DIRECTORY, key))
    );
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

async function ensureSampleDocument(
  client: PoolClient,
  ownerId: string,
  title: string,
  content: string,
  masterKey: string,
  createdStorageKeys: string[]
): Promise<string> {
  const existing = await client.query<{ id: string }>(
    `SELECT id::text FROM documents
     WHERE owner_id = $1 AND title = $2 AND deleted_at IS NULL`,
    [ownerId, title]
  );
  if (existing.rows[0]?.id) {
    return existing.rows[0].id;
  }

  const upload = validateUpload(
    "readme.txt",
    "text/plain",
    Buffer.from(content, "utf8")
  );
  const encrypted = await encryptAndStore(STORAGE_DIRECTORY, masterKey, upload);
  createdStorageKeys.push(encrypted.storageKey);
  try {
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO documents
        (owner_id, title, declared_mime_type, original_filename)
       VALUES ($1, $2, $3, $4) RETURNING id::text`,
      [ownerId, title, upload.mimeType, upload.filename]
    );
    const documentId = inserted.rows[0]?.id;
    if (!documentId) {
      throw new Error("Could not create sample document.");
    }
    const version = await client.query<{ id: string }>(
      `INSERT INTO document_versions
        (document_id, version_number, storage_key, wrapped_data_key,
         key_wrap_nonce, key_wrap_auth_tag, file_nonce, file_auth_tag,
         sha256, size_bytes, detected_mime_type, created_by, scan_status)
       VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'clean')
       RETURNING id::text`,
      [
        documentId,
        encrypted.storageKey,
        encrypted.wrappedDataKey,
        encrypted.keyWrapNonce,
        encrypted.keyWrapAuthTag,
        encrypted.fileNonce,
        encrypted.fileAuthTag,
        encrypted.sha256,
        encrypted.sizeBytes,
        upload.mimeType,
        ownerId
      ]
    );
    const versionId = version.rows[0]?.id;
    if (!versionId) {
      throw new Error("Could not create sample document version.");
    }
    await client.query(
      "UPDATE documents SET current_version_id = $2 WHERE id = $1",
      [documentId, versionId]
    );
    return documentId;
  } catch (error) {
    await removeStoredFile(STORAGE_DIRECTORY, encrypted.storageKey);
    createdStorageKeys.splice(createdStorageKeys.indexOf(encrypted.storageKey), 1);
    throw error;
  }
}

async function appendSeedAuditOnce(
  client: PoolClient,
  secret: string,
  event: Parameters<typeof appendAudit>[2]
): Promise<void> {
  const existing = await client.query(
    "SELECT 1 FROM audit_log WHERE request_id = $1",
    [event.requestId]
  );
  if (existing.rowCount === 0) {
    await appendAudit(client, secret, event);
  }
}

function requireUser(users: Map<string, string>, email: string): string {
  const id = users.get(email);
  if (!id) {
    throw new Error(`Missing seeded user ${email}`);
  }
  return id;
}

void seed().catch((error: unknown) => {
  console.error(
    "Seed failed:",
    error instanceof Error ? error.message : "Unknown seed error."
  );
  process.exitCode = 1;
});
