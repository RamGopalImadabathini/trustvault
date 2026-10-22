import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { PoolClient } from "pg";

export interface AuditEvent {
  actorId: string | null;
  actorRole: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  documentId: string | null;
  action: string;
  outcome: "allowed" | "denied";
  reason: string;
  requestId: string;
}

interface CanonicalAuditRow extends AuditEvent {
  id: string;
  eventId: string;
  occurredAt: string;
  prevHash: string;
}

export function canonicalAuditRow(row: CanonicalAuditRow): string {
  return JSON.stringify({
    id: row.id,
    eventId: row.eventId,
    occurredAt: row.occurredAt,
    actorId: row.actorId,
    actorRole: row.actorRole,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    documentId: row.documentId,
    action: row.action,
    outcome: row.outcome,
    reason: row.reason,
    requestId: row.requestId,
    prevHash: row.prevHash
  });
}

export async function appendAudit(
  client: PoolClient,
  secret: string,
  event: AuditEvent
): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock($1)", [1_415_530_821]);
  const latest = await client.query<{ row_hash: Buffer }>(
    "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
  );
  const prevHash = latest.rows[0]?.row_hash ?? Buffer.alloc(32);
  const sequence = await client.query<{ id: string }>(
    "SELECT nextval('audit_log_id_seq')::text AS id"
  );
  const id = sequence.rows[0]?.id;
  if (!id) {
    throw new Error("Could not allocate audit event sequence.");
  }

  const eventId = randomUUID();
  const occurredAt = new Date().toISOString();
  const canonical = canonicalAuditRow({
    ...event,
    id,
    eventId,
    occurredAt,
    prevHash: prevHash.toString("hex")
  });
  const rowHash = createHmac("sha256", secret).update(canonical).digest();

  await client.query(
    `INSERT INTO audit_log
      (id, event_id, occurred_at, actor_id, actor_role, ip_address, user_agent,
       document_id, action, outcome, reason, request_id, prev_hash, row_hash)
      OVERRIDING SYSTEM VALUE
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [
      id,
      eventId,
      occurredAt,
      event.actorId,
      event.actorRole,
      event.ipAddress,
      event.userAgent,
      event.documentId,
      event.action,
      event.outcome,
      event.reason,
      event.requestId,
      prevHash,
      rowHash
    ]
  );
}

export async function verifyAuditChain(
  client: PoolClient,
  secret: string
): Promise<{ valid: boolean; checked: number; firstInvalidId: string | null }> {
  const rows = await client.query<{
    id: string;
    event_id: string;
    occurred_at: Date;
    actor_id: string | null;
    actor_role: string | null;
    ip_address: string | null;
    user_agent: string | null;
    document_id: string | null;
    action: string;
    outcome: "allowed" | "denied";
    reason: string;
    request_id: string;
    prev_hash: Buffer;
    row_hash: Buffer;
  }>(
    `SELECT id::text, event_id::text, occurred_at, actor_id::text, actor_role,
            host(ip_address) AS ip_address, user_agent, document_id::text,
            action, outcome, reason, request_id, prev_hash, row_hash
     FROM audit_log ORDER BY audit_log.id`
  );
  let previous: Buffer<ArrayBufferLike> = Buffer.alloc(32);

  for (const row of rows.rows) {
    if (!row.prev_hash.equals(previous)) {
      return { valid: false, checked: rows.rows.length, firstInvalidId: row.id };
    }

    const canonical = canonicalAuditRow({
      id: row.id,
      eventId: row.event_id,
      occurredAt: row.occurred_at.toISOString(),
      actorId: row.actor_id,
      actorRole: row.actor_role,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      documentId: row.document_id,
      action: row.action,
      outcome: row.outcome,
      reason: row.reason,
      requestId: row.request_id,
      prevHash: row.prev_hash.toString("hex")
    });
    const expected = createHmac("sha256", secret).update(canonical).digest();
    if (
      expected.length !== row.row_hash.length ||
      !timingSafeEqual(expected, row.row_hash)
    ) {
      return { valid: false, checked: rows.rows.length, firstInvalidId: row.id };
    }
    previous = row.row_hash;
  }

  return { valid: true, checked: rows.rows.length, firstInvalidId: null };
}
