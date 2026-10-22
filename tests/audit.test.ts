import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { appendAudit, canonicalAuditRow, verifyAuditChain } from "../src/server/audit.js";
import type { PoolClient } from "pg";

const event = {
  actorId: null,
  actorRole: null,
  ipAddress: "127.0.0.1",
  userAgent: "test",
  documentId: "00000000-0000-4000-8000-000000000001",
  action: "document.read_metadata",
  outcome: "denied" as const,
  reason: "not_permitted",
  requestId: "request-1"
};

describe("audit chain", () => {
  it("hashes canonical rows including the previous hash and event sequence", () => {
    const row = canonicalAuditRow({
      ...event,
      id: "1",
      eventId: "00000000-0000-4000-8000-000000000010",
      occurredAt: "2026-10-22T00:00:00.000Z",
      prevHash: "00".repeat(32)
    });
    const first = createHmac("sha256", "k".repeat(32)).update(row).digest("hex");
    const changed = createHmac("sha256", "k".repeat(32))
      .update(row.replace("not_permitted", "allowed"))
      .digest("hex");
    expect(first).not.toBe(changed);
  });

  it("serializes append and writes denied events with chained hashes", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ id: "7" }] })
      .mockResolvedValueOnce({ rows: [{ id: "7" }] })
      .mockResolvedValueOnce({ rows: [], rowCount: 1 });
    const client = { query } as unknown as PoolClient;
    await appendAudit(client, "k".repeat(32), event);
    expect(query.mock.calls[0]?.[0]).toContain("pg_advisory_xact_lock");
    expect(query.mock.calls[3]?.[0]).toContain("INSERT INTO audit_log");
    expect(query.mock.calls[3]?.[1]?.[9]).toBe("denied");
  });

  it("detects tampered or disconnected chain rows", async () => {
    const rowHash = Buffer.alloc(32, 1);
    const prevHash = Buffer.alloc(32);
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          id: "1",
          event_id: "00000000-0000-4000-8000-000000000010",
          occurred_at: new Date("2026-10-22T00:00:00.000Z"),
          actor_id: null,
          actor_role: null,
          ip_address: "127.0.0.1",
          user_agent: "test",
          document_id: event.documentId,
          action: event.action,
          outcome: event.outcome,
          reason: event.reason,
          request_id: event.requestId,
          prev_hash: prevHash,
          row_hash: rowHash
        }
      ]
    });
    const client = { query } as unknown as PoolClient;
    await expect(verifyAuditChain(client, "k".repeat(32))).resolves.toEqual({
      valid: false,
      checked: 1,
      firstInvalidId: "1"
    });
    expect(query).toHaveBeenCalledWith(expect.stringContaining("ORDER BY audit_log.id"));
  });
});
