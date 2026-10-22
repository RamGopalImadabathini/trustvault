import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const migrationSql = readFileSync(
  path.join(process.cwd(), "db", "migrations", "001_initial_schema.sql"),
  "utf8"
);

describe("phase 1 security foundation", () => {
  it("rejects public schema privileges on the migration", () => {
    expect(migrationSql).toContain("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    expect(migrationSql).toContain("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC");
  });

  it("restricts the application DB role to least-privilege reads and inserts", () => {
    expect(migrationSql).toContain("GRANT SELECT, INSERT ON users TO trustvault_app");
    expect(migrationSql).toContain("GRANT SELECT, INSERT ON sessions TO trustvault_app");
    expect(migrationSql).not.toContain("GRANT SELECT, INSERT, UPDATE ON");
    expect(migrationSql).not.toContain("GRANT UPDATE ON audit_log");
  });

  it("blocks update/delete/truncate mutations on audit_log", () => {
    expect(migrationSql).toContain("CREATE TRIGGER audit_log_no_update_delete");
    expect(migrationSql).toContain("BEFORE UPDATE OR DELETE ON audit_log");
    expect(migrationSql).toContain("CREATE TRIGGER audit_log_no_truncate");
    expect(migrationSql).toContain("BEFORE TRUNCATE ON audit_log");
  });

  it("requires a hash-chain row key in audit_log", () => {
    expect(migrationSql).toContain("prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32)");
    expect(migrationSql).toContain("row_hash bytea NOT NULL CHECK (octet_length(row_hash) = 32)");
  });

  it("requires request correlation and outcome fields for every audit row", () => {
    expect(migrationSql).toContain("request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200)");
    expect(migrationSql).toContain("outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied'))");
  });

  it("stores the previous hash in every audit record before hashing the row", () => {
    expect(migrationSql).toContain("prev_hash");
    expect(migrationSql).toContain("row_hash");
  });

  it("keeps the app DB role from mutating audit rows through UPDATE or DELETE grants", () => {
    expect(migrationSql).toContain("GRANT SELECT, INSERT ON audit_log TO trustvault_app");
    expect(migrationSql).not.toContain("GRANT UPDATE ON audit_log TO trustvault_app");
    expect(migrationSql).not.toContain("GRANT DELETE ON audit_log TO trustvault_app");
  });

  it("never exposes the app role to public privileges over the schema", () => {
    expect(migrationSql).toContain("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    expect(migrationSql).toContain("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC");
    expect(migrationSql).not.toContain("GRANT ALL ON SCHEMA public");
  });

});
