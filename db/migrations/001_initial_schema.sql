CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
  is_active boolean NOT NULL DEFAULT true,
  failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  locked_until timestamptz,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deactivated_at timestamptz,
  CHECK ((is_active AND deactivated_at IS NULL) OR (NOT is_active AND deactivated_at IS NOT NULL))
);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id),
  secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  revoked_at timestamptz,
  csrf_secret bytea NOT NULL CHECK (octet_length(csrf_secret) >= 32),
  created_ip inet,
  user_agent text CHECK (user_agent IS NULL OR length(user_agent) <= 1024)
);

CREATE INDEX sessions_user_expiry_idx ON sessions (user_id, expires_at);

CREATE TABLE folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  parent_id uuid REFERENCES folders(id),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE INDEX folders_parent_name_idx ON folders (parent_id, name);
CREATE INDEX folders_creator_idx ON folders (created_by);

CREATE TABLE documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES users(id),
  folder_id uuid REFERENCES folders(id),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  description text CHECK (description IS NULL OR length(description) <= 10000),
  declared_mime_type text NOT NULL CHECK (length(declared_mime_type) BETWEEN 1 AND 255),
  original_filename text NOT NULL CHECK (length(original_filename) BETWEEN 1 AND 255),
  current_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE INDEX documents_owner_idx ON documents (owner_id);
CREATE INDEX documents_folder_idx ON documents (folder_id);
CREATE INDEX documents_active_idx ON documents (created_at) WHERE deleted_at IS NULL;

CREATE TABLE document_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES documents(id),
  version_number integer NOT NULL CHECK (version_number > 0),
  storage_key text NOT NULL UNIQUE CHECK (length(storage_key) BETWEEN 32 AND 255),
  wrapped_data_key bytea NOT NULL,
  key_wrap_nonce bytea NOT NULL CHECK (octet_length(key_wrap_nonce) = 12),
  key_wrap_auth_tag bytea NOT NULL CHECK (octet_length(key_wrap_auth_tag) = 16),
  file_nonce bytea NOT NULL CHECK (octet_length(file_nonce) = 12),
  file_auth_tag bytea NOT NULL CHECK (octet_length(file_auth_tag) = 16),
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  detected_mime_type text NOT NULL CHECK (length(detected_mime_type) BETWEEN 1 AND 255),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  scan_status text NOT NULL CHECK (scan_status IN ('pending', 'clean', 'rejected', 'error')),
  UNIQUE (document_id, version_number),
  UNIQUE (document_id, id)
);

CREATE INDEX document_versions_created_idx ON document_versions (document_id, created_at);

ALTER TABLE documents
  ADD CONSTRAINT documents_current_version_fk
  FOREIGN KEY (id, current_version_id)
  REFERENCES document_versions (document_id, id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE document_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES documents(id),
  user_id uuid NOT NULL REFERENCES users(id),
  level text NOT NULL CHECK (level IN ('read', 'edit', 'manage')),
  granted_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES users(id)
);

CREATE UNIQUE INDEX document_grants_active_unique
  ON document_grants (document_id, user_id)
  WHERE revoked_at IS NULL;
CREATE INDEX document_grants_user_document_idx ON document_grants (user_id, document_id);
CREATE INDEX document_grants_document_user_idx ON document_grants (document_id, user_id);

CREATE TABLE groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE UNIQUE INDEX groups_active_name_unique
  ON groups (lower(name))
  WHERE deleted_at IS NULL;

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups(id),
  user_id uuid NOT NULL REFERENCES users(id),
  added_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE download_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  user_id uuid NOT NULL REFERENCES users(id),
  document_id uuid NOT NULL REFERENCES documents(id),
  version_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  redeemed_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (document_id, version_id)
    REFERENCES document_versions (document_id, id)
);

CREATE INDEX download_tokens_subject_idx
  ON download_tokens (user_id, document_id, expires_at);

CREATE TABLE ai_suggestions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES documents(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 100),
  input_metadata_hash bytea NOT NULL CHECK (octet_length(input_metadata_hash) = 32),
  suggestions jsonb NOT NULL CHECK (jsonb_typeof(suggestions) = 'array'),
  created_at timestamptz NOT NULL DEFAULT now(),
  decision text CHECK (decision IS NULL OR decision IN ('accepted', 'rejected', 'modified')),
  decided_by uuid REFERENCES users(id),
  decided_at timestamptz,
  CHECK (
    (decision IS NULL AND decided_by IS NULL AND decided_at IS NULL) OR
    (decision IS NOT NULL AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
  )
);

CREATE INDEX ai_suggestions_document_idx ON ai_suggestions (document_id, created_at);

CREATE TABLE audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_id uuid REFERENCES users(id),
  actor_role text CHECK (actor_role IS NULL OR actor_role IN ('admin', 'owner', 'viewer')),
  ip_address inet,
  user_agent text CHECK (user_agent IS NULL OR length(user_agent) <= 1024),
  document_id uuid REFERENCES documents(id),
  action text NOT NULL CHECK (action ~ '^[a-z0-9_.-]{1,100}$'),
  outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied')),
  reason text NOT NULL CHECK (reason ~ '^[a-z0-9_.-]{1,100}$'),
  request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200),
  prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
  row_hash bytea NOT NULL CHECK (octet_length(row_hash) = 32)
);

CREATE INDEX audit_log_occurred_idx ON audit_log (occurred_at, id);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_id);
CREATE INDEX audit_log_document_idx ON audit_log (document_id);
CREATE INDEX audit_log_action_outcome_idx ON audit_log (action, outcome);

CREATE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_audit_mutation() FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO trustvault_app;
GRANT SELECT, INSERT, UPDATE ON users TO trustvault_app;
GRANT SELECT, INSERT ON sessions TO trustvault_app;
GRANT SELECT, INSERT ON folders TO trustvault_app;
GRANT SELECT, INSERT ON documents TO trustvault_app;
GRANT SELECT, INSERT ON document_versions TO trustvault_app;
GRANT SELECT, INSERT ON document_grants TO trustvault_app;
GRANT SELECT, INSERT ON groups TO trustvault_app;
GRANT SELECT, INSERT ON group_members TO trustvault_app;
GRANT SELECT, INSERT ON download_tokens TO trustvault_app;
GRANT SELECT, INSERT ON ai_suggestions TO trustvault_app;
GRANT SELECT, INSERT ON audit_log TO trustvault_app;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO trustvault_app;
