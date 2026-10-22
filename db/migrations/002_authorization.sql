CREATE FUNCTION trustvault_authorize(
  requested_actor uuid,
  requested_document uuid,
  requested_action text
) RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $$
DECLARE
  actor_role text;
  document_owner uuid;
  document_deleted timestamptz;
  grant_level text;
  required_level integer;
BEGIN
  IF requested_action = 'auth.login' OR requested_action = 'system.health' THEN
    RETURN true;
  END IF;

  IF requested_actor IS NULL THEN
    RETURN false;
  END IF;

  SELECT role INTO actor_role FROM users
  WHERE id = requested_actor AND is_active = true;
  IF actor_role IS NULL THEN
    RETURN false;
  END IF;

  IF requested_action IN ('auth.me', 'auth.logout') THEN
    RETURN true;
  ELSIF requested_action = 'document.create' THEN
    RETURN actor_role = 'owner';
  ELSIF requested_action = 'admin.users.manage' THEN
    RETURN actor_role = 'admin';
  ELSIF requested_action = 'document.search' THEN
    RETURN true;
  END IF;

  IF requested_document IS NULL THEN
    RETURN false;
  END IF;

  SELECT owner_id, deleted_at
  INTO document_owner, document_deleted
  FROM documents
  WHERE id = requested_document;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  IF document_deleted IS NOT NULL AND requested_action <> 'document.restore' THEN
    RETURN false;
  END IF;

  IF document_owner = requested_actor THEN
    RETURN requested_action IN (
      'document.read_metadata',
      'document.edit_metadata',
      'document.delete',
      'document.restore',
      'document.grant',
      'document.revoke',
      'document.grants.read',
      'document.versions.read',
      'document.version.create',
      'document.download',
      'document.download.issue'
    );
  END IF;

  SELECT level INTO grant_level
  FROM document_grants
  WHERE document_id = requested_document
    AND user_id = requested_actor
    AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > transaction_timestamp());

  required_level := CASE requested_action
    WHEN 'document.read_metadata' THEN 1
    WHEN 'document.versions.read' THEN 1
    WHEN 'document.download' THEN 1
    WHEN 'document.download.issue' THEN 1
    WHEN 'document.edit_metadata' THEN 2
    WHEN 'document.version.create' THEN 2
    WHEN 'document.delete' THEN 3
    WHEN 'document.restore' THEN 3
    WHEN 'document.grant' THEN 3
    WHEN 'document.revoke' THEN 3
    WHEN 'document.grants.read' THEN 3
    ELSE NULL
  END;

  RETURN CASE grant_level
    WHEN 'read' THEN required_level = 1
    WHEN 'edit' THEN required_level BETWEEN 1 AND 2
    WHEN 'manage' THEN required_level BETWEEN 1 AND 3
    ELSE false
  END;
END;
$$;

REVOKE ALL ON FUNCTION trustvault_authorize(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION trustvault_authorize(uuid, uuid, text) TO trustvault_app;

GRANT SELECT, INSERT, UPDATE ON
  users,
  sessions,
  folders,
  documents,
  document_versions,
  document_grants,
  groups,
  group_members,
  download_tokens,
  ai_suggestions
TO trustvault_app;
GRANT SELECT, INSERT ON audit_log TO trustvault_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE audit_log_id_seq TO trustvault_app;
