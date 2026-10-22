import type { PoolClient } from "pg";

export const AUTHZ_ACTIONS = [
  "system.health",
  "system.not_found",
  "system.request_error",
  "auth.login",
  "auth.me",
  "auth.logout",
  "document.create",
  "document.read_metadata",
  "document.edit_metadata",
  "document.delete",
  "document.restore",
  "document.grant",
  "document.revoke",
  "document.grants.read",
  "document.versions.read",
  "document.version.create",
  "document.download",
  "document.download.issue",
  "document.search",
  "admin.users.manage",
  "admin.audit.read",
  "admin.audit.verify",
  "admin.anomalies.read",
  "folder.list",
  "folder.create",
  "folder.manage",
  "document.version.read",
  "document.ai.suggest",
  "document.ai.decide",
  "document.grant.targets"
] as const;

export type AuthzAction = (typeof AUTHZ_ACTIONS)[number];

export interface Actor {
  id: string;
  role: "admin" | "owner" | "viewer";
  csrfSecret: Buffer;
  sessionId: string;
}

export async function authorize(
  client: PoolClient,
  actor: Actor | null,
  documentId: string | null,
  action: AuthzAction
): Promise<boolean> {
  const result = await client.query<{ allowed: boolean }>(
    "SELECT trustvault_authorize($1::uuid, $2::uuid, $3::text) AS allowed",
    [actor?.id ?? null, documentId, action]
  );
  return result.rows[0]?.allowed === true;
}

export function validateRouteRegistry(
  routes: readonly {
    method: string;
    url: string;
    config?: { authzAction?: string };
  }[]
): void {
  const allowedActions = new Set<string>(AUTHZ_ACTIONS);
  const missing = routes
    .filter(
      (route) =>
        !route.config?.authzAction ||
        !allowedActions.has(route.config.authzAction)
    )
    .map((route) => `${route.method} ${route.url}`);

  if (missing.length > 0) {
    throw new Error(
      `Routes missing a valid authorization declaration: ${missing.join(", ")}`
    );
  }
}
