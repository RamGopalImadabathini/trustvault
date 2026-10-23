export interface DocumentSearchFilters {
  query: string;
  name: string;
  owner: string;
  category: string;
  from: string;
  to: string;
  includeDeleted: boolean;
}

export interface DocumentPermissions {
  can_edit: boolean;
  can_manage: boolean;
  can_restore: boolean;
}

export function createDocumentSearchParams(
  filters: DocumentSearchFilters
): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of ["query", "name", "owner", "category", "from", "to"] as const) {
    const value = filters[key].trim();
    if (value) {
      params.set(key === "query" ? "q" : key, value);
    }
  }
  if (filters.includeDeleted) {
    params.set("includeDeleted", "true");
  }
  return params;
}

export function documentActionVisibility(permissions: DocumentPermissions) {
  return {
    edit: permissions.can_edit,
    share: permissions.can_manage,
    suggest: permissions.can_manage,
    delete: permissions.can_manage,
    restore: permissions.can_restore
  };
}
