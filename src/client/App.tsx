import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import "./style.css";
import {
  createDocumentSearchParams,
  documentActionVisibility
} from "./document-controls.js";

interface User {
  id: string;
  role: "admin" | "owner" | "viewer";
  csrfToken: string;
}

interface DocumentRecord {
  id: string;
  title: string;
  description: string | null;
  category: string | null;
  owner_name: string;
  can_edit: boolean;
  can_manage: boolean;
  can_restore: boolean;
  created_at: string;
  deleted_at: string | null;
}

interface Grant {
  user_id: string;
  display_name: string;
  email: string;
  level: "read" | "edit" | "manage";
}

interface Folder {
  id: string;
  name: string;
}

interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_name: string | null;
  action: string;
  outcome: "allowed" | "denied";
  reason: string;
  document_title: string | null;
}

interface GrantTarget {
  id: string;
  display_name: string;
  email: string;
}

interface AiSuggestion {
  userId: string;
  displayName: string;
  reason: string;
}

async function request<T>(
  url: string,
  options: RequestInit = {},
  csrfToken?: string
): Promise<T> {
  const headers = new Headers(options.headers);
  if (csrfToken) headers.set("x-csrf-token", csrfToken);
  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "same-origin"
  });
  const contentType = response.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const message =
      typeof body === "object" && body && "error" in body
        ? String(body.error)
        : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return body as T;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [anomalies, setAnomalies] = useState<{ type: string; count: number }[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [category, setCategory] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [editingDocument, setEditingDocument] = useState<string | null>(null);
  const [selectedDocument, setSelectedDocument] = useState<string | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [targets, setTargets] = useState<GrantTarget[]>([]);
  const [grantUser, setGrantUser] = useState("");
  const [grantLevel, setGrantLevel] = useState<"read" | "edit" | "manage">("read");
  const [aiSuggestion, setAiSuggestion] = useState<{
    documentId: string;
    suggestionId: string;
    suggestions: AiSuggestion[];
  } | null>(null);
  const [chainStatus, setChainStatus] = useState("");

  const loadWorkspace = useCallback(async (currentUser: User) => {
    const [documentBody, folderBody] = await Promise.all([
      request<{ documents: DocumentRecord[] }>("/api/documents"),
      request<{ folders: Folder[] }>("/api/folders")
    ]);
    setDocuments(documentBody.documents);
    setFolders(folderBody.folders);
    if (currentUser.role === "admin") {
      const [auditBody, anomalyBody] = await Promise.all([
        request<{ events: AuditEvent[] }>("/api/admin/audit"),
        request<{ anomalies: { type: string; count: number }[] }>("/api/admin/anomalies")
      ]);
      setEvents(auditBody.events);
      setAnomalies(anomalyBody.anomalies);
    }
  }, []);

  const loadDocuments = useCallback(async () => {
    const params = createDocumentSearchParams({
      query,
      name,
      owner,
      category,
      from,
      to,
      includeDeleted
    });
    const search = params.toString();
    const suffix = search ? `?${search}` : "";
    const body = await request<{ documents: DocumentRecord[] }>(`/api/documents${suffix}`);
    setDocuments(body.documents);
  }, [category, from, includeDeleted, name, owner, query, to]);

  useEffect(() => {
    void (async () => {
      try {
        const response = await fetch("/api/auth/me", { credentials: "same-origin" });
        if (response.status === 401) {
          setUser(null);
          return;
        }
        if (!response.ok) {
          throw new Error(`Could not load session (${response.status})`);
        }
        const body = (await response.json()) as User;
        setUser(body);
        await loadWorkspace(body);
      } catch (caught) {
        setUser(null);
        setError(caught instanceof Error ? caught.message : "Could not load workspace");
      }
    })();
  }, [loadWorkspace]);

  async function run(action: () => Promise<void>) {
    setError("");
    setMessage("");
    try {
      await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed");
    }
  }

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await run(async () => {
      await request("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: String(form.get("email")),
          password: String(form.get("password"))
        })
      });
      const current = await request<User>("/api/auth/me");
      setUser(current);
      await loadWorkspace(current);
    });
  }

  async function logout() {
    if (!user) return;
    await run(async () => {
      await request("/api/auth/logout", { method: "POST" }, user.csrfToken);
      setUser(null);
      setDocuments([]);
      setEvents([]);
    });
  }

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    await run(async () => {
      await request("/api/documents", { method: "POST", body: form }, user.csrfToken);
      formElement.reset();
      await loadDocuments();
      setMessage("Upload completed.");
    });
  }

  async function saveMetadata(
    event: FormEvent<HTMLFormElement>,
    documentId: string
  ) {
    event.preventDefault();
    if (!user) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    await run(async () => {
      await request(
        `/api/documents/${documentId}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            title: String(form.get("title")),
            category: String(form.get("category")) || null
          })
        },
        user.csrfToken
      );
      setEditingDocument(null);
      await loadDocuments();
      setMessage("Document details updated.");
    });
  }

  async function uploadVersion(
    event: FormEvent<HTMLFormElement>,
    documentId: string
  ) {
    event.preventDefault();
    if (!user) return;
    const formElement = event.currentTarget;
    await run(async () => {
      await request(
        `/api/documents/${documentId}/versions`,
        { method: "POST", body: new FormData(formElement) },
        user.csrfToken
      );
      formElement.reset();
      await loadDocuments();
      setMessage("New version uploaded.");
    });
  }

  async function deleteDocument(documentId: string) {
    if (!user || !window.confirm("Delete this document?")) return;
    await run(async () => {
      await request(`/api/documents/${documentId}`, { method: "DELETE" }, user.csrfToken);
      await loadDocuments();
      setMessage("Document deleted.");
    });
  }

  async function restoreDocument(documentId: string) {
    if (!user) return;
    await run(async () => {
      await request(
        `/api/documents/${documentId}/restore`,
        { method: "POST" },
        user.csrfToken
      );
      await loadDocuments();
      setMessage("Document restored.");
    });
  }

  async function openSharing(documentId: string) {
    if (!user) return;
    await run(async () => {
      const [grantBody, targetBody] = await Promise.all([
        request<{ grants: Grant[] }>(`/api/documents/${documentId}/grants`),
        request<{ users: GrantTarget[] }>(`/api/documents/${documentId}/grant-targets`)
      ]);
      setSelectedDocument(documentId);
      setGrants(grantBody.grants);
      setTargets(targetBody.users);
    });
  }

  async function addGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user || !selectedDocument) return;
    await run(async () => {
      await request(
        `/api/documents/${selectedDocument}/grants`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ userId: grantUser, level: grantLevel })
        },
        user.csrfToken
      );
      await openSharing(selectedDocument);
      setMessage("Grant created.");
    });
  }

  async function revokeGrant(userId: string) {
    if (!user || !selectedDocument) return;
    await run(async () => {
      await request(
        `/api/documents/${selectedDocument}/grants/${userId}`,
        { method: "DELETE" },
        user.csrfToken
      );
      await openSharing(selectedDocument);
      setMessage("Grant revoked.");
    });
  }

  async function suggest(documentId: string) {
    if (!user) return;
    await run(async () => {
      const result = await request<{
        id: string;
        suggestions: AiSuggestion[];
      }>(
        `/api/documents/${documentId}/ai-suggestions`,
        { method: "POST" },
        user.csrfToken
      );
      setAiSuggestion({
        documentId,
        suggestionId: result.id,
        suggestions: result.suggestions
      });
      if (result.suggestions.length === 0) setMessage("No eligible suggestions.");
    });
  }

  async function decideSuggestion(decision: "accepted" | "rejected") {
    if (!user || !aiSuggestion) return;
    await run(async () => {
      await request(
        `/api/documents/${aiSuggestion.documentId}/ai-suggestions/${aiSuggestion.suggestionId}/decision`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ decision })
        },
        user.csrfToken
      );
      setAiSuggestion(null);
      setMessage(
        `Suggestion ${decision}. No grant was created; use Share to make any approved access change.`
      );
    });
  }

  async function verifyChain() {
    await run(async () => {
      const result = await request<{ valid: boolean; checked: number }>(
        "/api/admin/audit/verify"
      );
      setChainStatus(
        result.valid
          ? `Valid (${result.checked} audit rows checked)`
          : `INVALID (${result.checked} audit rows checked)`
      );
    });
  }

  async function createFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!user) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    await run(async () => {
      await request(
        "/api/folders",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ name: form.get("name") })
        },
        user.csrfToken
      );
      const body = await request<{ folders: Folder[] }>("/api/folders");
      setFolders(body.folders);
      formElement.reset();
    });
  }

  if (!user) {
    return (
      <main className="shell">
        <header className="brand"><span className="brand-mark">TV</span><div><h1>TrustVault</h1><p>Private document sharing</p></div></header>
        {error && <p className="alert" role="alert">{error}</p>}
        <form className="panel login" onSubmit={(event) => void login(event)}>
          <h2>Sign in</h2>
          <label>Email<input name="email" type="email" autoComplete="username" required /></label>
          <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
          <button type="submit">Sign in</button>
        </form>
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark">TV</span><div><h1>TrustVault</h1><p>{user.role} workspace</p></div></div>
        <button className="secondary" onClick={() => void logout()}>Sign out</button>
      </header>
      {error && <p className="alert" role="alert">{error}</p>}
      {message && <p className="notice" role="status">{message}</p>}
      {aiSuggestion && (
        <section className="panel suggestion-panel" aria-live="polite">
          <div className="section-heading">
            <div><h2>Suggested viewers</h2><p>Review only. Confirming does not create a grant.</p></div>
          </div>
          {aiSuggestion.suggestions.length === 0 ? <p className="empty">No eligible suggestions.</p> : (
            <ul className="grant-list">{aiSuggestion.suggestions.map((suggestion) => (
              <li key={suggestion.userId}><span>{suggestion.displayName} · {suggestion.reason}</span></li>
            ))}</ul>
          )}
          <div className="actions">
            <button className="secondary" onClick={() => void decideSuggestion("rejected")}>Reject suggestions</button>
            <button onClick={() => void decideSuggestion("accepted")}>Confirm for separate sharing</button>
          </div>
        </section>
      )}
      <section className="panel">
        <div className="section-heading"><div><h2>Documents</h2><p>Only documents currently available to your account appear here.</p></div></div>
        <form className="filters" onSubmit={(event) => { event.preventDefault(); void run(loadDocuments); }}>
          <label>Search<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Any text" /></label>
          <label>Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Document name" /></label>
          <label>Owner<input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Owner name" /></label>
          <label>Category<input value={category} onChange={(event) => setCategory(event.target.value)} placeholder="Any category" /></label>
          <label>From<input type="date" value={from} onChange={(event) => setFrom(event.target.value)} /></label>
          <label>To<input type="date" value={to} onChange={(event) => setTo(event.target.value)} /></label>
          <label className="checkbox-filter"><input type="checkbox" checked={includeDeleted} onChange={(event) => setIncludeDeleted(event.target.checked)} />Include deleted</label>
          <button type="submit">Search</button>
        </form>
        {documents.length === 0 ? <p className="empty">No accessible documents found.</p> : (
          <div className="document-list">
            {documents.map((document) => (
              <article className="document" key={document.id}>
                <div><h3>{document.title}</h3><p>{document.category || "Uncategorised"} · {document.owner_name} · {new Date(document.created_at).toLocaleDateString()}</p></div>
                <div className="actions">
                  {!document.deleted_at && <a className="button-link" href={`/api/documents/${document.id}/download`}>Download</a>}
                  {documentActionVisibility(document).edit && <button className="secondary" onClick={() => setEditingDocument(editingDocument === document.id ? null : document.id)}>Edit</button>}
                  {documentActionVisibility(document).share && <button className="secondary" onClick={() => void openSharing(document.id)}>Share</button>}
                  {documentActionVisibility(document).suggest && <button className="secondary" onClick={() => void suggest(document.id)}>Suggest viewers</button>}
                  {documentActionVisibility(document).delete && !document.deleted_at && <button className="text-button" onClick={() => void deleteDocument(document.id)}>Delete</button>}
                  {documentActionVisibility(document).restore && <button className="secondary" onClick={() => void restoreDocument(document.id)}>Restore</button>}
                </div>
                {editingDocument === document.id && documentActionVisibility(document).edit && (
                  <div className="document-editor">
                    <form className="inline-form" onSubmit={(event) => void saveMetadata(event, document.id)}>
                      <label>Title<input name="title" defaultValue={document.title} maxLength={500} required /></label>
                      <label>Category<input name="category" defaultValue={document.category ?? ""} maxLength={100} /></label>
                      <button type="submit">Save details</button>
                    </form>
                    <form className="inline-form" onSubmit={(event) => void uploadVersion(event, document.id)}>
                      <label>New version<input name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt" required /></label>
                      <button type="submit">Upload version</button>
                    </form>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
      {user.role === "owner" && (
        <div className="columns">
          <section className="panel">
            <h2>Upload a document</h2>
            <p>Upload scanning is fail-closed. If no scanner is configured, the server will refuse the upload.</p>
            <form className="stack" onSubmit={(event) => void upload(event)}>
              <label>Title<input name="title" maxLength={500} required /></label>
              <label>Category<input name="category" maxLength={100} /></label>
              <label>Folder<select name="folderId" defaultValue=""><option value="">No folder</option>{folders.map((folder) => <option value={folder.id} key={folder.id}>{folder.name}</option>)}</select></label>
              <label>File<input name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt" required /></label>
              <button type="submit">Upload</button>
            </form>
          </section>
          <section className="panel">
            <h2>Folders</h2>
            <p>Folders organize documents; they never grant access.</p>
            <ul className="folder-list">{folders.map((folder) => <li key={folder.id}>{folder.name}</li>)}</ul>
            <form className="inline-form" onSubmit={(event) => void createFolder(event)}>
              <label className="visually-hidden" htmlFor="folder-name">New folder name</label>
              <input id="folder-name" name="name" placeholder="New folder" maxLength={200} required />
              <button type="submit">Add</button>
            </form>
          </section>
        </div>
      )}
      {selectedDocument && (
        <div className="modal-backdrop" role="presentation" onClick={() => setSelectedDocument(null)}>
          <section className="panel modal" role="dialog" aria-modal="true" aria-labelledby="sharing-title" onClick={(event) => event.stopPropagation()}>
            <div className="section-heading"><h2 id="sharing-title">Manage access</h2><button className="secondary" onClick={() => setSelectedDocument(null)}>Close</button></div>
            <form className="inline-form" onSubmit={(event) => void addGrant(event)}>
              <label className="visually-hidden" htmlFor="grant-user">User</label>
              <select id="grant-user" value={grantUser} onChange={(event) => setGrantUser(event.target.value)} required>
                <option value="">Choose user</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.display_name} ({target.email})</option>)}
              </select>
              <label className="visually-hidden" htmlFor="grant-level">Permission</label>
              <select id="grant-level" value={grantLevel} onChange={(event) => setGrantLevel(event.target.value as typeof grantLevel)}>
                <option value="read">Read</option><option value="edit">Edit</option><option value="manage">Manage</option>
              </select>
              <button type="submit">Grant</button>
            </form>
            <ul className="grant-list">{grants.map((grant) => (
              <li key={grant.user_id}><span>{grant.display_name} · {grant.level}</span><button className="text-button" onClick={() => void revokeGrant(grant.user_id)}>Revoke</button></li>
            ))}</ul>
          </section>
        </div>
      )}
      {user.role === "admin" && (
        <section className="panel admin-panel">
          <div className="section-heading"><div><h2>Audit and activity</h2><p>Document titles are shown only when you have an explicit metadata grant.</p></div></div>
          <div className="verify-row">
            <button className="secondary" onClick={() => void verifyChain()}>Verify audit chain</button>
            {chainStatus && <span role="status">{chainStatus}</span>}
          </div>
          <h3>Anomaly flags</h3>
          {anomalies.length ? <ul className="anomaly-list">{anomalies.map((item) => <li key={item.type}>{item.type.replaceAll("_", " ")} <strong>{item.count}</strong></li>)}</ul> : <p className="empty">No current anomaly flags.</p>}
          <h3>Recent events</h3>
          <div className="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Document</th></tr></thead>
            <tbody>{events.map((event) => <tr key={event.id}><td>{new Date(event.occurred_at).toLocaleString()}</td><td>{event.actor_name ?? "System"}</td><td>{event.action}</td><td><span className={`badge ${event.outcome}`}>{event.outcome}</span></td><td>{event.document_title ?? "Restricted"}</td></tr>)}</tbody>
          </table></div>
        </section>
      )}
    </main>
  );
}
