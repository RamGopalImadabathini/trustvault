import "dotenv/config";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

const baseUrl = requiredEnv("TRUSTVAULT_BASE_URL").replace(/\/+$/, "");
const ownerEmail = requiredEnv("TRUSTVAULT_OWNER_EMAIL");
const ownerPassword = requiredEnv("TRUSTVAULT_OWNER_PASSWORD");
const viewerEmail = requiredEnv("TRUSTVAULT_VIEWER_EMAIL");
const viewerPassword = requiredEnv("TRUSTVAULT_VIEWER_PASSWORD");
const adminEmail = requiredEnv("TRUSTVAULT_ADMIN_EMAIL");
const adminPassword = requiredEnv("TRUSTVAULT_ADMIN_PASSWORD");
const documentId = process.env.TRUSTVAULT_DOCUMENT_ID;
const uploadPath = process.env.TRUSTVAULT_SMOKE_FILE;

interface Login {
  cookie: string;
  csrfToken: string;
  userId: string;
}

async function main(): Promise<void> {
  const owner = await login(ownerEmail, ownerPassword);
  const viewer = await login(viewerEmail, viewerPassword);
  const admin = await login(adminEmail, adminPassword);
  let targetDocumentId = documentId;

  if (!targetDocumentId && !uploadPath) {
    const search = await api("/api/search", {
      headers: { cookie: owner.cookie }
    });
    requireStatus("owner document search", search, 200);
    targetDocumentId = (search.body as { results?: { id: string }[] }).results?.[0]
      ?.id;
  }

  if (uploadPath) {
    const form = new FormData();
    form.set("title", `Smoke test ${randomUUID()}`);
    form.set(
      "file",
      new Blob([await readFile(uploadPath)], { type: "application/pdf" }),
      "smoke-test.pdf"
    );
    const uploaded = await api("/api/documents", {
      method: "POST",
      headers: csrfHeader(owner),
      body: form
    });
    requireStatus("upload", uploaded, 201);
    targetDocumentId = (uploaded.body as { id: string }).id;
    console.info("upload: passed");
  }

  if (!targetDocumentId) {
    throw new Error(
      "No owner-accessible document was found. Seed a demo document, set TRUSTVAULT_DOCUMENT_ID, or set TRUSTVAULT_SMOKE_FILE to a PDF. Upload requires a configured malware scanner."
    );
  }

  const priorRevoke = await api(
    `/api/documents/${targetDocumentId}/grants/${viewer.userId}`,
    {
      method: "DELETE",
      headers: csrfHeader(owner)
    }
  );
  if (priorRevoke.status !== 200 && priorRevoke.status !== 404) {
    requireStatus("clear prior test grant", priorRevoke, 404);
  }

  const grant = await api(`/api/documents/${targetDocumentId}/grants`, {
    method: "POST",
    headers: {
      ...csrfHeader(owner),
      "content-type": "application/json"
    },
    body: JSON.stringify({ userId: viewer.userId, level: "read" })
  });
  requireStatus("grant", grant, 201);

  const tokenOne = await issueToken(targetDocumentId, viewer);
  const tokenTwo = await issueToken(targetDocumentId, viewer);
  const downloaded = await api(`/api/downloads/${tokenOne}`, {
    headers: { cookie: viewer.cookie }
  });
  requireStatus("download", downloaded, 200);
  const revoked = await api(
    `/api/documents/${targetDocumentId}/grants/${viewer.userId}`,
    { method: "DELETE", headers: csrfHeader(owner) }
  );
  requireStatus("revoke", revoked, 200);
  const afterRevoke = await api(`/api/downloads/${tokenTwo}`, {
    headers: { cookie: viewer.cookie }
  });
  requireStatus("download after revoke", afterRevoke, 404);

  const chain = await api("/api/admin/audit/verify", {
    headers: { cookie: admin.cookie }
  });
  requireStatus("verify-chain endpoint", chain, 200);
  if (!(chain.body as { valid?: boolean }).valid) {
    throw new Error("Audit chain verification failed.");
  }

  console.info("login(owner/viewer/admin): passed");
  console.info("grant: passed");
  console.info("download: passed");
  console.info("revoke: passed");
  console.info("download after revoke: denied as expected");
  console.info("verify-chain: passed");
}

async function login(email: string, password: string): Promise<Login> {
  const result = await api("/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  requireStatus(`login for ${email}`, result, 200);
  const cookieHeader = result.headers.get("set-cookie");
  const cookie = cookieHeader?.split(";")[0];
  if (!cookie) {
    throw new Error("Login response did not provide a session cookie.");
  }
  const me = await api("/api/auth/me", { headers: { cookie } });
  requireStatus(`session lookup for ${email}`, me, 200);
  const body = me.body as { id: string; csrfToken: string };
  return { cookie, csrfToken: body.csrfToken, userId: body.id };
}

async function issueToken(documentId: string, viewer: Login): Promise<string> {
  const result = await api(`/api/documents/${documentId}/download-tokens`, {
    method: "POST",
    headers: csrfHeader(viewer)
  });
  requireStatus("download-token issue", result, 201);
  return (result.body as { token: string }).token;
}

function csrfHeader(login: Login): Record<string, string> {
  return {
    cookie: login.cookie,
    "x-csrf-token": login.csrfToken
  };
}

async function api(
  route: string,
  init: RequestInit = {}
): Promise<{ status: number; headers: Headers; body: unknown }> {
  const response = await fetch(`${baseUrl}${route}`, {
    ...init,
    headers: new Headers(init.headers),
    redirect: "error"
  });
  const contentType = response.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.arrayBuffer();
  return { status: response.status, headers: response.headers, body };
}

function requireStatus(
  step: string,
  response: { status: number; body: unknown },
  expected: number
): void {
  if (response.status !== expected) {
    const error =
      typeof response.body === "object" &&
      response.body !== null &&
      "error" in response.body
        ? String(response.body.error)
        : "";
    throw new Error(
      `${step} expected HTTP ${expected}, received ${response.status}${error ? `: ${error}` : ""}`
    );
  }
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

void main().catch((error: unknown) => {
  console.error(
    "TrustVault smoke test failed:",
    error instanceof Error ? error.message : "Unknown error."
  );
  process.exitCode = 1;
});
