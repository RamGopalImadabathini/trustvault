// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/client/App.js";

const owner = {
  id: "owner-id",
  role: "owner" as const,
  csrfToken: "csrf-token"
};

function makeDocument(overrides: Record<string, unknown> = {}) {
  return {
    id: "document-id",
    title: "Private report",
    description: null,
    category: "finance",
    owner_name: "Owner One",
    can_edit: false,
    can_manage: false,
    can_restore: false,
    created_at: "2026-01-15T00:00:00.000Z",
    deleted_at: null,
    ...overrides
  };
}

function mockWorkspace(
  documents: ReturnType<typeof makeDocument>[],
  role: "owner" | "viewer" = "owner"
) {
  const fetchMock = vi.fn(async (...request: [RequestInfo | URL, RequestInit?]) => {
    const input = request[0];
    const url = String(input);
    const body =
      url === "/api/auth/me"
        ? { ...owner, role }
        : url.startsWith("/api/documents")
          ? { documents }
          : { folders: [] };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("document workspace UI", () => {
  it("provides name, owner, category and date filters to the documents API", async () => {
    const fetchMock = mockWorkspace([]);
    render(<App />);
    await screen.findByRole("heading", { name: "Documents" });

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "report" } });
    fireEvent.change(screen.getByLabelText("Owner"), { target: { value: "Owner One" } });
    const searchForm = screen.getByRole("button", { name: "Search" }).closest("form");
    if (!searchForm) throw new Error("Search form was not rendered.");
    fireEvent.change(within(searchForm).getByLabelText("Category"), { target: { value: "finance" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-01-01" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-01-31" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => {
        const url = new URL(String(input), "http://localhost");
        return url.pathname === "/api/documents" &&
          url.searchParams.get("name") === "report" &&
          url.searchParams.get("owner") === "Owner One" &&
          url.searchParams.get("category") === "finance" &&
          url.searchParams.get("from") === "2026-01-01" &&
          url.searchParams.get("to") === "2026-01-31";
      })).toBe(true);
    });
  });

  it("shows editing and new-version controls only when the API reports edit permission", async () => {
    const fetchMock = mockWorkspace([makeDocument({ can_edit: true })]);
    render(<App />);
    await screen.findByRole("heading", { name: "Private report" });
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    expect(screen.getByRole("button", { name: "Save details" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Upload version" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();

    const card = screen.getByRole("heading", { name: "Private report" }).closest("article");
    if (!card) throw new Error("Document card was not rendered.");
    fireEvent.change(within(card).getByLabelText("Title"), {
      target: { value: "Renamed report" }
    });
    fireEvent.change(within(card).getByLabelText("Category"), {
      target: { value: "legal" }
    });
    fireEvent.click(within(card).getByRole("button", { name: "Save details" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input) === "/api/documents/document-id" && init?.method === "PATCH"
      );
      expect(patch).toBeDefined();
      expect(JSON.parse(String(patch?.[1]?.body))).toEqual({
        title: "Renamed report",
        category: "legal"
      });
      expect(new Headers(patch?.[1]?.headers).get("x-csrf-token")).toBe("csrf-token");
    });

    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const refreshedCard = screen.getByRole("heading", { name: "Private report" }).closest("article");
    if (!refreshedCard) throw new Error("Refreshed document card was not rendered.");
    const versionFile = new File(["new version"], "new.txt", { type: "text/plain" });
    fireEvent.change(within(refreshedCard).getByLabelText("New version"), {
      target: { files: [versionFile] }
    });
    const versionForm = within(refreshedCard)
      .getByRole("button", { name: "Upload version" })
      .closest("form");
    if (!versionForm) throw new Error("Version form was not rendered.");
    fireEvent.submit(versionForm);
    await waitFor(() => {
      const versionRequest = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input) === "/api/documents/document-id/versions" &&
          init?.method === "POST"
      );
      expect(versionRequest).toBeDefined();
      expect(new Headers(versionRequest?.[1]?.headers).get("x-csrf-token")).toBe(
        "csrf-token"
      );
    });
  });

  it("hides edit and management controls from read-only viewers and offers restore only when allowed", async () => {
    const fetchMock = mockWorkspace([
      makeDocument(),
      makeDocument({
        id: "deleted-document",
        title: "Deleted report",
        can_restore: true,
        deleted_at: "2026-02-01T00:00:00.000Z"
      })
    ], "viewer");
    render(<App />);
    await screen.findByRole("heading", { name: "Private report" });

    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
    expect(screen.getByRole("button", { name: "Restore" })).toBeTruthy();
    const deletedCard = screen.getByRole("heading", { name: "Deleted report" }).closest("article");
    if (!deletedCard) throw new Error("Deleted document card was not rendered.");
    expect(within(deletedCard).queryByRole("link", { name: "Download" })).toBeNull();
    fireEvent.click(within(deletedCard).getByRole("button", { name: "Restore" }));
    await waitFor(() => {
      const restoreRequest = fetchMock.mock.calls.find(
        ([input, init]) =>
          String(input) === "/api/documents/deleted-document/restore" &&
          init?.method === "POST"
      );
      expect(restoreRequest).toBeDefined();
      expect(new Headers(restoreRequest?.[1]?.headers).get("x-csrf-token")).toBe(
        "csrf-token"
      );
    });
  });

  it("shows delete only to a manager", async () => {
    const fetchMock = mockWorkspace([makeDocument({ can_edit: true, can_manage: true })]);
    vi.stubGlobal("confirm", vi.fn(() => true));
    render(<App />);
    await screen.findByRole("heading", { name: "Private report" });
    expect(screen.getByRole("button", { name: "Delete" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Share" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input) === "/api/documents/document-id" &&
            init?.method === "DELETE"
        )
      ).toBe(true);
    });
  });
});
