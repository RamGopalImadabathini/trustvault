import { describe, expect, it } from "vitest";
import {
  createDocumentSearchParams,
  documentActionVisibility
} from "../src/client/document-controls.js";

describe("document controls", () => {
  it("sends every UI search filter to the authorized search API", () => {
    const params = createDocumentSearchParams({
      query: "annual",
      name: "report",
      owner: "Owner One",
      category: "finance",
      from: "2026-01-01",
      to: "2026-02-01",
      includeDeleted: true
    });

    expect(Object.fromEntries(params)).toEqual({
      q: "annual",
      name: "report",
      owner: "Owner One",
      category: "finance",
      from: "2026-01-01",
      to: "2026-02-01",
      includeDeleted: "true"
    });
  });

  it("shows edit actions for edit grants, management actions only for managers, and restore only when allowed", () => {
    expect(
      documentActionVisibility({
        can_edit: true,
        can_manage: false,
        can_restore: false
      })
    ).toEqual({
      edit: true,
      share: false,
      suggest: false,
      delete: false,
      restore: false
    });
    expect(
      documentActionVisibility({
        can_edit: false,
        can_manage: false,
        can_restore: false
      })
    ).toEqual({
      edit: false,
      share: false,
      suggest: false,
      delete: false,
      restore: false
    });
    expect(
      documentActionVisibility({
        can_edit: false,
        can_manage: false,
        can_restore: true
      }).restore
    ).toBe(true);
  });
});
