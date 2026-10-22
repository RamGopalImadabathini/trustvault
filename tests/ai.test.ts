import { describe, expect, it } from "vitest";
import {
  deterministicSuggestions,
  validateSuggestions,
  type SuggestionCandidate
} from "../src/server/ai.js";

const candidates: SuggestionCandidate[] = [
  {
    userId: "active-viewer",
    displayName: "Active Viewer",
    role: "viewer"
  },
  {
    userId: "active-owner",
    displayName: "Active Owner",
    role: "owner"
  }
];

describe("AI suggestion validation", () => {
  it("accepts only unique suggestions for active candidates", () => {
    expect(
      validateSuggestions(
        [
          { userId: "active-viewer", reason: "Relevant team" },
          { userId: "inactive-user", reason: "Not eligible" },
          { userId: "active-viewer", reason: "Duplicate" },
          { userId: "active-owner", reason: "Relevant owner" }
        ],
        candidates
      )
    ).toEqual([
      { userId: "active-viewer", reason: "Relevant team" },
      { userId: "active-owner", reason: "Relevant owner" }
    ]);
  });

  it("rejects malformed provider responses and limits untrusted fields", () => {
    expect(() => validateSuggestions({ userId: "active-viewer" }, candidates)).toThrow(
      "invalid response"
    );
    expect(() =>
      validateSuggestions(
        [{ userId: "active-viewer", reason: "x".repeat(241) }],
        candidates
      )
    ).toThrow("invalid response");
    expect(() =>
      validateSuggestions(
        [{ userId: "active-viewer", reason: "reason", grantLevel: "manage" }],
        candidates
      )
    ).toThrow("invalid response");
    expect(() =>
      validateSuggestions(
        Array.from({ length: 21 }, (_, index) => ({
          userId: `user-${index}`,
          reason: "reason"
        })),
        candidates
      )
    ).toThrow("invalid response");
  });

  it("uses a deterministic viewer-only fallback", () => {
    expect(deterministicSuggestions(candidates)).toEqual([
      {
        userId: "active-viewer",
        reason: "Active viewer suggested for owner review."
      }
    ]);
  });
});
