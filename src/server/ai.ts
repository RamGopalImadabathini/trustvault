export interface SuggestionMetadata {
  title: string;
  description: string | null;
  category: string | null;
  ownerName: string;
}

export interface SuggestionCandidate {
  userId: string;
  displayName: string;
  role: "owner" | "viewer" | "admin";
}

export interface AiSuggestionProvider {
  name: string;
  suggest(input: {
    metadata: SuggestionMetadata;
    candidates: readonly SuggestionCandidate[];
  }): Promise<unknown>;
}

export interface ValidatedSuggestion {
  userId: string;
  reason: string;
}

export function validateSuggestions(
  output: unknown,
  candidates: readonly SuggestionCandidate[]
): ValidatedSuggestion[] {
  if (!Array.isArray(output) || output.length > 20) {
    throw new Error("Suggestion provider returned an invalid response.");
  }

  const allowedUsers = new Set(candidates.map((candidate) => candidate.userId));
  const seenUsers = new Set<string>();
  const suggestions: ValidatedSuggestion[] = [];
  for (const item of output) {
    if (
      typeof item !== "object" ||
      item === null ||
      !("userId" in item) ||
      !("reason" in item) ||
      typeof item.userId !== "string" ||
      typeof item.reason !== "string" ||
      item.reason.length > 240 ||
      Object.keys(item).some((key) => key !== "userId" && key !== "reason")
    ) {
      throw new Error("Suggestion provider returned an invalid response.");
    }
    if (!allowedUsers.has(item.userId) || seenUsers.has(item.userId)) {
      continue;
    }
    seenUsers.add(item.userId);
    suggestions.push({ userId: item.userId, reason: item.reason });
    if (suggestions.length === 5) {
      break;
    }
  }
  return suggestions;
}

export function deterministicSuggestions(
  candidates: readonly SuggestionCandidate[]
): ValidatedSuggestion[] {
  return candidates
    .filter((candidate) => candidate.role === "viewer")
    .slice(0, 3)
    .map((candidate) => ({
      userId: candidate.userId,
      reason: "Active viewer suggested for owner review."
    }));
}
