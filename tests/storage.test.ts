import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  decryptFromStorage,
  encryptAndStore,
  safeDownloadHeaders,
  sanitizeFilename,
  validateUpload
} from "../src/server/storage.js";

const tempDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

async function createTempDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "trustvault-storage-test-"));
  tempDirectories.push(directory);
  return directory;
}

describe("upload validation", () => {
  it("sanitizes traversal filenames and validates PDF magic bytes", () => {
    const upload = validateUpload(
      "..\\..\\private.pdf",
      "application/pdf",
      Buffer.from("%PDF-1.7\n", "ascii")
    );
    expect(upload.filename).toBe("private.pdf");
  });

  it("rejects MIME mismatches, invalid magic bytes, and ZIP archives", () => {
    expect(() =>
      validateUpload("payload.pdf", "application/pdf", Buffer.from("not pdf"))
    ).toThrowError("does not match");
    expect(() =>
      validateUpload("payload.zip", "application/zip", Buffer.from("PK\u0003\u0004"))
    ).toThrowError("not allowed");
  });

  it("rejects oversized files", () => {
    expect(() =>
      validateUpload("large.txt", "text/plain", Buffer.alloc(10 * 1024 * 1024 + 1, 65))
    ).toThrowError("size");
  });

  it("bounds and sanitizes displayed filenames", () => {
    expect(sanitizeFilename("folder/unsafe?.txt")).toBe("unsafe_.txt");
    expect(() => sanitizeFilename("")).toThrowError("Filename");
  });

  it("sets attachment and nosniff headers", () => {
    expect(safeDownloadHeaders("report.txt", "text/plain")).toEqual({
      "Content-Disposition":
        "attachment; filename=\"report.txt\"; filename*=UTF-8''report.txt",
      "Content-Type": "text/plain",
      "X-Content-Type-Options": "nosniff"
    });
  });
});

describe("encrypted storage", () => {
  it("stores ciphertext under a random key and decrypts only with the wrapping key", async () => {
    const directory = await createTempDirectory();
    const bytes = Buffer.from("%PDF-1.7 confidential", "ascii");
    const upload = validateUpload("private.pdf", "application/pdf", bytes);
    const encrypted = await encryptAndStore(directory, "m".repeat(40), upload);
    const stored = await readFile(path.join(directory, encrypted.storageKey));

    expect(encrypted.storageKey).not.toContain("private");
    expect(stored).not.toEqual(bytes);
    await expect(
      decryptFromStorage(directory, "m".repeat(40), encrypted)
    ).resolves.toEqual(bytes);
    await expect(
      decryptFromStorage(directory, "x".repeat(40), encrypted)
    ).rejects.toThrow();
  });

  it("rejects tampered ciphertext before returning plaintext", async () => {
    const directory = await createTempDirectory();
    const bytes = Buffer.from("%PDF-1.7 tamper test", "ascii");
    const upload = validateUpload("private.pdf", "application/pdf", bytes);
    const encrypted = await encryptAndStore(directory, "m".repeat(40), upload);
    const ciphertext = await readFile(path.join(directory, encrypted.storageKey));
    ciphertext[0] = ciphertext[0]! ^ 1;
    await writeFile(path.join(directory, encrypted.storageKey), ciphertext);

    await expect(
      decryptFromStorage(directory, "m".repeat(40), encrypted)
    ).rejects.toThrow();
  });
});
