import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync
} from "node:crypto";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const EXTENSION_MIME = new Map<string, string>([
  [".pdf", "application/pdf"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".txt", "text/plain"]
]);

export interface ValidatedUpload {
  filename: string;
  mimeType: string;
  bytes: Buffer;
  sha256: Buffer;
}

export interface EncryptedFile {
  storageKey: string;
  wrappedDataKey: Buffer;
  keyWrapNonce: Buffer;
  keyWrapAuthTag: Buffer;
  fileNonce: Buffer;
  fileAuthTag: Buffer;
  sha256: Buffer;
  sizeBytes: number;
}

export function validateUpload(
  filenameInput: string,
  declaredMime: string,
  bytes: Buffer
): ValidatedUpload {
  if (bytes.length === 0 || bytes.length > MAX_UPLOAD_BYTES) {
    throw new Error("File size is outside the accepted range.");
  }

  const filename = sanitizeFilename(filenameInput);
  const extension = path.extname(filename).toLowerCase();
  const expectedMime = EXTENSION_MIME.get(extension);
  if (!expectedMime || declaredMime.toLowerCase() !== expectedMime) {
    throw new Error("File type is not allowed.");
  }
  if (!matchesMagicBytes(expectedMime, bytes)) {
    throw new Error("File content does not match its declared type.");
  }
  if (expectedMime === "text/plain") {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new Error("Text files must contain valid UTF-8.");
    }
  }

  return {
    filename,
    mimeType: expectedMime,
    bytes,
    sha256: createHash("sha256").update(bytes).digest()
  };
}

export function sanitizeFilename(value: string): string {
  const withoutControls = [...value.normalize("NFKC")]
    .filter((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint > 0x1f && codePoint !== 0x7f;
    })
    .join("");
  const basename = path.win32.basename(withoutControls.replace(/\//g, "\\"));
  const safe = basename.replace(/[<>:"/\\|?*]/g, "_").trim();
  if (!safe || safe === "." || safe === ".." || safe.length > 180) {
    throw new Error("Filename is invalid.");
  }
  return safe;
}

function matchesMagicBytes(mimeType: string, bytes: Buffer): boolean {
  switch (mimeType) {
    case "application/pdf":
      return bytes.subarray(0, 5).toString("ascii") === "%PDF-";
    case "image/png":
      return bytes.subarray(0, 8).equals(
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
      );
    case "image/jpeg":
      return (
        bytes.length >= 3 &&
        bytes[0] === 0xff &&
        bytes[1] === 0xd8 &&
        bytes[2] === 0xff
      );
    case "text/plain":
      return !bytes.includes(0);
    default:
      return false;
  }
}

function masterWrappingKey(masterKey: string): Buffer {
  return scryptSync(masterKey, "trustvault-data-key-wrap-v1", 32);
}

export async function encryptAndStore(
  directory: string,
  masterKey: string,
  upload: ValidatedUpload
): Promise<EncryptedFile> {
  await mkdir(directory, { recursive: true });
  const dataKey = randomBytes(32);
  const fileNonce = randomBytes(12);
  const fileCipher = createCipheriv("aes-256-gcm", dataKey, fileNonce);
  const ciphertext = Buffer.concat([
    fileCipher.update(upload.bytes),
    fileCipher.final()
  ]);
  const fileAuthTag = fileCipher.getAuthTag();

  const keyWrapNonce = randomBytes(12);
  const keyCipher = createCipheriv(
    "aes-256-gcm",
    masterWrappingKey(masterKey),
    keyWrapNonce
  );
  const wrappedDataKey = Buffer.concat([
    keyCipher.update(dataKey),
    keyCipher.final()
  ]);
  const keyWrapAuthTag = keyCipher.getAuthTag();
  const storageKey = randomUUID();
  await writeFile(path.join(directory, storageKey), ciphertext, { flag: "wx" });

  return {
    storageKey,
    wrappedDataKey,
    keyWrapNonce,
    keyWrapAuthTag,
    fileNonce,
    fileAuthTag,
    sha256: upload.sha256,
    sizeBytes: upload.bytes.length
  };
}

export async function decryptFromStorage(
  directory: string,
  masterKey: string,
  file: EncryptedFile
): Promise<Buffer> {
  const ciphertext = await readFile(path.join(directory, file.storageKey));
  const keyDecipher = createDecipheriv(
    "aes-256-gcm",
    masterWrappingKey(masterKey),
    file.keyWrapNonce
  );
  keyDecipher.setAuthTag(file.keyWrapAuthTag);
  const dataKey = Buffer.concat([
    keyDecipher.update(file.wrappedDataKey),
    keyDecipher.final()
  ]);
  const decipher = createDecipheriv("aes-256-gcm", dataKey, file.fileNonce);
  decipher.setAuthTag(file.fileAuthTag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
  const digest = createHash("sha256").update(plaintext).digest();
  if (!digest.equals(file.sha256)) {
    throw new Error("Stored document integrity check failed.");
  }
  return plaintext;
}

export async function removeStoredFile(
  directory: string,
  storageKey: string
): Promise<void> {
  await unlink(path.join(directory, storageKey));
}

export function safeDownloadHeaders(filename: string, mimeType: string): {
  "Content-Disposition": string;
  "Content-Type": string;
  "X-Content-Type-Options": "nosniff";
} {
  const safeAscii = filename.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return {
    "Content-Disposition": `attachment; filename="${safeAscii}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
    "Content-Type": mimeType,
    "X-Content-Type-Options": "nosniff"
  };
}
