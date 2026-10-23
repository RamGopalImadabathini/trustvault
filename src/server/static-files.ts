import { realpath, readFile } from "node:fs/promises";
import path from "node:path";
import type { FastifyReply } from "fastify";

const CONTENT_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2"
};

export function resolveBuildFilePath(
  buildDirectory: string,
  requestPath: string
): string | null {
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(requestPath);
  } catch {
    return null;
  }

  const root = path.resolve(buildDirectory);
  const normalizedPath = decodedPath === "/" ? "/index.html" : decodedPath;
  const candidate = path.resolve(root, `.${normalizedPath.replaceAll("\\", "/")}`);
  const relativePath = path.relative(root, candidate);
  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    return null;
  }
  return candidate;
}

export async function serveClientFile(
  buildDirectory: string,
  requestPath: string,
  reply: FastifyReply
): Promise<boolean> {
  const candidate = resolveBuildFilePath(buildDirectory, requestPath);
  if (!candidate) {
    return false;
  }

  try {
    const rootRealPath = await realpath(buildDirectory);
    const fileRealPath = await realpath(candidate);
    const relativePath = path.relative(rootRealPath, fileRealPath);
    if (
      relativePath === ".." ||
      relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath)
    ) {
      return false;
    }

    const bytes = await readFile(fileRealPath);
    reply.type(CONTENT_TYPES[path.extname(fileRealPath).toLowerCase()] ?? "application/octet-stream");
    if (reply.request.method === "HEAD") {
      reply.header("Content-Length", bytes.byteLength);
      reply.send();
      return true;
    }
    reply.send(bytes);
    return true;
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "EISDIR")
    ) {
      return false;
    }
    throw error;
  }
}
