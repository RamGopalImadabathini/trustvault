import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

interface Mutation {
  name: string;
  file: string;
  from: string;
  to: string;
}

interface MutationResult {
  mutation: string;
  result: "KILLED" | "SURVIVED" | "ERROR";
  failingTests: string[];
}

interface VitestResult {
  testResults?: Array<{
    assertionResults?: Array<{
      fullName?: string;
      status?: string;
    }>;
  }>;
}

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const vitestCliPath = path.join(projectRoot, "node_modules", "vitest", "vitest.mjs");

const mutations: Mutation[] = [
  {
    name: "Allow UPDATE on users through app DB role",
    file: "db/migrations/001_initial_schema.sql",
    from: "GRANT SELECT, INSERT ON users TO trustvault_app;",
    to: "GRANT SELECT, INSERT, UPDATE ON users TO trustvault_app;"
  },
  {
    name: "Disable audit UPDATE protection",
    file: "db/migrations/001_initial_schema.sql",
    from: "BEFORE UPDATE OR DELETE ON audit_log",
    to: "BEFORE DELETE ON audit_log"
  },
  {
    name: "Disable audit TRUNCATE protection",
    file: "db/migrations/001_initial_schema.sql",
    from: "BEFORE TRUNCATE ON audit_log",
    to: "BEFORE UPDATE ON audit_log"
  },
  {
    name: "Accept undersized secrets",
    file: "src/server/config.ts",
    from: 'Buffer.byteLength(value, "utf8") < MIN_SECRET_BYTES',
    to: 'Buffer.byteLength(value, "utf8") < 1'
  },
  {
    name: "Accept non-PostgreSQL database URLs",
    file: "src/server/config.ts",
    from: `function isPostgresUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:") &&
      parsed.hostname.length > 0 &&
      parsed.pathname.length > 1
    );
  } catch {
    return false;
  }
}`,
    to: `function isPostgresUrl(_value: string): boolean {
  return true;
}`
  }
];

async function run(): Promise<void> {
  const results: MutationResult[] = [];

  for (const mutation of mutations) {
    results.push(await runMutation(mutation));
  }

  const deferred = await findDeferredTargets();
  printResults(results, deferred);

  const survivors = results.filter((result) => result.result !== "KILLED");
  if (survivors.length > 0 || deferred.length > 0) {
    process.exitCode = 1;
  }
}

async function runMutation(mutation: Mutation): Promise<MutationResult> {
  const filePath = path.join(projectRoot, mutation.file);
  const original = await readFile(filePath, "utf8");
  const from = mutation.from.replace(/\n/g, os.EOL);
  const to = mutation.to.replace(/\n/g, os.EOL);
  const firstIndex = original.indexOf(from);

  if (firstIndex < 0 || original.indexOf(from, firstIndex + 1) >= 0) {
    return {
      mutation: mutation.name,
      result: "ERROR",
      failingTests: [`Expected exactly one mutation anchor in ${mutation.file}`]
    };
  }

  const mutated =
    original.slice(0, firstIndex) +
    to +
    original.slice(firstIndex + from.length);

  let tempDirectory: string | undefined;

  try {
    await writeFile(filePath, mutated, "utf8");
    tempDirectory = await mkdtemp(path.join(os.tmpdir(), "trustvault-mut-"));
    const outputFile = path.join(tempDirectory, "vitest.json");
    const testRun = spawnSync(
      process.execPath,
      [
        vitestCliPath,
        "run",
        "--reporter=json",
        `--outputFile=${outputFile}`
      ],
      {
        cwd: projectRoot,
        encoding: "utf8",
        windowsHide: true
      }
    );

    if (testRun.error) {
      return {
        mutation: mutation.name,
        result: "ERROR",
        failingTests: [testRun.error.message]
      };
    }

    let report: VitestResult | undefined;
    try {
      report = JSON.parse(await readFile(outputFile, "utf8")) as VitestResult;
    } catch {
      return {
        mutation: mutation.name,
        result: "ERROR",
        failingTests: [
          `Could not read Vitest JSON report (exit ${testRun.status ?? "unknown"}).`,
          testRun.stderr.trim() || testRun.stdout.trim()
        ].filter(Boolean)
      };
    }

    const failingTests = (report.testResults ?? []).flatMap((fileResult) =>
      (fileResult.assertionResults ?? [])
        .filter((test) => test.status === "failed")
        .map((test) => test.fullName ?? "unnamed failing test")
    );

    if (testRun.status === 0 && failingTests.length === 0) {
      return {
        mutation: mutation.name,
        result: "SURVIVED",
        failingTests
      };
    }

    if (testRun.status !== 0 && failingTests.length > 0) {
      return {
        mutation: mutation.name,
        result: "KILLED",
        failingTests
      };
    }

    return {
      mutation: mutation.name,
      result: "ERROR",
      failingTests: [
        `Vitest exited with status ${testRun.status ?? "unknown"} without reporting an assertion failure.`
      ]
    };
  } finally {
    await writeFile(filePath, original, "utf8");
    if (tempDirectory) {
      await rm(tempDirectory, { recursive: true, force: true });
    }
  }
}

async function findDeferredTargets(): Promise<string[]> {
  const scanRoots = ["src/server", "src/client", "db"];
  const sourceFiles = await collectSourceFiles(scanRoots);
  const sourceContent = await Promise.all(
    sourceFiles.map((file) => readFile(file, "utf8"))
  );
  const allSource = sourceContent.join("\n");
  const authorizeCalls = allSource.match(/\bauthorize\s*\(/g)?.length ?? 0;
  const hasRouteRegistry = /route.?registry|registry.?guard/i.test(allSource);
  const hasAuditWrite =
    /audit(?:Log|_log)?\s*\.(?:insert|write|append)|writeAudit|appendAudit/i.test(
      allSource
    );
  const hasSearchGrantFilter = sourceContent.some(
    (content) =>
      /\bsearch\b/i.test(content) &&
      /document_grants|documentGrants|grants?\.user_id/i.test(content)
  );

  return [
    authorizeCalls === 0
      ? "Every authorize() call site (no call sites exist in Phase 1)"
      : `Every authorize() call site (${authorizeCalls} found; mutation adapter not implemented)`,
    hasRouteRegistry
      ? "Route-registry authorization guard (mutation adapter not implemented)"
      : "Route-registry authorization guard (not implemented in Phase 1)",
    hasAuditWrite
      ? "Audit write call (mutation adapter not implemented)"
      : "Audit write call (not implemented in Phase 1)",
    hasSearchGrantFilter
      ? "Search grant filter (mutation adapter not implemented)"
      : "Search grant filter (not implemented in Phase 1)"
  ];
}

async function collectSourceFiles(relativeRoots: string[]): Promise<string[]> {
  const files: string[] = [];

  for (const relativeRoot of relativeRoots) {
    const absoluteRoot = path.join(projectRoot, relativeRoot);
    await visit(absoluteRoot);
  }
  return files;

  async function visit(directory: string): Promise<void> {
    const { readdir, stat } = await import("node:fs/promises");
    const entries = await readdir(directory);

    for (const entry of entries) {
      const entryPath = path.join(directory, entry);
      const entryStat = await stat(entryPath);

      if (entryStat.isDirectory()) {
        await visit(entryPath);
      } else if (/\.(?:ts|tsx|js|jsx|sql)$/.test(entry)) {
        files.push(entryPath);
      }
    }
  }
}

function printResults(results: MutationResult[], deferred: string[]): void {
  console.log("| Mutation | Result | Failing test(s) |");
  console.log("|---|---|---|");

  for (const result of results) {
    const tests =
      result.failingTests.length > 0
        ? result.failingTests.join("<br>")
        : "None (mutation survived)";
    console.log(`| ${result.mutation} | ${result.result} | ${tests} |`);
  }

  for (const target of deferred) {
    console.log(`| ${target} | NOT TESTED | No applicable mutation result |`);
  }

  if (deferred.length > 0) {
    console.error(
      `Mutation coverage incomplete: ${deferred.join(", ")}. Add mutation adapters and regression tests before treating authorization mutation testing as complete.`
    );
  }
}

void run().catch((error: unknown) => {
  console.error(
    "Mutation check failed:",
    error instanceof Error ? error.message : "Unknown error."
  );
  process.exitCode = 1;
});
