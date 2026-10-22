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
  occurrence?: number;
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
  },
  {
    name: "Bypass document authorize() call site",
    file: "src/server/app.ts",
    from: "const allowed = await authorize(client, actor, documentId, action);",
    to: "const allowed = true;"
  },
  {
    name: "Bypass framework failure authorize() call site",
    file: "src/server/app.ts",
    from: "const allowed = await authorize(client, actor, null, action);",
    to: "const allowed = true;"
  },
  {
    name: "Disable route-registry authorization guard",
    file: "src/server/authorization.ts",
    from: "if (missing.length > 0) {",
    to: "if (false) {"
  },
  {
    name: "Disable audit_log insert",
    file: "src/server/audit.ts",
    from: "  await client.query(\n    `INSERT INTO audit_log",
    to: "  return;\n\n  await client.query(\n    `INSERT INTO audit_log"
  },
  {
    name: "Remove active-document SQL permission filter",
    file: "src/server/app.ts",
    from: `WHEN d.deleted_at IS NULL THEN
           trustvault_authorize($1::uuid, d.id, 'document.read_metadata')`,
    to: `WHEN d.deleted_at IS NULL THEN
           true`
  },
  {
    name: "Remove deleted-document restore permission filter",
    file: "src/server/app.ts",
    from: `trustvault_authorize($1::uuid, d.id, 'document.restore')`,
    to: "true"
  }
];

async function run(): Promise<void> {
  const results: MutationResult[] = [];

  for (const mutation of mutations) {
    results.push(await runMutation(mutation));
  }

  printResults(results);

  const survivors = results.filter((result) => result.result !== "KILLED");
  if (survivors.length > 0) {
    process.exitCode = 1;
  }
}

async function runMutation(mutation: Mutation): Promise<MutationResult> {
  const filePath = path.join(projectRoot, mutation.file);
  const original = await readFile(filePath, "utf8");
  const from = mutation.from.replace(/\n/g, os.EOL);
  const to = mutation.to.replace(/\n/g, os.EOL);
  const occurrence = mutation.occurrence ?? 1;
  let firstIndex = -1;
  let searchFrom = 0;
  for (let current = 0; current < occurrence; current += 1) {
    firstIndex = original.indexOf(from, searchFrom);
    if (firstIndex < 0) {
      break;
    }
    searchFrom = firstIndex + from.length;
  }
  if (firstIndex < 0) {
    return {
      mutation: mutation.name,
      result: "ERROR",
      failingTests: [
        `Expected occurrence ${occurrence} of mutation anchor in ${mutation.file}`
      ]
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
        windowsHide: true,
        timeout: 240_000
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

function printResults(results: MutationResult[]): void {
  console.log("| Mutation | Result | Failing test(s) |");
  console.log("|---|---|---|");

  for (const result of results) {
    const tests =
      result.failingTests.length > 0
        ? result.failingTests.join("<br>")
        : "None (mutation survived)";
    console.log(`| ${result.mutation} | ${result.result} | ${tests} |`);
  }

}

void run().catch((error: unknown) => {
  console.error(
    "Mutation check failed:",
    error instanceof Error ? error.message : "Unknown error."
  );
  process.exitCode = 1;
});
