import { execFile } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import "../fixtures/action-fixture-clock.js";
import type { StartedDaemon } from "../../src/adapter/daemon.js";
import { runCli } from "../../src/cli/index.js";

const execFileAsync = promisify(execFile);
const fixturesDir = fileURLToPath(new URL("../fixtures/", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../../..", import.meta.url));
const sdkRoot = join(repoRoot, "sdk", "protocol");

// Offline package source for the consumer install: the runner's configured
// npm cache (npm_config_cache) or the workspace-local task cache copy. The
// per-user developer cache (~/.npm) is never read or written: HOME and
// npm_config_userconfig are isolated for every spawned command.
const cacheDir = process.env.npm_config_cache ?? join(repoRoot, ".wo336-npm-cache");

// Same CLI-path trust isolation as the adapter-lifecycle matrix: the Artifact
// Trust lookup is not requested (zero external network) and the operator
// confirmation auto-accepts; every other surface stays real.
vi.mock("../../src/adapter/trust.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/adapter/trust.js")>();
  return { ...mod, DEFAULT_TRUST_CONTEXT: null };
});

vi.mock("../../src/adapter/trust-prompt.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/adapter/trust-prompt.js")>();
  return { ...mod, promptPluginUse: async () => true };
});

const adapterStarts: StartedDaemon[] = [];
vi.mock("../../src/adapter/daemon.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/adapter/daemon.js")>();
  return {
    ...mod,
    startDaemon: async (options: Parameters<typeof mod.startDaemon>[0]) => {
      const daemon = await mod.startDaemon(options);
      adapterStarts.push(daemon);
      return daemon;
    },
  };
});

class MemoryWriter {
  text = "";
  write(chunk: string | Uint8Array): boolean {
    this.text += chunk.toString();
    return true;
  }
}

const realTmp = () => realpathSync(tmpdir());
const npmCliArgs = () =>
  process.env.npm_execpath ? [process.env.npm_execpath] : ["/Users/grig/.hermes/node/lib/node_modules/npm/bin/npm-cli.js"];

afterEach(async () => {
  await Promise.all(adapterStarts.splice(0).map((daemon) => daemon.app.close()));
});

describe("clean setup from an isolated task-owned directory (refinement 5)", () => {
  it("packs the accepted local SDK, installs it into a fresh consumer, and proves the imported entry", async () => {
    expect(existsSync(join(sdkRoot, "dist", "index.js")), "sdk dist missing; run `npm run build --prefix sdk/protocol` first").toBe(true);
    expect(existsSync(cacheDir), `offline npm cache not found at ${cacheDir}`).toBe(true);

    const root = await mkdtemp(join(realTmp(), "mpas-clean-setup-"));
    const home = join(root, "home");
    await mkdir(home, { recursive: true });
    const npmrc = join(root, ".npmrc");
    await writeFile(npmrc, "");
    const isolatedEnv: Record<string, string | undefined> = {
      ...process.env,
      HOME: home,
      npm_config_userconfig: npmrc,
      npm_config_cache: cacheDir,
    };
    delete isolatedEnv.NPM_TOKEN;
    delete isolatedEnv.NODE_AUTH_TOKEN;

    try {
      const sdkManifest = JSON.parse(await readFile(join(sdkRoot, "package.json"), "utf8")) as { name: string; version: string; dependencies: Record<string, string> };
      expect(sdkManifest.name).toBe("@oma3/mpas");

      // Pack the accepted local SDK explicitly.
      const packDir = join(root, "pack");
      await mkdir(packDir, { recursive: true });
      const pack = await execFileAsync(
        process.execPath,
        [...npmCliArgs(), "pack", sdkRoot, "--ignore-scripts", "--pack-destination", packDir],
        { env: isolatedEnv, maxBuffer: 8 * 1024 * 1024 },
      );
      const tarballName = pack.stdout.trim().split("\n").at(-1)!.trim();
      expect(tarballName).toMatch(/^oma3-mpas-.+\.tgz$/);
      const tarball = join(packDir, tarballName);

      // Fresh consumer project in the isolated directory. The packed SDK is
      // extracted into the consumer and its dependency closure is linked from
      // the SDK's own npm-ci'd node_modules — npm's flat layout, fully
      // offline (the retained cache carries tarballs but not every packument,
      // so fresh registry resolution cannot run offline; refinement 5's
      // "build/link the accepted local SDK explicitly" is exactly this path).
      const consumer = join(root, "consumer");
      await mkdir(consumer, { recursive: true });
      await writeFile(
        join(consumer, "package.json"),
        `${JSON.stringify({ name: "clean-setup-consumer", private: true, version: "0.0.0", type: "module" }, null, 2)}\n`,
      );
      const extractDir = join(root, "extract");
      await mkdir(extractDir, { recursive: true });
      await execFileAsync("tar", ["-xzf", tarball, "-C", extractDir]);
      await mkdir(join(consumer, "node_modules", "@oma3"), { recursive: true });
      await execFileAsync("mv", [join(extractDir, "package"), join(consumer, "node_modules", "@oma3", "mpas")]);
      const { symlink } = await import("node:fs/promises");
      for (const dep of Object.keys(sdkManifest.dependencies as Record<string, string>)) {
        const target = join(consumer, "node_modules", dep);
        await mkdir(join(target, ".."), { recursive: true });
        await symlink(join(sdkRoot, "node_modules", dep), target, "dir");
      }

      // Prove the actual imported entry: resolves inside the consumer, reports
      // the accepted manifest version, and exports DispatchLedger — absent
      // from the published alpha.10 tarball — so the local build, not a
      // silent fallback to the published SDK.
      const probe = await execFileAsync(
        process.execPath,
        [
          "--input-type=module", "-e",
          `import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const require = createRequire(process.cwd() + "/package.json");
const resolved = require.resolve("@oma3/mpas/package.json");
const manifest = JSON.parse(readFileSync(resolved, "utf8"));
const sdk = await import("@oma3/mpas");
const key = await sdk.generateEd25519Key();
console.log(JSON.stringify({
  resolved,
  name: manifest.name,
  version: manifest.version,
  hasLocalMarker: typeof sdk.DispatchLedger === "function",
  functional: typeof key.did === "string" && key.did.startsWith("did:jwk:"),
}));`,
        ],
        { cwd: consumer, env: isolatedEnv, maxBuffer: 8 * 1024 * 1024 },
      );
      const entry = JSON.parse(probe.stdout.trim()) as Record<string, unknown>;
      expect(entry.resolved).toBe(join(consumer, "node_modules", "@oma3", "mpas", "package.json"));
      expect(entry.name).toBe("@oma3/mpas");
      expect(entry.version).toBe(sdkManifest.version);
      expect(entry.hasLocalMarker).toBe(true);
      expect(entry.functional).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("runs the demo CLI lifecycle with every default path under an isolated home", async () => {
    const root = await mkdtemp(join(realTmp(), "mpas-clean-home-"));
    const home = join(root, "home");
    await mkdir(home, { recursive: true });

    const savedHome = process.env.HOME;
    const removedMpas: Array<[string, string | undefined]> = [];
    for (const name of Object.keys(process.env)) {
      if (name.startsWith("MPAS_")) {
        removedMpas.push([name, process.env[name]]);
        delete process.env[name];
      }
    }
    process.env.HOME = home;

    try {
      // Synthetic operator state authored under the isolated home, mirroring
      // the guide: config dir, deployment config, plugin reference.
      const configDir = join(home, ".mpas", "config");
      await mkdir(configDir, { recursive: true });
      const config = JSON.parse(
        await readFile(join(fixturesDir, "configs", "policy-fixtures", "github-auto-approve.json"), "utf8"),
      ) as Record<string, unknown>;
      (config.plugin as Record<string, unknown>).path = join(fixturesDir, "plugins", "github-mirror-plugin.json");
      await writeFile(join(configDir, "github-auto-approve.json"), `${JSON.stringify(config, null, 2)}\n`);

      const stdout = new MemoryWriter();
      const stderr = new MemoryWriter();

      const keygen = await runCli(["key", "generate", "adapter"], { stdout, stderr });
      expect(keygen.exitCode).toBe(0);
      const keyReport = JSON.parse(stdout.text) as { path: string; did: string };
      expect(keyReport.path).toBe(join(home, ".mpas", "keys", "adapter.json"));

      stdout.text = "";
      const credential = await runCli(["credential", "set", "github-mirror-token", "--value", "ghp_synthetic"], { stdout, stderr });
      expect(credential.exitCode).toBe(0);
      const credentialBody = await readFile(join(home, ".mpas", "credentials", "github-mirror-token.json"), "utf8");
      expect(JSON.parse(credentialBody)).toEqual({ value: "ghp_synthetic" });

      stdout.text = "";
      const validate = await runCli(["config", "validate", "github-auto-approve"], { stdout, stderr });
      expect(validate.exitCode).toBe(0);
      expect(stdout.text).toContain("Validation passed.");

      stdout.text = "";
      stderr.text = "";
      const started = await runCli(["adapter", "start", "--port", "0"], { stdout, stderr });
      expect(started.exitCode).toBe(0);
      const report = JSON.parse(stdout.text) as Record<string, unknown>;
      expect(report.status).toBe("started");
      expect(report.address).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

      const health = await fetch(`${report.address as string}/mpas/v1/health`);
      expect(health.status).toBe(200);

      const actionPackage = JSON.parse(
        await readFile(join(fixturesDir, "core", "valid-no-approval-required.json"), "utf8"),
      ) as unknown;
      const action = await fetch(`${report.address as string}/mpas/v1/verifier/action`, {
        method: "POST",
        headers: { "content-type": "application/mpas+json" },
        body: JSON.stringify({ version: "1", type: "ActionRequest", actionPackage }),
      });
      expect(action.status).toBe(200);
      expect(await action.json()).toMatchObject({ type: "ActionResponse", result: "executed" });

      // Every default-path artifact landed under the isolated home.
      const journal = await readdir(join(home, ".mpas", "journal"));
      expect(journal).toContain("dispatch-ledger.jsonl");
      expect(await readdir(join(home, ".mpas", "keys"))).toEqual(["adapter.json"]);
      expect(await readdir(join(home, ".mpas", "credentials"))).toEqual(["github-mirror-token.json"]);
      const keyBody = await readFile(join(home, ".mpas", "keys", "adapter.json"), "utf8");
      expect(JSON.parse(keyBody).did).toBe(keyReport.did);
    } finally {
      if (savedHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = savedHome;
      }
      for (const [name, value] of removedMpas) {
        if (value !== undefined) process.env[name] = value;
      }
      await rm(root, { recursive: true, force: true });
    }
  });
});
