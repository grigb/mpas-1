import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const packageRoot = fileURLToPath(new URL("../..", import.meta.url));
const releasingPath = join(packageRoot, "RELEASING.md");
const manifestPath = join(packageRoot, "package.json");

/**
 * The release-tag rule RELEASING.md documents: a prerelease publishes under
 * its prerelease channel tag (the first prerelease identifier) and never
 * under `latest`; only stable versions select `latest`.
 */
function intendedDistTag(version: string): string {
  const prereleaseStart = version.indexOf("-");
  if (prereleaseStart === -1) {
    return "latest";
  }
  const channel = version.slice(prereleaseStart + 1).split(".")[0];
  if (!/^[0-9A-Za-z-]+$/.test(channel) || channel.length === 0) {
    throw new Error(`Cannot derive a dist-tag channel from version ${version}.`);
  }
  return channel;
}

async function npmPublishDryRun(
  packageDir: string,
  cacheDir: string,
  extraArgs: string[] = [],
): Promise<string> {
  const npmExecPath = process.env.npm_execpath;
  const command = npmExecPath ? process.execPath : "npm";
  const args = [
    ...(npmExecPath ? [npmExecPath] : []),
    "publish",
    "--dry-run",
    "--ignore-scripts",
    "--cache",
    cacheDir,
    ...extraArgs,
  ];
  const env = { ...process.env };
  delete env.NPM_TOKEN;
  delete env.NODE_AUTH_TOKEN;
  const { stdout, stderr } = await execFileAsync(command, args, { cwd: packageDir, env });
  return `${stdout}\n${stderr}`;
}

async function syntheticPackage(version: string): Promise<{ dir: string; cacheDir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "mpas-release-tag-"));
  const cacheDir = join(dir, "npm-cache");
  await mkdir(join(dir, "pkg", "dist"), { recursive: true });
  await mkdir(cacheDir, { recursive: true });
  const manifest = {
    name: "@oma3/mpas",
    version,
    description: "synthetic dry-run control package",
    license: "Apache-2.0",
    type: "module",
    main: "./dist/index.js",
    files: ["dist", "README.md"],
    publishConfig: { access: "public" },
  };
  await writeFile(join(dir, "pkg", "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(join(dir, "pkg", "README.md"), "# synthetic dry-run control\n");
  await writeFile(join(dir, "pkg", "dist", "index.js"), "export {};\n");
  return { dir: join(dir, "pkg"), cacheDir };
}

describe("release dist-tag selection (N38)", () => {
  it("maps stable versions to latest and prereleases to their channel, never latest", () => {
    expect(intendedDistTag("1.0.0")).toBe("latest");
    expect(intendedDistTag("2.3.4")).toBe("latest");
    expect(intendedDistTag("0.1.0-alpha.1")).toBe("alpha");
    expect(intendedDistTag("2.0.0-beta.3")).toBe("beta");
    expect(intendedDistTag("1.0.0-rc.1")).toBe("rc");
    for (const prerelease of ["0.1.0-alpha.1", "2.0.0-beta.3", "1.0.0-rc.1"]) {
      expect(intendedDistTag(prerelease)).not.toBe("latest");
    }
  });

  it("derives a non-latest channel tag from the current SDK manifest version", async () => {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { name: string; version: string };
    expect(manifest.name).toBe("@oma3/mpas");
    const tag = intendedDistTag(manifest.version);
    if (manifest.version.includes("-")) {
      expect(tag).not.toBe("latest");
    }
    expect(tag).toBe("alpha");
  });

  it("documents the dist-tag rule and never promotes a prerelease to latest", async () => {
    const releasing = await readFile(releasingPath, "utf8");

    // The prerelease publish command always carries its channel tag.
    expect(releasing).toContain("npm publish --access public --tag alpha");

    // No line anywhere in the guide promotes a prerelease to latest.
    const promotion = releasing.split("\n").find((line) =>
      line.includes("dist-tag add") && line.includes("latest") && /alpha|beta|rc|next|canary/.test(line));
    expect(promotion).toBeUndefined();

    // The guide states the rule: prereleases never receive latest; stable does.
    expect(releasing).toContain("never given the `latest` dist-tag");
    expect(releasing).toContain("`latest` must");
  });

  it("npm resolves the documented prerelease command to the channel tag (dry-run, nothing published)", async () => {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { version: string };
    const tag = intendedDistTag(manifest.version);
    const { dir, cacheDir } = await syntheticPackage(manifest.version);
    try {
      const output = await npmPublishDryRun(dir, cacheDir, ["--tag", tag]);
      expect(output).toContain(`with tag ${tag} and public access (dry-run)`);
      expect(output).toContain("(dry-run)");
      expect(output).not.toContain("with tag latest");
    } finally {
      await rm(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("npm resolves the stable command to latest (dry-run, nothing published)", async () => {
    const { dir, cacheDir } = await syntheticPackage("1.0.0");
    try {
      const output = await npmPublishDryRun(dir, cacheDir);
      expect(output).toContain("with tag latest and public access (dry-run)");
      expect(output).toContain("(dry-run)");
    } finally {
      await rm(join(dir, ".."), { recursive: true, force: true });
    }
  });

  it("npm would select latest for an untagged prerelease — the hazard the rule forbids (dry-run control)", async () => {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { version: string };
    if (!manifest.version.includes("-")) {
      return;
    }
    const { dir, cacheDir } = await syntheticPackage(manifest.version);
    try {
      const output = await npmPublishDryRun(dir, cacheDir);
      // Bare `npm publish` on a prerelease defaults to latest; the documented
      // prerelease command therefore always carries --tag <channel>.
      expect(output).toContain("with tag latest and public access (dry-run)");
      expect(intendedDistTag(manifest.version)).not.toBe("latest");
    } finally {
      await rm(join(dir, ".."), { recursive: true, force: true });
    }
  });
});
