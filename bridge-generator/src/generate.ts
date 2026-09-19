/**
 * `bridge-generator generate` — application packaging orchestrator (spec.md §2, §3, §5).
 *
 * Runs discovery once and writes the full applications/<name>/ layout.
 * Regeneration semantics: generated surface overwritten; CHANGELOG.md created
 * once; harness-config and classification merged; .generator-keep respected.
 * plugin.json is merged, not rebuilt: membership = (old plugin ∩ new upstream)
 * ∪ tools new since the old snapshot, so operations a reviewer removed from
 * the plugin stay removed (spec.md §5). Identity fields and reviewed impacts
 * in the old plugin are preserved; descriptions/schemas refresh from discovery.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { canonicalize } from "json-canonicalize";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import * as raw from "multiformats/codecs/raw";
import { base32 } from "multiformats/bases/base32";
import {
  buildClassificationDraft,
  buildDiscoveryMetadata,
  buildHarnessConfig,
  buildToolsListSnapshot,
  mergeClassificationDraft,
  mergeHarnessConfig,
  type ClassificationDraft,
  type HarnessConfig,
} from "./artifacts.js";
import { generateBridge, generateToolsJson, generateWorkflowStore } from "./bridge-codegen.js";
import { generatePlugin } from "./plugin-codegen.js";
import { discoverUpstream } from "./discovery.js";
import { loadResultDisclosurePolicy } from "./result-disclosure.js";
import type { CredentialRequirement, GeneratedPlugin, McpToolDefinition, UpstreamInfo } from "./types.js";

export const GENERATOR_VERSION = "0.2.0";

export interface OrgConfig {
  publisher: {
    name: string;
    githubOrg: string;
    publisherDid?: string;
    repository?: string;
  };
  application: {
    name: string;
    description: string;
    applicationDid: string;
    website?: string;
  };
  /** Optional publish location of the generated plugin.json. */
  plugin?: {
    repository?: string;
  };
}

export interface GenerateOptions {
  appName: string;
  outDir: string;
  orgConfigPath?: string;
  applicationDid?: string;
  /** Reviewed result-disclosure policy. Defaults to the application output directory. */
  resultDisclosurePath?: string;
  upstreamCommand: string;
  upstreamArgs: string[];
  /** Injectable for deterministic tests. */
  capturedAt?: string;
  /** Injectable for tests; defaults to real discovery. */
  discover?: (command: string, args: string[]) => Promise<UpstreamInfo>;
  log?: (message: string) => void;
}

export class GenerateError extends Error {
  readonly exitCode = 5;
}

const APP_NAME_PATTERN = /^[a-z][a-z0-9-]*$/;

export async function runGenerate(options: GenerateOptions): Promise<void> {
  const log = options.log ?? ((message: string) => process.stderr.write(`${message}\n`));
  if (!APP_NAME_PATTERN.test(options.appName)) {
    throw new GenerateError(`Invalid --app name "${options.appName}" (lowercase, hyphenated).`);
  }

  const orgConfig = options.orgConfigPath ? await loadOrgConfig(options.orgConfigPath) : undefined;
  const discover = options.discover ?? discoverUpstream;
  const upstream = await discover(options.upstreamCommand, options.upstreamArgs);

  const appDir = resolve(options.outDir, options.appName);
  const disclosurePath = options.resultDisclosurePath ?? join(appDir, "result-disclosure.json");
  const disclosure = await loadResultDisclosurePolicy(disclosurePath, upstream.tools.map((tool) => tool.name));
  await mkdir(join(appDir, "build-artifacts"), { recursive: true });
  await mkdir(join(appDir, "bridge", "src"), { recursive: true });

  const keep = await loadKeepList(appDir);
  const writeGenerated = async (relativePath: string, contents: string): Promise<void> => {
    if (keep.has(relativePath)) {
      log(`Preserved (in .generator-keep): ${relativePath}`);
      return;
    }
    const path = join(appDir, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents, "utf8");
    log(`Wrote: ${relativePath}`);
  };

  // The reviewed source bytes are copied exactly. The validated in-memory map,
  // rather than this sidecar at runtime, is embedded into the generated bridge.
  await writeFile(join(appDir, "result-disclosure.json"), disclosure.rawText, "utf8");
  log("Wrote: result-disclosure.json");

  // Prior state must be read before the generated surface is overwritten:
  // regeneration membership is derived from old snapshot − old plugin.
  const previousSnapshot = await readJsonIfExists<{ tools?: Array<{ name: string }> }>(
    join(appDir, "build-artifacts", "tools-list.snapshot.json"),
  );
  const previousPlugin = await readJsonIfExists<Partial<GeneratedPlugin>>(join(appDir, "plugin.json"));
  const previousCredentialRequirements = previousPlugin?.credentialRequirements === undefined
    ? undefined
    : validateCredentialRequirements(previousPlugin.credentialRequirements);

  // --- build-artifacts ---
  const snapshot = buildToolsListSnapshot(upstream.tools);
  await writeGenerated("build-artifacts/tools-list.snapshot.json", jsonFile(snapshot));

  const metadata = buildDiscoveryMetadata(upstream, {
    protocolVersion: upstream.protocolVersion,
    generatorVersion: GENERATOR_VERSION,
    capturedAt: options.capturedAt,
  });
  await writeGenerated("build-artifacts/metadata.json", jsonFile(metadata));

  const classification = await mergedClassification(appDir, upstream);
  await writeGenerated("build-artifacts/classification.json", jsonFile(classification));

  // --- plugin.json ---
  // Membership in plugin.operations is the governance control (Application
  // Plugin profile): tools the reviewer deleted from an existing plugin are
  // intentional pass-through and must not be re-added. classification.json is
  // advisory only and never drives membership.
  const governedTools = selectGovernedTools(snapshot.tools, previousPlugin, previousSnapshot, log);
  const plugin = JSON.parse(generatePlugin(governedTools, upstream.protocolVersion)) as GeneratedPlugin;
  if (previousPlugin) {
    plugin.pluginDid = previousPlugin.pluginDid ?? plugin.pluginDid;
    plugin.pluginVersion = previousPlugin.pluginVersion ?? plugin.pluginVersion;
    plugin.publisherDid = previousPlugin.publisherDid ?? plugin.publisherDid;
    plugin.applicationDid = previousPlugin.applicationDid ?? plugin.applicationDid;
    plugin.credentialRequirements = previousCredentialRequirements ?? validateCredentialRequirements(plugin.credentialRequirements);
  }
  if (options.applicationDid ?? orgConfig?.application.applicationDid) {
    plugin.applicationDid = options.applicationDid ?? orgConfig!.application.applicationDid;
  }
  for (const [name, operation] of Object.entries(plugin.operations)) {
    const previousOperation = previousPlugin?.operations?.[name];
    if (previousOperation?.impact) {
      operation.impact = previousOperation.impact;
    } else if (classification.operations[name]) {
      operation.impact = classification.operations[name].impact;
    }
  }
  await writeGenerated("plugin.json", jsonFile(plugin));

  // --- harness-config.json (merge preserves manual edits) ---
  const harnessConfig = await mergedHarnessConfig(appDir, upstream);
  await writeGenerated("harness-config.json", jsonFile(harnessConfig));

  // --- registry-entry.json ---
  // Publishable only when every publish field is real: no draft marker and full
  // validation against application-registry/schema.v1.json before writing. While
  // any generated placeholder remains the file is an explicit nonpublishable draft.
  const registryEntry = buildRegistryEntry(options.appName, upstream, plugin, snapshot.toolSurface, orgConfig);
  registryEntry.plugin.artifactDid = await computeArtifactDid(plugin);
  if (containsPlaceholder(registryEntry)) {
    await writeGenerated("registry-entry.json", jsonFile({ ...registryEntry, draft: true }));
    log("registry-entry.json is a nonpublishable draft (generated placeholders remain); it is not valid against application-registry/schema.v1.json.");
  } else {
    validateRegistryEntry(registryEntry, plugin.applicationDid);
    await writeGenerated("registry-entry.json", jsonFile(registryEntry));
  }

  // --- bridge/ ---
  await writeGenerated("bridge/src/index.ts", generateBridge(upstream, disclosure.disclosureMap));
  await writeGenerated("bridge/src/tools.json", generateToolsJson(upstream.tools));
  await writeGenerated("bridge/src/sqlite-workflow-store.ts", generateWorkflowStore());
  await writeGenerated("bridge/package.json", jsonFile(bridgePackageJson(options.appName)));
  await writeGenerated("bridge/tsconfig.json", jsonFile(bridgeTsconfig()));
  await writeGenerated("bridge/README.md", bridgeReadme(options.appName, upstream));

  // --- CHANGELOG.md (create once, never overwrite) ---
  const changelogPath = join(appDir, "CHANGELOG.md");
  if (!existsSync(changelogPath)) {
    await writeFile(changelogPath, `# Changelog — ${options.appName}\n\nRecord manual review decisions and regenerations here.\n`, "utf8");
    log("Wrote: CHANGELOG.md");
  } else {
    log("Preserved: CHANGELOG.md");
  }

  log(`Application packaged: ${appDir}`);
}

/** Same construction as the demo adapter's plugin integrity check. */
export async function computeArtifactDid(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(value));
  const hash = await sha256.digest(bytes);
  const cid = CID.createV1(raw.code, hash);
  return `did:artifact:${cid.toString(base32)}`;
}

export interface RegistryEntry {
  version: "1";
  application: { name: string; description: string; applicationDid: string; website?: string };
  native: false;
  protocol: "mcp";
  upstream: { name: string; protocolVersion: string; toolSurface: { alg: string; value: string } };
  plugin: { repository: string; pluginDid?: string; artifactDid?: string };
  publisher: { name: string; githubOrg: string; publisherDid?: string; repository?: string };
  status: "beta";
}

function buildRegistryEntry(
  appName: string,
  upstream: UpstreamInfo,
  plugin: { applicationDid: string },
  toolSurface: { alg: "sha-256"; value: string },
  orgConfig?: OrgConfig,
): RegistryEntry {
  return {
    version: "1",
    application: orgConfig
      ? { ...orgConfig.application }
      : {
          name: appName,
          description: `MPAS-protected ${appName} via ${upstream.serverName}. PLACEHOLDER: review before submitting.`,
          applicationDid: plugin.applicationDid,
        },
    native: false,
    protocol: "mcp",
    upstream: {
      name: upstream.serverName,
      protocolVersion: upstream.protocolVersion,
      toolSurface,
    },
    plugin: {
      repository: orgConfig?.plugin?.repository ?? "PLACEHOLDER: URL to the published plugin.json",
    },
    publisher: orgConfig
      ? { ...orgConfig.publisher }
      : { name: "PLACEHOLDER", githubOrg: "PLACEHOLDER" },
    status: "beta",
  };
}

/**
 * Dependency-free evaluator for the application-registry v1 publish contract
 * (`application-registry/schema.v1.json`). The checked-in JSON Schema is the
 * external machine contract; this evaluator must agree with it for every
 * constraint. `expectedApplicationDid`, when given, additionally binds the
 * entry to the generated plugin's `applicationDid` — a cross-field equality
 * the schema cannot express.
 */
export function checkRegistryEntryV1(value: unknown, expectedApplicationDid?: string): RegistryValidationIssue[] {
  const issues: RegistryValidationIssue[] = [];
  const fail = (path: string, message: string): void => {
    issues.push({ path, message });
  };
  if (!isPlainObject(value)) {
    fail("$", "entry must be an object.");
    return issues;
  }

  checkExactMembers(value, ["version", "application", "native", "protocol", "upstream", "plugin", "publisher", "status"], "$", fail);
  requireMembers(value, ["version", "application", "native", "protocol", "plugin", "publisher", "status"], "$", fail);

  if ("version" in value && value.version !== "1") {
    fail("$.version", 'version must be exactly "1".');
  }
  if ("native" in value && typeof value.native !== "boolean") {
    fail("$.native", "native must be a boolean.");
  }
  if ("protocol" in value && value.protocol !== "mcp") {
    fail("$.protocol", 'protocol must be "mcp" (schema v1 covers MCP integrations only).');
  }
  if ("status" in value && !REGISTRY_STATUS_VOCABULARY.has(value.status as string)) {
    fail("$.status", `status must be one of: ${[...REGISTRY_STATUS_VOCABULARY].join(", ")}.`);
  }

  if ("application" in value) {
    const application = value.application;
    if (!isPlainObject(application)) {
      fail("$.application", "application must be an object.");
    } else {
      checkExactMembers(application, ["name", "description", "applicationDid", "website"], "$.application", fail);
      requireMembers(application, ["name", "description", "applicationDid"], "$.application", fail);
      checkNonEmptyString(application.name, "$.application.name", fail);
      checkNonEmptyString(application.description, "$.application.description", fail);
      checkDid(application.applicationDid, "$.application.applicationDid", fail);
      if ("website" in application) checkHttpsUrl(application.website, "$.application.website", fail);
    }
  }

  if ("plugin" in value) {
    const plugin = value.plugin;
    if (!isPlainObject(plugin)) {
      fail("$.plugin", "plugin must be an object.");
    } else {
      checkExactMembers(plugin, ["repository", "pluginDid", "artifactDid"], "$.plugin", fail);
      requireMembers(plugin, ["repository"], "$.plugin", fail);
      checkHttpsUrl(plugin.repository, "$.plugin.repository", fail);
      if ("pluginDid" in plugin) checkDid(plugin.pluginDid, "$.plugin.pluginDid", fail);
      if ("artifactDid" in plugin) checkDid(plugin.artifactDid, "$.plugin.artifactDid", fail);
    }
  }

  if ("publisher" in value) {
    const publisher = value.publisher;
    if (!isPlainObject(publisher)) {
      fail("$.publisher", "publisher must be an object.");
    } else {
      checkExactMembers(publisher, ["name", "githubOrg", "publisherDid", "repository"], "$.publisher", fail);
      requireMembers(publisher, ["name", "githubOrg"], "$.publisher", fail);
      checkNonEmptyString(publisher.name, "$.publisher.name", fail);
      checkNonEmptyString(publisher.githubOrg, "$.publisher.githubOrg", fail);
      if ("publisherDid" in publisher) checkDid(publisher.publisherDid, "$.publisher.publisherDid", fail);
      if ("repository" in publisher) checkHttpsUrl(publisher.repository, "$.publisher.repository", fail);
    }
  }

  const upstream = value.upstream;
  if (value.native === false) {
    if (!("upstream" in value)) {
      fail("$.upstream", "upstream is required when native is false.");
    }
  } else if (value.native === true && "upstream" in value) {
    fail("$.upstream", "upstream must be absent when native is true.");
  }
  if ("upstream" in value) {
    if (!isPlainObject(upstream)) {
      fail("$.upstream", "upstream must be an object.");
    } else {
      checkExactMembers(upstream, ["name", "protocolVersion", "repository", "distributionUrl", "package", "toolSurface"], "$.upstream", fail);
      requireMembers(upstream, ["name", "protocolVersion"], "$.upstream", fail);
      checkNonEmptyString(upstream.name, "$.upstream.name", fail);
      checkNonEmptyString(upstream.protocolVersion, "$.upstream.protocolVersion", fail);
      if ("repository" in upstream) checkHttpsUrl(upstream.repository, "$.upstream.repository", fail);
      if ("distributionUrl" in upstream) checkHttpsUrl(upstream.distributionUrl, "$.upstream.distributionUrl", fail);
      if ("package" in upstream) checkNonEmptyString(upstream.package, "$.upstream.package", fail);
      if ("toolSurface" in upstream) {
        const toolSurface = upstream.toolSurface;
        if (!isPlainObject(toolSurface)) {
          fail("$.upstream.toolSurface", "toolSurface must be an object.");
        } else {
          checkExactMembers(toolSurface, ["alg", "value"], "$.upstream.toolSurface", fail);
          requireMembers(toolSurface, ["alg", "value"], "$.upstream.toolSurface", fail);
          if ("alg" in toolSurface && toolSurface.alg !== "sha-256") {
            fail("$.upstream.toolSurface.alg", 'toolSurface.alg must be "sha-256".');
          }
          if (
            "value" in toolSurface &&
            (typeof toolSurface.value !== "string" || !BASE64URL_SHA256_PATTERN.test(toolSurface.value))
          ) {
            fail("$.upstream.toolSurface.value", "toolSurface.value must be a 43-character base64url SHA-256 digest.");
          }
        }
      }
    }
  }

  if (expectedApplicationDid !== undefined && isPlainObject(value.application)) {
    if (value.application.applicationDid !== expectedApplicationDid) {
      fail(
        "$.application.applicationDid",
        `application.applicationDid must equal the generated plugin's applicationDid (${expectedApplicationDid}).`,
      );
    }
  }

  return issues;
}

export interface RegistryValidationIssue {
  path: string;
  message: string;
}

const REGISTRY_STATUS_VOCABULARY = new Set(["active", "beta", "planned", "deprecated"]);
const REGISTRY_DID_PATTERN = /^did:[a-z0-9]+:.+$/;
const REGISTRY_HTTPS_URL_PATTERN = /^https:\/\/.+$/;
const BASE64URL_SHA256_PATTERN = /^[A-Za-z0-9_-]{43}$/;

type RegistryIssueSink = (path: string, message: string) => void;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkExactMembers(object: Record<string, unknown>, allowed: string[], path: string, fail: RegistryIssueSink): void {
  const declared = new Set(allowed);
  for (const key of Object.keys(object)) {
    if (!declared.has(key)) {
      fail(path, `undeclared member ${key}.`);
    }
  }
}

function requireMembers(object: Record<string, unknown>, required: string[], path: string, fail: RegistryIssueSink): void {
  for (const key of required) {
    if (!(key in object)) {
      fail(path, `missing required member ${key}.`);
    }
  }
}

function checkNonEmptyString(value: unknown, path: string, fail: RegistryIssueSink): void {
  if (typeof value !== "string" || value.length === 0) {
    fail(path, "must be a non-empty string.");
  }
}

function checkDid(value: unknown, path: string, fail: RegistryIssueSink): void {
  if (typeof value !== "string" || !REGISTRY_DID_PATTERN.test(value)) {
    fail(path, "must be a syntactically valid DID (did:<method>:<method-specific-id>).");
  }
}

function checkHttpsUrl(value: unknown, path: string, fail: RegistryIssueSink): void {
  if (typeof value !== "string" || !REGISTRY_HTTPS_URL_PATTERN.test(value)) {
    fail(path, "must be an HTTPS URL.");
  }
}

/** True when any generated placeholder string remains anywhere in the entry. */
function containsPlaceholder(value: unknown): boolean {
  if (typeof value === "string") {
    return value.includes("PLACEHOLDER");
  }
  if (Array.isArray(value)) {
    return value.some(containsPlaceholder);
  }
  if (isPlainObject(value)) {
    return Object.values(value).some(containsPlaceholder);
  }
  return false;
}

/** Publish gate: throw unless the entry fully satisfies the v1 publish contract. */
export function validateRegistryEntry(entry: unknown, expectedApplicationDid?: string): void {
  const issues = checkRegistryEntryV1(entry, expectedApplicationDid);
  if (issues.length > 0) {
    throw new GenerateError(
      `Registry entry is not publishable under application-registry/schema.v1.json:\n${issues.map((issue) => `  ${issue.path}: ${issue.message}`).join("\n")}`,
    );
  }
}

function validateCredentialRequirements(value: unknown): CredentialRequirement[] {
  if (!Array.isArray(value)) {
    throw new GenerateError("plugin credentialRequirements must be an array.");
  }
  const allowed = new Set(["type", "expectedAuthority", "refreshScope", "description"]);
  return value.map((item, index) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new GenerateError(`plugin credentialRequirements[${index}] must be an object.`);
    }
    const requirement = item as Record<string, unknown>;
    const unexpected = Object.keys(requirement).find((key) => !allowed.has(key));
    if (unexpected) {
      throw new GenerateError(`plugin credentialRequirements[${index}] contains undeclared member ${unexpected}.`);
    }
    if (typeof requirement.type !== "string") {
      throw new GenerateError(`plugin credentialRequirements[${index}].type must be a string.`);
    }
    if (
      requirement.expectedAuthority !== undefined &&
      (!Array.isArray(requirement.expectedAuthority) ||
        !requirement.expectedAuthority.every((entry) => typeof entry === "string"))
    ) {
      throw new GenerateError(`plugin credentialRequirements[${index}].expectedAuthority must be a string array.`);
    }
    if (
      requirement.refreshScope !== undefined &&
      (typeof requirement.refreshScope !== "string" || requirement.refreshScope.length === 0)
    ) {
      throw new GenerateError(`plugin credentialRequirements[${index}].refreshScope must be a non-empty string.`);
    }
    if (requirement.description !== undefined && typeof requirement.description !== "string") {
      throw new GenerateError(`plugin credentialRequirements[${index}].description must be a string.`);
    }
    return requirement as unknown as CredentialRequirement;
  });
}

async function loadOrgConfig(path: string): Promise<OrgConfig> {
  let parsed: OrgConfig;
  try {
    parsed = JSON.parse(await readFile(path, "utf8")) as OrgConfig;
  } catch (error) {
    throw new GenerateError(`Unable to read org config ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!parsed.publisher?.name || !parsed.publisher?.githubOrg || !parsed.application?.applicationDid) {
    throw new GenerateError(`Org config ${path} must define publisher.name, publisher.githubOrg, and application.applicationDid.`);
  }
  return parsed;
}

async function readJsonIfExists<T>(path: string): Promise<T | undefined> {
  if (!existsSync(path)) {
    return undefined;
  }
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch (error) {
    throw new GenerateError(`Unable to parse existing ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Regeneration membership (spec.md §5). A discovered tool is governed iff:
 * - there is no previous plugin (first generate → all tools), or
 * - it appears in the previous plugin's operations (still governed), or
 * - it is absent from the previous snapshot (new upstream tool — included so
 *   reviewers can't silently miss it).
 * A tool in the previous snapshot but not the previous plugin was reviewed
 * out (intentional pass-through) and stays out. Without a previous snapshot,
 * new and reviewed-out tools are indistinguishable; the previous plugin is
 * treated as authoritative and skipped tools are logged for review.
 */
function selectGovernedTools(
  tools: McpToolDefinition[],
  previousPlugin: Partial<GeneratedPlugin> | undefined,
  previousSnapshot: { tools?: Array<{ name: string }> } | undefined,
  log: (message: string) => void,
): McpToolDefinition[] {
  if (!previousPlugin) {
    return tools;
  }
  const previousOperations = new Set(Object.keys(previousPlugin.operations ?? {}));
  if (!previousSnapshot?.tools) {
    const skipped = tools.filter((tool) => !previousOperations.has(tool.name)).map((tool) => tool.name);
    if (skipped.length > 0) {
      log(
        `Warning: no previous tools-list.snapshot.json; kept the existing plugin's operations and left out: ${skipped.join(", ")}. Add any of these to plugin.json manually if they should be governed.`,
      );
    }
    return tools.filter((tool) => previousOperations.has(tool.name));
  }
  const previousSurface = new Set(previousSnapshot.tools.map((tool) => tool.name));
  return tools.filter((tool) => previousOperations.has(tool.name) || !previousSurface.has(tool.name));
}

async function loadKeepList(appDir: string): Promise<Set<string>> {
  const path = join(appDir, ".generator-keep");
  if (!existsSync(path)) {
    return new Set();
  }
  const lines = (await readFile(path, "utf8"))
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  return new Set(lines);
}

async function mergedClassification(appDir: string, upstream: UpstreamInfo): Promise<ClassificationDraft> {
  const path = join(appDir, "build-artifacts", "classification.json");
  if (!existsSync(path)) {
    return buildClassificationDraft(upstream.tools);
  }
  const existing = JSON.parse(await readFile(path, "utf8")) as ClassificationDraft;
  return mergeClassificationDraft(existing, upstream.tools);
}

async function mergedHarnessConfig(appDir: string, upstream: UpstreamInfo): Promise<HarnessConfig> {
  const path = join(appDir, "harness-config.json");
  if (!existsSync(path)) {
    return buildHarnessConfig(upstream);
  }
  const existing = JSON.parse(await readFile(path, "utf8")) as HarnessConfig;
  return mergeHarnessConfig(existing, upstream);
}

function bridgePackageJson(appName: string): object {
  return {
    name: `mpas-bridge-${appName}`,
    version: "0.1.0",
    description: `MPAS bridge MCP server for ${appName} (generated by bridge-generator)`,
    license: "Apache-2.0",
    type: "module",
    bin: { [`mpas-bridge-${appName}`]: "./dist/index.js" },
    scripts: {
      build: "rm -rf dist && tsc -p tsconfig.json && node -e \"require('node:fs').copyFileSync('src/tools.json', 'dist/tools.json')\"",
      start: "node dist/index.js",
    },
    dependencies: {
      "@modelcontextprotocol/server": "2.0.0",
      "@oma3/mpas": "0.1.0-alpha.13",
    },
    devDependencies: {
      "@types/node": "^22.15.29",
      typescript: "^5.8.3",
    },
    engines: { node: ">=22" },
  };
}

function bridgeTsconfig(): object {
  return {
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      declaration: true,
      sourceMap: true,
      outDir: "dist",
      rootDir: "src",
      skipLibCheck: true,
    },
    include: ["src/**/*.ts"],
  };
}

function bridgeReadme(appName: string, upstream: UpstreamInfo): string {
  const toolNames = upstream.tools.map((tool) => tool.name).join(", ");
  return `# mpas-bridge-${appName}

MPAS bridge MCP server for **${appName}**, generated by \`bridge-generator\` from upstream \`${upstream.serverName}\`.

Tools: ${toolNames}

The runtime in \`src/index.ts\` loads the verbatim discovered tool surface from \`src/tools.json\`. The build copies both into \`dist/\`; keep \`dist/index.js\` and \`dist/tools.json\` together when packaging or deploying the bridge.

## Usage

\`\`\`sh
npm install
npm run build
node dist/index.js --config <path-to-bridge-config.json>
\`\`\`

The bridge config format matches the MPAS demo proposer bridge (plugin path, direct Adapter URL or relay Action endpoint plus designated Verifier, agent key, independent Coordination Service URL, and workflow storage). The server auto-detects MCP 2026-07-28 Tasks clients and conventional MCP clients that need the MPAS wait-tool compatibility surface. All application tool calls are routed through MPAS: the bridge signs an initial Action Package and submits it through the configured Action endpoint; nothing is proxied directly to the upstream server. When additional approvals are required, the bridge retires that Action, constructs a replacement Action with a new Action ID and hash, explicitly creates its coordination workflow, and submits the completed replacement Action Package to the Action endpoint for the first time.

The generated package requires SDK \`0.1.0-alpha.13\` or later for dual-suite signing and verification. Use an existing Ed25519 key or generate a new P-256 key with \`mpas key generate <name> --suite P-256\`. The key selects the suite; no algorithm dispatch is generated into the bridge. Register a new DID explicitly and upgrade verification services before using it. The SDK release must be published before installing generated packages from the registry.

One bridge serves exactly one MCP client or agent identity and holds one private key for one proposer DID. Do not share a bridge process or key across independent clients; deploy a separate bridge instance and key for each agent.

This file is generated then checked in. Edit freely; regeneration preserves files listed in \`.generator-keep\`.
`;
}

function jsonFile(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
