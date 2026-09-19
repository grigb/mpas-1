import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createBridgeFromConfig } from "../../src/bridge/github-bridge.js";
import {
  ActionEndpointClient,
  ActionPackageBuilder,
  KeyManager,
  verifyMpasRfc9421,
  type MpasHeaders,
} from "@oma3/mpas";

const fixturesDir = join(process.cwd(), "tests", "fixtures");
const pluginFixture = join(fixturesDir, "plugins", "github-mirror-plugin.json");
const proposerKeyPath = join(fixturesDir, "test-keys", "proposer.json");
const maintainerKeyPath = join(fixturesDir, "test-keys", "maintainer-a.json");
const toolsPath = join(process.cwd(), "bridge-tools", "github-mirror-tools.json");

const VALID_ARGS = {
  owner: "example-org",
  repo: "mpas-demo-repository",
  pullNumber: 42,
  baseRef: "main",
  expectedHeadSha: "abc123",
  mergeMethod: "squash",
};

interface CapturedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

interface MockEndpoint {
  url: string;
  origin: string;
  captured: CapturedRequest[];
  close(): Promise<void>;
}

const openServers: Server[] = [];

afterEach(async () => {
  await Promise.allSettled(openServers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function startMockEndpoint(): Promise<MockEndpoint> {
  const captured: CapturedRequest[] = [];
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      captured.push({
        method: request.method ?? "",
        path: request.url ?? "",
        headers: request.headers,
        body: Buffer.concat(chunks),
      });
      response.writeHead(200, { "content-type": "application/mpas+json" });
      response.end(
        JSON.stringify({
          version: "1",
          type: "ActionResponse",
          result: "pending",
          actionEnvelopeHash: { alg: "sha-256", value: "A".repeat(43) },
        }),
      );
    });
  });
  openServers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    origin: `http://127.0.0.1:${port}`,
    captured,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function writeConfig(overrides: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "mpas-bridge-launch-"));
  const configPath = join(dir, "bridge-config.json");
  await writeFile(configPath, JSON.stringify(overrides));
  return configPath;
}

async function baseConfig(endpoint: MockEndpoint, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return {
    plugin: pluginFixture,
    adapter: { url: endpoint.url },
    agent: { keyFile: proposerKeyPath },
    tools: toolsPath,
    workflow: { pollIntervalMs: 100 },
    ...extra,
  };
}

async function stopQuietly(bridge: { stop?: () => void }): Promise<void> {
  bridge.stop?.();
  await new Promise((resolve) => setTimeout(resolve, 25));
}

describe("generated bridge launch controls (N35/N36)", () => {
  it("starts with a valid plugin through the exported SDK loader", async () => {
    const endpoint = await startMockEndpoint();
    const bridge = await createBridgeFromConfig(await writeConfig(await baseConfig(endpoint)));

    expect(bridge.getToolDefinitions().length).toBeGreaterThan(0);
    await bridge.start();
    await stopQuietly(bridge);
    expect(endpoint.captured).toHaveLength(0);
  });

  it("submits direct Actions with valid RFC 9421 headers by default", async () => {
    const endpoint = await startMockEndpoint();
    const keyManager = await KeyManager.fromFile(proposerKeyPath);
    const bridge = await createBridgeFromConfig(await writeConfig(await baseConfig(endpoint)));
    await bridge.start();
    try {
      await bridge.handleToolCall("merge_pull_request_mirror", VALID_ARGS);
    } finally {
      await stopQuietly(bridge);
    }

    expect(endpoint.captured).toHaveLength(1);
    const request = endpoint.captured[0];
    expect(request.method).toBe("POST");
    expect(request.path).toBe("/mpas/v1/verifier/action");
    const headerNames = Object.keys(request.headers).map((name) => name.toLowerCase());
    expect(headerNames).toContain("signature-input");
    expect(headerNames).toContain("signature");
    expect(headerNames).toContain("content-digest");

    const verification = await verifyMpasRfc9421({
      method: "POST",
      path: request.path,
      headers: request.headers as MpasHeaders,
      body: request.body,
      audiences: [endpoint.origin],
      clockSkewSeconds: 30,
    });
    expect(verification).toMatchObject({ ok: true, did: keyManager.did });

    // The signed body is bound to the endpoint audience and the proposer DID.
    const submitted = JSON.parse(request.body.toString("utf8")) as {
      audience?: string;
      actionPackage: { actionEnvelope: { proposer: { did: string } } };
    };
    expect(submitted.audience).toBe(endpoint.origin);
    expect(submitted.actionPackage.actionEnvelope.proposer.did).toBe(keyManager.did);
  });

  it("starts with matching legacy Application and profile values", async () => {
    const endpoint = await startMockEndpoint();
    const plugin = JSON.parse(await readFile(pluginFixture, "utf8")) as {
      applicationDid: string;
      executionProfile: { id: string; format?: string };
    };
    const bridge = await createBridgeFromConfig(
      await writeConfig(
        await baseConfig(endpoint, {
          applicationDid: plugin.applicationDid,
          executionProfile: {
            id: plugin.executionProfile.id,
            format: plugin.executionProfile.format ?? "mcp.toolsCall",
          },
        }),
      ),
    );
    expect(bridge.getToolDefinitions().length).toBeGreaterThan(0);
    await stopQuietly(bridge);
  });

  it.each([
    ["applicationDid", { applicationDid: "did:web:other.example" }],
    [
      "profile id",
      { executionProfile: { id: "did:web:profiles.example:other", format: "mcp.toolsCall" } },
    ],
    [
      "profile format",
      { executionProfile: { id: "did:web:profiles.oma3.org:mcp", format: "mcp.other" } },
    ],
  ])("fails before endpoint contact on %s mismatch", async (_label, binding) => {
    const endpoint = await startMockEndpoint();
    const config = await baseConfig(endpoint);
    if ("applicationDid" in binding) {
      config.applicationDid = binding.applicationDid;
    } else {
      config.executionProfile = binding.executionProfile;
    }
    await expect(createBridgeFromConfig(await writeConfig(config))).rejects.toThrow(/does not match the plugin/);
    expect(endpoint.captured).toHaveLength(0);
  });

  it.each([
    ["invalid JSON", () => Promise.resolve("{")],
    [
      "duplicate keys",
      async () =>
        JSON.stringify(JSON.parse(await readFile(pluginFixture, "utf8"))).replace(
          '"type":"MpasApplicationPlugin"',
          '"type":"MpasApplicationPlugin","type":"MpasApplicationPlugin"',
        ),
    ],
    [
      "resource-limit (unsafe regex)",
      () =>
        Promise.resolve(
          JSON.stringify({
            version: "1",
            type: "MpasApplicationPlugin",
            pluginDid: "did:web:plugins.example:hostile",
            pluginVersion: "1.0.0",
            publisherDid: "did:web:publisher.example",
            applicationDid: "did:web:app.example",
            executionProfile: { id: "did:web:profiles.example:mcp", protocolVersion: "2024-11-05" },
            operations: {
              probe: {
                executionPayloadSchema: {
                  type: "object",
                  properties: { a: { type: "string", pattern: "^a+$" } },
                },
              },
            },
          }),
        ),
    ],
  ])("fails before endpoint contact with a %s plugin", async (_label, buildDocument) => {
    const endpoint = await startMockEndpoint();
    const dir = await mkdtemp(join(tmpdir(), "mpas-bridge-hostile-"));
    const pluginPath = join(dir, "plugin.json");
    await writeFile(pluginPath, await buildDocument());
    const config = await baseConfig(endpoint);
    config.plugin = pluginPath;
    await expect(createBridgeFromConfig(await writeConfig(config))).rejects.toThrow(
      /Unable to load plugin/,
    );
    expect(endpoint.captured).toHaveLength(0);
  });

  it("is unsigned only with explicit trusted-unenforcing opt-out, with one startup warning", async () => {
    const endpoint = await startMockEndpoint();
    const warnings: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
      warnings.push(String(chunk));
      return (originalWrite as (...args: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stderr.write;
    let bridge: Awaited<ReturnType<typeof createBridgeFromConfig>>;
    try {
      bridge = await createBridgeFromConfig(
        await writeConfig(await baseConfig(endpoint, { adapter: { url: endpoint.url, trustedUnenforcingEndpoint: true } })),
      );
    } finally {
      process.stderr.write = originalWrite;
    }

    expect(warnings.filter((line) => line.includes("trusted_unenforcing_endpoint"))).toHaveLength(1);
    await bridge.start();
    try {
      await bridge.handleToolCall("merge_pull_request_mirror", VALID_ARGS);
    } finally {
      await stopQuietly(bridge);
    }

    expect(endpoint.captured).toHaveLength(1);
    const headerNames = Object.keys(endpoint.captured[0].headers).map((name) => name.toLowerCase());
    expect(headerNames).not.toContain("signature-input");
    expect(headerNames).not.toContain("signature");
  });

  it("fails signer identity mismatch before transmission", async () => {
    const endpoint = await startMockEndpoint();
    const proposer = await KeyManager.fromFile(proposerKeyPath);
    const maintainer = await KeyManager.fromFile(maintainerKeyPath);
    const plugin = JSON.parse(await readFile(pluginFixture, "utf8")) as {
      applicationDid: `did:${string}:${string}`;
      executionProfile: { id: `did:${string}:${string}`; format?: string };
    };
    const builder = new ActionPackageBuilder({
      applicationDid: plugin.applicationDid,
      executionProfile: { id: plugin.executionProfile.id, format: plugin.executionProfile.format ?? "mcp.toolsCall" },
      keyManager: proposer,
    });
    const pkg = await builder.buildFromToolCall("merge_pull_request_mirror", VALID_ARGS);
    const mismatched = new ActionEndpointClient({ url: endpoint.url, signer: Promise.resolve(maintainer) });

    await expect(
      mismatched.submitActionRequest({ version: "1", type: "ActionRequest", actionPackage: pkg }),
    ).rejects.toThrow(/does not match signer DID/);
    expect(endpoint.captured).toHaveLength(0);
  });

  it("contains no raw plugin cast in the checked-in generated bridge", async () => {
    const source = await readFile(join(process.cwd(), "src", "bridge", "github-bridge.ts"), "utf8");
    expect(source).not.toContain("JSON.parse(readFileSync(plugin");
    expect(source).toContain("loadPlugin as loadSdkPlugin");
  });
});
