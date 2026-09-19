import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { realpathSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type ActionRelayWebSocket,
  type DeliveryEnvelope,
  type ActionRequest,
  type ActionResponse,
  type RelayDeliveryResponse,
  type RelayPollResponse,
} from "@oma3/mpas";
import "../fixtures/action-fixture-clock.js";
import type { StartedDaemon } from "../../src/adapter/daemon.js";
import type { VerifierRelayClient, VerifierRelayState, VerifierRelayStateStore } from "../../src/adapter/verifier-relay-worker.js";
import { runCli } from "../../src/cli/index.js";
import { startDaemon } from "../../src/adapter/daemon.js";
import { startCoordinationDaemon } from "../../src/coordination/daemon.js";

// Recording wrappers around the REAL daemon entry points: every start goes
// through the accepted implementation and is captured for assertions and
// cleanup. `adapter start` proofs require that no Coordination start occurs.
const adapterStarts: StartedDaemon[] = [];
const coordinationStarts: Awaited<ReturnType<typeof startCoordinationDaemon>>[] = [];

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

vi.mock("../../src/coordination/daemon.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/coordination/daemon.js")>();
  return {
    ...mod,
    startCoordinationDaemon: async (options: Parameters<typeof mod.startCoordinationDaemon>[0]) => {
      const daemon = await mod.startCoordinationDaemon(options);
      coordinationStarts.push(daemon);
      return daemon;
    },
  };
});

// The CLI offers no trust injection, so these module boundaries carry the
// accepted test isolation (`trustContext: null, confirmPluginUse: async () =>
// true` in the accepted daemon fixtures) to the CLI path: the Artifact Trust
// lookup is not requested (zero external network) and the operator
// confirmation auto-accepts. Every other lifecycle surface stays real.
vi.mock("../../src/adapter/trust.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/adapter/trust.js")>();
  return { ...mod, DEFAULT_TRUST_CONTEXT: null };
});

vi.mock("../../src/adapter/trust-prompt.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/adapter/trust-prompt.js")>();
  return { ...mod, promptPluginUse: async () => true };
});

const fixturesDir = fileURLToPath(new URL("../fixtures/", import.meta.url));
const realTmp = () => realpathSync(tmpdir());

class MemoryWriter {
  text = "";
  write(chunk: string | Uint8Array): boolean {
    this.text += chunk.toString();
    return true;
  }
}

class FakeSocket implements ActionRelayWebSocket {
  readonly close = vi.fn((_code?: number, _reason?: string) => this.emit("close"));
  private readonly listeners = new Map<string, Set<(event: unknown) => void>>();

  addEventListener(type: "message" | "close" | "error", listener: (event: unknown) => void): void {
    const listeners = this.listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: "message" | "close" | "error", listener: (event: unknown) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  private emit(type: "message" | "close" | "error"): void {
    for (const listener of this.listeners.get(type) ?? []) listener({ type });
  }
}

class RecordingRelayClient implements VerifierRelayClient {
  readonly socket = new FakeSocket();
  polls = 0;
  readonly submissions: DeliveryEnvelope<ActionResponse>[] = [];

  constructor(private readonly relayUrl: string, private readonly verifierDid: DeliveryEnvelope<ActionRequest>["sender"]) {}

  async pollDeliveries(options: { cursor?: string } = {}): Promise<RelayPollResponse> {
    this.polls += 1;
    return { version: "1", type: "RelayPollResponse", deliveries: [], nextCursor: options.cursor ?? "cursor-0" };
  }

  async submitActionResponse(envelope: DeliveryEnvelope<ActionResponse>): Promise<RelayDeliveryResponse> {
    this.submissions.push(structuredClone(envelope));
    return { version: "1", type: "RelayDeliveryResponse", accepted: true };
  }

  async connectWorkNotifications(_input: { onWorkAvailable: () => void | Promise<void> }) {
    return {
      socket: this.socket,
      relayUrl: this.relayUrl,
      audience: this.relayUrl,
      did: this.verifierDid,
    };
  }
}

class MemoryStateStore implements VerifierRelayStateStore {
  state?: VerifierRelayState;

  async load(identity: { relayUrl: string; verifierDid: VerifierRelayState["verifierDid"] }): Promise<VerifierRelayState> {
    return {
      version: "1",
      type: "MpasVerifierRelayState",
      relayUrl: identity.relayUrl,
      verifierDid: identity.verifierDid,
      responses: {},
    };
  }

  async save(state: VerifierRelayState): Promise<void> {
    this.state = structuredClone(state);
  }
}

async function fixturePaths(): Promise<{ configDir: string; credentialDir: string; journalPath: string }> {
  const configDir = await mkdtemp(join(realTmp(), "mpas-lifecycle-config-"));
  const config = JSON.parse(
    await readFile(join(fixturesDir, "configs", "policy-fixtures", "github-auto-approve.json"), "utf8"),
  ) as Record<string, unknown>;
  (config.plugin as Record<string, unknown>).path = join(fixturesDir, "plugins", "github-mirror-plugin.json");
  await writeFile(join(configDir, "github-auto-approve.json"), `${JSON.stringify(config, null, 2)}\n`);

  const credentialDir = await mkdtemp(join(realTmp(), "mpas-lifecycle-credentials-"));
  const credentialPath = join(credentialDir, "github-mirror-token.json");
  await writeFile(credentialPath, `${JSON.stringify({ value: "ghp_test" })}\n`, { mode: 0o600 });
  await chmod(credentialPath, 0o600);

  const journalDir = await mkdtemp(join(realTmp(), "mpas-lifecycle-journal-"));
  return { configDir, credentialDir, journalPath: join(journalDir, "dispatch-ledger.jsonl") };
}

function cliOptions(paths: { configDir: string; credentialDir: string; journalPath: string }): string[] {
  return [
    "--config-dir", paths.configDir,
    "--credential-dir", paths.credentialDir,
    "--adapter-key", join(fixturesDir, "test-keys", "adapter.json"),
    "--journal-path", paths.journalPath,
    "--port", "0",
  ];
}

async function readActionRequest(): Promise<string> {
  const actionPackage = JSON.parse(
    await readFile(join(fixturesDir, "core", "valid-no-approval-required.json"), "utf8"),
  ) as unknown;
  return JSON.stringify({ version: "1", type: "ActionRequest", actionPackage });
}

afterEach(async () => {
  await Promise.all(adapterStarts.splice(0).map((daemon) => daemon.app.close()));
  await Promise.all(coordinationStarts.splice(0).map((daemon) => daemon.app.close()));
});

describe("adapter-only lifecycle matrix (issue 25)", () => {
  it("`mpas adapter start` runs without local Coordination, reports the bound address, serves health, and accepts an Action request", async () => {
    const paths = await fixturePaths();
    const stdout = new MemoryWriter();
    const stderr = new MemoryWriter();

    const result = await runCli(["adapter", "start", ...cliOptions(paths)], { stdout, stderr });

    expect(result.exitCode).toBe(0);
    expect(stderr.text).toBe("");
    const report = JSON.parse(stdout.text) as Record<string, unknown>;
    expect(report.status).toBe("started");
    expect(report.address).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect("coordinationAddress" in report).toBe(false);
    expect(coordinationStarts).toHaveLength(0);

    const address = report.address as string;
    const health = await fetch(`${address}/mpas/v1/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ status: "ok" });

    const action = await fetch(`${address}/mpas/v1/verifier/action`, {
      method: "POST",
      headers: { "content-type": "application/mpas+json" },
      body: await readActionRequest(),
    });
    expect(action.status).toBe(200);
    expect(await action.json()).toMatchObject({
      type: "ActionResponse",
      result: "executed",
      executionReceipt: { type: "ExecutionReceipt" },
    });
    expect(coordinationStarts).toHaveLength(0);
  });

  it("startup failure exits nonzero and closes partial resources", async () => {
    // CLI level: an unparseable deployment config fails the start with exit 1.
    const badConfigDir = await mkdtemp(join(realTmp(), "mpas-lifecycle-bad-config-"));
    await writeFile(join(badConfigDir, "broken.json"), "{ not json\n");
    const stdout = new MemoryWriter();
    const stderr = new MemoryWriter();
    const failed = await runCli(
      ["adapter", "start", "--config-dir", badConfigDir, "--credential-dir", await mkdtemp(join(realTmp(), "mpas-lifecycle-empty-cred-")), "--adapter-key", join(fixturesDir, "test-keys", "adapter.json")],
      { stdout, stderr },
    );
    expect(failed.exitCode).toBe(1);
    expect(stderr.text.length).toBeGreaterThan(0);

    // Partial-resource close: a listen failure after construction must release
    // the journal handle and leave no listener behind.
    const paths = await fixturePaths();
    const blocker = createHttpServer((_, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
    await new Promise<void>((resolveListen) => blocker.listen(0, "127.0.0.1", resolveListen));
    const blockedAddress = blocker.address();
    const blockedPort = typeof blockedAddress === "object" && blockedAddress !== null ? blockedAddress.port : 0;
    try {
      await expect(startDaemon({
        configDir: paths.configDir,
        credentialDir: paths.credentialDir,
        adapterKeyPath: join(fixturesDir, "test-keys", "adapter.json"),
        journalPath: paths.journalPath,
        port: blockedPort,
        trustContext: null,
        confirmPluginUse: async () => true,
      })).rejects.toThrow();
      // The port is still owned by the blocker — no partial adapter listener.
      const blockers = await fetch(`http://127.0.0.1:${blockedPort}/`);
      expect(blockers.status).toBe(200);
      // The failed start released the journal handle: a fresh start on the same
      // journal path succeeds.
      const recovered = await startDaemon({
        configDir: paths.configDir,
        credentialDir: paths.credentialDir,
        adapterKeyPath: join(fixturesDir, "test-keys", "adapter.json"),
        journalPath: paths.journalPath,
        port: 0,
        trustContext: null,
        confirmPluginUse: async () => true,
      });
      await recovered.app.close();
    } finally {
      blocker.close();
    }
  });

  it("shutdown closes the Adapter and the hosted-Verifier relay worker", async () => {
    const paths = await fixturePaths();
    const relayClient = new RecordingRelayClient("https://relay.example", "did:jwk:verifier" as DeliveryEnvelope<ActionRequest>["sender"]);
    const stateStore = new MemoryStateStore();

    const daemon = await startDaemon({
      configDir: paths.configDir,
      credentialDir: paths.credentialDir,
      adapterKeyPath: join(fixturesDir, "test-keys", "adapter.json"),
      journalPath: paths.journalPath,
      port: 0,
      trustContext: null,
      confirmPluginUse: async () => true,
      verifierRelayUrl: "https://relay.example",
      verifierRelayClient: relayClient,
      verifierRelayStateStore: stateStore,
      verifierPollIntervalMs: 600_000,
    });
    adapterStarts.push(daemon);
    const worker = daemon.verifierRelayWorker;
    expect(worker).toBeDefined();

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(worker?.getStatus()).toBe("connected");
    expect(relayClient.polls).toBeGreaterThan(0);

    const health = await fetch(`${daemon.address}/mpas/v1/health`);
    expect(health.status).toBe(200);

    await daemon.app.close();
    adapterStarts.length = 0;

    expect(worker?.getStatus()).toBe("stopped");
    expect(relayClient.socket.close).toHaveBeenCalledWith(1001, "Verifier shutdown");
    await expect(fetch(`${daemon.address}/mpas/v1/health`)).rejects.toThrow();

    // The close hook also released the dispatch ledger: a fresh start on the
    // same journal path succeeds.
    const recovered = await startDaemon({
      configDir: paths.configDir,
      credentialDir: paths.credentialDir,
      adapterKeyPath: join(fixturesDir, "test-keys", "adapter.json"),
      journalPath: paths.journalPath,
      port: 0,
      trustContext: null,
      confirmPluginUse: async () => true,
    });
    await recovered.app.close();
  });

  it("remote relay mode does not start local Coordination", async () => {
    const unreachableRelay: HttpServer = createHttpServer((_, response) => {
      response.writeHead(501, { "content-type": "application/json" });
      response.end("{}");
    });
    await new Promise<void>((resolveListen) => unreachableRelay.listen(0, "127.0.0.1", resolveListen));
    const relayAddress = unreachableRelay.address();
    const relayPort = typeof relayAddress === "object" && relayAddress !== null ? relayAddress.port : 0;

    try {
      const paths = await fixturePaths();
      const stdout = new MemoryWriter();
      const stderr = new MemoryWriter();
      const result = await runCli(
        ["adapter", "start", ...cliOptions(paths), "--verifier-relay-url", `http://127.0.0.1:${relayPort}`],
        { stdout, stderr },
      );

      expect(result.exitCode).toBe(0);
      const report = JSON.parse(stdout.text) as Record<string, unknown>;
      expect(report.status).toBe("started");
      expect(report.verifierRelayUrl).toBe(`http://127.0.0.1:${relayPort}`);
      expect("coordinationAddress" in report).toBe(false);
      expect(coordinationStarts).toHaveLength(0);

      const relayed = adapterStarts.at(-1);
      expect(relayed?.verifierRelayWorker).toBeDefined();
      const health = await fetch(`${report.address as string}/mpas/v1/health`);
      expect(health.status).toBe(200);
    } finally {
      unreachableRelay.close();
    }
  });

  it("`mpas daemon start` remains the combined local Adapter and Coordination command", async () => {
    const paths = await fixturePaths();
    const stdout = new MemoryWriter();
    const stderr = new MemoryWriter();

    const result = await runCli(
      ["daemon", "start", ...cliOptions(paths), "--coordination-port", "0"],
      { stdout, stderr },
    );

    expect(result.exitCode).toBe(0);
    const report = JSON.parse(stdout.text) as Record<string, unknown>;
    expect(report.status).toBe("started");
    expect(report.address).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(report.coordinationAddress).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(coordinationStarts).toHaveLength(1);

    const health = await fetch(`${report.address as string}/mpas/v1/health`);
    expect(health.status).toBe(200);
    const coordinationHealth = await fetch(`${report.coordinationAddress as string}/mpas/v1/coordination/health`);
    expect(coordinationHealth.status).toBe(200);
  });
});
