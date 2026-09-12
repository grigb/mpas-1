import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, copyFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { it, expect } from "vitest";
import { runGenerate } from "../src/generate.js";

const root = fileURLToPath(new URL("../../", import.meta.url));

it("builds a generated bridge against the candidate SDK and signs P-256 Action and relay requests", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "mpas-generated-es256-"));
  try {
    await runGenerate({
      appName: "suite-probe", outDir, upstreamCommand: "fixture", upstreamArgs: [],
      applicationDid: "did:web:suite-probe.example", log: () => {},
      discover: async () => ({ command: "fixture", args: [], serverName: "fixture", protocolVersion: "2024-11-05", tools: [{ name: "echo", inputSchema: { type: "object" } }] }),
    });
    const bridge = join(outDir, "suite-probe/bridge");
    const modules = join(bridge, "node_modules");
    await mkdir(join(modules, "@oma3"), { recursive: true });
    await mkdir(join(modules, "@modelcontextprotocol"), { recursive: true });
    await mkdir(join(modules, "@types"), { recursive: true });
    await symlink(join(root, "sdk/protocol"), join(modules, "@oma3/mpas"), "dir");
    await symlink(join(root, "sdk/protocol/node_modules/@modelcontextprotocol/server"), join(modules, "@modelcontextprotocol/server"), "dir");
    await symlink(join(root, "sdk/protocol/node_modules/@types/node"), join(modules, "@types/node"), "dir");
    execFileSync(process.execPath, [join(root, "bridge-generator/node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"], { cwd: bridge, stdio: "pipe" });
    await copyFile(join(bridge, "src/tools.json"), join(bridge, "dist/tools.json"));
    const probe = join(bridge, "probe.mjs");
    await writeFile(probe, `
import assert from "node:assert/strict";
import { GeneratedBridge } from "./dist/index.js";
import { generateP256Key, KeyManager, ActionRelayClient, verifyMpasRfc9421, verifyApproval, computeJsonHash } from "@oma3/mpas";
const key = await generateP256Key();
const manager = KeyManager.fromJwk(key.privateJwk);
let actions = 0, polls = 0;
globalThis.fetch = async (input, init) => {
  const url = new URL(input);
  const body = Buffer.from(init.body);
  assert.equal((await verifyMpasRfc9421({ method: init.method, path: url.pathname, body, headers: init.headers, audiences: [url.origin] })).ok, true);
  assert.match(init.headers["Signature-Input"], /ecdsa-p256-sha256/);
  const request = JSON.parse(body.toString());
  if (url.pathname === "/mpas/v1/relay/poll") {
    polls++;
    return new Response(JSON.stringify({ version: "1", type: "RelayPollResponse", deliveries: [] }), { status: 200 });
  }
  const pkg = request.type === "DeliveryEnvelope" ? request.payload.actionPackage : request.actionPackage;
  assert.equal(await verifyApproval(pkg.approvalBundle.approvals[0], key.publicJwk), true);
  actions++;
  return new Response(JSON.stringify({ version: "1", type: "ActionResponse", verifier: { did: manager.did }, actionEnvelopeHash: computeJsonHash(pkg.actionEnvelope), result: "rejected", error: { code: "FIXTURE_REJECTED", message: "Fixture only" } }), { status: 200 });
};
for (const relay of [false, true]) {
  const bridge = new GeneratedBridge({ plugin: new URL("../plugin.json", import.meta.url).pathname, applicationDid: "did:web:suite-probe.example", agentKey: key.privateJwk, adapterUrl: "https://adapter.example", ...(relay ? { actionEndpoint: { url: "https://relay.example", verifierDid: manager.did } } : {}) });
  try { await bridge.handleToolCall("echo", {}); } finally { bridge.stop(); }
}
await new ActionRelayClient({ url: "https://relay.example", signer: manager }).pollDeliveries();
assert.equal(actions, 2);
assert.equal(polls, 1);
console.log("generated dual-suite build and P-256 authenticated direct/relay paths passed");
`);
    const output = execFileSync(process.execPath, [probe], { cwd: bridge, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    expect(output).toContain("authenticated direct/relay paths passed");
  } finally { await rm(outDir, { recursive: true, force: true }); }
}, 20_000);
