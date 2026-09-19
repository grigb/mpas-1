import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { compactVerify, importJWK, type JWK } from "jose";
import { describe, expect, it } from "vitest";
import type { ActionPackage, ActionResponse, Did } from "../../src/index.js";
import type { CreateTaskResult } from "../../src/lib/mcp-tasks-extension.js";
import { MPAS_WAIT_TOOL_NAME } from "../../src/lib/bridge-compatibility.js";
import { ProposerBridge } from "../../src/lib/bridge-runtime.js";
import { BridgeWorkflowEngine } from "../../src/lib/workflow-engine.js";
import {
  InvalidResultDisclosureMapError,
  RESULT_DISCLOSURE_DENIED_CODE,
  RESULT_DISCLOSURE_DENIED_MESSAGE,
  validateResultDisclosureMap,
  type ResultDisclosureMap,
} from "../../src/lib/result-disclosure.js";
import {
  MemoryWorkflowStore,
  type BridgeWorkflowState,
  type WorkflowStore,
} from "../../src/lib/workflow-store.js";

const fixtures = fileURLToPath(new URL("../fixtures/", import.meta.url));
const CANARY = "SYNTHETIC_CREDENTIAL_CANARY_62";
const NOW = Date.parse("2026-09-06T08:00:00.000Z");

interface KeyFixture {
  did: Did;
  publicJwk: JWK;
}

async function fixture<T>(relative: string): Promise<T> {
  return JSON.parse(await readFile(`${fixtures}${relative}`, "utf8")) as T;
}

describe("result disclosure map", () => {
  it("copies a complete map, owns reserved names, and ignores later caller mutation", () => {
    const supplied = Object.create(null) as Record<string, "allow" | "deny">;
    Object.defineProperty(supplied, "__proto__", { value: "deny", enumerable: true, writable: true });
    Object.defineProperty(supplied, "constructor", { value: "allow", enumerable: true, writable: true });
    const validated = validateResultDisclosureMap(supplied, ["__proto__", "constructor"]);
    supplied["constructor"] = "deny" as "allow" | "deny";

    expect(Object.hasOwn(validated, "__proto__")).toBe(true);
    expect(Object.hasOwn(validated, "constructor")).toBe(true);
    expect(validated["constructor"]).toBe("allow");
    expect(Object.isFrozen(validated)).toBe(true);
  });

  it.each([
    ["missing", { allowed: "allow" }, ["allowed", "missing"]],
    ["unknown", { allowed: "allow", unknown: "deny" }, ["allowed"]],
    ["invalid", { allowed: "redact" }, ["allowed"]],
    ["duplicate tools", { allowed: "allow" }, ["allowed", "allowed"]],
  ])("rejects %s maps", (_label, supplied, toolNames) => {
    expect(() => validateResultDisclosureMap(supplied, toolNames)).toThrow(InvalidResultDisclosureMapError);
  });

  it("rejects accessor and symbol properties without invoking them", () => {
    let invoked = 0;
    const supplied = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(supplied, "allowed", { enumerable: true, get: () => { invoked += 1; return "allow"; } });
    expect(() => validateResultDisclosureMap(supplied, ["allowed"])).toThrow(InvalidResultDisclosureMapError);
    expect(invoked).toBe(0);
    expect(() => validateResultDisclosureMap({ allowed: "allow", [Symbol("x")]: "deny" }, ["allowed"]))
      .toThrow(InvalidResultDisclosureMapError);
  });
});

describe("BridgeWorkflowEngine disclosure boundary", () => {
  it("retains deny when the caller mutates the map before startup reconciliation", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const { taskId } = seedState(store, actionPackage, "created", 700);
    const observed = counters();
    const supplied: Record<string, "allow" | "deny"> = { secret_tool: "deny" };
    const engine = disclosureEngine(store, supplied, observed);

    supplied.secret_tool = "allow";
    await engine.reconcile();

    expect(observed).toEqual({ package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 });
    expect(store.getWorkflow(taskId)).toMatchObject({
      state: "unresolvable",
      resolution: {
        kind: "unresolvable",
        errorCode: RESULT_DISCLOSURE_DENIED_CODE,
        errorMessage: RESULT_DISCLOSURE_DENIED_MESSAGE,
      },
    });
  });

  it("retains deny when the caller mutates the map before a fresh proposal", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const observed = counters();
    const supplied: Record<string, "allow" | "deny"> = { secret_tool: "deny" };
    const engine = disclosureEngine(store, supplied, observed);

    supplied.secret_tool = "allow";
    const proposed = await engine.propose(workflowInput(actionPackage, "secret_tool", 701));

    expect(proposed).toMatchObject({ kind: "deferred", record: { state: "unresolvable" } });
    expect(observed.endpoint).toBe(0);
    expect(proposed.record.resolution).toMatchObject({
      kind: "unresolvable",
      errorCode: RESULT_DISCLOSURE_DENIED_CODE,
    });
  });

  it("ignores mutation, deletion, and addition after construction", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const response = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const observed = counters();
    const supplied: Record<string, "allow" | "deny"> = {
      denied_tool: "deny",
      allowed_tool: "allow",
    };
    const engine = disclosureEngine(store, supplied, observed, response);

    supplied.denied_tool = "allow";
    delete supplied.allowed_tool;
    supplied.added_tool = "allow";

    const denied = await engine.propose(workflowInput(actionPackage, "denied_tool", 702));
    const allowed = await engine.propose(workflowInput(actionPackage, "allowed_tool", 703));
    const added = await engine.propose(workflowInput(actionPackage, "added_tool", 704));

    expect(denied).toMatchObject({ kind: "deferred", record: { state: "unresolvable" } });
    expect(allowed).toMatchObject({ kind: "settled", record: { state: "resolved" } });
    expect(added).toMatchObject({ kind: "deferred", record: { state: "unresolvable" } });
    expect(observed.endpoint).toBe(1);
  });

  it("rejects accessor, symbol, and invalid-value maps without invoking accessors", () => {
    let invoked = 0;
    const accessor = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(accessor, "secret_tool", {
      enumerable: true,
      get: () => { invoked += 1; return "allow"; },
    });
    const symbol = { secret_tool: "deny", [Symbol("hidden")]: "allow" };

    expect(() => disclosureEngine(new MemoryWorkflowStore(), accessor as ResultDisclosureMap))
      .toThrow(InvalidResultDisclosureMapError);
    expect(invoked).toBe(0);
    expect(() => disclosureEngine(new MemoryWorkflowStore(), symbol as ResultDisclosureMap))
      .toThrow(InvalidResultDisclosureMapError);
    expect(() => disclosureEngine(new MemoryWorkflowStore(), { secret_tool: "redact" } as unknown as ResultDisclosureMap))
      .toThrow(InvalidResultDisclosureMapError);
  });

  it.each([
    ["missing", Object.create(null)],
    ["inherited", Object.create({ secret_tool: "allow" })],
  ])("denies %s operations because they are not own rules", async (_label, supplied) => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const observed = counters();
    const engine = disclosureEngine(store, supplied as ResultDisclosureMap, observed);

    const proposed = await engine.propose(workflowInput(actionPackage, "secret_tool", 705));

    expect(proposed).toMatchObject({
      kind: "deferred",
      record: {
        state: "unresolvable",
        resolution: { kind: "unresolvable", errorCode: RESULT_DISCLOSURE_DENIED_CODE },
      },
    });
    expect(observed.endpoint).toBe(0);
  });

  it("preserves true own reserved names and allows only the explicit allow entry", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const response = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const observed = counters();
    const supplied = Object.create(null) as Record<string, "allow" | "deny">;
    Object.defineProperty(supplied, "__proto__", { value: "deny", enumerable: true, writable: true });
    Object.defineProperty(supplied, "constructor", { value: "allow", enumerable: true, writable: true });
    const engine = disclosureEngine(store, supplied, observed, response);

    supplied.__proto__ = "allow";
    supplied["constructor"] = "deny" as "allow" | "deny";
    const denied = await engine.propose(workflowInput(actionPackage, "__proto__", 706));
    const allowed = await engine.propose(workflowInput(actionPackage, "constructor", 707));

    expect(denied).toMatchObject({ kind: "deferred", record: { state: "unresolvable" } });
    expect(allowed).toMatchObject({ kind: "settled", record: { state: "resolved" } });
    expect(observed).toMatchObject({ endpoint: 1, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 });
  });

  it("preserves direct-SDK behavior when the option is omitted", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const response = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const observed = counters();
    const engine = disclosureEngine(store, undefined, observed, response);

    const proposed = await engine.propose(workflowInput(actionPackage, "unlisted_tool", 708));

    expect(proposed).toMatchObject({ kind: "settled", record: { state: "resolved" } });
    expect(observed.endpoint).toBe(1);
  });
});

describe("ProposerBridge disclosure boundary", () => {
  it("denies before Action construction and returns fixed Tasks and compatibility errors", async () => {
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const counters = { package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 };
    const bridge = disclosureBridge(store, {
      counters,
      buildActionPackage: async () => {
        counters.package += 1;
        throw new Error(`credential access ${CANARY}`);
      },
    });

    const created = await bridge.handleToolCall("secret_tool", { credential: CANARY }) as CreateTaskResult;
    const observed = bridge.handleTasksGet(created.taskId);
    const compatibility = await bridge.handleCompatibilityToolCall("secret_tool", { credential: CANARY });

    expect(created).toMatchObject({ status: "completed", statusMessage: RESULT_DISCLOSURE_DENIED_MESSAGE });
    expect(observed).toMatchObject({
      status: "completed",
      result: {
        isError: true,
        structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE, message: RESULT_DISCLOSURE_DENIED_MESSAGE },
      },
    });
    expect(compatibility).toMatchObject({
      isError: true,
      structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE, message: RESULT_DISCLOSURE_DENIED_MESSAGE, retryable: false },
    });
    expect(counters).toEqual({ package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 });
    const freshRecord = store.getWorkflow(created.taskId);
    expect(freshRecord).toMatchObject({ state: "unresolvable", toolName: "secret_tool" });
    expect(JSON.stringify([created, observed, compatibility, freshRecord])).not.toContain(CANARY);

    await bridge.start();
    await bridge.pollOnce();
    expect(store.getWorkflow(created.taskId)).toEqual(freshRecord);
    expect(counters).toEqual({ package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 });
    bridge.stop();
  });

  it("keeps authentic allowed output and receipt byte-equivalent and cryptographically valid", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const response = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const adapter = await fixture<KeyFixture>("keys/adapter.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const bridge = allowedFixtureBridge(store, actionPackage, response);

    const created = await bridge.handleToolCall("create_issue", { ordinary: true });
    // The allowed call may settle immediately (CompleteToolCallResult) or defer (CreateTaskResult).
    // Find the task by listing recoverable or terminal workflows in the store.
    const allRecords = [...store.listRecoverableWorkflows()];
    // If no recoverable, check terminal by scanning (store has no listAll; the record was resolved).
    // Use the known action ID pattern from the fixture to find it.
    const taskId = "taskId" in created
      ? (created as CreateTaskResult).taskId
      : (() => {
        // Settled immediately; find the workflow by scanning store (MemoryWorkflowStore exposes getWorkflowByActionId)
        const actionEnvelope = actionPackage.actionEnvelope as { actionId: { value: string } };
        const rec = store.getWorkflowByActionId(actionEnvelope.actionId.value);
        return rec!.taskId;
      })();
    const tasksResult = bridge.handleTasksGet(taskId);
    const compatibility = await allowedFixtureBridge(
      new MemoryWorkflowStore({ now: () => NOW }),
      actionPackage,
      response,
    ).handleCompatibilityToolCall("create_issue", { ordinary: true });

    expect(tasksResult).toMatchObject({ result: response.executionResult });
    expect(compatibility).toEqual(response.executionResult);
    const stored = store.getWorkflow(taskId);
    expect(stored?.resolution).toEqual({
      kind: "resolved",
      actionResponse: response,
      executionReceipt: response.executionReceipt,
    });
    const key = await importJWK(adapter.publicJwk, "EdDSA");
    await expect(compactVerify(response.executionReceipt!.signature, key)).resolves.toBeDefined();
  });

  it("stops every recoverable state before new dispatch and exposes only fixed local errors", async () => {
    const packageTemplate = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const states: BridgeWorkflowState[] = [
      "created",
      "awaitingApprovals",
      "readyForSubmission",
      "submittingToVerifier",
      "awaitingVerifierResult",
      "policyUnavailable",
    ];
    const seeds = states.map((state, index) => seedState(store, packageTemplate, state, index));
    const counters = { package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 };
    const bridge = disclosureBridge(store, { counters });

    await bridge.start();
    await bridge.pollOnce();
    for (const { taskId, actionId } of seeds) {
      expect(store.getWorkflow(taskId)).toMatchObject({
        state: "unresolvable",
        resolution: { kind: "unresolvable", errorCode: RESULT_DISCLOSURE_DENIED_CODE },
      });
      const tasks = bridge.handleTasksGet(taskId);
      const compatibility = await bridge.handleCompatibilityToolCall(MPAS_WAIT_TOOL_NAME, { actionId, timeoutSeconds: 0 });
      expect(JSON.stringify([tasks, compatibility])).not.toContain(CANARY);
      expect(tasks).toMatchObject({ result: { structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE } } });
      expect(compatibility).toMatchObject({ structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE } });
    }
    expect(counters).toEqual({ package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 });
    bridge.stop();
  });

  it("filters hostile old terminal result and error views without changing stored signed evidence", async () => {
    const packageTemplate = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const signed = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const store = new MemoryWorkflowStore({ now: () => NOW });
    const resolved = seedState(store, packageTemplate, "created", 100);
    store.resolveWorkflow(resolved.taskId, {
      kind: "resolved",
      actionResponse: { ...signed, executionResult: { content: [{ type: "text", text: CANARY }], hostileContext: CANARY } },
      executionReceipt: signed.executionReceipt,
    });
    const errored = seedState(store, packageTemplate, "created", 101);
    store.resolveWorkflow(errored.taskId, { kind: "unresolvable", errorCode: CANARY, errorMessage: CANARY });
    const before = [store.getWorkflow(resolved.taskId), store.getWorkflow(errored.taskId)];
    const bridge = disclosureBridge(store);

    for (const { taskId, actionId } of [resolved, errored]) {
      const tasks = bridge.handleTasksGet(taskId);
      const compatibility = await bridge.handleCompatibilityToolCall(MPAS_WAIT_TOOL_NAME, { actionId, timeoutSeconds: 0 });
      expect(JSON.stringify([tasks, compatibility])).not.toContain(CANARY);
      expect(tasks).toMatchObject({ result: { structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE } } });
      expect(compatibility).toMatchObject({ structuredContent: { code: RESULT_DISCLOSURE_DENIED_CODE } });
    }
    expect([store.getWorkflow(resolved.taskId), store.getWorkflow(errored.taskId)]).toEqual(before);
  });

  it("preserves the prior direct-SDK behavior when the option is omitted", async () => {
    const actionPackage = await fixture<ActionPackage>("action-packages/valid-create-issue-package.json");
    const response = await fixture<ActionResponse>("responses/adapter-response-executed.json");
    const bridge = new ProposerBridge({
      tools: [{ name: "create_issue", inputSchema: { type: "object" } }],
      buildActionPackage: async () => actionPackage,
      buildCoordinationReplacement: async (prior, requirements) => ({
        actionPackage: prior,
        authorizationRequirements: requirements,
      }),
      store: new MemoryWorkflowStore({ now: () => NOW }),
      actionEndpoint: { submitActionRequest: async () => response },
      coordinationService: coordinationService(),
      proposerDid: actionPackage.actionEnvelope.proposer.did,
      resultRetentionSeconds: 86_400,
      now: () => NOW,
    });
    const created = await bridge.handleToolCall("create_issue", {});
    // Without resultDisclosure, the call settles immediately with the response result.
    expect(created).toMatchObject(response.executionResult);
  });
});

function disclosureBridge(
  store: WorkflowStore,
  options: {
    counters?: ReturnType<typeof counters>;
    buildActionPackage?: () => Promise<ActionPackage>;
  } = {},
): ProposerBridge {
  const observed = options.counters ?? counters();
  return new ProposerBridge({
    tools: [
      { name: "secret_tool", inputSchema: { type: "object" } },
      { name: "ordinary_tool", inputSchema: { type: "object" } },
    ],
    resultDisclosure: { secret_tool: "deny", ordinary_tool: "allow" },
    buildActionPackage: options.buildActionPackage ?? (async () => {
      observed.package += 1;
      throw new Error("unexpected package build");
    }),
    buildCoordinationReplacement: async (prior, requirements) => ({
      actionPackage: prior,
      authorizationRequirements: requirements,
    }),
    store,
    actionEndpoint: {
      async submitActionRequest() {
        observed.endpoint += 1;
        throw new Error("unexpected endpoint call");
      },
    },
    coordinationService: coordinationService(observed),
    proposerDid: fixtureProposerDid(),
    resultRetentionSeconds: 86_400,
    now: () => NOW,
  });
}

function allowedFixtureBridge(store: WorkflowStore, actionPackage: ActionPackage, response: ActionResponse): ProposerBridge {
  return new ProposerBridge({
    tools: [{ name: "create_issue", inputSchema: { type: "object" } }],
    resultDisclosure: { create_issue: "allow" },
    buildActionPackage: async () => actionPackage,
    buildCoordinationReplacement: async (prior, requirements) => ({
      actionPackage: prior,
      authorizationRequirements: requirements,
    }),
    store,
    actionEndpoint: { submitActionRequest: async () => response },
    coordinationService: coordinationService(),
    proposerDid: actionPackage.actionEnvelope.proposer.did,
    resultRetentionSeconds: 86_400,
    now: () => NOW,
  });
}

function counters() {
  return { package: 0, endpoint: 0, coordinationCreate: 0, coordinationPoll: 0, coordinationCancel: 0 };
}

function coordinationService(observed = counters()) {
  return {
    async createApprovalWorkflow(): Promise<never> {
      observed.coordinationCreate += 1;
      throw new Error("unexpected coordination create");
    },
    async pollWork() {
      observed.coordinationPoll += 1;
      return { version: "1" as const, type: "CoordinationPollResponse" as const, approvalRequests: [], actionUpdates: [] };
    },
    async cancelAction(): Promise<never> {
      observed.coordinationCancel += 1;
      throw new Error("unexpected coordination cancel");
    },
  };
}

function disclosureEngine(
  store: WorkflowStore,
  resultDisclosure: ResultDisclosureMap | undefined,
  observed = counters(),
  response?: ActionResponse,
): BridgeWorkflowEngine {
  return new BridgeWorkflowEngine({
    store,
    actionEndpoint: {
      async submitActionRequest() {
        observed.endpoint += 1;
        if (response === undefined) throw new Error("unexpected endpoint call");
        return response;
      },
    },
    coordinationService: coordinationService(observed),
    buildCoordinationReplacement: async (prior, requirements) => ({
      actionPackage: prior,
      authorizationRequirements: requirements,
    }),
    proposerDid: fixtureProposerDid(),
    resultDisclosure,
    now: () => NOW,
  });
}

function workflowInput(template: ActionPackage, toolName: string, index: number) {
  const actionPackage = structuredClone(template);
  const actionId = `urn:uuid:62000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  const taskId = `urn:uuid:72000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  actionPackage.actionEnvelope.actionId.value = actionId;
  actionPackage.executionPayload = { name: toolName, arguments: {} } as ActionPackage["executionPayload"];
  return {
    taskId,
    actionId,
    actionIdempotencyKey: `disclosure-idempotency-${index}`,
    actionEnvelopeHash: `disclosure-engine-hash-${index}`,
    toolName,
    actionPackage,
    expiresAt: "2030-01-01T00:00:00.000Z",
  };
}

function fixtureProposerDid(): Did {
  return "did:jwk:eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ims2TzdjaVFrbXBodUVFdDFpM3lBaW1KSldlR0ttT3EzdF9mc05renphNm8ifQ" as Did;
}

function seedState(
  store: WorkflowStore,
  template: ActionPackage,
  state: BridgeWorkflowState,
  index: number,
): { taskId: string; actionId: string } {
  const actionId = `urn:uuid:62000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  const taskId = `urn:uuid:72000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  const actionPackage = structuredClone(template);
  actionPackage.actionEnvelope.actionId.value = actionId;
  actionPackage.executionPayload = { name: "secret_tool", arguments: { historicalCredential: CANARY } } as ActionPackage["executionPayload"];
  store.createWorkflow({
    taskId,
    actionId,
    actionIdempotencyKey: `seed-idempotency-${index}`,
    actionEnvelopeHash: `historical-hash-${index}`,
    toolName: "secret_tool",
    actionPackage,
    expiresAt: "2030-01-01T00:00:00.000Z",
  });
  if (state !== "created") store.compareAndSetState(taskId, "created", state);
  if (state === "readyForSubmission" || state === "submittingToVerifier") {
    store.saveCompletedPackage(taskId, actionPackage);
  }
  if (state === "policyUnavailable" || state === "awaitingVerifierResult") {
    store.saveLastActionResponse(taskId, { version: "1", type: "ActionResponse", result: "pending", context: CANARY });
  }
  return { taskId, actionId };
}
