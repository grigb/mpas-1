import { describe, expect, it } from "vitest";
import { MPAS_POLICY_PROFILE_URL } from "../../src/lib/policy-config.js";
import { evaluatePolicy, type PolicyConfig } from "../../src/lib/policy-engine.js";
import type { ActionPackage, Did } from "../../src/types/mpas.js";
import type { VerifiedApprovals } from "../../src/lib/verification.js";

const proposer = "did:web:agents.example:proposer" as Did;
const cfo = "did:web:agents.example:cfo" as Did;
const noApprovals: VerifiedApprovals = { actionEnvelopeHash: { alg: "sha-256", value: "y" }, approvals: [] };

function pkg(amount?: unknown): ActionPackage {
  return {
    version: "1", type: "ActionPackage",
    executionPayload: { name: "send_payment", arguments: amount === undefined ? {} : { amount } },
    actionEnvelope: {
      version: "1", type: "ActionEnvelope", proposer: { did: proposer },
      target: { applicationDid: "did:web:app.example" as Did },
      executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
      executionPayloadHash: { alg: "sha-256", value: "x" }, actionId: { value: "test" },
      createdAt: "2026-06-05T18:00:00.000Z", expiresAt: "2030-01-01T00:00:00.000Z",
    },
    approvalBundle: { version: "1", type: "ApprovalBundle", actionEnvelopeHash: { alg: "sha-256", value: "y" }, approvals: [] },
  };
}

function policy(): PolicyConfig {
  return {
    version: "1", type: "MpasApplicationPolicy", policyProfileUrl: MPAS_POLICY_PROFILE_URL,
    applicationDid: "did:web:app.example" as Did,
    executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
    defaultRequirement: { type: "proposerOnly" },
    signerGroups: { all: [proposer, cfo], proposers: [proposer], cfo: [cfo] },
    policies: { send_payment: [{ match: { conditions: [
      { source: "executionPayload", path: "/arguments/amount", op: "gt", value: "100" },
    ] }, requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" } }] },
  };
}

describe("evaluatePolicy fail-closed boundaries", () => {
  it("returns malformed for an unparseable numeric input", () => {
    expect(evaluatePolicy(pkg("bad"), noApprovals, policy())).toMatchObject({
      status: "malformed", code: "NUMERIC_CONDITION_UNPARSEABLE",
    });
  });

  it("uses the default for a missing condition path", () => {
    expect(evaluatePolicy(pkg(), noApprovals, policy())).toEqual({ status: "satisfied" });
  });

  it("fails closed without throwing for deeply malformed policy", () => {
    const malformed = structuredClone(policy()) as unknown as Record<string, unknown>;
    malformed.defaultRequirement = { type: "allOf", requirements: [{ type: "anyOf", requirements: [null] }] };
    expect(() => evaluatePolicy(pkg(200), noApprovals, malformed)).not.toThrow();
    expect(evaluatePolicy(pkg(200), noApprovals, malformed)).toMatchObject({ status: "malformed", code: "POLICY_INVALID" });
  });

  it("rejects matched rules before considering positive entries", () => {
    const rejected = policy();
    rejected.policies!.send_payment.push({ reject: true });
    expect(evaluatePolicy(pkg(200), noApprovals, rejected)).toMatchObject({
      status: "rejected", code: "ACTION_BLOCKED_BY_POLICY",
    });
  });

  it("returns notSupported for application, profile, and format scope mismatches", () => {
    for (const mutate of [
      (value: PolicyConfig) => { value.applicationDid = "did:web:other.example" as Did; },
      (value: PolicyConfig) => { value.executionProfile.id = "did:web:profiles.example:other" as Did; },
      (value: PolicyConfig) => { value.executionProfile.format = "other"; },
    ]) {
      const value = policy();
      mutate(value);
      expect(evaluatePolicy(pkg(200), noApprovals, value)).toMatchObject({ status: "notSupported" });
    }
  });

  it.each([
    ["/arguments/toString", {}],
    ["/arguments/constructor", {}],
    ["/arguments/__proto__", {}],
    ["/arguments/nested/toString", { nested: {} }],
    ["/arguments/nested/constructor", { nested: {} }],
    ["/arguments/nested/__proto__", { nested: {} }],
  ])("treats inherited JSON Pointer path %s as missing", (path, argumentsValue) => {
    const action = pkg();
    action.executionPayload = { name: "send_payment", arguments: argumentsValue };
    const value = policy();
    value.defaultRequirement = { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" };
    value.policies = { send_payment: [{ match: { conditions: [
      { source: "executionPayload", path, op: "exists" },
    ] }, requirements: { type: "proposerOnly" } }] };
    expect(evaluatePolicy(action, noApprovals, value)).toMatchObject({ status: "additionalApprovalsRequired" });
  });

  it.each(["toString", "constructor", "__proto__"])(
    "matches an explicitly owned JSON key named %s",
    (key) => {
      const action = pkg();
      action.executionPayload = JSON.parse(JSON.stringify({
        name: "send_payment",
        arguments: { nested: { [key]: true } },
      }));
      const value = policy();
      value.policies = { send_payment: [{ match: { conditions: [
        { source: "executionPayload", path: `/arguments/nested/${key}`, op: "exists" },
      ] }, requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" } }] };
      expect(evaluatePolicy(action, noApprovals, value)).toMatchObject({ status: "additionalApprovalsRequired" });
    },
  );

  it("preserves escaped keys and ordinary array-index traversal", () => {
    const action = pkg();
    action.executionPayload = JSON.parse('{"name":"send_payment","arguments":{"a/b":{"til~de":[{"allowed":true}]}}}');
    const value = policy();
    value.policies = { send_payment: [{ match: { conditions: [
      { source: "executionPayload", path: "/arguments/a~1b/til~0de/0/allowed", op: "exists" },
    ] }, requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" } }] };
    expect(evaluatePolicy(action, noApprovals, value)).toMatchObject({ status: "additionalApprovalsRequired" });
  });

  it.each(["toString", "constructor", "__proto__"])(
    "uses the default for a missing inherited action policy named %s",
    (actionName) => {
      const action = pkg();
      action.executionPayload = { name: actionName, arguments: {} };
      const value = policy();
      value.defaultRequirement = { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" };
      value.policies = {};
      expect(Object.hasOwn(value.policies, actionName)).toBe(false);
      expect(() => evaluatePolicy(action, noApprovals, value)).not.toThrow();
      expect(evaluatePolicy(action, noApprovals, value)).toMatchObject({ status: "additionalApprovalsRequired" });
    },
  );

  it.each(["toString", "constructor", "__proto__"])(
    "applies an explicitly owned action policy named %s and preserves reject precedence",
    (actionName) => {
      const action = pkg();
      action.executionPayload = { name: actionName, arguments: {} };
      const value = policy();
      value.policies = JSON.parse(JSON.stringify({
        [actionName]: [
          { requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "cfo" } },
          { reject: true },
        ],
      })) as PolicyConfig["policies"];
      expect(Object.hasOwn(value.policies!, actionName)).toBe(true);
      expect(evaluatePolicy(action, noApprovals, value)).toMatchObject({
        status: "rejected", code: "ACTION_BLOCKED_BY_POLICY",
      });
    },
  );
});
