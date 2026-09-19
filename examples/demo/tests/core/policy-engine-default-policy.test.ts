import { describe, expect, it } from "vitest";
import {
  evaluatePolicy,
  MPAS_POLICY_PROFILE_URL,
  type PolicyConfig,
  type Requirement,
} from "../../src/core/policy-engine.js";
import type { ActionPackage, Decision, Did, JsonObject } from "../../src/core/types.js";
import type { VerifiedApprovals } from "../../src/core/verification.js";

const proposer = "did:web:agents.example:proposer" as Did;
const maintainerA = "did:web:agents.example:maintainer-a" as Did;
const maintainerB = "did:web:agents.example:maintainer-b" as Did;
const security = "did:web:agents.example:security" as Did;
const outsider = "did:web:agents.example:outsider" as Did;

function action(name: string, arguments_: JsonObject = {}): ActionPackage {
  return {
    version: "1", type: "ActionPackage", executionPayload: { name, arguments: arguments_ },
    actionEnvelope: {
      version: "1", type: "ActionEnvelope", proposer: { did: proposer },
      target: { applicationDid: "did:web:github-mirror.example" as Did },
      executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
      executionPayloadHash: { alg: "sha-256", value: "payload" }, actionId: { value: name },
      createdAt: "2026-06-01T00:00:00.000Z", expiresAt: "2030-06-02T00:00:00.000Z",
    },
    approvalBundle: { version: "1", type: "ApprovalBundle", actionEnvelopeHash: { alg: "sha-256", value: "envelope" }, approvals: [] },
  };
}

function approvals(entries: Array<[Did, Decision]>): VerifiedApprovals {
  return {
    actionEnvelopeHash: { alg: "sha-256", value: "envelope" },
    approvals: entries.map(([signerDid, decision]) => ({
      approval: {} as never, signerDid, decision, createdAt: "2026-06-01T00:01:00.000Z",
    })),
  };
}

function policy(
  defaultRequirement: Requirement,
  groups: Record<string, Did[]> = {},
  policies?: PolicyConfig["policies"],
): PolicyConfig {
  const all = [...new Set([proposer, ...Object.values(groups).flat()])];
  return {
    version: "1", type: "MpasApplicationPolicy", policyProfileUrl: MPAS_POLICY_PROFILE_URL,
    applicationDid: "did:web:github-mirror.example" as Did,
    executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
    defaultRequirement,
    signerGroups: { all, proposers: [proposer], ...groups },
    ...(policies ? { policies } : {}),
  };
}

describe("evaluatePolicy complete policy behavior", () => {
  it("uses the default requirement and resolves group members", () => {
    const configured = policy(
      { type: "threshold", threshold: 1, eligibleSignerGroup: "maintainers" },
      { maintainers: [maintainerA, maintainerB] },
    );
    const pending = evaluatePolicy(action("delete_branch"), approvals([]), configured);
    expect(pending).toMatchObject({
      status: "additionalApprovalsRequired",
      unsatisfiedRequirement: { threshold: 1, eligibleSigners: [maintainerA, maintainerB] },
    });
    expect(evaluatePolicy(action("delete_branch"), approvals([[maintainerA, "approve"]]), configured))
      .toEqual({ status: "satisfied" });
  });

  it("uses explicit proposerOnly rules instead of a default threshold", () => {
    const configured = policy(
      { type: "threshold", threshold: 1, eligibleSignerGroup: "maintainers" },
      { maintainers: [maintainerA] },
      { create_issue: [{ requirements: { type: "proposerOnly" } }] },
    );
    expect(evaluatePolicy(action("create_issue"), approvals([]), configured)).toEqual({ status: "satisfied" });
  });

  it("combines every matching rule with allOf and drops satisfied branches", () => {
    const configured = policy(
      { type: "proposerOnly" },
      { maintainers: [maintainerA, maintainerB], security: [security] },
      { merge: [
        { match: { conditions: [{ source: "executionPayload", path: "/arguments/base", op: "eq", value: "main" }] },
          requirements: { type: "threshold", threshold: 2, eligibleSignerGroup: "maintainers" } },
        { match: { conditions: [{ source: "executionPayload", path: "/arguments/base", op: "eq", value: "main" }] },
          requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "security" } },
      ] },
    );
    const empty = evaluatePolicy(action("merge", { base: "main" }), approvals([]), configured);
    expect(empty).toMatchObject({
      status: "additionalApprovalsRequired",
      unsatisfiedRequirement: { type: "allOf", requirements: [{ threshold: 2 }, { threshold: 1 }] },
    });
    const partial = evaluatePolicy(
      action("merge", { base: "main" }),
      approvals([[maintainerA, "approve"], [maintainerB, "approve"]]),
      configured,
    );
    expect(partial).toMatchObject({
      status: "additionalApprovalsRequired",
      unsatisfiedRequirement: { type: "allOf", requirements: [{ eligibleSigners: [security] }] },
    });
    expect(evaluatePolicy(
      action("merge", { base: "main" }),
      approvals([[maintainerA, "approve"], [maintainerB, "approve"], [security, "approve"]]),
      configured,
    )).toEqual({ status: "satisfied" });
  });

  it("preserves every viable anyOf alternative", () => {
    const configured = policy({
      type: "anyOf", requirements: [
        { type: "threshold", threshold: 1, eligibleSigners: [maintainerA] },
        { type: "threshold", threshold: 1, eligibleSigners: [security] },
      ],
    }, { participants: [maintainerA, security] });
    expect(evaluatePolicy(action("operate"), approvals([]), configured)).toMatchObject({
      status: "additionalApprovalsRequired",
      unsatisfiedRequirement: { type: "anyOf", requirements: [{ eligibleSigners: [maintainerA] }, { eligibleSigners: [security] }] },
    });
    expect(evaluatePolicy(action("operate"), approvals([[security, "approve"]]), configured)).toEqual({ status: "satisfied" });
  });

  it("applies numeric conditions and reject precedence", () => {
    const configured = policy(
      { type: "proposerOnly" },
      { admins: [maintainerA] },
      { transfer: [
        { match: { conditions: [{ source: "executionPayload", path: "/arguments/amount", op: "gt", value: "100" }] },
          requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "admins" } },
        { reject: true, match: { conditions: [{ source: "executionPayload", path: "/arguments/amount", op: "gt", value: "1000" }] } },
      ] },
    );
    expect(evaluatePolicy(action("transfer", { amount: 50 }), approvals([]), configured)).toEqual({ status: "satisfied" });
    expect(evaluatePolicy(action("transfer", { amount: 200 }), approvals([]), configured).status)
      .toBe("additionalApprovalsRequired");
    expect(evaluatePolicy(action("transfer", { amount: 2000 }), approvals([[maintainerA, "approve"]]), configured).status)
      .toBe("rejected");
  });

  it("does not count an outsider or the proposer", () => {
    const configured = policy(
      { type: "threshold", threshold: 1, eligibleSigners: [maintainerA] },
      { maintainers: [maintainerA] },
    );
    expect(evaluatePolicy(action("operate"), approvals([[outsider, "approve"]]), configured).status)
      .toBe("additionalApprovalsRequired");

    const selfOnly = policy(
      { type: "threshold", threshold: 1, eligibleSigners: [proposer] },
      {},
    );
    expect(evaluatePolicy(action("operate"), approvals([[proposer, "approve"]]), selfOnly))
      .toMatchObject({ status: "rejected", code: "POLICY_REQUIREMENT_UNREACHABLE" });
  });
});
