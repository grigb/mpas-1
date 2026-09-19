import { describe, expect, it } from "vitest";
import {
  buildAuthorizationRequirements,
  evaluateApprovalRequirements,
  evaluatePolicy,
  MPAS_POLICY_PROFILE_URL,
  validateApprovalRequirements,
  type ActionPackage,
  type Decision,
  type Did,
  type PolicyConfig,
  type VerifiedApprovals,
} from "../../src/index.js";

const proposer = "did:web:actors.example:proposer" as Did;
const a = "did:web:actors.example:a" as Did;
const b = "did:web:actors.example:b" as Did;
const c = "did:web:actors.example:c" as Did;
const d = "did:web:actors.example:d" as Did;
const signers = [a, b, c, d];
const states = [undefined, "propose", "approve", "reject", "abstain"] as const;

const actionPackage: ActionPackage = {
  version: "1", type: "ActionPackage", executionPayload: { name: "operate", arguments: {} },
  actionEnvelope: {
    version: "1", type: "ActionEnvelope", proposer: { did: proposer },
    target: { applicationDid: "did:web:app.example" as Did },
    executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
    executionPayloadHash: { alg: "sha-256", value: "payload" }, actionId: { value: "truth-table" },
    createdAt: "2026-09-05T00:00:00.000Z", expiresAt: "2030-09-05T00:00:00.000Z",
  },
  approvalBundle: { version: "1", type: "ApprovalBundle", actionEnvelopeHash: { alg: "sha-256", value: "envelope" }, approvals: [] },
};

const policy: PolicyConfig = {
  version: "1", type: "MpasApplicationPolicy", policyProfileUrl: MPAS_POLICY_PROFILE_URL,
  applicationDid: actionPackage.actionEnvelope.target.applicationDid,
  executionProfile: { ...actionPackage.actionEnvelope.executionProfile },
  defaultRequirement: {
    type: "anyOf",
    requirements: [
      { type: "allOf", requirements: [
        { type: "threshold", threshold: 1, eligibleSigners: [a], decision: "approve" },
        { type: "threshold", threshold: 1, eligibleSigners: [b], decision: "abstain" },
      ] },
      { type: "allOf", requirements: [
        { type: "threshold", threshold: 1, eligibleSigners: [c], decision: "approve" },
        { type: "threshold", threshold: 1, eligibleSigners: [d], decision: "abstain" },
      ] },
    ],
  },
  signerGroups: { all: [proposer, ...signers], proposers: [proposer] },
};

function approvals(assignment: readonly (Decision | undefined)[]): VerifiedApprovals {
  return {
    actionEnvelopeHash: { alg: "sha-256", value: "envelope" },
    approvals: assignment.flatMap((decision, index) => decision === undefined ? [] : [{
      approval: {} as never,
      signerDid: signers[index],
      decision,
      createdAt: "2026-09-05T00:01:00.000Z",
    }]),
  };
}

describe("recursive policy and Authorization Requirements round trip", () => {
  it("matches the complete 625-assignment truth table", () => {
    let checked = 0;
    for (const av of states) for (const bv of states) for (const cv of states) for (const dv of states) {
      const assignment = [av, bv, cv, dv] as const;
      const firstSatisfied = av === "approve" && bv === "abstain";
      const secondSatisfied = cv === "approve" && dv === "abstain";
      const firstReachable = (av === undefined || av === "approve") && (bv === undefined || bv === "abstain");
      const secondReachable = (cv === undefined || cv === "approve") && (dv === undefined || dv === "abstain");
      const result = evaluatePolicy(actionPackage, approvals(assignment), policy);
      if (firstSatisfied || secondSatisfied) {
        expect(result.status, JSON.stringify(assignment)).toBe("satisfied");
      } else if (firstReachable || secondReachable) {
        expect(result.status, JSON.stringify(assignment)).toBe("additionalApprovalsRequired");
        if (result.status === "additionalApprovalsRequired") {
          const authorization = buildAuthorizationRequirements({
            actionEnvelope: actionPackage.actionEnvelope,
            unsatisfiedRequirement: result.unsatisfiedRequirement,
            verifierDid: "did:web:verifier.example:main" as Did,
          });
          if (authorization.result !== "additionalApprovalsRequired") throw new Error("unexpected result");
          expect(validateApprovalRequirements(authorization.approvalRequirements)).toMatchObject({ ok: true });
          expect(evaluateApprovalRequirements(authorization.approvalRequirements, [])).toBe("pending");
        }
      } else {
        expect(result, JSON.stringify(assignment)).toMatchObject({
          status: "rejected", code: "POLICY_REQUIREMENT_UNREACHABLE",
        });
      }
      checked += 1;
    }
    expect(checked).toBe(625);
  });

  it("does not treat all approve decisions as satisfying abstain leaves", () => {
    expect(evaluatePolicy(actionPackage, approvals(["approve", "approve", "approve", "approve"]), policy))
      .toMatchObject({ status: "rejected", code: "POLICY_REQUIREMENT_UNREACHABLE" });
  });

  it("fails closed for a deeply malformed recursive response without throwing", () => {
    const malformed = { anyOf: [{ type: "allOf", requirements: [{ type: "anyOf", requirements: [null] }] }] };
    expect(validateApprovalRequirements(malformed)).toMatchObject({ ok: false });
    expect(() => evaluateApprovalRequirements(malformed as never, [])).not.toThrow();
    expect(evaluateApprovalRequirements(malformed as never, [])).toBe("unreachable");
  });

  it("preserves flat and override controls", () => {
    const flat = {
      anyOf: [{ type: "threshold" as const, threshold: 1, eligibleSigners: [a] }],
      overrideSigners: [{ signer: d, permissions: ["approve", "reject"] }],
    };
    expect(evaluateApprovalRequirements(flat, [])).toBe("pending");
    expect(evaluateApprovalRequirements(flat, [{ signerDid: a, decision: "approve" }])).toBe("satisfied");
    expect(evaluateApprovalRequirements(flat, [{ signerDid: d, decision: "reject" }])).toBe("unreachable");
  });
});
