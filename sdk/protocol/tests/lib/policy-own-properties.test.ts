import { describe, expect, it } from "vitest";
import { evaluatePolicy, validatePolicyConfig, type PolicyConfig } from "../../src/lib/policy-engine.js";
import type { ActionPackage, Did } from "../../src/types/mpas.js";
import type { VerifiedApprovals } from "../../src/lib/verification.js";

const proposer = "did:example:proposer" as Did;
const signer = "did:example:signer" as Did;
const actionPackage = {
  executionPayload: { name: "constructor", arguments: {} },
  actionEnvelope: { proposer: { did: proposer } },
} as ActionPackage;
const verifiedApprovals: VerifiedApprovals = {
  actionEnvelopeHash: { alg: "sha-256", value: "verified-envelope" },
  approvals: [{ signerDid: signer, decision: "approve", createdAt: "2026-06-05T18:00:00.000Z", approval: {} as never }],
};

describe("policy object own properties", () => {
  it("rejects a group name inherited from Object.prototype during validation", () => {
    const policy: PolicyConfig = {
      defaultRequirement: { type: "threshold", threshold: 1, eligibleSignerGroup: "constructor" },
      signerGroups: { all: [proposer, signer] },
    };
    expect(validatePolicyConfig(policy).ok).toBe(false);
  });

  it("does not count a signer from an inherited group in direct evaluation", () => {
    const policy: PolicyConfig = {
      defaultRequirement: { type: "threshold", threshold: 1, eligibleSignerGroup: "admins" },
      signerGroups: Object.assign(Object.create({ admins: [signer] }), { all: [proposer, signer] }),
    };
    expect(evaluatePolicy(actionPackage, verifiedApprovals, policy))
      .toMatchObject({ status: "additionalApprovalsRequired", unsatisfiedRules: [{ found: 0 }] });
  });

  it("uses the default for an operation name inherited from Object.prototype without throwing", () => {
    const policy: PolicyConfig = {
      defaultRequirement: { type: "threshold", threshold: 1, eligibleSigners: [proposer] },
      policies: {},
    };
    expect(evaluatePolicy(actionPackage, verifiedApprovals, policy).status).toBe("additionalApprovalsRequired");
  });

  it("does not let an inherited JSON Pointer member suppress a reject condition", () => {
    const policy: PolicyConfig = {
      defaultRequirement: { type: "proposerOnly" },
      policies: {
        constructor: [{ reject: true, match: { conditions: [
          { source: "executionPayload", path: "/arguments/toString", op: "notExists" },
        ] } }],
      },
    };
    expect(evaluatePolicy(actionPackage, verifiedApprovals, policy).status).toBe("rejected");
  });

  it("retains own JSON properties even when their names also occur on Object.prototype", () => {
    const policy = JSON.parse(JSON.stringify({
      defaultRequirement: { type: "threshold", threshold: 1, eligibleSignerGroup: "constructor" },
      signerGroups: { all: [proposer, signer], constructor: [signer] },
      policies: { constructor: [{ requirements: { type: "threshold", threshold: 1, eligibleSignerGroup: "constructor" } }] },
    })) as PolicyConfig;
    expect(validatePolicyConfig(policy).ok).toBe(true);
    expect(evaluatePolicy(actionPackage, verifiedApprovals, policy).status).toBe("satisfied");
  });
});
