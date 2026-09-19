import { describe, expect, it } from "vitest";
import { buildAuthorizationRequirements } from "../../src/core/auth-requirements-builder.js";
import type { ActionEnvelope, Did } from "../../src/core/types.js";
import { computeJsonHash } from "../../src/core/verification.js";

const envelope: ActionEnvelope = {
  version: "1", type: "ActionEnvelope", proposer: { did: "did:web:actors.example:proposer" as Did },
  target: { applicationDid: "did:web:app.example" as Did },
  executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
  executionPayloadHash: { alg: "sha-256", value: "payload" }, actionId: { value: "action" },
  createdAt: "2026-09-05T00:00:00.000Z", expiresAt: "2030-09-05T00:00:00.000Z",
};

describe("buildAuthorizationRequirements", () => {
  it("binds and preserves one recursive unmet expression", () => {
    const signerA = "did:web:actors.example:a" as Did;
    const signerB = "did:web:actors.example:b" as Did;
    const requirements = buildAuthorizationRequirements({
      actionEnvelope: envelope,
      verifierDid: "did:web:verifier.example:main" as Did,
      unsatisfiedRequirement: {
        type: "anyOf",
        requirements: [
          { type: "threshold", threshold: 1, eligibleSigners: [signerA], decision: "approve" },
          { type: "allOf", requirements: [
            { type: "threshold", threshold: 1, eligibleSigners: [signerB], decision: "abstain" },
          ] },
        ],
      },
    });

    expect(requirements).toMatchObject({
      version: "1", type: "AuthorizationRequirements",
      actionEnvelopeHash: computeJsonHash(envelope),
      result: "additionalApprovalsRequired",
      verifier: { did: "did:web:verifier.example:main" },
      approvalRequirements: {
        anyOf: [
          { type: "threshold", eligibleSigners: [signerA], decision: "approve" },
          { type: "allOf", requirements: [{ eligibleSigners: [signerB], decision: "abstain" }] },
        ],
      },
      expiresAt: envelope.expiresAt,
    });
  });
});
