import { describe, expect, it } from "vitest";
import { checkProposerAuthorization, type PolicyConfig } from "../../src/lib/policy-engine.js";
import { MPAS_POLICY_PROFILE_URL } from "../../src/lib/policy-config.js";
import { applyFailClosedDefaults } from "../../src/lib/plugin-loader.js";
import type { Did } from "../../src/types/mpas.js";

const proposer = "did:web:agents.example:proposer" as Did;
const maintainer = "did:web:agents.example:maintainer" as Did;
const stranger = "did:web:agents.example:stranger" as Did;

function policy(proposers?: Did[]): PolicyConfig {
  return {
    version: "1", type: "MpasApplicationPolicy", policyProfileUrl: MPAS_POLICY_PROFILE_URL,
    applicationDid: "did:web:app.example" as Did,
    executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did },
    defaultRequirement: { type: "proposerOnly" },
    signerGroups: { all: [proposer, maintainer], ...(proposers ? { proposers } : {}) },
  };
}

describe("checkProposerAuthorization", () => {
  it("enforces proposers and falls back to all", () => {
    expect(checkProposerAuthorization(proposer, policy([proposer]))).toEqual({ allowed: true });
    expect(checkProposerAuthorization(maintainer, policy([proposer])).allowed).toBe(false);
    expect(checkProposerAuthorization(maintainer, policy()).allowed).toBe(true);
    expect(checkProposerAuthorization(stranger, policy()).allowed).toBe(false);
  });

  it("validates the full policy before membership", () => {
    expect(checkProposerAuthorization(proposer, { defaultRequirement: { type: "proposerOnly" } })).toMatchObject({
      allowed: false, code: "POLICY_INVALID",
    });
  });
});

describe("applyFailClosedDefaults", () => {
  it("closes nested object schemas without changing explicit or scalar schemas", () => {
    const result = applyFailClosedDefaults({
      type: "object", properties: { arguments: { type: "object", properties: { a: { type: "string" } } } },
    }) as Record<string, unknown>;
    expect(result.additionalProperties).toBe(false);
    const args = (result.properties as Record<string, Record<string, unknown>>).arguments;
    expect(args.additionalProperties).toBe(false);
    expect(applyFailClosedDefaults({ type: "object", additionalProperties: true })).toMatchObject({ additionalProperties: true });
  });
});
