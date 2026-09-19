import { describe, expect, it } from "vitest";
import {
  MPAS_POLICY_PROFILE_URL,
  loadPolicyConfig,
  validatePolicyConfig,
  type PolicyConfig,
} from "../../src/lib/policy-config.js";
import type { Did } from "../../src/types/mpas.js";

const proposer = "did:web:agents.example:proposer" as Did;
const maintainer = "did:web:agents.example:maintainer" as Did;

function validPolicy(): PolicyConfig {
  return {
    version: "1",
    type: "MpasApplicationPolicy",
    policyProfileUrl: MPAS_POLICY_PROFILE_URL,
    applicationDid: "did:web:app.example" as Did,
    executionProfile: { id: "did:web:profiles.oma3.org:mcp" as Did, format: "mcp.toolsCall" },
    defaultRequirement: { type: "threshold", threshold: 1, eligibleSignerGroup: "maintainers" },
    signerGroups: { all: [proposer, maintainer], proposers: [proposer], maintainers: [maintainer] },
  };
}

describe("complete MpasApplicationPolicy validation", () => {
  it("returns the validated full policy from the one strict loader", () => {
    const policy = validPolicy();
    expect(loadPolicyConfig(policy)).toEqual({ ok: true, policy });
  });

  it.each([
    ["missing top-level field", (policy: Record<string, unknown>) => delete policy.applicationDid],
    ["unknown top-level field", (policy: Record<string, unknown>) => { policy.extra = true; }],
    ["wrong profile URL", (policy: Record<string, unknown>) => { policy.policyProfileUrl = "https://example.test/policy"; }],
    ["empty signer group", (policy: Record<string, unknown>) => { (policy.signerGroups as Record<string, unknown>).maintainers = []; }],
    ["group member outside all", (policy: Record<string, unknown>) => {
      (policy.signerGroups as Record<string, unknown>).maintainers = ["did:web:agents.example:outsider"];
    }],
    ["unknown nested requirement", (policy: Record<string, unknown>) => {
      policy.defaultRequirement = { type: "allOf", requirements: [{ type: "unknown" }] };
    }],
    ["unknown condition field", (policy: Record<string, unknown>) => {
      policy.policies = { op: [{ requirements: { type: "proposerOnly" }, match: {
        conditions: [{ source: "executionPayload", path: "/name", op: "eq", value: "op", extra: true }],
      } }] };
    }],
    ["non-JSON context", (policy: Record<string, unknown>) => { policy.context = { invalid: undefined }; }],
  ])("rejects %s", (_label, mutate) => {
    const policy = structuredClone(validPolicy()) as unknown as Record<string, unknown>;
    mutate(policy);
    expect(validatePolicyConfig(policy)).toMatchObject({ ok: false });
  });

  it("rejects zero, over-large, and reject thresholds", () => {
    for (const requirement of [
      { type: "threshold", threshold: 0, eligibleSignerGroup: "maintainers" },
      { type: "threshold", threshold: 2, eligibleSignerGroup: "maintainers" },
      { type: "threshold", threshold: 1, eligibleSignerGroup: "maintainers", decision: "reject" },
    ]) {
      const policy = validPolicy() as unknown as Record<string, unknown>;
      policy.defaultRequirement = requirement;
      expect(validatePolicyConfig(policy)).toMatchObject({ ok: false });
    }
  });

  it("rejects entries that both reject and require approvals", () => {
    const policy = validPolicy();
    policy.policies = {
      create_issue: [
        {
          reject: true,
          requirements: { type: "proposerOnly" },
        } as unknown as (typeof policy.policies)[string][number],
      ],
    };

    expect(validatePolicyConfig(policy)).toMatchObject({
      ok: false,
      message: expect.stringContaining("either reject: true or requirements"),
    });
  });

  it("accepts eligibleSigners instead of a group name", () => {
    const policy = validPolicy();
    policy.defaultRequirement = {
      type: "threshold",
      threshold: 1,
      eligibleSigners: [maintainer],
      decision: "approve",
    };

    expect(validatePolicyConfig(policy)).toEqual({ ok: true });
  });

  it("rejects a threshold that names both a group and eligibleSigners", () => {
    const policy = validPolicy();
    policy.defaultRequirement = {
      type: "threshold",
      threshold: 1,
      eligibleSignerGroup: "maintainers",
      eligibleSigners: [maintainer],
      decision: "approve",
    };

    expect(validatePolicyConfig(policy)).toMatchObject({
      ok: false,
      message: expect.stringContaining("exactly one of eligibleSignerGroup or eligibleSigners"),
    });
  });

  it.each(["toString", "constructor", "__proto__"])(
    "treats a missing inherited signer group named %s as invalid without throwing",
    (groupName) => {
      const policy = validPolicy();
      policy.defaultRequirement = { type: "threshold", threshold: 1, eligibleSignerGroup: groupName };
      expect(Object.hasOwn(policy.signerGroups, groupName)).toBe(false);
      expect(() => validatePolicyConfig(policy)).not.toThrow();
      expect(validatePolicyConfig(policy)).toMatchObject({ ok: false });
    },
  );

  it.each(["toString", "constructor", "__proto__"])(
    "accepts an explicitly owned signer group named %s with normal membership and feasibility checks",
    (groupName) => {
      const policy = validPolicy();
      policy.signerGroups = JSON.parse(JSON.stringify({
        all: [proposer, maintainer],
        proposers: [proposer],
        [groupName]: [maintainer],
      })) as PolicyConfig["signerGroups"];
      policy.defaultRequirement = { type: "threshold", threshold: 1, eligibleSignerGroup: groupName };
      expect(Object.hasOwn(policy.signerGroups, groupName)).toBe(true);
      expect(validatePolicyConfig(policy)).toEqual({ ok: true });

      policy.defaultRequirement = { type: "threshold", threshold: 2, eligibleSignerGroup: groupName };
      expect(validatePolicyConfig(policy)).toMatchObject({ ok: false });
    },
  );
});
