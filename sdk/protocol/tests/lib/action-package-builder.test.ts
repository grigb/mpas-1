import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { compactVerify, importJWK, type JWK } from "jose";
import { canonicalize } from "json-canonicalize";
import { describe, expect, it } from "vitest";
import {
  ActionPackageBuilder,
  computeJsonHash,
  KeyManager,
  verifyActionPackage,
  type TrustedExecutionProfile,
  type AdditionalApprovalsAuthorizationRequirements,
  type CanonicalApprovalPayload,
  type Did,
} from "../../src/index.js";

const fixturesDir = fileURLToPath(new URL("../fixtures/", import.meta.url));

interface KeyFixture {
  did: Did;
  publicJwk: JWK;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

describe("ActionPackageBuilder", () => {
  it("builds a valid Action Package from an MCP tool call", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const proposer = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const builder = new ActionPackageBuilder({
      applicationDid: "did:web:github.example",
      executionProfile: {
        id: "did:web:profiles.oma3.org:mcp",
        format: "mcp.toolsCall",
      },
      keyManager,
      defaultExpirationMinutes: 30,
    });

    const actionPackage = await builder.buildFromToolCall("create_issue", {
      owner: "oma3dao",
      repo: "test",
      title: "Hello",
    });

    expect(actionPackage.executionPayload).toEqual({
      name: "create_issue",
      arguments: {
        owner: "oma3dao",
        repo: "test",
        title: "Hello",
      },
    });
    expect(actionPackage.actionEnvelope).toMatchObject({
      version: "1",
      type: "ActionEnvelope",
      proposer: {
        did: proposer.did,
      },
      target: {
        applicationDid: "did:web:github.example",
      },
      executionProfile: {
        id: "did:web:profiles.oma3.org:mcp",
        format: "mcp.toolsCall",
      },
    });
    expect(actionPackage.actionEnvelope.actionId.value).toMatch(/^urn:uuid:/);
    expect(actionPackage.actionEnvelope.executionPayloadHash).toEqual(computeJsonHash(actionPackage.executionPayload));

    const actionEnvelopeHash = computeJsonHash(actionPackage.actionEnvelope);
    expect(actionPackage.approvalBundle.actionEnvelopeHash).toEqual(actionEnvelopeHash);
    expect(actionPackage.approvalBundle.approvals).toHaveLength(1);

    const approval = actionPackage.approvalBundle.approvals[0];
    expect(approval).toMatchObject({
      actionEnvelopeHash,
      decision: "propose",
      signature: {
        format: "jws",
      },
    });

    const publicKey = await importJWK(proposer.publicJwk, "EdDSA");
    const verified = await compactVerify(approval.signature.value, publicKey);
    const approvalPayload = JSON.parse(Buffer.from(verified.payload).toString("utf8")) as CanonicalApprovalPayload;

    expect(approvalPayload).toMatchObject({
      type: "ApprovalPayload",
      actionEnvelopeHash,
      decision: "propose",
      signerDid: proposer.did,
      createdAt: approval.createdAt,
    });
  });

  it("constructs a separately identified A2 and proposer-authored H2 requirements", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const builder = new ActionPackageBuilder({
      applicationDid: "did:web:github.example",
      executionProfile: { id: "did:web:profiles.oma3.org:mcp", format: "mcp.toolsCall" },
      keyManager,
      defaultExpirationMinutes: 30,
    });
    const a1 = await builder.buildFromToolCall("create_issue", { title: "Hello" });
    const h1 = computeJsonHash(a1.actionEnvelope);
    const verifierRequirements: AdditionalApprovalsAuthorizationRequirements = {
      version: "1",
      type: "AuthorizationRequirements",
      actionEnvelopeHash: h1,
      result: "additionalApprovalsRequired",
      verifier: { did: "did:jwk:verifier" },
      approvalRequirements: {
        anyOf: [{ type: "threshold", threshold: 1, eligibleSigners: ["did:jwk:signer"] }],
      },
      policyRef: "github-review-v1",
    };

    const replacement = await builder.buildCoordinationReplacement(a1, verifierRequirements);
    const a2 = replacement.actionPackage;
    const h2 = computeJsonHash(a2.actionEnvelope);

    expect(a2.executionPayload).toEqual(a1.executionPayload);
    expect(a2.actionEnvelope.actionId).not.toEqual(a1.actionEnvelope.actionId);
    expect(h2).not.toEqual(h1);
    expect(a2.approvalBundle.actionEnvelopeHash).toEqual(h2);
    expect(a2.approvalBundle.approvals).toHaveLength(1);
    expect(a2.approvalBundle.approvals[0]).toMatchObject({
      actionEnvelopeHash: h2,
      decision: "propose",
    });
    expect(replacement.authorizationRequirements).toMatchObject({
      actionEnvelopeHash: h2,
      result: "additionalApprovalsRequired",
      verifier: verifierRequirements.verifier,
      approvalRequirements: verifierRequirements.approvalRequirements,
      policyRef: verifierRequirements.policyRef,
      expiresAt: a2.actionEnvelope.expiresAt,
    });

    await expect(builder.buildCoordinationReplacement(a1, {
      ...verifierRequirements,
      actionEnvelopeHash: { alg: "sha-256", value: "not-h1" },
    })).rejects.toThrow("do not bind to the Action being replaced");
  });

  it("keeps the initial propose decision and canonical JWS bytes", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const proposer = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const builder = new ActionPackageBuilder({
      applicationDid: "did:web:github.example",
      executionProfile: {
        id: "did:web:profiles.oma3.org:mcp",
        format: "mcp.toolsCall",
      },
      keyManager,
    });

    const actionPackage = await builder.buildFromToolCall("create_issue", {});
    const approval = actionPackage.approvalBundle.approvals[0];
    const publicKey = await importJWK(proposer.publicJwk, "EdDSA");
    const verified = await compactVerify(approval.signature.value, publicKey);
    const payloadText = Buffer.from(verified.payload).toString("utf8");

    expect(approval.decision).toBe("propose");
    expect(JSON.parse(payloadText)).toMatchObject({ decision: "propose", signerDid: proposer.did });
    expect(payloadText).toBe(canonicalize(JSON.parse(payloadText)));
  });

  it("uses the trusted execution profile's payload and hash rules", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const profile: TrustedExecutionProfile = {
      id: "did:example:text-profile", format: "text",
      validatePayload: (payload) => typeof payload === "string",
      hashPayload: (payload) => computeJsonHash({ domain: "text-profile", payload }),
    };
    const builder = new ActionPackageBuilder({
      applicationDid: "did:example:text-app", executionProfile: { id: profile.id, format: profile.format },
      keyManager, hashPayload: profile.hashPayload,
    });
    const pkg = await builder.buildFromPayload("profile-native payload");
    const config = {
      trustedSigners: [{ did: keyManager.did }],
      trustedApplicationProfiles: [{ applicationDid: "did:example:text-app" as Did, executionProfile: profile }],
    };
    expect(await verifyActionPackage(pkg, config)).toMatchObject({ status: "verified" });
    expect(await verifyActionPackage(pkg, {
      ...config,
      trustedApplicationProfiles: [{ ...config.trustedApplicationProfiles[0], executionProfile: { ...profile, hashPayload: computeJsonHash } }],
    })).toMatchObject({ status: "rejected", code: "PAYLOAD_HASH_MISMATCH" });
    expect(await verifyActionPackage(pkg, {
      ...config,
      trustedApplicationProfiles: [{ ...config.trustedApplicationProfiles[0], executionProfile: { ...profile, validatePayload: () => false } }],
    })).toMatchObject({ status: "rejected", code: "INVALID_EXECUTION_PAYLOAD" });
  });

  it("accepts a deployment-defined scope without prescribing its spelling", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const builder = new ActionPackageBuilder({
      applicationDid: "did:example:app", keyManager,
      executionProfile: { id: "did:web:profiles.oma3.org:mcp", format: "mcp.toolsCall" },
    });
    const payload = builder.buildPayload("create_issue", {});
    const envelope = builder.buildEnvelope(payload);
    envelope.actionId = { scope: "deployment workspace A", value: "42" };
    const pkg = builder.assemblePackage(payload, envelope, await builder.signProposerApproval(envelope));
    expect(await verifyActionPackage(pkg, {
      trustedSigners: [{ did: keyManager.did }], trustedApplicationDids: ["did:example:app"],
    })).toMatchObject({ status: "verified" });
  });

  it("rejects builder validity windows over the Core 24-hour maximum", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));

    expect(
      () =>
        new ActionPackageBuilder({
          applicationDid: "did:web:github.example",
          executionProfile: {
            id: "did:web:profiles.oma3.org:mcp",
            format: "mcp.toolsCall",
          },
          keyManager,
          defaultExpirationMinutes: 24 * 60 + 1,
        }),
    ).toThrow("at most 1440 minutes");
  });

});
