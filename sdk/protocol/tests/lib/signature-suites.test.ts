import { createPrivateKey, sign, webcrypto } from "node:crypto";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "json-canonicalize";
import { CompactSign, importJWK, type JWK } from "jose";
import { describe, expect, it } from "vitest";
import {
  ApprovalBuilder, ActionPackageBuilder, KeyManager, deriveDidJwk, didJwkToJwk,
  generateMpasKey, generateP256Key, generateEd25519Key, getSignatureSuite,
  resolveSignatureSuite, validatePublicJwk, normalizePublicJwk,
  signMpasCompactJws, signMpasBytes, signMpasRfc9421, verifyMpasRfc9421,
  buildAndSignExecutionReceipt, verifyExecutionReceipt, verifyApproval,
  verifyApprovalSignature, verifyApprovalBundle, computeJsonHash,
  type ActionEnvelope, type Approval, type Did, type MpasSigner,
} from "../../src/index.js";

const fixture = JSON.parse(await readFile(new URL("../../../../conformance/signature-suites/p256.json", import.meta.url), "utf8"));
const now = new Date("2026-08-07T20:00:00.000Z");
const audience = "https://coordination.example.com";
const path = "/mpas/v1/coordination/poll";
const didWith = (jwk: JWK): Did => `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString("base64url")}`;

function opaque(jwk: JWK): MpasSigner {
  // Web Crypto retains the private key in an unexportable CryptoKey. The public
  // provider object contains only public metadata and signing methods.
  const { d: _d, ...publicKey } = jwk;
  const key = webcrypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const did = deriveDidJwk(publicKey);
  return {
    did, kid: `${did}#0`, publicKey, algorithm: "ES256",
    async signBytes(bytes) {
      return new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await key, bytes));
    },
    async signCompactJws(payload) {
      const input = `${Buffer.from(JSON.stringify({ alg: "ES256", kid: this.kid })).toString("base64url")}.${Buffer.from(payload).toString("base64url")}`;
      return `${input}.${Buffer.from(await this.signBytes(Buffer.from(input))).toString("base64url")}`;
    },
  };
}

describe("specification-governed signature suites", () => {
  it.each(["Ed25519", "P-256"] as const)("generates, signs and verifies %s, preserving public-only behavior", async (id) => {
    const generated = await generateMpasKey(id);
    const signer = KeyManager.fromJwk(generated.privateJwk, { suite: id });
    const verifier = KeyManager.fromJwk(generated.publicJwk);
    expect(signer.did).toBe(generated.did);
    const input = Buffer.from("MPAS complete input bytes");
    const jws = await signer.signCompactJws(input);
    expect(await verifier.verifyCompactJws(jws)).toBe(true);
    expect(await verifier.verifyBytes(input, await signer.signBytes(input))).toBe(true);
    await expect(verifier.signBytes(input)).rejects.toThrow("private key material");
    await expect(verifier.signCompactJws(input)).rejects.toThrow("private key material");
    expect(verifier.publicKey).not.toHaveProperty("d");
    expect(Object.isFrozen(getSignatureSuite(id))).toBe(true);
  });

  it("uses explicit P-256 generation and rejects unknown or mismatched signing selection", async () => {
    expect((await generateP256Key()).publicJwk.crv).toBe("P-256");
    expect((await generateEd25519Key()).publicJwk.crv).toBe("Ed25519");
    await expect(generateMpasKey("ES256K" as never)).rejects.toThrow("Unsupported");
    expect(() => KeyManager.fromJwk(fixture.privateJwk, { suite: "Ed25519" })).toThrow("does not match");
    expect(() => getSignatureSuite("RSA" as never)).toThrow("Unsupported");
  });

  it("matches fixed P-256 DID and canonical artifact vectors", async () => {
    expect(canonicalize(normalizePublicJwk(fixture.publicJwk))).toBe(fixture.canonicalPublicJwk);
    expect(deriveDidJwk(fixture.privateJwk)).toBe(fixture.did);
    expect(didJwkToJwk(fixture.did)).toEqual(fixture.publicJwk);
    expect(canonicalize(fixture.approvalPayload)).toBe(fixture.canonicalApprovalPayload);
    expect(canonicalize(fixture.receiptPayload)).toBe(fixture.canonicalReceiptPayload);
    expect(await verifyApproval(fixture.approval, fixture.publicJwk)).toBe(true);
    expect(await verifyExecutionReceipt(fixture.receipt, {
      verifier: { did: fixture.did }, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload,
    })).toBe(true);
  });

  it("preserves received DID metadata and exact identity without reminting", async () => {
    const { kid: _kid, ...local } = fixture.privateJwk;
    const jwk = { ...fixture.publicJwk, alg: "ES256", use: "sig", key_ops: ["verify"] };
    const did = didWith(jwk);
    expect(did).not.toBe(fixture.did);
    expect(didJwkToJwk(did)).toEqual(jwk);
    const manager = KeyManager.fromJwk(local, { did });
    const approval = await new ApprovalBuilder({ signer: manager }).buildApproval(fixture.actionEnvelope, "approve");
    expect(manager.did).toBe(did);
    expect(await verifyApproval(approval, jwk, did)).toBe(true);
    expect(await verifyApprovalBundle({ version: "1", type: "ApprovalBundle", actionEnvelopeHash: approval.actionEnvelopeHash, approvals: [approval] }, approval.actionEnvelopeHash, [{ did }])).toMatchObject({ ok: true });
    const dir = await mkdtemp(join(tmpdir(), "mpas-did-"));
    try {
      const file = join(dir, "key.json");
      await writeFile(file, JSON.stringify({ did, privateJwk: local }));
      expect((await KeyManager.fromFile(file)).did).toBe(did);
    } finally { await rm(dir, { recursive: true, force: true }); }
    expect(deriveDidJwk(jwk)).toBe(fixture.did);
  });

  it.each([
    { crv: "secp256k1" }, { crv: "P-384" }, { kty: "RSA" },
    { x: undefined }, { y: undefined }, { y: true }, { x: "x" },
    { x: Buffer.alloc(31).toString("base64url") }, { y: Buffer.alloc(33).toString("base64url") },
    { x: fixture.publicJwk.x + "=" }, { y: Buffer.alloc(32, 255).toString("base64url") },
    { x: Buffer.alloc(32).toString("base64url"), y: Buffer.alloc(32).toString("base64url") },
    { alg: "EdDSA" }, { use: "enc" }, { key_ops: ["encrypt"] }, { key_ops: [] },
  ])("rejects malformed/unsupported public key %#", (change) => {
    const key = { ...fixture.publicJwk, ...change };
    expect(() => validatePublicJwk(key)).toThrow();
    expect(() => didJwkToJwk(didWith(key))).toThrow();
  });

  it.each([null, "", fixture.privateJwk.d])("rejects private material in a DID (%s)", (d) => {
    expect(() => didJwkToJwk(didWith({ ...fixture.publicJwk, d } as JWK))).toThrow("private");
  });

  it("checks local private scalars, public/private consistency, and key metadata permissions", async () => {
    for (const d of ["", "AA", Buffer.alloc(32).toString("base64url"), Buffer.alloc(32, 255).toString("base64url")]) {
      expect(() => KeyManager.fromJwk({ ...fixture.privateJwk, d })).toThrow();
    }
    const other = await generateP256Key();
    expect(() => KeyManager.fromJwk({ ...fixture.privateJwk, d: other.privateJwk.d })).toThrow("do not match");
    const ed = await generateEd25519Key();
    const ed2 = await generateEd25519Key();
    expect(() => KeyManager.fromJwk({ ...ed.privateJwk, x: ed2.publicJwk.x })).toThrow("do not match");
    const onlyVerify = KeyManager.fromJwk({ ...fixture.privateJwk, key_ops: ["verify"] });
    await expect(onlyVerify.signBytes(Buffer.from("input"))).rejects.toThrow("key_ops");
    expect(() => didJwkToJwk(didWith({ ...fixture.publicJwk, key_ops: ["sign"] }))).toThrow("key_ops");
  });

  it("supports non-exporting Web Crypto signing through all three protocol consumers", async () => {
    const signer = opaque(fixture.privateJwk);
    expect(signer).not.toHaveProperty("privateJwk");
    const approval = await new ApprovalBuilder({ signer }).buildApproval(fixture.actionEnvelope, "approve");
    expect(await verifyApproval(approval, signer.publicKey)).toBe(true);
    const receipt = await buildAndSignExecutionReceipt({ signer, verifierDid: signer.did, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload, result: { result: "executed" } });
    expect(await verifyExecutionReceipt(receipt, { verifier: { did: signer.did }, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload })).toBe(true);
    const body = Buffer.from(JSON.stringify({ did: signer.did, audience }));
    const headers = await signMpasRfc9421({ method: "POST", path, body, signer, created: now });
    expect(await verifyMpasRfc9421({ method: "POST", path, body, headers, audiences: [audience], now })).toMatchObject({ ok: true, did: signer.did });
  });

  it("rejects provider metadata and returned payload/encoding/key mismatches", async () => {
    const signer = opaque(fixture.privateJwk);
    const input = Buffer.from("input");
    await expect(signMpasCompactJws({ ...signer, algorithm: "EdDSA" }, input)).rejects.toThrow("algorithm");
    await expect(signMpasCompactJws({ ...signer, kid: `${signer.did}#other` }, input)).rejects.toThrow("kid");
    await expect(signMpasCompactJws({ ...signer, signCompactJws: () => signer.signCompactJws(Buffer.from("other")) }, input)).rejects.toThrow("different JWS payload");
    await expect(signMpasBytes({ ...signer, signBytes: async () => new Uint8Array(65) }, input)).rejects.toThrow("invalid raw signature");
    const another = opaque((await generateP256Key()).privateJwk);
    await expect(signMpasBytes({ ...signer, signBytes: (bytes) => another.signBytes(bytes) }, input)).rejects.toThrow();
    await expect(signMpasCompactJws({ ...signer, signCompactJws: (bytes) => { bytes.fill(0); return signer.signCompactJws(bytes); } }, input)).rejects.toThrow("different JWS payload");
    await expect(signMpasBytes({ ...signer, signBytes: (bytes) => { bytes.fill(0); return signer.signBytes(bytes); } }, input)).rejects.toThrow("invalid raw signature");
    expect(input.toString()).toBe("input");
    const key = createPrivateKey({ key: fixture.privateJwk, format: "jwk" });
    await expect(signMpasBytes({ ...signer, signBytes: async (bytes) => sign("sha256", bytes, key) }, input)).rejects.toThrow();
  });

  it.each(["none", "EdDSA", "ES256K", "RS256", undefined])("rejects JWS algorithm %s with a P-256 key", async (alg) => {
    const parts = fixture.approval.signature.value.split(".");
    parts[0] = Buffer.from(JSON.stringify({ alg, kid: `${fixture.did}#0` })).toString("base64url");
    expect(await verifyApprovalSignature({ ...fixture.approval, signature: { format: "jws", value: parts.join(".") } }, fixture.publicJwk)).toBe(false);
  });

  it("rejects a valid signature with missing or unauthorized kid and cross-suite keys", async () => {
    const key = await importJWK(fixture.privateJwk, "ES256");
    for (const kid of [undefined, "different", `${fixture.did}#1`]) {
      const value = await new CompactSign(Buffer.from(fixture.canonicalApprovalPayload)).setProtectedHeader({ alg: "ES256", kid }).sign(key);
      expect(await verifyApprovalSignature({ ...fixture.approval, signature: { format: "jws", value } }, fixture.publicJwk)).toBe(false);
    }
    expect(await verifyApprovalSignature(fixture.approval, (await generateEd25519Key()).publicJwk)).toBe(false);
    const ed = KeyManager.fromJwk((await generateEd25519Key()).privateJwk);
    const approval = await new ApprovalBuilder({ signer: ed }).buildApproval(fixture.actionEnvelope, "approve");
    expect(await verifyApprovalSignature(approval, fixture.publicJwk)).toBe(false);
  });

  it("rejects raw/DER length and scalar errors, including on correctly bound JWS headers", async () => {
    const manager = KeyManager.fromJwk(fixture.publicJwk);
    const [header, payload] = fixture.approval.signature.value.split(".");
    const input = Buffer.from(`${header}.${payload}`);
    const der = sign("sha256", input, createPrivateKey({ key: fixture.privateJwk, format: "jwk" }));
    for (const raw of [der, Buffer.alloc(0), Buffer.alloc(63), Buffer.alloc(65), Buffer.alloc(64), Buffer.alloc(64, 255)]) {
      expect(await manager.verifyBytes(input, raw)).toBe(false);
      expect(await manager.verifyCompactJws(`${header}.${payload}.${raw.toString("base64url")}`)).toBe(false);
    }
  });

  it("binds Approval fields and receipt issuer, Action, payload, timestamps, and result", async () => {
    expect(await verifyApproval({ ...fixture.approval, decision: "reject" }, fixture.publicJwk)).toBe(false);
    const opts = { verifier: { did: fixture.did }, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload };
    expect(await verifyExecutionReceipt(fixture.receipt, { ...opts, verifier: { did: (await generateP256Key()).did } })).toBe(false);
    expect(await verifyExecutionReceipt(fixture.receipt, { ...opts, executionPayload: { name: "other" } })).toBe(false);
    expect(await verifyExecutionReceipt(fixture.receipt, { ...opts, actionEnvelope: { ...fixture.actionEnvelope, actionId: { value: "other" } } })).toBe(false);
    const signer = KeyManager.fromJwk(fixture.privateJwk);
    for (const change of [{ issuerDid: "did:web:other" }, { result: "unsupported" }, { issuedAt: "bad" }, { actionId: {} }]) {
      const signature = await signer.signCompactJws(Buffer.from(canonicalize({ ...fixture.receiptPayload, ...change })));
      expect(await verifyExecutionReceipt({ ...fixture.receipt, signature }, opts)).toBe(false);
    }
  });

  it("uses the same canonical payload and supports mixed-suite Approval bundles", async () => {
    const p256 = KeyManager.fromJwk(fixture.privateJwk);
    const ed = KeyManager.fromJwk((await generateEd25519Key()).privateJwk);
    const payload = Buffer.from(fixture.canonicalApprovalPayload);
    for (const signer of [p256, ed]) expect((await signer.signCompactJws(payload)).split(".")[1]).toBe(payload.toString("base64url"));
    const approvals = await Promise.all([p256, ed].map((signer) => new ApprovalBuilder({ signer }).buildApproval(fixture.actionEnvelope, "approve")));
    const hash = computeJsonHash(fixture.actionEnvelope);
    const result = await verifyApprovalBundle({ version: "1", type: "ApprovalBundle", actionEnvelopeHash: hash, approvals }, hash, [p256, ed].map(({ did }) => ({ did })));
    expect(result).toMatchObject({ ok: true });
    const pkg = await new ActionPackageBuilder({ applicationDid: "did:web:test", executionProfile: { id: "did:web:mcp", format: "mcp.toolsCall" }, signer: opaque(fixture.privateJwk) }).buildFromToolCall("echo", {});
    expect(await verifyApproval(pkg.approvalBundle.approvals[0], fixture.publicJwk)).toBe(true);
  });

  it("preserves optional receipt fields and checks scope, proposer, and application-defined results", async () => {
    const signer = KeyManager.fromJwk(fixture.privateJwk);
    const opts = { verifier: { did: fixture.did }, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload };
    const { actionId: _actionId, proposerDid: _proposerDid, ...required } = fixture.receiptPayload;
    const receipt = { ...fixture.receipt, signature: await signer.signCompactJws(Buffer.from(canonicalize(required))) };
    expect(await verifyExecutionReceipt(receipt, opts)).toBe(true);
    expect(await verifyExecutionReceipt({ ...receipt, payload: required }, opts)).toBe(false);
    for (const change of [
      { actionId: { ...fixture.actionEnvelope.actionId, scope: "other" } },
      { proposerDid: "did:web:other" },
    ]) {
      const signature = await signer.signCompactJws(Buffer.from(canonicalize({ ...required, ...change })));
      expect(await verifyExecutionReceipt({ ...receipt, signature }, opts)).toBe(false);
    }
    const signature = await signer.signCompactJws(Buffer.from(canonicalize({ ...required, result: "application-resolved" })));
    expect(await verifyExecutionReceipt({ ...receipt, signature }, opts)).toBe(false);
    expect(await verifyExecutionReceipt({ ...receipt, signature }, { ...opts, additionalResults: ["application-resolved"] })).toBe(true);
  });

  it("preserves private-JWK receipt calls with an explicitly trusted non-did:jwk issuer", async () => {
    const did: Did = "did:web:adapter.example.com";
    const kid = `${did}#receipt-key`;
    const signingKey = { ...(await generateEd25519Key()).privateJwk, kid };
    const { d: _d, ...publicJwk } = signingKey;
    const receipt = await buildAndSignExecutionReceipt({
      signingKey, verifierDid: did, actionEnvelope: fixture.actionEnvelope,
      executionPayload: fixture.executionPayload, result: { result: "executed" },
    });
    const opts = { verifier: { did, publicJwk }, actionEnvelope: fixture.actionEnvelope, executionPayload: fixture.executionPayload };
    expect(await verifyExecutionReceipt(receipt, opts)).toBe(true);
    expect(await verifyExecutionReceipt(receipt, { ...opts, verifier: { did, publicJwk: { ...publicJwk, kid: `${did}#other` } } })).toBe(false);
    expect(await verifyExecutionReceipt(receipt, { ...opts, verifier: { did } })).toBe(false);
  });
});

describe("dual-suite HTTP conformance", () => {
  it.each(["mpas-v1-ed25519.json", "mpas-v1-ed25519-explicit-alg.json", "mpas-v1-p256.json"])("verifies fixed %s and exact new-sender bases", async (name) => {
    const vector = JSON.parse(await readFile(new URL(`../../../../conformance/http-message-signatures/${name}`, import.meta.url), "utf8"));
    const opts = { method: vector.request.method, path: vector.request.path, body: Buffer.from(vector.request.body), audiences: [audience], now: new Date(vector.created * 1000) };
    const headers = { "Content-Digest": vector.contentDigest, "Signature-Input": vector.signatureInput, Signature: vector.signature };
    expect(await verifyMpasRfc9421({ ...opts, headers })).toMatchObject({ ok: true, did: vector.did });
    if (name === "mpas-v1-ed25519.json") return;
    const manager = name.includes("p256") ? KeyManager.fromJwk(fixture.privateJwk) : await KeyManager.fromFile(new URL("../fixtures/keys/proposer.json", import.meta.url).pathname);
    let observedBase = "";
    const signer = { did: manager.did, async signBytes(bytes: Uint8Array) { observedBase = Buffer.from(bytes).toString(); return manager.signBytes(bytes); } };
    const fresh = await signMpasRfc9421({ ...opts, signer, created: new Date(vector.created * 1000), expires: new Date(vector.expires * 1000), nonce: vector.nonce });
    expect(observedBase).toBe(vector.signatureBase);
    expect(fresh["Signature-Input"]).toBe(vector.signatureInput);
    expect(await verifyMpasRfc9421({ ...opts, headers: fresh })).toMatchObject({ ok: true });
    if (!name.includes("p256")) expect(fresh.Signature).toBe(vector.signature);
  });

  it("rejects absent/mismatched P-256 alg even with a valid signature over the received base", async () => {
    const vector = JSON.parse(await readFile(new URL("../../../../conformance/http-message-signatures/mpas-v1-p256.json", import.meta.url), "utf8"));
    const signer = KeyManager.fromJwk(fixture.privateJwk);
    for (const suffix of ["", ';alg="ed25519"', ';alg="ES256"', ';alg="unknown"']) {
      const input = vector.signatureInput.replace(';alg="ecdsa-p256-sha256"', suffix);
      const base = vector.signatureBase.replace(';alg="ecdsa-p256-sha256"', suffix);
      const signature = `mpas=:${Buffer.from(await signer.signBytes(Buffer.from(base))).toString("base64")}:`;
      expect(await verifyMpasRfc9421({ method: "POST", path, body: Buffer.from(vector.request.body), audiences: [audience], now: new Date(vector.created * 1000), headers: { "Content-Digest": vector.contentDigest, "Signature-Input": input, Signature: signature } })).toMatchObject({ ok: false, code: "signature_invalid" });
    }
  });

  it("detects removal of alg from a new Ed25519 signature", async () => {
    const signer = KeyManager.fromJwk((await generateEd25519Key()).privateJwk);
    const body = Buffer.from(JSON.stringify({ did: signer.did, audience }));
    const headers = await signMpasRfc9421({ method: "POST", path, signer, body, created: now });
    headers["Signature-Input"] = headers["Signature-Input"].replace(';alg="ed25519"', "");
    expect(await verifyMpasRfc9421({ method: "POST", path, body, headers, audiences: [audience], now })).toMatchObject({ ok: false, reason: "signature_unverifiable" });
  });

  it("rejects mismatched Ed25519 algorithms even when the changed base is correctly signed", async () => {
    const vector = JSON.parse(await readFile(new URL("../../../../conformance/http-message-signatures/mpas-v1-ed25519-explicit-alg.json", import.meta.url), "utf8"));
    const signer = await KeyManager.fromFile(new URL("../fixtures/keys/proposer.json", import.meta.url).pathname);
    for (const alg of ["ecdsa-p256-sha256", "EdDSA", "unknown"]) {
      const input = vector.signatureInput.replace(';alg="ed25519"', `;alg="${alg}"`);
      const base = vector.signatureBase.replace(';alg="ed25519"', `;alg="${alg}"`);
      const signature = `mpas=:${Buffer.from(await signer.signBytes(Buffer.from(base))).toString("base64")}:`;
      expect(await verifyMpasRfc9421({ method: "POST", path, body: Buffer.from(vector.request.body), audiences: [audience], now: new Date(vector.created * 1000), headers: { "Content-Digest": vector.contentDigest, "Signature-Input": input, Signature: signature } })).toMatchObject({ ok: false, code: "signature_invalid" });
    }
  });

  it("rejects DER, invalid scalars, and wrong lengths on the HTTP wire", async () => {
    const vector = JSON.parse(await readFile(new URL("../../../../conformance/http-message-signatures/mpas-v1-p256.json", import.meta.url), "utf8"));
    const der = sign("sha256", Buffer.from(vector.signatureBase), createPrivateKey({ key: fixture.privateJwk, format: "jwk" }));
    for (const raw of [der, Buffer.alloc(63), Buffer.alloc(65), Buffer.alloc(64), Buffer.alloc(64, 255)]) {
      const signature = `mpas=:${raw.toString("base64")}:`;
      expect(await verifyMpasRfc9421({ method: "POST", path, body: Buffer.from(vector.request.body), audiences: [audience], now: new Date(vector.created * 1000), headers: { "Content-Digest": vector.contentDigest, "Signature-Input": vector.signatureInput, Signature: signature } })).toMatchObject({ ok: false, code: "signature_invalid" });
    }
  });
});
