// Explicit test keys only. Generation deliberately uses Node crypto directly,
// not MPAS signing helpers. ECDSA signature bytes change if regenerated.
import { createECDH, createHash, createPrivateKey, sign } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { canonicalize } from "json-canonicalize";

const root = new URL("../../../../", import.meta.url);
const read = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));
const write = async (path, value) => {
  const url = new URL(path, root);
  await mkdir(new URL("./", url), { recursive: true });
  await writeFile(url, `${JSON.stringify(value, null, 2)}\n`);
};
const hash = (value) => ({ alg: "sha-256", value: createHash("sha256").update(canonicalize(value)).digest("base64url") });
const b64 = (value) => Buffer.from(value).toString("base64url");
const d = Buffer.alloc(32); d[31] = 1;
const ecdh = createECDH("prime256v1"); ecdh.setPrivateKey(d);
const point = ecdh.getPublicKey();
const publicJwk = { crv: "P-256", kty: "EC", x: b64(point.subarray(1, 33)), y: b64(point.subarray(33)) };
const canonicalPublicJwk = canonicalize(publicJwk);
const did = `did:jwk:${b64(canonicalPublicJwk)}`;
const privateJwk = { ...publicJwk, d: b64(d), kid: `${did}#0` };
const key = createPrivateKey({ key: privateJwk, format: "jwk" });
const seedPackage = await read("sdk/protocol/tests/fixtures/action-packages/valid-merge-pr-package.json");
const actionEnvelope = { ...seedPackage.actionEnvelope, proposer: { did }, createdAt: "2026-08-07T20:00:00.000Z", expiresAt: "2026-08-07T20:30:00.000Z" };
const executionPayload = seedPackage.executionPayload;
const approvalPayload = { type: "ApprovalPayload", actionEnvelopeHash: hash(actionEnvelope), decision: "approve", signerDid: did, createdAt: "2026-08-07T20:01:00.000Z" };
const receiptPayload = { issuerDid: did, actionEnvelopeHash: hash(actionEnvelope), executionPayloadHash: hash(executionPayload), actionId: actionEnvelope.actionId, proposerDid: did, result: "executed", issuedAt: "2026-08-07T20:02:00.000Z" };
function jws(payload) {
  const input = `${b64(JSON.stringify({ alg: "ES256", kid: `${did}#0` }))}.${b64(canonicalize(payload))}`;
  return `${input}.${b64(sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }))}`;
}
const approvalJws = jws(approvalPayload);
const receiptJws = jws(receiptPayload);
await write("conformance/signature-suites/p256.json", {
  description: "Public test scalar d=1 on P-256; never use for real identities.",
  generatedWith: { node: process.version, openssl: process.versions.openssl },
  publicJwk, canonicalPublicJwk, did, privateJwk, actionEnvelope, executionPayload,
  approvalPayload, canonicalApprovalPayload: canonicalize(approvalPayload),
  approval: { version: "1", type: "Approval", actionEnvelopeHash: hash(actionEnvelope), decision: "approve", createdAt: approvalPayload.createdAt, signature: { format: "jws", value: approvalJws } },
  receiptPayload, canonicalReceiptPayload: canonicalize(receiptPayload),
  receipt: { version: "1", type: "ExecutionReceipt", format: "jws", signature: receiptJws },
});

const original = await read("conformance/http-message-signatures/mpas-v1-ed25519.json");
const ed = await read("sdk/protocol/tests/fixtures/keys/proposer.json");
for (const [filename, httpAlg, jwk, identity] of [
  ["mpas-v1-p256.json", "ecdsa-p256-sha256", privateJwk, did],
  ["mpas-v1-ed25519-explicit-alg.json", "ed25519", ed.privateJwk, ed.did],
]) {
  const fixture = structuredClone(original);
  fixture.algorithm = httpAlg; fixture.did = identity;
  fixture.publicJwk = httpAlg === "ed25519" ? original.publicJwk : publicJwk;
  fixture.request.body = fixture.request.body.replaceAll(original.did, identity);
  fixture.contentDigest = `sha-256=:${createHash("sha256").update(fixture.request.body).digest("base64")}:`;
  const params = `("@method" "@path" "content-digest");created=${fixture.created};expires=${fixture.expires};keyid="${identity}";nonce="${fixture.nonce}";tag="mpas-v1";alg="${httpAlg}"`;
  fixture.signatureInput = `mpas=${params}`;
  fixture.signatureBase = `"@method": POST\n"@path": ${fixture.request.path}\n"content-digest": ${fixture.contentDigest}\n"@signature-params": ${params}`;
  const signature = sign(httpAlg === "ed25519" ? null : "sha256", Buffer.from(fixture.signatureBase), { key: createPrivateKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" });
  fixture.signature = `mpas=:${signature.toString("base64")}:`;
  await write(`conformance/http-message-signatures/${filename}`, fixture);
}
console.log("Generated P-256 and explicit-alg Ed25519 test fixtures; original vectors unchanged.");
