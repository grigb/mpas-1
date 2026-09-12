import {
  createECDH, ECDH, createPrivateKey, createPublicKey, generateKeyPairSync,
  sign, verify, timingSafeEqual, type JsonWebKey,
} from "node:crypto";
import { CompactSign, compactVerify, importJWK, type JWK } from "jose";
import { strictJsonParse } from "../utils/strict-json.js";

export type SignatureSuiteId = "Ed25519" | "P-256";
export type MpasJwsAlgorithm = "EdDSA" | "ES256";
export type MpasHttpSignatureAlgorithm = "ed25519" | "ecdsa-p256-sha256";
type KeyOperation = "sign" | "verify";

/** Immutable MPAS-defined policy. There is deliberately no registration API. */
export interface MpasSignatureSuite {
  readonly id: SignatureSuiteId;
  readonly kty: "OKP" | "EC";
  readonly jwsAlgorithm: MpasJwsAlgorithm;
  readonly httpSignatureAlgorithm: MpasHttpSignatureAlgorithm;
}

const suites: readonly MpasSignatureSuite[] = Object.freeze([
  Object.freeze({ id: "Ed25519", kty: "OKP", jwsAlgorithm: "EdDSA", httpSignatureAlgorithm: "ed25519" } as const),
  Object.freeze({ id: "P-256", kty: "EC", jwsAlgorithm: "ES256", httpSignatureAlgorithm: "ecdsa-p256-sha256" } as const),
]);
const p256Order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/** Selection is for signing/key generation only; all verifiers support both. */
export function getSignatureSuite(id: SignatureSuiteId): MpasSignatureSuite {
  const suite = suites.find((candidate) => candidate.id === id);
  if (!suite) throw new Error("Unsupported MPAS signature suite.");
  return suite;
}

/** Select using the key, never an incoming algorithm name. Validates key material. */
export function resolveSignatureSuite(jwk: JWK): MpasSignatureSuite {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) throw new Error("JWK must be an object.");
  const matches = suites.filter((suite) => suite.kty === jwk.kty && suite.id === jwk.crv);
  if (matches.length !== 1) throw new Error("Unsupported or ambiguous MPAS public-key suite.");
  const suite = matches[0];
  const x = fixedBytes(jwk.x, "x");
  if (suite.id === "P-256") {
    const y = fixedBytes(jwk.y, "y");
    // OpenSSL checks field bounds and curve membership; infinity is not a JWK point.
    ECDH.convertKey(Buffer.concat([Buffer.from([4]), x, y]), "prime256v1");
  }
  validateMetadata(jwk, suite);
  return suite;
}

export function validatePublicJwk(jwk: JWK, operation?: KeyOperation): MpasSignatureSuite {
  const suite = resolveSignatureSuite(jwk);
  if (privateMembers.some((name) => Object.hasOwn(jwk, name))) throw new Error("Public JWK must not contain private key material.");
  validateMetadata(jwk, suite, operation);
  return suite;
}

/** Only for already trusted local key material; DID decoding must validate first. */
export function publicJwkFromLocal(jwk: JWK): JWK {
  const copy = structuredClone(jwk);
  for (const name of privateMembers) delete (copy as Record<string, unknown>)[name];
  return copy;
}

export function normalizePublicJwk(jwk: JWK): JWK {
  const suite = validatePublicJwk(jwk);
  return suite.id === "P-256"
    ? { crv: suite.id, kty: suite.kty, x: jwk.x, y: jwk.y }
    : { crv: suite.id, kty: suite.kty, x: jwk.x };
}

export function validateLocalJwk(jwk: JWK): MpasSignatureSuite {
  const suite = resolveSignatureSuite(jwk);
  if (privateMembers.filter((name) => name !== "d").some((name) => Object.hasOwn(jwk, name))) {
    throw new Error("Unsupported private JWK parameters.");
  }
  if (!Object.hasOwn(jwk, "d")) return validatePublicJwk(jwk);
  const d = fixedBytes(jwk.d, "d");
  let derived: JWK;
  if (suite.id === "P-256") {
    if (!validScalar(d)) throw new Error("Invalid P-256 private scalar.");
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(d);
    const point = ecdh.getPublicKey();
    derived = { x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") };
  } else {
    // Derive from the seed alone: importing a JWK with both d and x is not a
    // public/private consistency check in every crypto implementation.
    const seedKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), d]),
      format: "der", type: "pkcs8",
    });
    derived = createPublicKey(seedKey).export({ format: "jwk" }) as JWK;
  }
  if (derived.x !== jwk.x || (suite.id === "P-256" && derived.y !== jwk.y)) {
    throw new Error("Public and private JWK material do not match.");
  }
  return suite;
}

export function generateSuiteJwk(id: SignatureSuiteId): JWK {
  const suite = getSignatureSuite(id);
  const pair = suite.id === "Ed25519"
    ? generateKeyPairSync("ed25519")
    : generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return pair.privateKey.export({ format: "jwk" }) as JWK;
}

export function validateSignatureEncoding(suite: MpasSignatureSuite, signature: Uint8Array): void {
  if (signature.length !== 64) throw new Error("MPAS signatures must be exactly 64 raw bytes.");
  if (suite.id === "P-256" && (!validScalar(signature.subarray(0, 32)) || !validScalar(signature.subarray(32)))) {
    throw new Error("Invalid P-256 signature scalar.");
  }
}

/** Message bytes, not a digest. Node performs P-256 SHA-256 exactly once. */
export function signSuiteBytes(jwk: JWK, input: Uint8Array): Uint8Array {
  const suite = validateLocalJwk(jwk);
  if (!Object.hasOwn(jwk, "d")) throw new Error("Signing requires private key material.");
  validateMetadata(jwk, suite, "sign");
  const key = createPrivateKey({ key: jwk as JsonWebKey, format: "jwk" });
  const result = sign(suite.id === "P-256" ? "sha256" : null, input, { key, dsaEncoding: "ieee-p1363" });
  validateSignatureEncoding(suite, result);
  return result;
}

export function verifySuiteBytes(jwk: JWK, input: Uint8Array, signature: Uint8Array): boolean {
  try {
    const suite = validatePublicJwk(jwk, "verify");
    validateSignatureEncoding(suite, signature);
    const key = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
    return verify(suite.id === "P-256" ? "sha256" : null, input, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch { return false; }
}

export async function signSuiteCompactJws(jwk: JWK, payload: Uint8Array, kid: string): Promise<string> {
  const suite = validateLocalJwk(jwk);
  if (!Object.hasOwn(jwk, "d")) throw new Error("Signing requires private key material.");
  validateMetadata(jwk, suite, "sign");
  const key = await importJWK(jwk, suite.jwsAlgorithm);
  return new CompactSign(payload).setProtectedHeader({ alg: suite.jwsAlgorithm, kid }).sign(key);
}

/** Verifies protected headers, expected key authorization, and exact wire encoding. */
export async function verifySuiteCompactJws(jws: string, publicJwk: JWK, expectedKid: string): Promise<Uint8Array> {
  const suite = validatePublicJwk(publicJwk, "verify");
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("Invalid compact JWS.");
  const header = strictJsonParse(decodeBase64url(parts[0]).toString("utf8"));
  if (!header || typeof header !== "object" || Array.isArray(header) ||
      (header as Record<string, unknown>).alg !== suite.jwsAlgorithm || (header as Record<string, unknown>).kid !== expectedKid ||
      (header as Record<string, unknown>).b64 === false) throw new Error("Invalid protected JWS algorithm or key identifier.");
  // MPAS uses ordinary base64url-encoded JWS payloads, never RFC 7797 b64=false.
  decodeBase64url(parts[1], true);
  validateSignatureEncoding(suite, decodeBase64url(parts[2]));
  const key = await importJWK(publicJwk, suite.jwsAlgorithm);
  const { payload } = await compactVerify(jws, key, { algorithms: [suite.jwsAlgorithm] });
  return payload;
}

export function samePublicKey(left: JWK, right: JWK): boolean {
  return JSON.stringify(normalizePublicJwk(left)) === JSON.stringify(normalizePublicJwk(right));
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function fixedBytes(value: unknown, name: string): Buffer {
  if (typeof value !== "string") throw new Error(`JWK ${name} must be base64url-encoded 32 bytes.`);
  const decoded = decodeBase64url(value);
  if (decoded.length !== 32) throw new Error(`JWK ${name} must contain exactly 32 bytes.`);
  return decoded;
}

function decodeBase64url(value: string, allowEmpty = false): Buffer {
  if (!(allowEmpty ? /^[A-Za-z0-9_-]*$/ : /^[A-Za-z0-9_-]+$/).test(value)) throw new Error("Invalid unpadded base64url.");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error("Non-canonical base64url.");
  return decoded;
}

function validScalar(bytes: Uint8Array): boolean {
  const value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  return value > 0n && value < p256Order;
}

function validateMetadata(jwk: JWK, suite: MpasSignatureSuite, operation?: KeyOperation): void {
  if (Object.hasOwn(jwk, "alg") && jwk.alg !== suite.jwsAlgorithm) throw new Error("JWK alg does not match its suite.");
  if (Object.hasOwn(jwk, "use") && jwk.use !== "sig") throw new Error("JWK use must permit signatures.");
  if (Object.hasOwn(jwk, "key_ops")) {
    if (!Array.isArray(jwk.key_ops) || jwk.key_ops.length === 0 ||
        new Set(jwk.key_ops).size !== jwk.key_ops.length ||
        jwk.key_ops.some((op) => op !== "sign" && op !== "verify") ||
        (operation && !jwk.key_ops.includes(operation))) throw new Error("JWK key_ops does not permit this operation.");
  }
}
