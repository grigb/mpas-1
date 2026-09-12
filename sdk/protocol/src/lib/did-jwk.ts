import type { JWK } from "jose";
import { strictJsonParse } from "../utils/strict-json.js";
import { generateSuiteJwk, normalizePublicJwk, publicJwkFromLocal, validateLocalJwk, validatePublicJwk, type SignatureSuiteId } from "./signature-suites.js";
import { canonicalize } from "json-canonicalize";
import type { Did } from "../types/mpas.js";

export interface GeneratedKey {
  did: Did;
  kid: string;
  privateJwk: JWK;
  publicJwk: JWK;
}

/**
 * Derives a `did:jwk` DID from an Ed25519 or P-256 JWK.
 *
 * MPAS normative derivation rule: the base64url value encodes the
 * JCS-canonicalized (RFC 8785) minimal public JWK — exactly the members
 * required by RFC 7638 for the key type (`crv`, `kty`, `x` for Ed25519; also `y` for P-256),
 * in lexicographic order, with no whitespace. This makes derivation
 * deterministic across independent implementations: same key, same DID.
 *
 * The did:jwk method itself does not mandate a canonical serialization
 * (the DID string, once minted, is the identifier of record). This rule
 * governs minting only; runtime comparison is always exact string match.
 */
export function deriveDidJwk(jwk: JWK): Did {
  validateLocalJwk(jwk);
  const minimalPublicJwk = normalizePublicJwk(publicJwkFromLocal(jwk));
  const encoded = Buffer.from(canonicalize(minimalPublicJwk), "utf8").toString("base64url");
  return `did:jwk:${encoded}`;
}

/**
 * Decodes the public JWK embedded in a `did:jwk` DID. The DID is the source
 * of truth for the key: any separately configured JWK is redundant for
 * did:jwk identities.
 *
 * Throws if the DID is not a valid did:jwk, if the embedded JWK contains
 * private key material (`d` — the method spec requires rejection), or if the
 * key is not a specification-approved signing key.
 */
export function didJwkToJwk(did: string): JWK {
  if (!did.startsWith("did:jwk:")) {
    throw new Error(`Not a did:jwk DID: ${did}`);
  }

  const encoded = did.slice("did:jwk:".length);
  if (encoded.length === 0 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error("did:jwk payload is not canonical unpadded base64url.");
  }

  let parsed: unknown;
  try {
    const decoded = Buffer.from(encoded, "base64url");
    if (decoded.toString("base64url") !== encoded) {
      throw new Error("non-canonical base64url");
    }
    parsed = strictJsonParse(decoded.toString("utf8"));
  } catch {
    throw new Error("did:jwk payload is not valid base64url-encoded JSON.");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("did:jwk payload must be a JWK object.");
  }

  const jwk = parsed as JWK;
  validatePublicJwk(jwk, "verify");

  return jwk;
}

/** True when the DID uses the did:jwk method. */
export function isDidJwk(did: string): boolean {
  return did.startsWith("did:jwk:");
}

/**
 * The DID URL for the single verification method of a did:jwk document.
 * Per the did:jwk method spec, the fragment is always `#0`.
 */
export function didJwkToKid(did: Did): string {
  return `${did}#0`;
}

/** Generates a fresh Ed25519 signing key with its derived `did:jwk` and `kid`. */
export async function generateEd25519Key(): Promise<GeneratedKey> {
  return generateMpasKey("Ed25519");
}

/** Explicit opt-in P-256 identity generation; never converts an existing DID. */
export async function generateP256Key(): Promise<GeneratedKey> {
  return generateMpasKey("P-256");
}

/** Signing/key-generation selection only. Verifiers always implement both suites. */
export async function generateMpasKey(suite: SignatureSuiteId = "Ed25519"): Promise<GeneratedKey> {
  const privateJwk = generateSuiteJwk(suite);
  const publicJwk = publicJwkFromLocal(privateJwk);
  const did = deriveDidJwk(publicJwk);
  const kid = didJwkToKid(did);
  return { did, kid, privateJwk: { ...privateJwk, kid }, publicJwk: { ...publicJwk, kid } };
}
