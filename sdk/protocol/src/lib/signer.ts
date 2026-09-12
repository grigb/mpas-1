import type { JWK } from "jose";
import type { Did } from "../types/mpas.js";
import { deriveDidJwk, didJwkToJwk, didJwkToKid, isDidJwk } from "./did-jwk.js";
import {
  equalBytes, samePublicKey, validatePublicJwk, verifySuiteBytes, verifySuiteCompactJws,
  type MpasJwsAlgorithm, type MpasSignatureSuite,
} from "./signature-suites.js";

/** Shared #56 signing contract. Public metadata never grants signer authority. */
export interface MpasSignerIdentity {
  readonly did: Did;
  readonly kid: string;
  readonly algorithm: MpasJwsAlgorithm;
  readonly publicKey: JWK;
}

export interface MpasJwsSigner extends MpasSignerIdentity {
  /** Complete canonical payload bytes in; complete compact JWS out. Do not pre-hash. */
  signCompactJws(payload: Uint8Array): Promise<string>;
}

export interface MpasRawSigner extends MpasSignerIdentity {
  /** Complete message bytes in; raw suite signature out. Do not pre-hash. */
  signBytes(payload: Uint8Array): Promise<Uint8Array>;
}

export interface MpasSigner extends MpasJwsSigner, MpasRawSigner {}

/** Compatibility with the original did + signBytes HTTP surface, not a provider registry. */
export type MpasHttpSigner = Pick<MpasRawSigner, "did" | "signBytes"> & Partial<MpasSignerIdentity>;

export function validateSignerIdentity(signer: MpasSignerIdentity): MpasSignatureSuite {
  const suite = validatePublicJwk(signer.publicKey);
  if (signer.algorithm !== suite.jwsAlgorithm) throw new Error("Signer algorithm does not match public key.");
  if (typeof signer.did !== "string" || !signer.did.startsWith("did:") || typeof signer.kid !== "string" || !signer.kid) {
    throw new Error("Signer identity metadata is required.");
  }
  if (isDidJwk(signer.did) && (!samePublicKey(didJwkToJwk(signer.did), signer.publicKey) || signer.kid !== didJwkToKid(signer.did))) {
    throw new Error("Signer DID or kid does not match public key.");
  }
  // Other methods require the caller's trusted DID/key binding; no new resolver here.
  return suite;
}

export function resolveHttpSigner(signer: MpasHttpSigner): MpasRawSigner {
  const publicKey = didJwkToJwk(signer.did);
  const suite = validatePublicJwk(publicKey, "verify");
  const resolved: MpasRawSigner = {
    did: signer.did, kid: signer.kid ?? didJwkToKid(signer.did),
    publicKey: signer.publicKey ?? publicKey, algorithm: signer.algorithm ?? suite.jwsAlgorithm,
    signBytes: (payload) => signer.signBytes(payload),
  };
  validateSignerIdentity(resolved);
  return resolved;
}

/** Prevent a provider from returning mismatched headers, payload, encoding, or key. */
export async function signMpasCompactJws(signer: MpasJwsSigner, payload: Uint8Array): Promise<string> {
  const identity = snapshotIdentity(signer);
  validateSignerIdentity(identity);
  const expectedPayload = new Uint8Array(payload);
  const jws = await signer.signCompactJws(new Uint8Array(expectedPayload));
  // A private key can carry key_ops:[sign]. Verify output with its public
  // projection; the provider's sign permission remains independently enforced.
  const publicKey = { ...identity.publicKey, key_ops: ["verify"] };
  const verified = await verifySuiteCompactJws(jws, publicKey, identity.kid);
  if (!equalBytes(expectedPayload, verified)) throw new Error("Signer returned a different JWS payload.");
  return jws;
}

export async function signMpasBytes(signer: MpasRawSigner, payload: Uint8Array): Promise<Uint8Array> {
  const identity = snapshotIdentity(signer);
  validateSignerIdentity(identity);
  const expectedPayload = new Uint8Array(payload);
  const signature = await signer.signBytes(new Uint8Array(expectedPayload));
  if (!verifySuiteBytes({ ...identity.publicKey, key_ops: ["verify"] }, expectedPayload, signature)) {
    throw new Error("Signer returned an invalid raw signature.");
  }
  return signature;
}

/** Authorize against a trusted identity; DID-embedded optional kid never overrides #0. */
export function verificationKid(publicKey: JWK, did?: Did): string {
  const identity = did ?? deriveDidJwk(publicKey);
  if (isDidJwk(identity)) {
    if (!samePublicKey(didJwkToJwk(identity), publicKey)) throw new Error("Verification key does not match DID.");
    return didJwkToKid(identity);
  }
  if (typeof publicKey.kid !== "string" || !publicKey.kid) throw new Error("Trusted key binding requires kid.");
  return publicKey.kid;
}

function snapshotIdentity(signer: MpasSignerIdentity): MpasSignerIdentity {
  return { did: signer.did, kid: signer.kid, algorithm: signer.algorithm, publicKey: structuredClone(signer.publicKey) };
}
