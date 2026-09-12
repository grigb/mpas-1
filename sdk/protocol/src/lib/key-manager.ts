import { readFile } from "node:fs/promises";
import type { JWK } from "jose";
import { strictJsonParse } from "../utils/strict-json.js";
import type { Did } from "../types/mpas.js";
import { deriveDidJwk, didJwkToJwk, didJwkToKid } from "./did-jwk.js";
import { validateSignerIdentity, verificationKid, type MpasSigner } from "./signer.js";
import {
  getSignatureSuite, publicJwkFromLocal, samePublicKey, signSuiteBytes,
  signSuiteCompactJws, validateLocalJwk, verifySuiteBytes, verifySuiteCompactJws,
  type SignatureSuiteId, type MpasJwsAlgorithm,
} from "./signature-suites.js";

interface KeyFixtureFile {
  did?: Did;
  kid?: string;
  privateJwk?: JWK;
  publicJwk?: JWK;
}

export interface KeyManagerOptions {
  /** Explicit trusted identity/key binding; no DID network resolution is performed. */
  did?: Did;
  /** Optional signing selection; it must match the supplied key. */
  suite?: SignatureSuiteId;
}

/** Local implementation of the shared signer. Public-only instances can verify. */
export class KeyManager implements MpasSigner {
  private constructor(private readonly jwk: JWK, readonly did: Did, readonly algorithm: MpasJwsAlgorithm) {}

  static async fromFile(path: string, options: KeyManagerOptions = {}): Promise<KeyManager> {
    const parsed = strictJsonParse(await readFile(path, "utf8")) as JWK | KeyFixtureFile;
    const storedDid = "did" in parsed && parsed.did ? parsed.did : undefined;
    if (storedDid && options.did && storedDid !== options.did) throw new Error("Configured DID does not match stored DID.");
    const manager = KeyManager.fromJwk(selectJwk(parsed), { ...options, did: storedDid ?? options.did });
    if ("kid" in parsed && parsed.kid && parsed.kid !== manager.kid) throw new Error("Configured kid does not match DID.");
    if ("publicJwk" in parsed && parsed.publicJwk && !samePublicKey(parsed.publicJwk, manager.publicKey)) {
      throw new Error("Configured public key does not match private key.");
    }
    return manager;
  }

  static fromJwk(jwk: JWK, options: KeyManagerOptions = {}): KeyManager {
    const suite = validateLocalJwk(jwk);
    if (options.suite !== undefined && getSignatureSuite(options.suite).id !== suite.id) {
      throw new Error("Selected signing suite does not match the configured key.");
    }
    const publicKey = publicJwkFromLocal(jwk);
    const did = options.did ?? deriveDidJwk(jwk);
    if (options.did?.startsWith("did:jwk:")) {
      try {
        if (!samePublicKey(didJwkToJwk(did), publicKey)) throw new Error("mismatch");
      } catch { throw new Error("Configured DID does not match derived DID key."); }
    }
    const kid = did.startsWith("did:jwk:") ? didJwkToKid(did) : jwk.kid;
    if (!kid) throw new Error("Explicit non-did:jwk binding requires a configured kid.");
    if (jwk.kid !== undefined && jwk.kid !== kid) throw new Error("Configured kid does not match DID.");
    const manager = new KeyManager(structuredClone({ ...jwk, kid }), did, suite.jwsAlgorithm);
    validateSignerIdentity(manager);
    return manager;
  }

  get kid(): string { return this.jwk.kid!; }
  get publicKey(): JWK { return publicJwkFromLocal(this.jwk); }

  async signCompactJws(payload: Uint8Array): Promise<string> {
    return signSuiteCompactJws(this.jwk, payload, this.kid);
  }

  async signBytes(payload: Uint8Array): Promise<Uint8Array> {
    return signSuiteBytes(this.jwk, payload);
  }

  async verifyCompactJws(jws: string): Promise<boolean> {
    try {
      await verifySuiteCompactJws(jws, this.publicKey, verificationKid(this.publicKey, this.did));
      return true;
    } catch { return false; }
  }

  async verifyBytes(payload: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return verifySuiteBytes(this.publicKey, payload, signature);
  }

  /** @deprecated Use signCompactJws. */
  async sign(payload: Uint8Array): Promise<string> { return this.signCompactJws(payload); }
  /** @deprecated Use verifyCompactJws. */
  async verify(jws: string): Promise<boolean> { return this.verifyCompactJws(jws); }
}

function selectJwk(parsed: JWK | KeyFixtureFile): JWK {
  if ("privateJwk" in parsed && parsed.privateJwk) return parsed.privateJwk;
  if ("publicJwk" in parsed && parsed.publicJwk) return parsed.publicJwk;
  return parsed as JWK;
}
