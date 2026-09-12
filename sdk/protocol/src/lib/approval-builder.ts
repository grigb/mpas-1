import type { JWK } from "jose";
import { canonicalize } from "json-canonicalize";
import type { ActionEnvelope, Approval, CanonicalApprovalPayload, Decision } from "../types/mpas.js";
import { computeJsonHash } from "../utils/hash.js";
import type { KeyManager } from "./key-manager.js";
import { signMpasCompactJws, validateSignerIdentity, type MpasJwsSigner } from "./signer.js";
import { verifyApproval } from "./verification.js";

/** Reusable signer configuration for constructing MPAS Approvals. */
export interface ApprovalBuilderConfig {
  /** Signer key used to derive the signer DID and produce the Approval JWS. */
  keyManager?: KeyManager;
  /** Shared signing capability; supply exactly one of signer or keyManager. */
  signer?: MpasJwsSigner;
}

/** Builds Signer Approvals with one configured did:jwk signing identity. */
export class ApprovalBuilder {
  private readonly signer: MpasJwsSigner;
  constructor(config: ApprovalBuilderConfig) {
    if (Boolean(config.signer) === Boolean(config.keyManager)) throw new Error("Supply exactly one signer or keyManager.");
    this.signer = config.signer ?? config.keyManager!;
    validateSignerIdentity(this.signer);
  }

  /** Builds an approve or reject decision bound to the exact Action Envelope hash. */
  async buildApproval(envelope: ActionEnvelope, decision: Extract<Decision, "approve" | "reject">): Promise<Approval> {
    const actionEnvelopeHash = computeJsonHash(envelope);
    const createdAt = new Date().toISOString();
    const approvalPayload: CanonicalApprovalPayload = {
      type: "ApprovalPayload",
      actionEnvelopeHash,
      decision,
      signerDid: this.signer.did,
      createdAt,
    };
    const signature = await signMpasCompactJws(this.signer, Buffer.from(canonicalize(approvalPayload)));

    return {
      version: "1",
      type: "Approval",
      actionEnvelopeHash,
      decision,
      signature: {
        format: "jws",
        value: signature,
      },
      createdAt,
    };
  }

  /** @deprecated Use the stateless {@link verifyApproval} function. */
  async verifyApproval(approval: Approval, signerPublicKey: JWK): Promise<boolean> {
    return verifyApproval(approval, signerPublicKey);
  }
}
