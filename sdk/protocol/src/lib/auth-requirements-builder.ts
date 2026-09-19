import type {
  ActionEnvelope,
  ApprovalRequirement,
  ApprovalRequirements,
  AuthorizationRequirements,
  Did,
} from "../types/mpas.js";
import { computeJsonHash } from "./verification.js";

export interface BuildAuthorizationRequirementsInput {
  actionEnvelope: ActionEnvelope;
  unsatisfiedRequirement: ApprovalRequirement;
  verifierDid: Did;
}

/** Emits the one normalized unmet expression as Core Authorization Requirements. */
export function buildAuthorizationRequirements(
  input: BuildAuthorizationRequirementsInput,
): AuthorizationRequirements {
  return {
    version: "1",
    type: "AuthorizationRequirements",
    actionEnvelopeHash: computeJsonHash(input.actionEnvelope),
    result: "additionalApprovalsRequired",
    verifier: { did: input.verifierDid },
    approvalRequirements: asApprovalRequirements(input.unsatisfiedRequirement),
    createdAt: new Date().toISOString(),
    expiresAt: input.actionEnvelope.expiresAt,
  };
}

function asApprovalRequirements(requirement: ApprovalRequirement): ApprovalRequirements {
  if (requirement.type === "allOf") return { allOf: requirement.requirements };
  if (requirement.type === "anyOf") return { anyOf: requirement.requirements };
  return { anyOf: [requirement] };
}
