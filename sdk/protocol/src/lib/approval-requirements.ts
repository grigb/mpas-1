import type {
  ApprovalRequirement,
  ApprovalRequirements,
  Decision,
  Did,
  ThresholdRequirement,
} from "../types/mpas.js";

export interface SignerDecision {
  signerDid: Did;
  decision: Decision;
}

export type ApprovalRequirementsStatus = "satisfied" | "pending" | "unreachable";

export type ApprovalRequirementsValidationResult =
  | { ok: true; requirements: ApprovalRequirements }
  | { ok: false; path: string; message: string };

/** Validates the closed recursive Core approval-path grammar. */
export function validateApprovalRequirements(value: unknown): ApprovalRequirementsValidationResult {
  if (!isRecord(value)) return invalid("$", "Approval Requirements must be an object.");
  if (unexpected(value, ["anyOf", "allOf", "overrideSigners"])) {
    return invalid("$", "Approval Requirements contain an undeclared member.");
  }
  const present = ["anyOf", "allOf", "overrideSigners"].filter((key) => Object.hasOwn(value, key));
  if (present.length === 0) return invalid("$", "Approval Requirements contain no approval path.");
  for (const field of ["anyOf", "allOf"] as const) {
    if (value[field] === undefined) continue;
    if (!Array.isArray(value[field]) || value[field].length === 0) {
      return invalid(`$.${field}`, `${field} must be a non-empty array.`);
    }
    for (const [index, requirement] of value[field].entries()) {
      const error = validateRequirement(requirement, `$.${field}[${index}]`);
      if (error) return error;
    }
  }
  if (value.overrideSigners !== undefined) {
    if (!Array.isArray(value.overrideSigners) || value.overrideSigners.length === 0) {
      return invalid("$.overrideSigners", "overrideSigners must be a non-empty array.");
    }
    const seen = new Set<string>();
    for (const [index, entry] of value.overrideSigners.entries()) {
      const path = `$.overrideSigners[${index}]`;
      if (!isRecord(entry) || unexpected(entry, ["signer", "permissions", "description"]) ||
          !isDid(entry.signer) || !isNonEmptyUniqueStrings(entry.permissions) ||
          (entry.description !== undefined && typeof entry.description !== "string")) {
        return invalid(path, "Override Signer is malformed.");
      }
      if (seen.has(entry.signer)) return invalid(`${path}.signer`, "Override Signer DIDs must be unique.");
      seen.add(entry.signer);
    }
  }
  return { ok: true, requirements: value as unknown as ApprovalRequirements };
}

/** Returns every threshold leaf in deterministic document order. */
export function approvalRequirementThresholds(requirements: ApprovalRequirements): ThresholdRequirement[] {
  const validation = validateApprovalRequirements(requirements);
  if (!validation.ok) return [];
  return [...(requirements.anyOf ?? []), ...(requirements.allOf ?? [])].flatMap(thresholdsIn);
}

/** Returns all decisions for which one Signer appears in an ordinary or override path. */
export function approvalRequirementDecisionsForSigner(
  requirements: ApprovalRequirements,
  signer: Did,
): Decision[] {
  const decisions = new Set<Decision>();
  for (const threshold of approvalRequirementThresholds(requirements)) {
    if (threshold.eligibleSigners.includes(signer)) decisions.add(threshold.decision ?? "approve");
  }
  for (const override of requirements.overrideSigners ?? []) {
    if (override.signer !== signer) continue;
    for (const permission of override.permissions) {
      if (isDecision(permission)) decisions.add(permission);
    }
  }
  return [...decisions];
}

export function isSignerEligibleForDecision(
  requirements: ApprovalRequirements,
  signer: Did,
  decision: Decision,
): boolean {
  return approvalRequirementDecisionsForSigner(requirements, signer).includes(decision);
}

/** Evaluates immutable Signer decisions over nested anyOf/allOf paths. */
export function evaluateApprovalRequirements(
  requirements: ApprovalRequirements,
  decisions: Iterable<SignerDecision>,
): ApprovalRequirementsStatus {
  const validation = validateApprovalRequirements(requirements);
  if (!validation.ok) return "unreachable";
  const bySigner = immutableDecisionMap(decisions);
  const overrides = requirements.overrideSigners ?? [];
  if (overrides.some((entry) =>
    entry.permissions.includes("reject") && bySigner.get(entry.signer) === "reject")) return "unreachable";
  if (overrides.some((entry) =>
    entry.permissions.includes("approve") && bySigner.get(entry.signer) === "approve")) return "satisfied";

  const anyStatus = requirements.anyOf === undefined
    ? undefined
    : combineAny(requirements.anyOf.map((entry) => requirementStatus(entry, bySigner)));
  const allStatus = requirements.allOf === undefined
    ? undefined
    : combineAll(requirements.allOf.map((entry) => requirementStatus(entry, bySigner)));
  const ordinaryStatus = anyStatus === undefined && allStatus === undefined
    ? "unreachable"
    : combineAll([...(anyStatus === undefined ? [] : [anyStatus]), ...(allStatus === undefined ? [] : [allStatus])]);
  if (ordinaryStatus === "satisfied") return "satisfied";
  if (ordinaryStatus === "pending") return "pending";
  const pendingApproveOverride = overrides.some((entry) =>
    entry.permissions.includes("approve") && !bySigner.has(entry.signer));
  return pendingApproveOverride ? "pending" : "unreachable";
}

function validateRequirement(value: unknown, path: string): Extract<ApprovalRequirementsValidationResult, { ok: false }> | null {
  if (!isRecord(value) || typeof value.type !== "string") return invalid(path, "Approval requirement must be an object.");
  if (value.type === "threshold") {
    if (unexpected(value, ["type", "threshold", "eligibleSigners", "decision", "description"]) ||
        !Number.isInteger(value.threshold) || (value.threshold as number) < 1 ||
        !isDidArray(value.eligibleSigners) ||
        (value.threshold as number) > value.eligibleSigners.length ||
        (value.decision !== undefined && !isSatisfyingDecision(value.decision)) ||
        (value.description !== undefined && typeof value.description !== "string")) {
      return invalid(path, "Threshold requirement is malformed or unreachable.");
    }
    return null;
  }
  if (value.type === "allOf" || value.type === "anyOf") {
    if (unexpected(value, ["type", "requirements"]) ||
        !Array.isArray(value.requirements) || value.requirements.length === 0) {
      return invalid(path, `${value.type} requirement must contain a non-empty requirements array.`);
    }
    for (const [index, nested] of value.requirements.entries()) {
      const error = validateRequirement(nested, `${path}.requirements[${index}]`);
      if (error) return error;
    }
    return null;
  }
  return invalid(`${path}.type`, "Approval requirement type is invalid.");
}

function thresholdsIn(requirement: ApprovalRequirement): ThresholdRequirement[] {
  return requirement.type === "threshold"
    ? [requirement]
    : requirement.requirements.flatMap(thresholdsIn);
}

function requirementStatus(
  requirement: ApprovalRequirement,
  decisions: ReadonlyMap<Did, Decision>,
): ApprovalRequirementsStatus {
  if (requirement.type === "threshold") return thresholdStatus(requirement, decisions);
  const statuses = requirement.requirements.map((entry) => requirementStatus(entry, decisions));
  return requirement.type === "allOf" ? combineAll(statuses) : combineAny(statuses);
}

function combineAll(statuses: ApprovalRequirementsStatus[]): ApprovalRequirementsStatus {
  if (statuses.some((status) => status === "unreachable")) return "unreachable";
  return statuses.every((status) => status === "satisfied") ? "satisfied" : "pending";
}

function combineAny(statuses: ApprovalRequirementsStatus[]): ApprovalRequirementsStatus {
  if (statuses.some((status) => status === "satisfied")) return "satisfied";
  return statuses.every((status) => status === "unreachable") ? "unreachable" : "pending";
}

function thresholdStatus(
  requirement: ThresholdRequirement,
  decisions: ReadonlyMap<Did, Decision>,
): ApprovalRequirementsStatus {
  const expected = requirement.decision ?? "approve";
  let matching = 0;
  let undecided = 0;
  for (const signer of new Set(requirement.eligibleSigners)) {
    const decision = decisions.get(signer);
    if (decision === expected) matching += 1;
    else if (decision === undefined) undecided += 1;
  }
  if (matching >= requirement.threshold) return "satisfied";
  return matching + undecided >= requirement.threshold ? "pending" : "unreachable";
}

function immutableDecisionMap(decisions: Iterable<SignerDecision>): Map<Did, Decision> {
  const result = new Map<Did, Decision>();
  for (const entry of decisions) {
    const existing = result.get(entry.signerDid);
    if (existing !== undefined && existing !== entry.decision) {
      throw new Error(`Signer ${entry.signerDid} has conflicting decisions for one Action Envelope.`);
    }
    result.set(entry.signerDid, entry.decision);
  }
  return result;
}

function invalid(path: string, message: string): Extract<ApprovalRequirementsValidationResult, { ok: false }> {
  return { ok: false, path, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unexpected(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).some((key) => !allowed.includes(key));
}

function isDid(value: unknown): value is Did {
  return typeof value === "string" && /^did:[a-z0-9]+:\S+$/.test(value);
}

function isDidArray(value: unknown): value is Did[] {
  return Array.isArray(value) && value.length > 0 && value.every(isDid) && new Set(value).size === value.length;
}

function isNonEmptyUniqueStrings(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 &&
    value.every((entry) => typeof entry === "string" && entry.length > 0) && new Set(value).size === value.length;
}

function isDecision(value: string): value is Decision {
  return ["propose", "approve", "reject", "abstain"].includes(value);
}

function isSatisfyingDecision(value: unknown): value is Exclude<Decision, "reject"> {
  return value === "approve" || value === "propose" || value === "abstain";
}
