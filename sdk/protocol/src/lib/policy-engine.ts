/** Deterministic evaluator for the MPAS JSON Verifier Policy Profile. */

import type {
  ActionPackage,
  ApprovalRequirement,
  Decision,
  Did,
  ThresholdRequirement as ConcreteThresholdRequirement,
} from "../types/mpas.js";
import {
  loadPolicyConfig,
  MPAS_POLICY_PROFILE_URL,
  validatePolicyConfig,
  type AllOfRequirement,
  type AnyOfRequirement,
  type ConditionOp,
  type ConditionSource,
  type MpasApplicationPolicy,
  type PolicyCondition,
  type PolicyConfig,
  type PolicyConfigLoadResult,
  type PolicyConfigValidationResult,
  type PolicyEntry,
  type PolicyThresholdRequirement,
  type ProposerOnlyRequirement,
  type RejectPolicyEntry,
  type Requirement,
  type RequirementPolicyEntry,
} from "./policy-config.js";
import type { VerifiedApprovals } from "./verification.js";

export {
  loadPolicyConfig,
  MPAS_POLICY_PROFILE_URL,
  validatePolicyConfig,
  type AllOfRequirement,
  type AnyOfRequirement,
  type ConditionOp,
  type ConditionSource,
  type MpasApplicationPolicy,
  type PolicyCondition,
  type PolicyConfig,
  type PolicyConfigLoadResult,
  type PolicyConfigValidationResult,
  type PolicyEntry,
  type PolicyThresholdRequirement,
  type ProposerOnlyRequirement,
  type RejectPolicyEntry,
  type Requirement,
  type RequirementPolicyEntry,
};

/** @deprecated Use PolicyThresholdRequirement. */
export type ThresholdRequirement = PolicyThresholdRequirement;

export type PolicyResult =
  | { status: "satisfied" }
  | { status: "rejected"; code: "ACTION_BLOCKED_BY_POLICY" | "POLICY_REQUIREMENT_UNREACHABLE"; message: string }
  | { status: "notSupported"; code: "POLICY_SCOPE_MISMATCH"; message: string }
  | { status: "additionalApprovalsRequired"; unsatisfiedRequirement: ApprovalRequirement }
  | { status: "malformed"; code: "NUMERIC_CONDITION_UNPARSEABLE" | "POLICY_INVALID"; message: string };

export type ProposerGateResult =
  | { allowed: true }
  | { allowed: false; code: "POLICY_INVALID" | "PROPOSER_NOT_AUTHORIZED"; message: string };

type RequirementEvaluation =
  | { status: "satisfied" }
  | { status: "pending"; requirement: ApprovalRequirement }
  | { status: "unreachable" };

/** Applies the profile's proposer gate after validating the complete policy. */
export function checkProposerAuthorization(proposerDid: Did, policy: unknown): ProposerGateResult {
  const loaded = loadPolicyConfig(policy);
  if (!loaded.ok) return { allowed: false, code: "POLICY_INVALID", message: loaded.message };
  const allowed = loaded.policy.signerGroups.proposers ?? loaded.policy.signerGroups.all;
  if (!allowed.includes(proposerDid)) {
    return {
      allowed: false,
      code: "PROPOSER_NOT_AUTHORIZED",
      message: `Proposer ${proposerDid} is not in the allowed proposer set.`,
    };
  }
  return { allowed: true };
}

/** Evaluates a complete policy only after validating its shape and scope. */
export function evaluatePolicy(
  actionPackage: ActionPackage,
  verifiedApprovals: VerifiedApprovals,
  policyValue: unknown,
): PolicyResult {
  const loaded = loadPolicyConfig(policyValue);
  if (!loaded.ok) return { status: "malformed", code: "POLICY_INVALID", message: loaded.message };
  const policy = loaded.policy;
  const envelope = actionPackage.actionEnvelope;
  if (policy.applicationDid !== envelope.target.applicationDid ||
      policy.executionProfile.id !== envelope.executionProfile.id ||
      (policy.executionProfile.format !== undefined &&
        policy.executionProfile.format !== envelope.executionProfile.format)) {
    return {
      status: "notSupported",
      code: "POLICY_SCOPE_MISMATCH",
      message: "The policy does not match the Action Envelope application or execution profile.",
    };
  }

  const payload = actionPackage.executionPayload;
  const actionName = isRecord(payload) && typeof payload.name === "string" ? payload.name : undefined;
  const entries = actionName && policy.policies && Object.hasOwn(policy.policies, actionName)
    ? policy.policies[actionName]
    : undefined;
  const matched: PolicyEntry[] = [];
  try {
    for (const entry of entries ?? []) {
      if (!entry.match?.conditions?.length || matchesConditions(entry.match.conditions, actionPackage)) matched.push(entry);
    }
  } catch (error) {
    if (error instanceof UnparseableNumericValueError) {
      return { status: "malformed", code: "NUMERIC_CONDITION_UNPARSEABLE", message: error.message };
    }
    throw error;
  }

  if (matched.some((entry) => entry.reject === true)) {
    return {
      status: "rejected",
      code: "ACTION_BLOCKED_BY_POLICY",
      message: `Action ${actionName ?? "(unknown)"} is blocked by policy.`,
    };
  }

  const positive = matched.filter((entry): entry is RequirementPolicyEntry => entry.reject !== true);
  const effective: Requirement = positive.length === 0
    ? policy.defaultRequirement
    : positive.length === 1
      ? positive[0].requirements
      : { type: "allOf", requirements: positive.map((entry) => entry.requirements) };
  const evaluated = evaluateRequirement(effective, verifiedApprovals, policy, envelope.proposer.did);
  if (evaluated.status === "satisfied") return evaluated;
  if (evaluated.status === "unreachable") {
    return {
      status: "rejected",
      code: "POLICY_REQUIREMENT_UNREACHABLE",
      message: "The policy requirement cannot be satisfied by any remaining eligible Signer decisions.",
    };
  }
  return { status: "additionalApprovalsRequired", unsatisfiedRequirement: evaluated.requirement };
}

function evaluateRequirement(
  requirement: Requirement,
  verifiedApprovals: VerifiedApprovals,
  policy: MpasApplicationPolicy,
  proposerDid: Did,
): RequirementEvaluation {
  if (requirement.type === "proposerOnly") return { status: "satisfied" };
  if (requirement.type === "threshold") return evaluateThreshold(requirement, verifiedApprovals, policy, proposerDid);
  const children = requirement.requirements.map((nested) =>
    evaluateRequirement(nested, verifiedApprovals, policy, proposerDid));
  if (requirement.type === "allOf") {
    if (children.some((entry) => entry.status === "unreachable")) return { status: "unreachable" };
    const pending = children.filter((entry): entry is Extract<RequirementEvaluation, { status: "pending" }> =>
      entry.status === "pending");
    if (pending.length === 0) return { status: "satisfied" };
    return {
      status: "pending",
      requirement: { type: "allOf", requirements: pending.map((entry) => entry.requirement) },
    };
  }
  if (children.some((entry) => entry.status === "satisfied")) return { status: "satisfied" };
  const viable = children.filter((entry): entry is Extract<RequirementEvaluation, { status: "pending" }> =>
    entry.status === "pending");
  if (viable.length === 0) return { status: "unreachable" };
  return {
    status: "pending",
    requirement: { type: "anyOf", requirements: viable.map((entry) => entry.requirement) },
  };
}

function evaluateThreshold(
  requirement: PolicyThresholdRequirement,
  verifiedApprovals: VerifiedApprovals,
  policy: MpasApplicationPolicy,
  proposerDid: Did,
): RequirementEvaluation {
  const expected = requirement.decision ?? "approve";
  const eligible = resolveEligibleSigners(requirement, policy).filter((did) => did !== proposerDid);
  const decisions = immutableVerifiedDecisionMap(verifiedApprovals);
  const matching = eligible.filter((did) => decisions.get(did) === expected);
  if (matching.length >= requirement.threshold) return { status: "satisfied" };
  const undecided = eligible.filter((did) => !decisions.has(did));
  const remaining = requirement.threshold - matching.length;
  if (undecided.length < remaining) return { status: "unreachable" };
  const concrete: ConcreteThresholdRequirement = {
    type: "threshold",
    threshold: remaining,
    eligibleSigners: undecided,
    decision: expected,
    ...(requirement.description !== undefined ? { description: requirement.description } : {}),
  };
  return { status: "pending", requirement: concrete };
}

function immutableVerifiedDecisionMap(verifiedApprovals: VerifiedApprovals): Map<Did, Decision> {
  const decisions = new Map<Did, Decision>();
  for (const approval of verifiedApprovals.approvals) {
    if (!decisions.has(approval.signerDid)) decisions.set(approval.signerDid, approval.decision);
  }
  return decisions;
}

function resolveEligibleSigners(requirement: PolicyThresholdRequirement, policy: MpasApplicationPolicy): Did[] {
  if (requirement.eligibleSigners) return requirement.eligibleSigners;
  return policy.signerGroups[requirement.eligibleSignerGroup as string] ?? [];
}

function matchesConditions(conditions: PolicyCondition[], actionPackage: ActionPackage): boolean {
  return conditions.every((condition) => conditionMatches(condition, actionPackage));
}

function conditionMatches(condition: PolicyCondition, actionPackage: ActionPackage): boolean {
  const source = condition.source === "actionEnvelope" ? actionPackage.actionEnvelope : actionPackage.executionPayload;
  const actual = getJsonPointerValue(source, condition.path);
  switch (condition.op) {
    case "eq": return Object.is(actual, condition.value);
    case "neq": return !Object.is(actual, condition.value);
    case "in": return Array.isArray(condition.value) && condition.value.some((entry) => Object.is(entry, actual));
    case "notIn": return Array.isArray(condition.value) && !condition.value.some((entry) => Object.is(entry, actual));
    case "gt": return toNumber(actual, condition) > toNumber(condition.value, condition);
    case "gte": return toNumber(actual, condition) >= toNumber(condition.value, condition);
    case "lt": return toNumber(actual, condition) < toNumber(condition.value, condition);
    case "lte": return toNumber(actual, condition) <= toNumber(condition.value, condition);
    case "exists": return actual !== undefined;
    case "notExists": return actual === undefined;
    case "contains": return Array.isArray(actual) && actual.some((entry) => Object.is(entry, condition.value));
    case "prefix": return typeof actual === "string" &&
      typeof condition.value === "string" && actual.startsWith(condition.value);
  }
}

export class UnparseableNumericValueError extends Error {
  constructor(condition: PolicyCondition, value: unknown) {
    super(
      `Value at ${condition.source}${condition.path} (${JSON.stringify(value)}) cannot be parsed as a number for the \"${condition.op}\" comparison. ` +
      "Numeric conditions over unparseable values make the Action Package malformed (JSON Verifier Policy Profile §5.4).",
    );
    this.name = "UnparseableNumericValueError";
  }
}

function toNumber(value: unknown, condition: PolicyCondition): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  if (value === undefined) return Number.NaN;
  throw new UnparseableNumericValueError(condition, value);
}

function getJsonPointerValue(value: unknown, pointer: string): unknown {
  if (pointer === "") return value;
  let current = value;
  for (const part of pointer.split("/").slice(1).map((entry) => entry.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    if (!isRecord(current) && !Array.isArray(current)) return undefined;
    if (!Object.hasOwn(current, part)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
