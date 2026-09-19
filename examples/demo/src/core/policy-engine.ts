/**
 * Re-exports all policy engine primitives from @oma3/mpas.
 * This file exists so that existing imports from "../core/policy-engine.js" continue to work.
 */
export {
  evaluatePolicy,
  checkProposerAuthorization,
  loadPolicyConfig,
  MPAS_POLICY_PROFILE_URL,
  validatePolicyConfig,
} from "@oma3/mpas/policy-engine";

export type {
  ProposerGateResult,
  PolicyConfig,
  MpasApplicationPolicy,
  PolicyConfigLoadResult,
  PolicyEntry,
  RequirementPolicyEntry,
  RejectPolicyEntry,
  PolicyCondition,
  ConditionSource,
  ConditionOp,
  PolicyResult,
  PolicyConfigValidationResult,
  Requirement,
  ProposerOnlyRequirement,
  ThresholdRequirement,
  PolicyThresholdRequirement,
  AllOfRequirement,
  AnyOfRequirement,
} from "@oma3/mpas/policy-engine";
