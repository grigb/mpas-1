import type { Did, JsonObject, JsonValue } from "../types/mpas.js";

export const MPAS_POLICY_PROFILE_URL =
  "https://github.com/oma3dao/mpas/blob/main/specs/mpas-profile-policy-json.md" as const;

export interface ProposerOnlyRequirement {
  type: "proposerOnly";
}

export interface PolicyThresholdRequirement {
  type: "threshold";
  threshold: number;
  eligibleSignerGroup?: string;
  eligibleSigners?: Did[];
  decision?: "approve" | "propose" | "abstain";
  description?: string;
}

export interface AllOfRequirement {
  type: "allOf";
  requirements: Requirement[];
}

export interface AnyOfRequirement {
  type: "anyOf";
  requirements: Requirement[];
}

export type Requirement =
  | ProposerOnlyRequirement
  | PolicyThresholdRequirement
  | AllOfRequirement
  | AnyOfRequirement;

export type ConditionSource = "executionPayload" | "actionEnvelope";
export type ConditionOp =
  | "eq"
  | "neq"
  | "in"
  | "notIn"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "exists"
  | "notExists"
  | "contains"
  | "prefix";

export interface PolicyCondition {
  source: ConditionSource;
  path: string;
  op: ConditionOp;
  value?: JsonValue;
}

interface PolicyEntryBase {
  description?: string;
  match?: { conditions?: PolicyCondition[] };
  context?: JsonObject;
}

export interface RequirementPolicyEntry extends PolicyEntryBase {
  reject?: false;
  requirements: Requirement;
}

export interface RejectPolicyEntry extends PolicyEntryBase {
  reject: true;
  requirements?: never;
}

export type PolicyEntry = RequirementPolicyEntry | RejectPolicyEntry;

export interface MpasApplicationPolicy {
  version: "1";
  type: "MpasApplicationPolicy";
  policyProfileUrl: typeof MPAS_POLICY_PROFILE_URL;
  applicationDid: Did;
  executionProfile: {
    id: Did;
    format?: string;
  };
  defaultRequirement: Requirement;
  signerGroups: Record<string, Did[]> & { all: Did[] };
  policies?: Record<string, PolicyEntry[]>;
  context?: JsonObject;
}

/** @deprecated Use MpasApplicationPolicy. */
export type PolicyConfig = MpasApplicationPolicy;

export type PolicyConfigValidationResult =
  | { ok: true }
  | { ok: false; message: string };

export type PolicyConfigLoadResult =
  | { ok: true; policy: MpasApplicationPolicy }
  | { ok: false; message: string };

/** Loads one exact, closed MpasApplicationPolicy from untrusted JSON. */
export function loadPolicyConfig(value: unknown): PolicyConfigLoadResult {
  const result = validatePolicyConfig(value);
  return result.ok
    ? { ok: true, policy: value as MpasApplicationPolicy }
    : result;
}

/** Validates the complete trusted policy boundary, including nested expressions. */
export function validatePolicyConfig(value: unknown): PolicyConfigValidationResult {
  if (!isRecord(value)) return invalid("Policy must be an object.");
  if (hasUnexpectedKeys(value, [
    "version", "type", "policyProfileUrl", "applicationDid", "executionProfile",
    "defaultRequirement", "signerGroups", "policies", "context",
  ])) return invalid("Policy has unsupported fields.");
  if (value.version !== "1") return invalid("Policy version must be \"1\".");
  if (value.type !== "MpasApplicationPolicy") return invalid("Policy type must be MpasApplicationPolicy.");
  if (value.policyProfileUrl !== MPAS_POLICY_PROFILE_URL) {
    return invalid(`Policy policyProfileUrl must be ${MPAS_POLICY_PROFILE_URL}.`);
  }
  if (!isDid(value.applicationDid)) return invalid("Policy applicationDid must be a DID.");
  if (!isRecord(value.executionProfile) ||
      hasUnexpectedKeys(value.executionProfile, ["id", "format"]) ||
      !isDid(value.executionProfile.id) ||
      (value.executionProfile.format !== undefined &&
        (typeof value.executionProfile.format !== "string" || value.executionProfile.format.length === 0))) {
    return invalid("Policy executionProfile must contain a DID id and optional non-empty format.");
  }
  if (value.context !== undefined && !isJsonObject(value.context)) {
    return invalid("Policy context must be a JSON object.");
  }
  if (!isRecord(value.signerGroups)) return invalid("Policy must define signerGroups.");
  const signerGroups = value.signerGroups as Record<string, unknown>;
  if (!isDidArray(signerGroups.all)) {
    return invalid("Policy signerGroups.all must be a non-empty array of unique DIDs.");
  }
  const allSigners = new Set(signerGroups.all);
  for (const [groupName, signers] of Object.entries(signerGroups)) {
    if (groupName.length === 0) return invalid("Policy signer group names must be non-empty.");
    if (!isDidArray(signers)) {
      return invalid(`Policy signerGroups.${groupName} must be a non-empty array of unique DIDs.`);
    }
    const outsider = signers.find((did) => !allSigners.has(did));
    if (outsider) return invalid(`Policy signerGroups.${groupName} contains DID ${outsider} outside signerGroups.all.`);
  }

  const groups = signerGroups as Record<string, Did[]>;
  const defaultError = validateRequirement(value.defaultRequirement, groups, "defaultRequirement");
  if (defaultError) return invalid(defaultError);

  if (value.policies !== undefined) {
    if (!isRecord(value.policies)) return invalid("Policy policies must be an object keyed by operation name.");
    for (const [operation, entries] of Object.entries(value.policies)) {
      if (operation.length === 0) return invalid("Policy operation names must be non-empty.");
      if (!Array.isArray(entries) || entries.length === 0) {
        return invalid(`Policy policies.${operation} must be a non-empty array.`);
      }
      for (const [index, entry] of entries.entries()) {
        const error = validatePolicyEntry(entry, groups, `policies.${operation}[${index}]`);
        if (error) return invalid(error);
      }
    }
  }
  return { ok: true };
}

function validatePolicyEntry(value: unknown, groups: Record<string, Did[]>, path: string): string | null {
  if (!isRecord(value)) return `${path} must be an object.`;
  if (hasUnexpectedKeys(value, ["reject", "description", "match", "requirements", "context"])) {
    return `${path} has unsupported fields.`;
  }
  if (value.reject !== undefined && typeof value.reject !== "boolean") return `${path}.reject must be a boolean.`;
  if (value.description !== undefined && typeof value.description !== "string") return `${path}.description must be a string.`;
  if (value.context !== undefined && !isJsonObject(value.context)) return `${path}.context must be a JSON object.`;
  const reject = value.reject === true;
  const hasRequirements = Object.hasOwn(value, "requirements");
  if (reject === hasRequirements) return `${path} must contain either reject: true or requirements, but not both.`;
  if (!reject) {
    const error = validateRequirement(value.requirements, groups, `${path}.requirements`);
    if (error) return error;
  }
  return validateMatch(value.match, `${path}.match`);
}

function validateMatch(value: unknown, path: string): string | null {
  if (value === undefined) return null;
  if (!isRecord(value)) return `${path} must be an object.`;
  if (hasUnexpectedKeys(value, ["conditions"])) return `${path} has unsupported fields.`;
  if (value.conditions === undefined) return null;
  if (!Array.isArray(value.conditions)) return `${path}.conditions must be an array.`;
  for (const [index, condition] of value.conditions.entries()) {
    const error = validateCondition(condition, `${path}.conditions[${index}]`);
    if (error) return error;
  }
  return null;
}

function validateCondition(value: unknown, path: string): string | null {
  if (!isRecord(value)) return `${path} must be an object.`;
  if (hasUnexpectedKeys(value, ["source", "path", "op", "value"])) return `${path} has unsupported fields.`;
  if (value.source !== "executionPayload" && value.source !== "actionEnvelope") return `${path}.source is invalid.`;
  if (typeof value.path !== "string" || !isJsonPointer(value.path)) return `${path}.path must be a valid JSON Pointer.`;
  if (value.source === "actionEnvelope" && !isActionEnvelopePointer(value.path)) {
    return `${path}.path does not address an Action Envelope field.`;
  }
  if (typeof value.op !== "string" || !CONDITION_OPERATORS.has(value.op as ConditionOp)) return `${path}.op is invalid.`;
  const hasValue = Object.hasOwn(value, "value");
  if (value.op === "exists" || value.op === "notExists") {
    return hasValue ? `${path}.value must be absent for ${value.op}.` : null;
  }
  if (!hasValue || !isJsonValue(value.value)) return `${path}.value must be a JSON value.`;
  if ((value.op === "in" || value.op === "notIn") && !Array.isArray(value.value)) return `${path}.value must be an array for ${value.op}.`;
  if (value.op === "contains" && isComposite(value.value)) return `${path}.value must be a scalar for contains.`;
  if (value.op === "prefix" && typeof value.value !== "string") return `${path}.value must be a string for prefix.`;
  if (NUMERIC_OPERATORS.has(value.op as ConditionOp) && toFiniteNumber(value.value) === null) {
    return `${path}.value must be numeric for ${value.op}.`;
  }
  return null;
}

function validateRequirement(value: unknown, groups: Record<string, Did[]>, path: string): string | null {
  if (!isRecord(value) || typeof value.type !== "string") return `${path} must be an approval requirement object.`;
  if (value.type === "proposerOnly") {
    return Object.keys(value).length === 1 ? null : `${path}.proposerOnly has unsupported fields.`;
  }
  if (value.type === "threshold") {
    if (hasUnexpectedKeys(value, ["type", "threshold", "eligibleSignerGroup", "eligibleSigners", "decision", "description"])) {
      return `${path}.threshold has unsupported fields.`;
    }
    if (!Number.isInteger(value.threshold) || (value.threshold as number) < 1) return `${path}.threshold must be a positive integer.`;
    const group = typeof value.eligibleSignerGroup === "string" && value.eligibleSignerGroup.length > 0;
    const signers = isDidArray(value.eligibleSigners);
    if (group === signers) return `${path} must define exactly one of eligibleSignerGroup or eligibleSigners.`;
    const groupName = value.eligibleSignerGroup as string;
    const eligible = group
      ? Object.hasOwn(groups, groupName) ? groups[groupName] : undefined
      : value.eligibleSigners as Did[];
    if (!eligible) return `${path}.eligibleSignerGroup does not exist in signerGroups.`;
    const outsider = eligible.find((did) => !groups.all.includes(did));
    if (outsider) return `${path}.eligibleSigners contains DID ${outsider} outside signerGroups.all.`;
    if ((value.threshold as number) > eligible.length) return `${path}.threshold exceeds the eligible Signer count.`;
    if (value.decision !== undefined && !SATISFYING_DECISIONS.has(value.decision as string)) return `${path}.decision is invalid.`;
    if (value.description !== undefined && typeof value.description !== "string") return `${path}.description must be a string.`;
    return null;
  }
  if (value.type === "allOf" || value.type === "anyOf") {
    if (hasUnexpectedKeys(value, ["type", "requirements"])) return `${path}.${value.type} has unsupported fields.`;
    if (!Array.isArray(value.requirements) || value.requirements.length === 0) return `${path}.requirements must be a non-empty array.`;
    for (const [index, nested] of value.requirements.entries()) {
      const error = validateRequirement(nested, groups, `${path}.requirements[${index}]`);
      if (error) return error;
    }
    return null;
  }
  return `${path}.type is invalid.`;
}

const SATISFYING_DECISIONS = new Set(["approve", "propose", "abstain"]);
const CONDITION_OPERATORS = new Set<ConditionOp>([
  "eq", "neq", "in", "notIn", "gt", "gte", "lt", "lte", "exists", "notExists", "contains", "prefix",
]);
const NUMERIC_OPERATORS = new Set<ConditionOp>(["gt", "gte", "lt", "lte"]);
const ACTION_ENVELOPE_ROOTS = new Set([
  "version", "type", "proposer", "target", "executionProfile", "executionPayloadHash", "actionId", "createdAt", "expiresAt",
]);

function invalid(message: string): { ok: false; message: string } {
  return { ok: false, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDid(value: unknown): value is Did {
  return typeof value === "string" && /^did:[a-z0-9]+:\S+$/.test(value);
}

function isDidArray(value: unknown): value is Did[] {
  return Array.isArray(value) && value.length > 0 && value.every(isDid) && new Set(value).size === value.length;
}

function hasUnexpectedKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).some((key) => !allowed.includes(key));
}

function isJsonPointer(value: string): boolean {
  return value === "" || (value.startsWith("/") && !/(?:^|[^~])~(?:[^01]|$)/.test(value));
}

function isActionEnvelopePointer(value: string): boolean {
  if (value === "") return true;
  const root = value.slice(1).split("/", 1)[0].replaceAll("~1", "/").replaceAll("~0", "~");
  return ACTION_ENVELOPE_ROOTS.has(root);
}

function isJsonObject(value: unknown): value is JsonObject {
  return isRecord(value) && Object.values(value).every((entry) => entry !== undefined && isJsonValue(entry));
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  return isJsonObject(value);
}

function isComposite(value: unknown): boolean {
  return Array.isArray(value) || isRecord(value);
}

function toFiniteNumber(value: unknown): number | null {
  if ((typeof value !== "string" && typeof value !== "number") || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}
