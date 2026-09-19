export type ResultDisclosureDecision = "allow" | "deny";
export type ResultDisclosureMap = Readonly<Record<string, ResultDisclosureDecision>>;

export const RESULT_DISCLOSURE_DENIED_CODE = "RESULT_DISCLOSURE_DENIED";
export const RESULT_DISCLOSURE_DENIED_MESSAGE =
  "This bridge does not disclose results for this operation.";

export class InvalidResultDisclosureMapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidResultDisclosureMapError";
  }
}

/** Copy and validate a local allow/deny map, optionally against a complete tool surface. */
export function validateResultDisclosureMap(
  value: unknown,
  toolNames?: readonly string[],
): ResultDisclosureMap {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InvalidResultDisclosureMapError("resultDisclosure must be an object.");
  }

  let names: Set<string> | undefined;
  if (toolNames !== undefined) {
    names = new Set<string>();
    for (const name of toolNames) {
      if (typeof name !== "string" || name.length === 0 || names.has(name)) {
        throw new InvalidResultDisclosureMapError("Bridge tool names must be unique non-empty strings.");
      }
      names.add(name);
    }
  }

  const copy = Object.create(null) as Record<string, ResultDisclosureDecision>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || (names !== undefined && !names.has(key))) {
      throw new InvalidResultDisclosureMapError(`resultDisclosure contains unknown operation ${String(key)}.`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || (descriptor.value !== "allow" && descriptor.value !== "deny")) {
      throw new InvalidResultDisclosureMapError(
        `resultDisclosure.${key} must be either "allow" or "deny".`,
      );
    }
    Object.defineProperty(copy, key, {
      value: descriptor.value,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }

  if (names !== undefined) {
    for (const name of names) {
      if (!Object.hasOwn(copy, name)) {
        throw new InvalidResultDisclosureMapError(`resultDisclosure is missing operation ${name}.`);
      }
    }
  }
  return Object.freeze(copy);
}

export function resultDisclosureAllows(
  policy: ResultDisclosureMap | undefined,
  toolName: string,
): boolean {
  return policy === undefined || (Object.hasOwn(policy, toolName) && policy[toolName] === "allow");
}
