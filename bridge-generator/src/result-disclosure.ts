import { readFile } from "node:fs/promises";

export type ResultDisclosureDecision = "allow" | "deny";
export type ResultDisclosureMap = Readonly<Record<string, ResultDisclosureDecision>>;

export interface ResultDisclosureOperation {
  credentialBearing: boolean;
  resultDisclosure: ResultDisclosureDecision;
}

export interface ResultDisclosureDocument {
  version: "1";
  type: "MpasResultDisclosurePolicy";
  operations: Record<string, ResultDisclosureOperation>;
}

export interface LoadedResultDisclosurePolicy {
  document: ResultDisclosureDocument;
  disclosureMap: ResultDisclosureMap;
  rawText: string;
}

export class ResultDisclosureError extends Error {
  readonly exitCode = 5;
}

export async function loadResultDisclosurePolicy(
  path: string,
  toolNames: readonly string[],
): Promise<LoadedResultDisclosurePolicy> {
  let rawText: string;
  try {
    rawText = await readFile(path, "utf8");
  } catch (error) {
    throw new ResultDisclosureError(
      `Unable to read result disclosure policy ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return { ...parseResultDisclosurePolicy(rawText, toolNames), rawText };
}

export function parseResultDisclosurePolicy(
  text: string,
  toolNames: readonly string[],
): Omit<LoadedResultDisclosurePolicy, "rawText"> {
  let parsed: unknown;
  try {
    parsed = strictJsonParse(text);
  } catch (error) {
    throw new ResultDisclosureError(
      `Invalid result disclosure policy JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const root = requireObject(parsed, "result disclosure policy");
  requireExactKeys(root, ["version", "type", "operations"], "result disclosure policy");
  if (root.version !== "1") {
    throw new ResultDisclosureError('result disclosure policy version must be "1".');
  }
  if (root.type !== "MpasResultDisclosurePolicy") {
    throw new ResultDisclosureError('result disclosure policy type must be "MpasResultDisclosurePolicy".');
  }

  const uniqueTools = new Set<string>();
  for (const name of toolNames) {
    if (typeof name !== "string" || name.length === 0 || uniqueTools.has(name)) {
      throw new ResultDisclosureError("Discovered tool names must be unique non-empty strings.");
    }
    uniqueTools.add(name);
  }

  const rawOperations = requireObject(root.operations, "result disclosure policy operations");
  const actualNames = Object.keys(rawOperations);
  const unknown = actualNames.find((name) => !uniqueTools.has(name));
  if (unknown !== undefined) {
    throw new ResultDisclosureError(`result disclosure policy contains unknown operation ${JSON.stringify(unknown)}.`);
  }
  const missing = toolNames.find((name) => !Object.hasOwn(rawOperations, name));
  if (missing !== undefined) {
    throw new ResultDisclosureError(`result disclosure policy is missing operation ${JSON.stringify(missing)}.`);
  }

  const operations = Object.create(null) as Record<string, ResultDisclosureOperation>;
  const disclosureMap = Object.create(null) as Record<string, ResultDisclosureDecision>;
  for (const name of toolNames) {
    const operation = requireObject(rawOperations[name], `result disclosure operation ${JSON.stringify(name)}`);
    requireExactKeys(
      operation,
      ["credentialBearing", "resultDisclosure"],
      `result disclosure operation ${JSON.stringify(name)}`,
    );
    if (typeof operation.credentialBearing !== "boolean") {
      throw new ResultDisclosureError(
        `result disclosure operation ${JSON.stringify(name)} credentialBearing must be a boolean.`,
      );
    }
    if (operation.resultDisclosure !== "allow" && operation.resultDisclosure !== "deny") {
      throw new ResultDisclosureError(
        `result disclosure operation ${JSON.stringify(name)} resultDisclosure must be "allow" or "deny".`,
      );
    }
    if (operation.credentialBearing && operation.resultDisclosure !== "deny") {
      throw new ResultDisclosureError(
        `credential-bearing operation ${JSON.stringify(name)} must set resultDisclosure to "deny".`,
      );
    }
    const validated = Object.freeze({
      credentialBearing: operation.credentialBearing,
      resultDisclosure: operation.resultDisclosure,
    });
    Object.defineProperty(operations, name, {
      value: validated,
      enumerable: true,
      configurable: false,
      writable: false,
    });
    Object.defineProperty(disclosureMap, name, {
      value: operation.resultDisclosure,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }

  return {
    document: Object.freeze({
      version: "1",
      type: "MpasResultDisclosurePolicy",
      operations: Object.freeze(operations),
    }),
    disclosureMap: Object.freeze(disclosureMap),
  };
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ResultDisclosureError(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const expected = new Set(allowed);
  const unknown = Object.keys(value).find((key) => !expected.has(key));
  if (unknown !== undefined) {
    throw new ResultDisclosureError(`${label} contains undeclared member ${JSON.stringify(unknown)}.`);
  }
  const missing = allowed.find((key) => !Object.hasOwn(value, key));
  if (missing !== undefined) {
    throw new ResultDisclosureError(`${label} is missing required member ${JSON.stringify(missing)}.`);
  }
}

class DuplicateJsonKeyError extends SyntaxError {
  constructor(key: string, jsonPath: string) {
    super(`Duplicate JSON member name ${JSON.stringify(key)} at ${jsonPath}`);
    this.name = "DuplicateJsonKeyError";
  }
}

const NUMBER_PATTERN = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

/** Generator-local strict parser: raw duplicate names, including escaped names, are malformed. */
function strictJsonParse(text: string): unknown {
  let index = 0;

  function error(message: string): SyntaxError {
    return new SyntaxError(`${message} at position ${index}`);
  }
  function skipWhitespace(): void {
    while (index < text.length && [" ", "\t", "\n", "\r"].includes(text[index]!)) index += 1;
  }
  function parseString(): string {
    if (text[index] !== '"') throw error("Expected string");
    const start = index++;
    while (index < text.length) {
      const character = text[index];
      if (character === "\\") {
        index += 2;
      } else if (character === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index)) as string;
      } else {
        index += 1;
      }
    }
    throw error("Unterminated string");
  }
  function parseValue(path: string): unknown {
    skipWhitespace();
    const character = text[index];
    if (character === undefined) throw error("Unexpected end of input");
    if (character === "{") return parseObject(path);
    if (character === "[") return parseArray(path);
    if (character === '"') return parseString();
    if (text.startsWith("true", index)) {
      index += 4;
      return true;
    }
    if (text.startsWith("false", index)) {
      index += 5;
      return false;
    }
    if (text.startsWith("null", index)) {
      index += 4;
      return null;
    }
    const match = NUMBER_PATTERN.exec(text.slice(index));
    if (!match) throw error("Unexpected token");
    index += match[0].length;
    return Number(match[0]);
  }
  function parseObject(path: string): Record<string, unknown> {
    index += 1;
    const result: Record<string, unknown> = {};
    const seen = new Set<string>();
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return result;
    }
    for (;;) {
      skipWhitespace();
      const key = parseString();
      if (seen.has(key)) throw new DuplicateJsonKeyError(key, path);
      seen.add(key);
      skipWhitespace();
      if (text[index] !== ":") throw error('Expected ":"');
      index += 1;
      Object.defineProperty(result, key, {
        value: parseValue(`${path}.${key}`),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      skipWhitespace();
      if (text[index] === ",") {
        index += 1;
        continue;
      }
      if (text[index] === "}") {
        index += 1;
        return result;
      }
      throw error('Expected "," or "}"');
    }
  }
  function parseArray(path: string): unknown[] {
    index += 1;
    const result: unknown[] = [];
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return result;
    }
    for (;;) {
      result.push(parseValue(`${path}[${result.length}]`));
      skipWhitespace();
      if (text[index] === ",") {
        index += 1;
        continue;
      }
      if (text[index] === "]") {
        index += 1;
        return result;
      }
      throw error('Expected "," or "]"');
    }
  }

  const value = parseValue("$");
  skipWhitespace();
  if (index !== text.length) throw error("Unexpected trailing characters");
  return value;
}
