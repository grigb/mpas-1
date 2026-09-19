import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runGenerate } from "../src/generate.js";
import {
  ResultDisclosureError,
  parseResultDisclosurePolicy,
} from "../src/result-disclosure.js";
import type { UpstreamInfo } from "../src/types.js";

const tools = ["credential_tool", "ordinary_tool", "__proto__", "constructor"];

describe("result disclosure policy validation", () => {
  it("accepts complete exact coverage and preserves reserved operation names as own properties", () => {
    const raw = policyText([
      ["credential_tool", true, "deny"],
      ["ordinary_tool", false, "deny"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ]);
    const result = parseResultDisclosurePolicy(raw, tools);

    expect(Object.keys(result.document.operations)).toEqual(tools);
    expect(Object.hasOwn(result.document.operations, "__proto__")).toBe(true);
    expect(Object.hasOwn(result.disclosureMap, "constructor")).toBe(true);
    expect(result.disclosureMap.credential_tool).toBe("deny");
    expect(result.disclosureMap.ordinary_tool).toBe("deny");
    expect(Object.isFrozen(result.document.operations)).toBe(true);
    expect(Object.isFrozen(result.disclosureMap)).toBe(true);
  });

  it.each([
    ["missing top-level member", '{"version":"1","type":"MpasResultDisclosurePolicy"}'],
    ["unknown top-level member", '{"version":"1","type":"MpasResultDisclosurePolicy","operations":{},"extra":1}'],
    ["wrong version", '{"version":"2","type":"MpasResultDisclosurePolicy","operations":{}}'],
    ["wrong type", '{"version":"1","type":"Other","operations":{}}'],
    ["missing operation", policyText([["credential_tool", true, "deny"]])],
    ["unknown operation", policyText([
      ["credential_tool", true, "deny"],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
      ["unknown", false, "allow"],
    ])],
    ["unknown operation field", policyText([
      ["credential_tool", true, "deny", '"extra":true'],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ])],
    ["wrong credential type", policyText([
      ["credential_tool", "yes", "deny"],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ])],
    ["invalid disclosure value", policyText([
      ["credential_tool", true, "redact"],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ])],
    ["credential-bearing allow", policyText([
      ["credential_tool", true, "allow"],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ])],
  ])("rejects %s", (_label, raw) => {
    expect(() => parseResultDisclosurePolicy(raw, tools)).toThrow(ResultDisclosureError);
  });

  it("rejects raw, escaped, and nested duplicate member names", () => {
    const complete = policyText([
      ["credential_tool", true, "deny"],
      ["ordinary_tool", false, "allow"],
      ["__proto__", false, "allow"],
      ["constructor", false, "allow"],
    ]);
    expect(() => parseResultDisclosurePolicy(complete.replace('"version":"1"', '"version":"1","version":"1"'), tools))
      .toThrow(/Duplicate JSON member name/);
    expect(() => parseResultDisclosurePolicy(complete.replace('"ordinary_tool"', '"ordinary_tool"').replace(
      '"credentialBearing":false,"resultDisclosure":"allow"',
      '"credentialBearing":false,"resultDisclosure":"allow","result\\u0044isclosure":"deny"',
    ), tools)).toThrow(/Duplicate JSON member name/);
  });

  it("rejects duplicate discovered tool names", () => {
    expect(() => parseResultDisclosurePolicy(policyText([["same", false, "allow"]]), ["same", "same"]))
      .toThrow(/unique non-empty/);
  });
});

describe("generation input gate", () => {
  const upstream: UpstreamInfo = {
    command: "fixture",
    args: [],
    serverName: "fixture",
    protocolVersion: "2024-11-05",
    tools: [{ name: "credential_tool", inputSchema: { type: "object" } }],
  };

  it("does not create the target tree when the reviewed policy is missing", async () => {
    const root = await mkdtemp(join(tmpdir(), "result-disclosure-missing-"));
    const appDir = join(root, "app");
    await expect(runGenerate({
      appName: "app",
      outDir: root,
      resultDisclosurePath: join(root, "missing.json"),
      upstreamCommand: "fixture",
      upstreamArgs: [],
      discover: async () => upstream,
      log: () => {},
    })).rejects.toThrow(ResultDisclosureError);
    expect(await readdir(root)).toEqual([]);
    await expect(readFile(appDir)).rejects.toThrow();
  });

  it("leaves an existing target tree byte-for-byte unchanged when validation fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "result-disclosure-invalid-"));
    const appDir = join(root, "app");
    const sentinel = join(root, "sentinel.txt");
    const policy = join(root, "invalid.json");
    await writeFile(sentinel, "unchanged\n");
    await writeFile(policy, policyText([["credential_tool", true, "allow"]]));
    const before = await Promise.all([readFile(sentinel, "utf8"), readdir(root)]);

    await expect(runGenerate({
      appName: "app",
      outDir: root,
      resultDisclosurePath: policy,
      upstreamCommand: "fixture",
      upstreamArgs: [],
      discover: async () => upstream,
      log: () => {},
    })).rejects.toThrow(ResultDisclosureError);

    expect(await Promise.all([readFile(sentinel, "utf8"), readdir(root)])).toEqual(before);
    await expect(readFile(appDir)).rejects.toThrow();
  });
});

type PolicyEntry = readonly [string, boolean | string, string, string?];

function policyText(entries: readonly PolicyEntry[]): string {
  const operations = entries.map(([name, credentialBearing, resultDisclosure, extra]) =>
    `${JSON.stringify(name)}:{"credentialBearing":${JSON.stringify(credentialBearing)},"resultDisclosure":${JSON.stringify(resultDisclosure)}${extra ? `,${extra}` : ""}}`,
  ).join(",");
  return `{"version":"1","type":"MpasResultDisclosurePolicy","operations":{${operations}}}\n`;
}
