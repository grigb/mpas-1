import { describe, expect, it } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import type { ActionPackage, AdapterResponse, McpToolDefinition, PolicyConfig } from "../src/index.js";

function compileVirtualTypeProbe(source: string): readonly ts.Diagnostic[] {
  const testDirectory = path.dirname(fileURLToPath(import.meta.url));
  const virtualFile = path.join(testDirectory, "virtual-approval-requirements.mts");
  const options: ts.CompilerOptions = {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
  };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  host.fileExists = (fileName) => fileName === virtualFile || fileExists(fileName);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreateNewSourceFile) =>
    fileName === virtualFile
      ? ts.createSourceFile(virtualFile, source, languageVersion, true)
      : getSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
  return ts.getPreEmitDiagnostics(ts.createProgram([virtualFile], options, host));
}

describe("MPAS Bridge types", () => {
  it("allows a fully typed sample Action Package", () => {
    const actionPackage: ActionPackage = {
      version: "1",
      type: "ActionPackage",
      executionPayload: {
        name: "create_issue",
        arguments: {
          owner: "oma3dao",
          repo: "app-registry",
          title: "Add MPAS bridge fixture coverage",
        },
      },
      actionEnvelope: {
        version: "1",
        type: "ActionEnvelope",
        proposer: {
          did: "did:web:agents.example:proposer",
        },
        target: {
          applicationDid: "did:web:github.example",
          resource: "repo:oma3dao/app-registry",
        },
        executionProfile: {
          id: "did:web:profiles.oma3.org:mcp",
          format: "mcp.toolsCall",
        },
        executionPayloadHash: {
          alg: "sha-256",
          value: "base64url-encoded-digest",
        },
        actionId: {
          value: "urn:uuid:3f82f6e1-135e-44c5-90a9-58f760f6d9f1",
        },
        createdAt: "2026-06-05T18:00:00Z",
        expiresAt: "2026-06-05T18:30:00Z",
      },
      approvalBundle: {
        version: "1",
        type: "ApprovalBundle",
        actionEnvelopeHash: {
          alg: "sha-256",
          value: "base64url-encoded-envelope-digest",
        },
        approvals: [
          {
            version: "1",
            type: "Approval",
            actionEnvelopeHash: {
              alg: "sha-256",
              value: "base64url-encoded-envelope-digest",
            },
            decision: "propose",
            signature: {
              format: "jws",
              value: "eyJhbGciOiJFZERTQSJ9.eyJ0eXBlIjoiQXBwcm92YWxQYXlsb2FkIn0.signature",
            },
            createdAt: "2026-06-05T18:01:00Z",
          },
        ],
        assembledBy: "did:web:agents.example:proposer",
        createdAt: "2026-06-05T18:10:00Z",
      },
      createdAt: "2026-06-05T18:10:00Z",
    };

    expect((actionPackage.executionPayload as { name?: string }).name).toBe("create_issue");
  });

  it("models adapter responses and MCP tool definitions", () => {
    const tool: McpToolDefinition = {
      name: "create_issue",
      description: "Create a new issue in a repository.",
      inputSchema: {
        type: "object",
        required: ["owner", "repo", "title"],
        properties: {
          owner: { type: "string" },
          repo: { type: "string" },
          title: { type: "string" },
        },
      },
    };

    const response: AdapterResponse = {
      version: "1",
      type: "ActionResponse",
      result: "additionalApprovalsRequired",
      authorizationRequirements: {
        version: "1",
        type: "AuthorizationRequirements",
        actionEnvelopeHash: {
          alg: "sha-256",
          value: "base64url-encoded-envelope-digest",
        },
        result: "additionalApprovalsRequired",
        verifier: {
          did: "did:web:agents.example:adapter",
        },
        approvalRequirements: {
          anyOf: [
            {
              type: "threshold",
              threshold: 1,
              eligibleSigners: ["did:web:agents.example:signer"],
              decision: "approve",
            },
          ],
        },
      },
    };

    expect(tool.name).toBe("create_issue");
    expect(response.result).toBe("additionalApprovalsRequired");
  });

  it("models informative ActionResponse diagnostics", () => {
    const response: AdapterResponse = {
      version: "1",
      type: "ActionResponse",
      result: "indeterminate",
      context: {
        diagnostic: {
          code: "DISPATCH_TIMEOUT",
          phase: "tools/call",
          transport: "stdio",
          message: "The upstream MCP server did not respond before the dispatch timeout.",
        },
      },
    };

    expect(response.context?.diagnostic?.code).toBe("DISPATCH_TIMEOUT");
  });

  it("models requirement and reject policy entries", () => {
    const policy: PolicyConfig = {
      version: "1",
      type: "MpasApplicationPolicy",
      policyProfileUrl: "https://github.com/oma3dao/mpas/blob/main/specs/mpas-profile-policy-json.md",
      applicationDid: "did:web:github.example",
      executionProfile: { id: "did:web:profiles.oma3.org:mcp", format: "mcp.toolsCall" },
      defaultRequirement: {
        type: "anyOf",
        requirements: [{ type: "allOf", requirements: [{ type: "proposerOnly" }] }],
      },
      signerGroups: {
        all: ["did:web:agents.example:proposer"],
        proposers: ["did:web:agents.example:proposer"],
      },
      policies: {
        create_issue: [
          { reject: false, requirements: { type: "proposerOnly" } },
          { reject: true, description: "Issue creation is disabled." },
        ],
      },
    };

    expect(policy.policies?.create_issue[1].reject).toBe(true);
  });

  it("compiles valid flat and recursive decisions while rejecting an ordinary nested reject leaf", () => {
    const valid = compileVirtualTypeProbe(`
      import type { Approval, ApprovalRequirements, Decision } from "../src/index.js";
      const approve: ApprovalRequirements = { anyOf: [{ type: "threshold", threshold: 1, eligibleSigners: ["did:web:agents.example:approve"], decision: "approve" }] };
      const propose: ApprovalRequirements = { allOf: [{ type: "threshold", threshold: 1, eligibleSigners: ["did:web:agents.example:propose"], decision: "propose" }] };
      const abstain: ApprovalRequirements = { anyOf: [{ type: "anyOf", requirements: [{ type: "allOf", requirements: [{ type: "threshold", threshold: 1, eligibleSigners: ["did:web:agents.example:abstain"], decision: "abstain" }] }] }] };
      const override: ApprovalRequirements = { overrideSigners: [{ signer: "did:web:agents.example:override", permissions: ["execute"] }] };
      const approvalDecision: Approval["decision"] = "reject";
      const coreDecision: Decision = "reject";
      export { approve, propose, abstain, override, approvalDecision, coreDecision };
    `);
    expect(valid.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))).toEqual([]);

    const invalid = compileVirtualTypeProbe(`
      import type { ApprovalRequirements } from "../src/index.js";
      export const rejected: ApprovalRequirements = { anyOf: [{ type: "anyOf", requirements: [{ type: "threshold", threshold: 1, eligibleSigners: ["did:web:agents.example:reject"], decision: "reject" }] }] };
    `);
    expect(invalid.length).toBeGreaterThan(0);
    expect(invalid.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")).join("\n"))
      .toContain('Type \'"reject"\' is not assignable');
  });
});
