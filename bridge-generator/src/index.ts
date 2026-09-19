#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { generateBridge, generateToolsJson } from "./bridge-codegen.js";
import { discoverUpstream } from "./discovery.js";
import { loadMpasSdkVersion, runGenerate } from "./generate.js";
import { generatePlugin } from "./plugin-codegen.js";
import { applyPromptSecrets } from "./prompt-secret.js";
import { loadResultDisclosurePolicy } from "./result-disclosure.js";

interface CliArgs {
  outputBridge: string;
  outputPlugin?: string;
  resultDisclosurePath?: string;
  promptSecrets: string[];
  upstreamCommand: string;
  upstreamArgs: string[];
}

interface GenerateCliArgs {
  appName: string;
  outDir: string;
  orgConfigPath?: string;
  applicationDid?: string;
  resultDisclosurePath?: string;
  promptSecrets: string[];
  upstreamCommand: string;
  upstreamArgs: string[];
}

export async function run(argv = process.argv.slice(2)): Promise<void> {
  if (argv[0] === "generate") {
    const args = parseGenerateArgs(argv.slice(1));
    await applyPromptSecrets(args.promptSecrets);
    // The SDK manifest is read once here, before any output is generated; a
    // missing, malformed, wrong-name, or versionless manifest fails the run.
    const mpasVersion = await loadMpasSdkVersion();
    await runGenerate({ ...args, mpasVersion });
    return;
  }

  const args = parseArgs(argv);
  await applyPromptSecrets(args.promptSecrets);
  const upstream = await discoverUpstream(args.upstreamCommand, args.upstreamArgs);
  const resultDisclosurePath = args.resultDisclosurePath ?? join(dirname(args.outputBridge), "result-disclosure.json");
  const disclosure = await loadResultDisclosurePolicy(
    resultDisclosurePath,
    upstream.tools.map((tool) => tool.name),
  );

  await writeOutput(args.outputBridge, generateBridge(upstream, disclosure.disclosureMap));
  const outputTools = join(dirname(args.outputBridge), "tools.json");
  await writeOutput(outputTools, generateToolsJson(upstream.tools));
  const outputDisclosure = join(dirname(args.outputBridge), "result-disclosure.json");
  await writeOutput(outputDisclosure, disclosure.rawText);
  process.stderr.write(`Bridge written to: ${args.outputBridge}\n`);
  process.stderr.write(`Tools written to: ${outputTools}\n`);
  process.stderr.write(`Result disclosure policy written to: ${outputDisclosure}\n`);

  if (args.outputPlugin) {
    await writeOutput(args.outputPlugin, generatePlugin(upstream.tools, upstream.protocolVersion));
    process.stderr.write(`Plugin written to: ${args.outputPlugin}\n`);
  }
}

function parseGenerateArgs(argv: string[]): GenerateCliArgs {
  let appName: string | undefined;
  let outDir: string | undefined;
  let orgConfigPath: string | undefined;
  let applicationDid: string | undefined;
  let resultDisclosurePath: string | undefined;
  const promptSecrets: string[] = [];
  let delimiterIndex = -1;

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--") {
      delimiterIndex = index;
      break;
    }
    if (arg === "--app") {
      appName = argv[++index];
      continue;
    }
    if (arg === "--out") {
      outDir = argv[++index];
      continue;
    }
    if (arg === "--org-config") {
      orgConfigPath = argv[++index];
      continue;
    }
    if (arg === "--application-did") {
      applicationDid = argv[++index];
      continue;
    }
    if (arg === "--result-disclosure") {
      resultDisclosurePath = argv[++index];
      continue;
    }
    if (arg === "--prompt-secret") {
      const name = argv[++index];
      if (!name || name.startsWith("--")) {
        throw usage("Missing value for --prompt-secret <ENV_VAR>.");
      }
      promptSecrets.push(name);
      continue;
    }
    throw usage(`Unknown argument: ${arg}`);
  }

  if (!appName) {
    throw usage("Missing required --app <name>.");
  }
  if (!outDir) {
    throw usage("Missing required --out <dir>.");
  }
  if (delimiterIndex < 0 || !argv[delimiterIndex + 1]) {
    throw usage("Missing upstream command after --.");
  }

  return {
    appName,
    outDir: resolve(outDir),
    ...(orgConfigPath ? { orgConfigPath: resolve(orgConfigPath) } : {}),
    ...(applicationDid ? { applicationDid } : {}),
    ...(resultDisclosurePath ? { resultDisclosurePath: resolve(resultDisclosurePath) } : {}),
    promptSecrets,
    upstreamCommand: argv[delimiterIndex + 1],
    upstreamArgs: argv.slice(delimiterIndex + 2),
  };
}

function parseArgs(argv: string[]): CliArgs {
  let outputBridge: string | undefined;
  let outputPlugin: string | undefined;
  let resultDisclosurePath: string | undefined;
  const promptSecrets: string[] = [];
  let delimiterIndex = -1;

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--") {
      delimiterIndex = index;
      break;
    }
    if (arg === "--output-bridge") {
      outputBridge = argv[++index];
      continue;
    }
    if (arg === "--output-plugin") {
      outputPlugin = argv[++index];
      continue;
    }
    if (arg === "--result-disclosure") {
      resultDisclosurePath = argv[++index];
      continue;
    }
    if (arg === "--prompt-secret") {
      const name = argv[++index];
      if (!name || name.startsWith("--")) {
        throw usage("Missing value for --prompt-secret <ENV_VAR>.");
      }
      promptSecrets.push(name);
      continue;
    }
    throw usage(`Unknown argument: ${arg}`);
  }

  if (!outputBridge) {
    throw usage("Missing required --output-bridge <path>.");
  }
  if (delimiterIndex < 0 || !argv[delimiterIndex + 1]) {
    throw usage("Missing upstream command after --.");
  }

  return {
    outputBridge: resolve(outputBridge),
    ...(outputPlugin ? { outputPlugin: resolve(outputPlugin) } : {}),
    ...(resultDisclosurePath ? { resultDisclosurePath: resolve(resultDisclosurePath) } : {}),
    promptSecrets,
    upstreamCommand: argv[delimiterIndex + 1],
    upstreamArgs: argv.slice(delimiterIndex + 2),
  };
}

async function writeOutput(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents, "utf8");
}

function usage(message: string): Error {
  return new Error(`${message}

Usage:
  bridge-generator [--prompt-secret <ENV_VAR>]... --output-bridge <path> [--output-plugin <path>] [--result-disclosure <path>] -- <upstream-command> [upstream-args...]
  bridge-generator generate --app <name> --out <dir> [--org-config <path>] [--application-did <did>] [--result-disclosure <path>] [--prompt-secret <ENV_VAR>]... -- <upstream-command> [upstream-args...]

  --prompt-secret <ENV_VAR>  If ENV_VAR is unset, prompt on the TTY with echo disabled
                             (like an SSH passphrase) and export it for the upstream spawn.
                             Repeatable. Skipped when the variable is already set.`);
}

function exitCodeFor(error: unknown): number {
  if (typeof error === "object" && error !== null && "exitCode" in error) {
    const code = (error as { exitCode?: unknown }).exitCode;
    if (typeof code === "number") {
      return code;
    }
  }
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await run();
  } catch (error) {
    process.stderr.write(`ERROR: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(exitCodeFor(error));
  }
}
