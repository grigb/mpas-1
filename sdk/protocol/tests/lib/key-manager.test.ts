import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { JWK } from "jose";
import { describe, expect, it } from "vitest";
import { didJwkToJwk, DuplicateJsonKeyError, KeyManager } from "../../src/index.js";
import type { Did } from "../../src/index.js";

const fixturesDir = fileURLToPath(new URL("../fixtures/", import.meta.url));

interface KeyFixture {
  did: Did;
  privateJwk: JWK;
  publicJwk: JWK;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

describe("KeyManager", () => {
  it("loads fixture keys and derives their did:jwk identifiers", async () => {
    for (const file of ["proposer.json", "maintainer-a.json", "maintainer-b.json", "adapter.json"]) {
      const fixture = await readJson<KeyFixture>(join(fixturesDir, "keys", file));
      const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", file));

      expect(keyManager.did).toBe(fixture.did);
      expect(keyManager.publicKey).toEqual(fixture.publicJwk);
      expect(keyManager.publicKey).not.toHaveProperty("d");
    }
  });

  it("signs and verifies payloads round-trip", async () => {
    const keyManager = await KeyManager.fromFile(join(fixturesDir, "keys", "proposer.json"));
    const payload = Buffer.from("mpas bridge key manager test");
    const jws = await keyManager.signCompactJws(payload);

    await expect(keyManager.verifyCompactJws(jws)).resolves.toBe(true);
    await expect(keyManager.sign(payload)).resolves.toBe(jws);
    await expect(keyManager.verify(jws)).resolves.toBe(true);

    const rawSignature = await keyManager.signBytes(payload);
    await expect(keyManager.verifyBytes(payload, rawSignature)).resolves.toBe(true);
    await expect(keyManager.verifyBytes(Buffer.from("tampered"), rawSignature)).resolves.toBe(false);
  });

  it("rejects signing when only a public JWK is available", async () => {
    const fixture = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const keyManager = KeyManager.fromJwk(fixture.publicJwk);

    expect(keyManager.did).toBe(fixture.did);
    await expect(keyManager.signCompactJws(Buffer.from("payload"))).rejects.toThrow("private key material");
    await expect(keyManager.signBytes(Buffer.from("payload"))).rejects.toThrow("private key material");
  });

  it("rejects unsupported JWKs and mismatched configured DIDs", async () => {
    expect(() => KeyManager.fromJwk({ kty: "EC", crv: "P-256", x: "x", y: "y" })).toThrow(/base64url|32 bytes/);
    expect(() => KeyManager.fromJwk({ kty: "OKP", crv: "X25519", x: "x" })).toThrow("Unsupported");

    const fixture = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const mismatched = { did: "did:jwk:bWlzbWF0Y2g", privateJwk: fixture.privateJwk };
    const path = join(fixturesDir, "keys", "mismatched.tmp.json");
    await import("node:fs/promises").then(({ writeFile, rm }) =>
      writeFile(path, JSON.stringify(mismatched)).then(async () => {
        await expect(KeyManager.fromFile(path)).rejects.toThrow("does not match derived DID");
        await rm(path);
      }),
    );
  });

  it("strictly parses the JWK embedded in did:jwk while preserving its public error", async () => {
    const fixture = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const valid = JSON.stringify(fixture.publicJwk);
    const did = `did:jwk:${Buffer.from(valid).toString("base64url")}`;
    expect(didJwkToJwk(did)).toMatchObject(fixture.publicJwk);

    const duplicateDocuments = [
      valid.replace('"kty":"OKP"', '"kty":"OKP","kty":"OKP"'),
      valid.replace(/}$/, ',"metadata":{"label":"first","label":"second"}}'),
      valid.replace('"kty":"OKP"', '"kty":"OKP","\\u006bty":"OKP"'),
    ];
    for (const document of duplicateDocuments) {
      const duplicateDid = `did:jwk:${Buffer.from(document).toString("base64url")}`;
      expect(() => didJwkToJwk(duplicateDid)).toThrow(
        "did:jwk payload is not valid base64url-encoded JSON.",
      );
    }
  });

  it("strictly parses direct and fixture-wrapped key files", async () => {
    const fixture = await readJson<KeyFixture>(join(fixturesDir, "keys", "proposer.json"));
    const directory = await mkdtemp(join(tmpdir(), "mpas-key-manager-"));
    const path = join(directory, "key.json");
    const valid = JSON.stringify(fixture.privateJwk);
    const nestedDuplicate = JSON.stringify({ privateJwk: fixture.privateJwk }).replace(
      `"x":${JSON.stringify(fixture.privateJwk.x)}`,
      `"x":${JSON.stringify(fixture.privateJwk.x)},"x":${JSON.stringify(fixture.privateJwk.x)}`,
    );
    const duplicateDocuments = [
      valid.replace('"kty":"OKP"', '"kty":"OKP","kty":"OKP"'),
      nestedDuplicate,
      valid.replace('"kty":"OKP"', '"kty":"OKP","\\u006bty":"OKP"'),
    ];

    try {
      await writeFile(path, valid);
      await expect(KeyManager.fromFile(path)).resolves.toMatchObject({ did: fixture.did });

      for (const document of duplicateDocuments) {
        await writeFile(path, document);
        await expect(KeyManager.fromFile(path)).rejects.toBeInstanceOf(DuplicateJsonKeyError);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
