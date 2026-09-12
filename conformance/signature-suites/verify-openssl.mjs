// Independent CLI verification: no MPAS or jose imports. Node only serializes
// the public key and converts the MPAS wire signature to OpenSSL's DER input.
import { createPublicKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fixture = JSON.parse(readFileSync(new URL("./p256.json", import.meta.url), "utf8"));
const http = JSON.parse(readFileSync(new URL("../http-message-signatures/mpas-v1-p256.json", import.meta.url), "utf8"));
const dir = mkdtempSync(join(tmpdir(), "mpas-es256-openssl-"));
function derInteger(bytes) {
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([2, bytes.length]), bytes]);
}
function toDer(raw) {
  if (raw.length !== 64) throw new Error("Expected raw MPAS signature.");
  const body = Buffer.concat([derInteger(raw.subarray(0, 32)), derInteger(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function check(input, signature) {
  writeFileSync(join(dir, "input"), input);
  writeFileSync(join(dir, "signature.der"), toDer(signature));
  execFileSync("openssl", ["dgst", "-sha256", "-verify", join(dir, "public.pem"), "-signature", join(dir, "signature.der"), join(dir, "input")], { stdio: "pipe" });
  writeFileSync(join(dir, "input"), Buffer.concat([Buffer.from(input), Buffer.from("tampered")]));
  let rejected = false;
  try {
    execFileSync("openssl", ["dgst", "-sha256", "-verify", join(dir, "public.pem"), "-signature", join(dir, "signature.der"), join(dir, "input")], { stdio: "pipe" });
  } catch { rejected = true; }
  if (!rejected) throw new Error("Independent verifier accepted tampering.");
}
try {
  writeFileSync(join(dir, "public.pem"), createPublicKey({ key: fixture.publicJwk, format: "jwk" }).export({ format: "pem", type: "spki" }));
  for (const jws of [fixture.approval.signature.value, fixture.receipt.signature]) {
    const [header, payload, signature] = jws.split(".");
    check(Buffer.from(`${header}.${payload}`), Buffer.from(signature, "base64url"));
  }
  check(Buffer.from(http.signatureBase), Buffer.from(http.signature.split(":")[1], "base64"));
  console.log(`${execFileSync("openssl", ["version"], { encoding: "utf8" }).trim()}: Approval, receipt, HTTP vectors verified; tampering rejected.`);
} finally { rmSync(dir, { recursive: true, force: true }); }
