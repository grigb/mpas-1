# MPAS Signature Suites and ES256/P-256 — Specification

**Status:** Implemented (reference SDK; see plan for validation and rollout)
**Created:** 2026-09-08
**Issue:** [#78 — Add spec-governed signature suites and full ES256/P-256 support](https://github.com/oma3dao/mpas/issues/78)
**Related:** [#56 — Add pluggable signer providers for MPAS](https://github.com/oma3dao/mpas/issues/56)
**Affects:** Core and HTTP specifications, protocol SDK, demo services and CLI, bridge generator, conformance tests
**Normative output:** [Core specification](../../../specs/mpas-specification.md), [HTTP profile](../../../specs/mpas-profile-http.md)
**Companion:** [plan.md](./plan.md)

---

## 1. Purpose

Add P-256/ES256 as a fully specified and implemented MPAS signature suite alongside
the existing Ed25519/EdDSA baseline. Ed25519 remains fully supported; this feature
does not deprecate it or change existing participant identities.

Centralize public-key validation, suite selection, algorithm bindings, and
signature encoding so every signing and verification path follows the same
specification-defined rules. Separate those rules from private-key storage and
the mechanism used to perform signing.

## 2. Scope and Design Decisions

### 2.1 Included

- Normative definitions for both suites in Core and the HTTP profile.
- Public JWK validation, minimal JWK normalization, and `did:jwk` handling.
- Software signing and verification for both suites, including public-only keys.
- Approval and Execution Receipt signing through a shared signer contract.
- Dual-suite HTTP Message Signatures wherever the MPAS HTTP profile applies,
  including Coordination, direct Action submission, and relay operations.
- Signing-implementation selection of which specified suite to generate, without
  allowing a verifier to disable either specified suite.
- HTTP `alg` required on new senders; when it is absent, the claimed algorithm
  is `ed25519` and MUST still match the key.
- Fixed conformance fixtures, independent verification, and negative tests.
- SDK exports and documentation, demo key generation and services, and generated
  bridge compatibility.

### 2.2 Excluded

- Runtime registration or loading of arbitrary cryptographic suites.
- ES256K, other curves, or algorithms accepted only because a crypto library
  supports them.
- Platform-specific KMS, HSM, hardware-wallet, or remote-signing providers.
- A second provider interface competing with #56, or the entire provider system
  proposed there.
- Changes to Action Envelope, Approval, Canonical Approval Payload, Approval
  Bundle, or Execution Receipt data models.
- New DID resolution methods, automatic key rotation, or conversion of an
  Ed25519 private key into a P-256 private key.
- Verifier configuration that accepts only a subset of the specified suites.

### 2.3 Agreed Clarifications to Issue #78

1. **Shared signer prerequisite.** #56 remains related work, but its later
   discussion allows deferring the abstraction. This feature therefore includes
   establishing or reusing the minimal shared signer contract needed for both
   compact JWS and raw-byte signing before migrating builders. It must converge
   with #56 rather than wait indefinitely for it or invent a parallel provider
   system. Implementing unrelated #56 provider features is not required here.
2. **HTTP `alg` default.** New senders of either suite MUST include `alg`. When
   HTTP `alg` is absent, the claimed algorithm for the SUITE-04 check is
   `ed25519`. That default MUST NOT be inserted into the reconstructed
   `@signature-params` or signature base. A P-256 key with absent `alg` is a
   key/algorithm mismatch. This default is HTTP-only; JWS still requires a
   protected `alg`. Omission is not an allowed sender format for new
   implementations.
3. **Fixed vectors, not deterministic production signing.** Conformance uses
   committed keys, inputs, signatures, and expected results. Production ECDSA
   signers need not reproduce identical signature bytes on repeated calls.

---

## 3. Specification-Governed Suites

In this document, a **signing implementation** is any component that creates a
signed HTTP request, Approval, or Execution Receipt. That includes HTTP clients,
Approval Signers, and Verifiers that issue receipts. It is not limited to the
MPAS Signer role.

| Suite | Public JWK | JWS protected `alg` | RFC 9421 `alg` | Signature bytes |
|---|---|---|---|---|
| Ed25519 | `kty: "OKP"`, `crv: "Ed25519"` | `EdDSA` | `ed25519` | 64-byte Ed25519 signature |
| P-256 | `kty: "EC"`, `crv: "P-256"` | `ES256` | `ecdsa-p256-sha256` | 64-byte raw `R || S` |

| # | Requirement |
|---|---|
| SUITE-01 | The implementation MUST have one centralized, code-defined source of suite rules. Configuration and incoming messages MUST NOT add suite definitions. Adding a suite requires a future specification change and conformance vectors. |
| SUITE-02 | Conforming verifiers MUST verify both specified suites. They MUST NOT be configurable to reject a specified suite. A signing implementation MAY generate either suite. Ed25519 remains the default for existing key-generation behavior unless explicitly selected otherwise. |
| SUITE-03 | Suite resolution MUST use the trusted or resolved public key and MUST produce exactly one supported match. Unknown or ambiguous matches, unsupported key types, and unsupported curves MUST fail closed. |
| SUITE-04 | An incoming algorithm identifier MUST NOT independently select a verification operation. The implementation MUST validate the key, derive its permitted algorithm for the protocol context, check the claimed algorithm against it, and only then verify cryptographically. For HTTP, the claimed algorithm is the received `alg` when present and `ed25519` when absent. JWS has no absent-`alg` default. |
| SUITE-05 | Deployment policy MAY select which specified suite a signing implementation uses for key generation and newly created signatures. Unknown suite names in that configuration MUST fail validation. Signing-suite selection MUST remain distinct from provider selection and from Signer authorization. It MUST NOT be used to disable verification of either specified suite. |

Cryptographic support does not authorize an identity. A valid P-256 signature
does not make its signer eligible for an Approval, change a threshold, or bypass
any existing identity, payload-binding, or execution-policy check.

## 4. Key Validation and `did:jwk`

### 4.1 Minimal Public JWKs

Ed25519 retains exactly these members:

```json
{"crv":"Ed25519","kty":"OKP","x":"..."}
```

P-256 uses exactly these members:

```json
{"crv":"P-256","kty":"EC","x":"...","y":"..."}
```

| # | Requirement |
|---|---|
| KEY-01 | Public-key validation MUST check the key type, curve, required parameters, canonical unpadded base64url encoding, and decoded lengths. Ed25519 `x` and P-256 `x`/`y` MUST each decode to exactly 32 bytes. P-256 coordinates MUST be the unsigned big-endian field elements defined by [RFC 7518 §6.2.1](https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1). Compressed P-256 points, omitted `y`, and parity-only `y` encodings MUST be rejected. |
| KEY-02 | A P-256 public key MUST represent a valid point on P-256. Missing coordinates, out-of-range coordinates, points off the curve, and the point at infinity MUST be rejected using a vetted cryptographic implementation. |
| KEY-03 | Public-only validation and DID decoding MUST reject private key material, including the presence of `d` even when its value is empty or null. Normalization MUST NOT silently strip private material from an incoming DID and accept it. |
| KEY-04 | DID minting MUST apply the existing MPAS JCS rule to the minimal public JWK, then base64url-encode the canonical UTF-8 bytes without padding. Optional `alg`, `kid`, `use`, and `key_ops` members MUST NOT enter the minimal JWK. Existing Ed25519 minting results MUST remain byte-for-byte unchanged. |
| KEY-05 | DID decoding MUST preserve the existing separation between minting and identity comparison. Validate the embedded public key, but MUST NOT rewrite a received or stored DID into a different identifier. Identity equality remains exact string equality; `did:jwk` verification keys come from the DID, without network resolution. |
| KEY-06 | Local private-JWK import MUST validate private material appropriate to the selected suite, including a 32-byte `d`, valid P-256 scalar range, and consistency of the public and private key. Trusted local import MAY derive a public-only projection before DID minting; private fields MUST never be serialized into a DID or public-key export. |
| KEY-07 | Optional JWK metadata (`alg`, `use`, `key_ops`) MAY appear on imported or local JWKs and on a received `did:jwk` embedded key. Newly minted DIDs MUST still use the minimal public JWK (KEY-04). Optional metadata MUST NOT override key-derived suite selection. If present, `alg` MUST agree with the suite's JWS algorithm; `use` and `key_ops` MUST permit the requested operation. Metadata absent from a key MUST remain optional. A received or stored DID MUST NOT be rejected solely because it contains such metadata, and MUST NOT be rewritten into a different identifier (KEY-05). |

Preserve `generateEd25519Key()` and its existing return shape. Add an explicit
P-256 generation utility with equivalent DID, `kid`, public-key, and private-key
results for software providers and tests. Do not regenerate fixture keys merely
to adopt the new module.

## 5. Shared Signer Contract and SDK Architecture

The signature suite answers which cryptographic rules are permitted. The signer
answers how an authorized key performs signing. Neither responsibility implies
that a caller can export the private key.

| # | Requirement |
|---|---|
| SIGN-01 | The shared signer contract MUST expose enough public identity metadata to validate its DID/key binding, authorized `kid`, and specification-approved algorithm. It MUST support compact-JWS signing and raw-byte signing as explicit capabilities, without requiring private-JWK access. Existing #56 work MUST be reused when available. |
| SIGN-02 | Signing inputs MUST have unambiguous semantics: compact-JWS signing consumes payload bytes and produces the complete compact JWS; raw signing consumes the complete message bytes and produces suite-encoded signature bytes. Callers MUST NOT pre-hash. Provider adapters MUST prevent double hashing and MUST adapt provider-internal digest APIs or DER output before crossing this contract. |
| SIGN-03 | Provider metadata MUST agree with the selected public-key suite and expected identity. Unsupported or inconsistent metadata MUST fail before producing or sending an artifact. Tests MUST demonstrate signing through a provider with no private-key export capability. |
| SIGN-04 | `KeyManager` MUST implement the shared contract for local Ed25519 and P-256 keys by using the suite and signer modules. Public-only instances MUST verify but reject signing. Existing usable Ed25519 constructors, signing methods, aliases, and builder call forms MUST remain supported by routing them through that shared implementation. The SDK MUST NOT keep a parallel Ed25519-only signing or verification path. |
| SIGN-05 | The protocol SDK MUST implement the modules in the table below under `sdk/protocol/src/lib/`, and those modules MUST own the listed responsibilities. Callers MUST NOT duplicate algorithm dispatch. Public algorithm options MUST be a closed type; accepting an arbitrary string MUST NOT imply support. If #56 already provides the shared signer module, reuse that file rather than adding a second one; otherwise add `signer.ts`. |

For P-256, the signing operation MUST apply SHA-256 exactly once to the specified
signing input; callers MUST NOT pre-hash, and provider adapters MUST prevent
double hashing.

- Compact JWS: the signing input is the RFC 7515 signing-input string
  `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))`.
- Raw signing, including HTTP Message Signatures: the signing input is the
  complete message bytes. For this profile those bytes are the RFC 9421
  signature base.

Required protocol SDK modules:

| Module | Responsibility |
|---|---|
| `signature-suites.ts` | Closed suite definitions, validation, normalization, algorithm bindings, raw encoding, and verification |
| `signer.ts` | Public metadata and explicit signing capabilities aligned with #56 |
| `did-jwk.ts` | DID serialization, decoding, exact identity semantics, and generation helpers using suite rules |
| `key-manager.ts` | Local key import and signing; public-only verification |
| `approval-builder.ts` | Approval payload construction and signing through the shared signer contract |
| `receipt-builder.ts` | Execution Receipt payload construction and signing through the shared signer contract |
| `verification.ts` | Shared cryptographic validation plus artifact-specific identity and payload checks |
| `rfc9421.ts` | HTTP signature-base construction and profile enforcement using suite-derived algorithms |

---

## 6. JWS Approvals and Execution Receipts

| # | Requirement |
|---|---|
| JWS-01 | Approvals and Execution Receipts MUST support both suites. Their protected JWS headers MUST contain the suite's `alg` and a `kid` identifying a key authorized for the signer or issuer DID. For `did:jwk`, the verification method is the exact DID followed by `#0`. |
| JWS-02 | Verification MUST reject `none`, unknown algorithms, ES256K, missing required protected headers, unauthorized `kid`, and every key/algorithm mismatch. All public verification entry points and internal payload-verification helpers MUST enforce the same suite rules. |
| JWS-03 | ES256 signatures MUST be exactly 64 bytes: unsigned, big-endian `R` followed by `S`, each padded to 32 bytes. Verification MUST reject wrong lengths and invalid ECDSA scalar values, and MUST NOT accept ASN.1 DER as an alternative wire encoding. Ed25519 signatures MUST also be exactly 64 bytes. |
| JWS-04 | The suite MUST NOT change payload canonicalization or protocol object shapes. Given the same payload fields, canonical payload bytes MUST be identical across suites. Approval hashes, decisions, timestamps, signer binding, receipt issuer, Action identity, payload hashes, and execution outcome MUST retain their existing validation semantics. |
| JWS-05 | Approval and receipt builders MUST use the shared signer contract. Existing private-JWK receipt inputs MAY remain as constructors that build a local signer through `KeyManager` and the suite modules; the builder's common path MUST NOT request private material from a provider. |

An ES256 signature is not a unique identifier for a payload. Neither deterministic
production ECDSA nor a new low-S-only acceptance rule is required by this feature.
Existing nonce, Action identity, Approval counting, and dispatch protections must
not be replaced with comparisons of signature bytes.

## 7. HTTP Message Signatures

Retain RFC 9421 signature-base construction and RFC 9530 Content-Digest handling.
Apply the same suite behavior to every caller and endpoint using this profile.

New requests of either suite include `alg`. When `alg` is absent, the claimed
HTTP algorithm is `ed25519`. Reconstruct the signature base from the received
parameters as sent; do not insert that default into `@signature-params`.
Omission is not an allowed sender format for new implementations.

| # | Requirement |
|---|---|
| HTTP-01 | Every newly generated Ed25519 or P-256 request MUST include `alg` in the signed `Signature-Input` parameters. It MUST equal the RFC 9421 algorithm derived from the public key embedded in `keyid`. JWS identifiers such as `ES256` or `EdDSA` are not valid substitutes in this profile. New implementations MUST NOT omit `alg`. |
| HTTP-02 | When HTTP `alg` is absent, the claimed algorithm for the SUITE-04 check MUST be `ed25519`. The verifier MUST reconstruct the RFC 9421 signature base from the received parameters without adding `alg`. Absent `alg` with a P-256 key MUST be rejected as a key/algorithm mismatch. This default MUST NOT apply to JWS. Omission MUST NOT bypass any other check. |
| HTTP-03 | HTTP signatures MUST use the selected suite's exact raw encoding, including 64-byte `R || S` for P-256. Unsupported curves, wrong lengths, DER wire signatures, and present but mismatched or unknown `alg` values MUST be rejected. |
| HTTP-04 | Suite support MUST preserve covered components, label/tag selection, public-only `keyid`, Content-Digest verification, freshness, lifetime limits, audience matching, endpoint identity equality, authorization, nonce-claim ordering, replay retention, and external error behavior. |

Expected verification matrix, assuming all other checks pass:

| Key | `alg` | Result |
|---|---|---|
| Ed25519 | `ed25519` | Accept |
| Ed25519 | Absent | Accept (claimed `ed25519`; signature base unchanged) |
| P-256 | `ecdsa-p256-sha256` | Accept |
| P-256 | Absent | Reject (claimed `ed25519` does not match the key) |
| Either | Unknown or mismatched | Reject |

The original Ed25519 HTTP vector remains an unchanged fixture for absent `alg`.
Add a separate explicit-`alg` Ed25519 vector for new sender behavior rather than
overwriting the existing vector or requiring new senders to emit the old format.

## 8. Normative Documentation and Integration

| # | Requirement |
|---|---|
| INT-01 | Core MUST contain complete suite, key, DID, JWS, and conformance rules. Update repeated rules in appendices and requirement summaries, including the current ES256K recommendation, so no section independently authorizes an unspecified suite. |
| INT-02 | The HTTP profile MUST define both algorithm bindings, new-sender `alg` inclusion, and the absent-`alg` claimed-algorithm default of `ed25519` without rewriting the signature base. Related authentication feature documentation MUST identify the revised rules instead of retaining conflicting Ed25519-only guidance, including the previous SHOULD-omit-`alg` sender rule. |
| INT-03 | SDK exports, configuration validation, demo services, CLI key generation, and bridge-generator output MUST support both suites without duplicating cryptographic policy. Existing Ed25519 configuration remains valid; P-256 generation is explicitly selected. |
| INT-04 | Examples and guides MUST retain Ed25519 examples and add focused P-256 and mixed-suite examples. Missing, unreadable, or mismatched configured keys MUST fail without silently creating a new key or DID. |

## 9. Conformance and Acceptance

Committed P-256 fixtures must include the minimal public JWK, canonical minting
bytes, DID, Approval JWS, Execution Receipt JWS, and HTTP request signature with
its exact signature base. Add
`conformance/http-message-signatures/mpas-v1-p256.json` and document the location
and provenance of artifact and DID fixtures in the conformance index.

| # | Requirement |
|---|---|
| TEST-01 | Conformance MUST retain existing Ed25519 vectors and add fixed positive vectors for both suites, including the existing absent-`alg` and new explicit-`alg` Ed25519 HTTP formats. P-256 signing tests MUST verify fresh signatures rather than compare them with a single fixture signature. |
| TEST-02 | At least one committed ES256 vector MUST be verified through an independent implementation or tool path, not solely generated and consumed by the same MPAS helper. Record tool/version, input bytes, encoding conversions, and a reproducible command or script. CI MUST exercise the recorded independent check. |
| TEST-03 | Automated negative tests MUST cover malformed keys and signatures, private material in DIDs, unsupported curves and algorithms, missing or conflicting algorithm identifiers, unauthorized keys, and attempts to override suite selection. The full HTTP verification matrix, unknown signing-suite configuration, and rejection of verifier-side suite disablement MUST be tested. |
| TEST-04 | Integration tests MUST cover a mixed-suite workflow through authenticated submission, Approval verification, and receipt verification, plus public-only verification and non-exporting signing providers. Existing Ed25519 tests and authorization/replay protections MUST continue to pass. |

Minimum negative cases include `none`; ES256 with Ed25519; EdDSA or ES256K with
P-256; unknown HTTP/JWS algorithms; missing, malformed, short, or oversized
coordinates; compressed P-256 points; invalid EC points; private `d` in a DID;
DER ECDSA wire signatures; truncated or oversized signatures; missing or
unauthorized `kid`; invalid local private keys; tampered signed payloads; and
unknown signing-suite configuration. Test an Ed25519 signature whose `alg`
parameter was removed after signing: claimed `ed25519` still applies, but the
signature base no longer matches, so verification MUST fail.

Acceptance requires every numbered requirement above to map to a test or a
specific documentation/configuration change, with evidence recorded in the plan.

## 10. Compatibility and Rollout

1. Deliver dual-suite verifiers, Credential Adapters, relay services where used,
   and Coordination Services. New senders include `alg`. Verifiers treat absent
   HTTP `alg` as claimed `ed25519` without rewriting the signature base.
2. Confirm both-suite conformance and interoperability before registering or
   using ES256 identities against those services.
3. Permit explicit P-256 identity registration and start generating ES256 where
   desired. Signing-implementation configuration selects the generated suite;
   verifiers continue to verify both.
4. Retain Ed25519 identity and artifact support. The absent-`alg` default is a
   standing HTTP rule, not a deployment switch, and does not allow a verifier to
   refuse a specified suite.

A P-256 key creates a different `did:jwk`. An existing participant must explicitly
rotate or register its identity and update the relevant trust configuration;
there is no private-key migration that preserves its Ed25519 DID.

Repository implementation and reproducible local integration are the scope of
the execution plan. Publishing packages, registering live identities, and
deploying downstream services are operational rollout actions; record their
readiness and actual status separately from local validation.

## 11. References

- [Issue #78](https://github.com/oma3dao/mpas/issues/78)
- [Issue #56](https://github.com/oma3dao/mpas/issues/56) and its [scope clarification](https://github.com/oma3dao/mpas/issues/56#issuecomment-5376180268)
- [RFC 7518 §3.4 — ECDSA signatures](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)
- [RFC 7518 §6.2.1 — EC public key coordinates](https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1)
- [RFC 7515 §5.1 — JWS signing input](https://www.rfc-editor.org/rfc/rfc7515#section-5.1)
- [RFC 9421 §3.3.4 — P-256 HTTP signatures](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3.4)
- [RFC 9421 §7.3.5 — Nondeterministic signature primitives](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.3.5)
- [Existing authentication specification](../auth/spec.md)
