# Implementation Plan: MPAS Signature Suites and ES256/P-256

**Status:** Complete (repository implementation and local validation)
**Spec:** [spec.md](./spec.md)
**Issue:** [#78](https://github.com/oma3dao/mpas/issues/78)
**Related:** [#56](https://github.com/oma3dao/mpas/issues/56)
**Created:** 2026-09-08

---

## 1. Execution Model

This plan is intended for one implementation prompt carried through from start
to finish. Phases are progress checkpoints, not separate assignments, approval
gates, or reasons to stop. When implementation is requested, execute each phase
in dependency order, resolve ordinary implementation choices, run its checks,
record evidence, and continue automatically to the next phase.

Implementation was authorized after review of the revised specification.
All checkpoints below are complete; evidence and operational rollout actions are recorded in §6.

If #56's shared signer contract is absent, implement the minimal common contract
in Phase 2 as part of this run. Do not wait for a separate issue or implement a
competing provider system. If it exists, adapt and reuse it.

Keep the checklist and final evidence current. Stop only for a genuine blocker
that cannot be resolved within the agreed scope, and identify precisely what
remains. Do not mark a failed or unexecuted check complete.

## 2. Scope and Constraints

- Work in the local `wivity/mpas` checkout. Its fork remote is `signerset/mpas`
  and upstream is `oma3dao/mpas`; preserve the existing remote configuration.
- Implement all repository changes, tests, conformance fixtures, documentation,
  and reproducible local integration needed by the feature specification.
- Preserve Ed25519 as a supported baseline and existing identities byte-for-byte.
- Preserve artifact schemas, authorization semantics, and HTTP replay controls.
- Add only the two specification-approved suites. Do not add a runtime crypto
  plugin registry or platform-specific signer providers.
- Keep production publishing, downstream deployment, and live identity
  registration distinct from repository completion. Document the rollout order
  and remaining operator actions without claiming they were performed.

---

## Phase 0: Establish the Baseline and Impact Map

- [x] Read applicable repository instructions, inspect the worktree, and preserve
  unrelated changes. Confirm the working branch and current dependency versions.
- [x] Inspect the current state of #56's code and record whether the shared
  contract will be reused or introduced here. The approved minimal contract is
  sufficient; provider expansion is not a prerequisite.
- [x] Inventory algorithm assumptions in SDK source and exports, demo wrappers
  and services, CLI/config validation, bridge-generator templates, tests, guides,
  and Core/HTTP requirement summaries.
- [x] Identify every receipt verification consumer and every caller of compact
  JWS or raw signing; include internal helpers that currently import keys using
  an incoming `alg`.
- [x] Run the existing SDK, demo, and generator validation commands from §4 and
  record any pre-existing failures before editing implementation code.
- [x] Record existing Ed25519 DID and HTTP fixture bytes as regression baselines;
  preserve the committed fixtures throughout implementation.

**Checkpoint:** A concrete impact map and baseline are recorded. Proceed to
normative changes without requiring another prompt.

## Phase 1: Update the Normative Specifications

**Areas:** `specs/mpas-specification.md`, `specs/mpas-profile-http.md`, related
authentication documentation.

- [x] Replace the brief algorithm recommendation with the complete two-suite
  table, mandatory verification of both suites, and signing-implementation
  suite selection (SUITE-01–05). Verifiers MUST NOT be configurable to reject a
  specified suite.
- [x] Define complete P-256 key validation and minimal `did:jwk` derivation;
  preserve existing Ed25519 derivation and exact DID comparison (KEY-01–07).
- [x] Specify protected `alg`/authorized `kid`, raw 64-byte ECDSA encoding,
  rejection behavior, and common Approval/receipt rules (JWS-01–05).
- [x] Define both HTTP algorithm bindings, signed `alg` for new senders, and
  the absent-`alg` claimed-algorithm default of `ed25519` without rewriting the
  signature base (HTTP-01–04).
- [x] Update repeated rules, examples, appendices, conformance summaries, and
  the existing ES256K recommendation so they agree with the closed suite set.
- [x] Update `docs/features/auth/spec.md`, `plan.md`, and `decisions.md` where
  necessary to identify superseded algorithm guidance, preserving historical
  completed-work context rather than pretending old vectors used the new format.

**Checkpoint:** Core, HTTP, and related guidance agree with the feature spec.
Record changed sections and continue.

## Phase 2: Centralize Suites and Establish the Shared Signer

**Areas:** New suite/shared-signer modules, `key-manager.ts`, `did-jwk.ts`, SDK
exports and tests.

- [x] Add a closed suite module with key validation, normalization, algorithm
  bindings, exact raw signature encoding, and fail-closed key-to-suite resolution.
- [x] Use vetted crypto APIs for EC point/scalar validation and signature
  operations. Keep algorithm-specific handling inside suite/local-provider code.
- [x] Separate strict public-only validation from trusted local private-key
  import/projection; preserve private-input DID-derivation compatibility where
  needed without allowing private material in a received DID or public export.
- [x] Add tests for coordinate encoding/length, invalid points, private scalar
  validity and public/private mismatch, optional metadata, and unknown suites.
- [x] Generalize DID decoding and minting for both suites. Preserve Ed25519
  helpers and add an explicit P-256 key generator with the same result shape.
- [x] Reuse or introduce the shared signer contract aligned with #56: public
  identity, authorized key identifier, closed algorithm metadata, compact-JWS
  signing, and raw-byte signing. Document full-message versus digest semantics.
- [x] Implement the required `sdk/protocol/src/lib/` modules from SIGN-05.
  `KeyManager` MUST use the suite and signer modules for both suites, preserving
  existing method names, aliases, and public-only verification behavior by
  routing them through that shared implementation. Do not keep a parallel
  Ed25519-only path.
- [x] Add an opaque test signer that exposes no private JWK or export operation.
  Exercise both signing capabilities and reject inconsistent identity/algorithm
  metadata. Any provider-internal DER conversion stays behind the contract.
- [x] Prove Ed25519 DID generation and existing API examples still work; test
  P-256 software import/generation and public-only signing rejection.
- [x] Export only the supported public types/helpers needed by consumers; review
  both root exports and package subpath exports.

**Checkpoint:** Both suites work through one validation source and one shared
signer contract. SDK unit checks pass before migrating protocol consumers.

## Phase 3: Migrate Artifact Signing and Verification

**Areas:** `approval-builder.ts`, `receipt-builder.ts`, `verification.ts`,
artifact consumers and tests.

- [x] Make Approval and Execution Receipt builders consume the shared signer.
  Keep existing `keyManager`/private-JWK call forms by constructing or reusing a
  local signer through `KeyManager` and the suite modules. Reject ambiguous
  new/old inputs. Do not retain a parallel Ed25519-only signing path.
- [x] Remove direct EdDSA receipt-signing assumptions from the common path.
- [x] Centralize JWS verification so the key-derived algorithm is checked before
  import/verification; cover `verifyApprovalSignature`, bundle validation, and
  internal verified-payload helpers.
- [x] Add or generalize receipt verification at the existing consumer boundary;
  use the same suite checks and enforce issuer/key authorization and expected
  receipt payload bindings. Do not treat cryptographic validity alone as receipt
  authorization.
- [x] Require protected `alg` and authorized `kid`; test missing headers,
  mismatched key IDs, `none`, unknown algorithms, ES256K, and cross-suite confusion.
- [x] Test raw ECDSA length/scalar rules and rejection of DER wire signatures.
- [x] Test identical canonical payload bytes for identical fields regardless of
  suite, and retain all signed/top-level Approval and receipt binding checks.
- [x] Exercise Approval and receipt generation with the opaque signer, and verify
  both artifacts without any private-key access.
- [x] Retain existing Approval counting, rejection, expiry, and policy tests;
  include mixed-suite eligible signers without changing threshold semantics.

**Checkpoint:** Both artifacts can be signed and verified with either suite,
including non-exporting signers. Relevant SDK artifact tests pass.

## Phase 4: Generalize HTTP Signing and Policy

**Areas:** `rfc9421.ts`, Coordination/Action/relay clients and service integration.

- [x] Adapt the RFC 9421 signer surface to the shared contract without creating
  another provider abstraction. Preserve existing usable Ed25519 signer call
  forms by deriving missing metadata from their DID where safe.
- [x] Include suite-derived `alg` in newly signed signature parameters and ensure
  it is covered by the signature base for both suites.
- [x] Resolve verification behavior from the public key in `keyid`, enforcing
  exact algorithm binding and raw signature encoding.
- [x] Add explicit, validated signing-suite selection for key generation and
  newly created signatures. Signing config selects Ed25519 (default) or P-256.
  Verifiers always accept both suites. Absent HTTP `alg` is claimed `ed25519`
  and MUST NOT be inserted into the reconstructed signature base; unknown
  signing-suite names fail validation. There is no verifier-side suite
  allow-list.
- [x] Thread signing-suite selection and the absent-`alg` default through
  consumers and service configuration without allowing a verifier to disable a
  specified suite.
- [x] Test every verification-matrix row, unknown signing-suite configuration,
  and removal or substitution of `alg` after signing. Preserve the original
  HTTP vector.
- [x] Run existing authentication tests for digest, freshness, audience, covered
  components, signature selection, identity equality, authorization, and atomic
  nonce claiming. Add focused P-256 coverage at the same boundaries.
- [x] Exercise signed Coordination, direct Action submission, and relay client
  paths so suite support is not confined to Coordination polling.

**Checkpoint:** New senders include `alg`, absent HTTP `alg` is claimed
`ed25519` without rewriting the signature base, P-256 omission fails as a
mismatch, and all existing HTTP protections remain intact.

## Phase 5: Add Fixed Conformance Fixtures and Independent Verification

**Areas:** `conformance/`, SDK fixture tests and reproducibility scripts.

- [x] Add fixed P-256 minimal JWK/DID fixtures with exact canonical bytes and
  expected identifiers, plus compact JWS Approval and Execution Receipt fixtures.
- [x] Add `conformance/http-message-signatures/mpas-v1-p256.json` with the public
  key, request/body bytes, signed parameters, exact signature base, raw signature,
  and expected verification outcome.
- [x] Add a separate new-format Ed25519 HTTP fixture containing signed `alg`;
  retain `mpas-v1-ed25519.json` unchanged for absent-`alg` verification.
- [x] Document fixture generation and test-key provenance. Commit only explicit
  test keys, never operational participant keys.
- [x] Implement an independent verification check for at least one ES256 vector
  using OpenSSL or another suitable implementation path. Record versions and
  commands, and any raw/DER conversion needed by that tool; MPAS wire verification
  must still reject DER. Do not use the MPAS helper to check its own vector.
- [x] Assert byte-for-byte DID, payload, and signature-base results. Verify fresh
  ECDSA signatures cryptographically instead of expecting fixture-byte equality.
- [x] Cover the full malformed-key, algorithm-confusion, unauthorized-key,
  signature-encoding, unknown signing-suite, and HTTP verification negative
  matrix.
- [x] Update conformance READMEs and map fixture/tests to feature requirement IDs.

**Checkpoint:** Fixtures are stable, existing Ed25519 vectors are unchanged, and
the independent verification command succeeds reproducibly.

## Phase 6: Update Demo, CLI, and Generated Bridges

**Areas:** `examples/demo/`, `bridge-generator/`, SDK consumer configuration.

- [x] Extend CLI key generation with an explicit P-256 choice while preserving
  the existing Ed25519 default, output shape, and missing-key failure behavior.
- [x] Update demo DID re-exports, config validation, and key loading to use shared
  suite rules rather than local Ed25519 assumptions.
- [x] Migrate adapter receipt construction and signer-server/bridge consumers to
  the common signer path, retaining existing configuration compatibility.
- [x] Review `bridge-generator/src/bridge-codegen.ts` and configuration types;
  generate and build a representative bridge against the candidate SDK.
- [x] Add focused P-256 and mixed-suite fixtures instead of replacing all demo
  keys. Verify stored DID mismatch and unavailable-key failures remain explicit.
- [x] Run a local authenticated workflow with a P-256 proposer, eligible signers
  using both suites, and a P-256 receipt issuer; verify the receipt and Action
  bindings. Keep the existing all-Ed25519 workflow passing.
- [x] Confirm a service that generates only P-256 signatures still verifies
  Ed25519 Approvals and HTTP requests, and that unknown signing-suite
  configuration fails closed.
- [x] Prove generated bridges and demo services use the candidate SDK build, not
  only an older published `@oma3/mpas` dependency. Use temporary package wiring
  or packing as needed; leave no machine-specific dependency paths committed.

**Checkpoint:** The local integration succeeds for both suites and generated
code compiles and signs through the shared implementation.

## Phase 7: Complete Documentation, CI, and Repository Validation

- [x] Update `sdk/protocol/README.md` and public API examples for suite selection,
  public-only verification, shared signers, and compatible existing calls.
- [x] Update setup/participant guides with explicit P-256 generation, mixed-suite
  operation, the absent-`alg` HTTP default, and DID rotation semantics.
- [x] Document verifier-first rollout for downstream adapters, Coordination
  Services, and relay services, including any package/version requirements.
- [x] Update `.github/workflows/ci.yml` and test runners as needed so both suites,
  positive/negative vectors, and the independent ES256 check run in required CI.
- [x] Complete the validation matrix below, fix introduced failures, and rerun
  affected checks. Keep unrelated pre-existing failures separately identified.
- [x] Review the final diff for scattered algorithm dispatch, accidental key or
  DID replacement, changes to artifact schemas, and outdated normative guidance.
- [x] Finish requirement-to-evidence mapping and record remaining operational
  rollout actions. Update plan status to complete only when repository work and
  required validation are complete.

**Checkpoint:** The full repository implementation is reviewable, tested, and
documented. Report changes, validation evidence, and actual rollout status in
the implementation run's final response.

---

## 3. Requirement Coverage

The evidence below refers to the SDK's [suite tests](../../../sdk/protocol/tests/lib/signature-suites.test.ts),
the demo's [mixed-suite integration](../../../examples/demo/tests/e2e/signature-suites.test.ts),
and the generator's [candidate-SDK integration](../../../bridge-generator/tests/signature-suites.test.ts).
Existing SDK authentication, policy, fixture, and API tests remain part of the full validation run.

| Requirements | Primary checkpoints | Evidence |
|---|---|---|
| SUITE-01, 03 | Phases 1, 2 | Frozen closed suite definitions in `signature-suites.ts`; suite tests for unsupported/malformed keys and unknown selection. Core §5.5.6.1. |
| SUITE-02, 05 | Phases 1, 4, 6 | Suite generation/public-only tests for both suites; unknown/mismatched selection tests; CLI default/explicit selection; demo rejects a verifier suite allow-list. |
| SUITE-04 | Phases 2, 3, 4 | Key-derived JWS/HTTP dispatch; suite tests reject absent, unknown, and mismatched algorithms, including correctly signed HTTP bases claiming the wrong algorithm. |
| KEY-01–03 | Phases 1, 2, 5 | Suite tests `rejects malformed/unsupported public key`, `rejects private material in a DID`, and raw/DER/scalar checks; Node/OpenSSL P-256 point validation. Core §5.1.5 DID derivation. |
| KEY-04, 05 | Phases 2, 5 | `matches fixed P-256 DID and canonical artifact vectors`, `preserves received DID metadata and exact identity without reminting`; original Ed25519 DID/HTTP fixtures unchanged. |
| KEY-06, 07 | Phases 2, 5 | `checks local private scalars, public/private consistency, and key metadata permissions`; local scalar/seed derivation, public-only exports, optional DID metadata round trip, full configured-key comparison. |
| SIGN-01, 02, 05 | Phases 2, 3, 4 | Shared `signer.ts` public identity plus compact-JWS/raw-byte capabilities, suite-local crypto, SDK root/subpath exports and README input semantics. Non-exporting Web Crypto test and independent OpenSSL input verification. |
| SIGN-03 | Phases 2, 3 | `supports non-exporting Web Crypto signing through all three protocol consumers`; provider metadata, wrong key/payload, input mutation, and DER output rejection tests. |
| SIGN-04 | Phases 2, 3 | Existing KeyManager, ApprovalBuilder, ActionPackageBuilder and receipt tests pass; both-suite public-only test and private-JWK receipt compatibility test. |
| JWS-01–03 | Phases 1, 3, 5 | Fixed Approval/receipt vectors; missing/unauthorized kid and cross-suite tests; `none`, unknown, EdDSA/ES256/ES256K mismatches; raw/DER length and scalar tests. Core §§5.5.6–5.5.6.1 and 5.9.6. |
| JWS-04 | Phases 3, 5 | Canonical payload/mixed-bundle test; Approval binding and receipt issuer, Action, payload, timestamp, result, optional-field and scoped-Action-ID tests. |
| JWS-05 | Phases 2, 3 | All builders use shared signing; opaque provider exercises Approval/receipt construction; existing private-JWK calls remain valid, including explicitly trusted non-did:jwk receipt issuers. |
| HTTP-01–03 | Phases 1, 4, 5 | All three HTTP fixtures verify; new-sender bases match exactly; absent/mismatched P-256 and mismatched Ed25519 algorithms reject; removed `alg`, DER, bad scalar and length cases reject. HTTP §4.6.2. |
| HTTP-04 | Phases 4, 6 | Existing RFC 9421/client/authentication tests pass; mixed-suite integration covers endpoint authorization, atomic nonce replay rejection, dispatch replay, and P-256 receipt verification; generated direct/relay/poll requests verify. |
| INT-01, 02 | Phases 1, 7 | Core DID/JWS/receipt sections and repeated summaries updated; HTTP §4.6.2 and examples updated; auth spec/plan/decisions identify superseded guidance while preserving history. |
| INT-03, 04 | Phases 6, 7 | SDK exports, demo key loading/config/CLI, generated bridge signing, participant/setup guides; CLI test covers explicit P-256, default Ed25519, invalid selection, no overwrite and key round trip. Existing missing/mismatched key tests pass. |
| TEST-01, 02 | Phases 5, 7 | Fixed P-256 DID/Approval/receipt/HTTP and explicit-alg Ed25519 fixtures; original fixtures unchanged; independent OpenSSL CLI verification of three ES256 signatures and tampering failures, wired into CI. |
| TEST-03, 04 | Phases 5, 6, 7 | SDK suite negatives and full HTTP matrix, mixed-suite authenticated demo, opaque/public-only signers, generated build and authenticated direct/relay paths; full package validation below. |

## 4. Validation Matrix

Run commands from their listed package directory using the supported Node
runtime and repository lockfiles. Run the baseline once; repeat checks when
changes or failures justify it, followed by the final integration validation.

| Directory | Checks |
|---|---|
| `sdk/protocol` | `npm run typecheck`, `npm run build`, `npm test` |
| `bridge-generator` | `npm run build`, `npm test` |
| `examples/demo` | `npm run typecheck`, `npm run build`, `npm test` |
| Repository conformance | Existing Ed25519 vectors, new P-256/artifact vectors, new-format Ed25519 vector, independent ES256 verification command added in Phase 5 |
| Generated bridge and local integration | Generated build/type checks and authenticated mixed-suite workflow against the candidate SDK |
| Repository root | `git diff --check`, final scope/fixture review, Markdown link and requirement coverage review |

Prefer local fixture-backed integration over live upstream services. Do not make
required conformance depend on production credentials or external signer hardware.

## 5. Definition of Done

- [x] All phase tasks are complete with concrete evidence, or any genuinely
  blocked work is explicitly reported without marking the feature complete.
- [x] Core and HTTP normatively define exactly the two supported suites.
  Verifiers MUST verify both; deployment policy selects only which suite a
  signing implementation generates.
- [x] Keys, DID derivation, artifact signatures, HTTP signatures, and callers all
  use centralized suite validation.
- [x] Shared signing supports non-exporting providers without private-JWK access
  in builders and without a competing #56 interface.
- [x] Existing Ed25519 APIs, identities, fixtures, and the absent-`alg` HTTP
  default remain supported; P-256 identity creation is explicit.
- [x] Positive, negative, independent-vector, generated-bridge, and mixed-suite
  integration checks pass against the candidate implementation and run in CI
  where specified.
- [x] Documentation is consistent, operational rollout prerequisites are clear,
  and no live deployment or package publication is implied by local completion.

## 6. Execution Evidence

Repository implementation and local validation completed on 2026-09-08 with
Node 22.23.2 and npm 10.9.8. All baseline package checks passed before code edits.
The sandbox initially denied socket-listening tests with `EPERM`; the same
commands passed with approved local-socket access. This was an environment
restriction, not a pre-existing test failure.

| Item | Result |
|---|---|
| Baseline branch/revision and pre-existing failures | `feat/es256`, `54e27d6327f0b1f1af08a160982f891ada5915b6`; origin `signerset/mpas`, upstream `oma3dao/mpas`, unchanged. No applicable AGENTS.md found. Baseline SDK 254 tests, demo 428, generator 68, with all listed builds/typechecks passing. |
| Shared signer contract and #56 alignment | No shared capability contract existed in the checkout. Introduced the approved minimal `signer.ts` contract with public metadata and two explicit capabilities; KeyManager is its local provider. No platform provider or runtime suite registry was added. |
| Impact map and receipt boundary | Crypto previously lived in KeyManager and direct `jose` imports in receipt/verification helpers. Migrated those plus DID utilities, Approval/proposer builders and RFC 9421; demo adapter/daemon/signer-server/bridge/CLI/config and generated bridges consume the SDK. No existing receipt-verification API was present; added `verifyExecutionReceipt` with trusted issuer and expected Action/payload inputs. |
| Normative sections and requirement coverage | Core DID derivation, §§5.5.6–5.5.6.1 and 5.9.6, repeated requirement summaries; HTTP §4.6.2 and wire examples; auth-history supersession notes. All numbered requirements map to evidence in §3. |
| SDK checks | `npm run typecheck`, `npm run build`, `npm test`: **32 files / 299 tests passed**. Includes 45 new suite tests. Final SDK run includes provider-input isolation and receipt/HTTP review additions. |
| Demo checks | `npm run typecheck`, `npm run build`, `npm test`: **54 files / 430 tests passed**. Mixed-suite and receipt tests rerun against the final SDK build after the last shared-signer change. |
| Generator checks | `npm run build`, `npm test`: **7 files / 69 tests passed**. Generated candidate-SDK build/signature integration rerun after the last shared-signer change. |
| Fixed vectors and independent verifier/version | `node conformance/signature-suites/verify-openssl.mjs`: **passed**, OpenSSL 3.6.3 (9 Jun 2026). Independently verifies Approval, receipt and HTTP signatures and rejects altered inputs; raw-to-DER conversion only for OpenSSL's CLI interface. Provenance and reproduction in conformance README. Original Ed25519 fixture files have no diff against baseline. |
| Candidate SDK integration and generated bridge | SDK candidate `0.1.0-alpha.13`; demo uses portable `file:../../sdk/protocol` dependency and matching lockfile. Generated bridge test compiles actual emitted TypeScript against the built candidate, verifies direct/relay submission and relay polling signatures. Demo integration executes a fixture MCP tool with P-256 proposer/issuer and Ed25519 plus P-256 approvers. |
| Final diff and documentation review | `git diff --check` passed; local Markdown target review passed; demo `npm ci --dry-run --ignore-scripts --offline` passed; obsolete normative suite rules removed/superseded; crypto dispatch centralized; artifact schemas and operational participant keys unchanged. SDK, demo and generator README/API/setup instructions updated. |
| Downstream release/deployment readiness and remaining actions | Candidate and generated dependency version prepared, **not published**. Maintainers must review/release the SDK before registry installation of generated packages, deploy dual-suite verifiers/adapters/Coordination/relay services, then explicitly register or rotate P-256 identities. No package publication, production deployment, or live identity registration performed. Ed25519 support and the standing absent-HTTP-alg default remain. |
