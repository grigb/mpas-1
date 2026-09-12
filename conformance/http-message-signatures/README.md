# MPAS HTTP Message Signature Fixtures

`mpas-v1-ed25519.json` fixes the original absent-`alg` MPAS v1 covered-component set, signature-parameter order, Content-Digest serialization, and Ed25519 output for a deterministic Coordination Poll request. It remains unchanged and valid: absent HTTP `alg` claims `ed25519`, without adding a parameter to the signature base.

`mpas-v1-ed25519-explicit-alg.json` covers new Ed25519 senders, which include signed `alg="ed25519"`. `mpas-v1-p256.json` covers P-256 with signed `alg="ecdsa-p256-sha256"` and a 64-byte raw `R || S` signature. Every verifier supports both suites; missing `alg` with a P-256 key is an algorithm/key mismatch.

The MPAS fixture is checked only after the independent RFC 9421 Appendix B.2.6 known-answer gate in `sdk/protocol/tests/fixtures/rfc9421-b2.6.json`. The RFC fixture detects shared signature-base defects; this fixture detects drift in the MPAS application profile.

The private key used to reproduce the MPAS fixture is the committed SDK `proposer.json` test key. Only its public JWK is repeated here.

P-256 key provenance, generation, independent OpenSSL verification, and test mapping are documented in [signature-suite conformance](../signature-suites/README.md). Compare fixed signature-base bytes, but verify fresh ECDSA signatures rather than expecting deterministic signature bytes.
