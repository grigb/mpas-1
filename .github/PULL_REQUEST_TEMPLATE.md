## Risk Level

<!-- Choose one: low / medium / high / red-zone -->

**Risk:** low

## Summary

<!-- What does this PR do? Keep it brief. -->

## Testing Performed

<!-- What did you test? Manual steps, automated tests, etc. Check the commands
     you actually ran; delete the ones that do not apply. -->

- [ ] `sdk/protocol`: `npm run build && npm run docs:check && npm test && npm run typecheck`
- [ ] `bridge-generator`: `npm test && npm run build`
- [ ] `examples/demo`: `npm test && npm run typecheck && npm run build && npm run test:e2e:mcp-bridge`
- [ ] Docs updated where behavior or public API changed (`npm run docs:check` covers the SDK README)

Conformance test tools are planned but not yet available (see `conformance/`); do not claim a
conformance run in this template. No pull request runs publication or release commands
(`npm publish`, `npm dist-tag`, version bumps): releasing is maintainer-only per
`sdk/protocol/RELEASING.md`.

## CI Status

<!-- Confirm CI is green before merging. -->

- [ ] All required checks pass

## Self-Merge

<!-- If you are merging this without a second reviewer, fill out this section. Otherwise delete it. -->

- [ ] This is a self-merge
- **Reason for emergency self-merge:**
  <!-- e.g., failed build blocking work, docs correction, low-risk typo -->
- **Post-merge reviewer:** @<!-- tag someone to review after merge -->

---

### Self-Merge Policy Reference

**Allowed self-merge examples:**
- Failed build blocking work
- Low-risk typo / config fix
- Docs correction
- Dependency / security patch
- Test-only or fixture-only changes
- CI / workflow fixes that do not broaden permissions

**Never self-merge (red-zone):**
- Auth / signature verification
- Permission model or signer-group changes
- Policy engine or approval-threshold changes
- Self-approval prevention logic
- Action Package / envelope verification
- Credential Adapter dispatch behavior
- Normative protocol or profile spec changes
- Production secrets
- GitHub Actions permission changes
- Deployment credentials

---

### Labels

Apply any that fit:
`self-merged` · `emergency` · `post-merge-review-needed` · `launch-blocker` · `low-risk` · `security` · `red-zone`
