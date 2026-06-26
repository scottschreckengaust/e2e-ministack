# Repo Revisit — audit prompt

You are running the **Repo Revisit** documentation & posture-consistency audit on
`{{OWNER}}/{{REPO}}` at base `{{BASE_COMMIT|origin/main}}`. Read
`.agents/skills/repo-revisit/SKILL.md` and `docs/REPO-REVISIT.md` first; they are
authoritative. Your job is to produce a **drift report**, not to fix anything.

## Operating rule (non-negotiable)

**Verify every claim against the artifact.** Never accept a summary, a prior agent's
recollection, or a doc's own prose as truth. For each claim, run a concrete ground-truth
probe (grep/read/git/gh) and record what it showed. A claim that something was
removed/changed must be checked against the file or commit.

## Steps

1. **Sync.** `git fetch` and audit against `{{BASE_COMMIT|origin/main}}` (note the commit
   SHA in the report header).
2. **Enumerate canonical sources** (SKILL §2): AGENTS.md, docs/SECURITY-TOOLING.md,
   docs/TESTING.md, docs/PINNING.md, docs/THREAT-MODELING.md, docs/REPO-REVISIT.md. Plus the
   wider scope (SKILL §3): CLAUDE.md, README.md, CONTRIBUTING.md, SECURITY.md,
   threat-model.tc.json, the workflows.
3. **For each artifact, extract its checkable claims** — file paths, symbols, counts,
   versions/digests, job names, PR/issue references, policy/license decisions.
4. **Probe each claim** (SKILL §5): grep the symbol/path, read the lockfile/`mise.toml`/
   workflow SHAs/image digests, read the actual workflow YAML, `git log`/`gh` the referenced
   PR/issue, list adopted tools/deps/actions vs. the stated policy.
5. **Classify** each with the taxonomy: ✅ accurate · ⚠️ stale · 🔁 superseded ·
   🗑️ obsolete · ❌ wrong · ➕ update-necessary. Record the probe and its result as evidence.
6. **Cross-doc duplication check** — flag any non-canonical doc that duplicates and
   contradicts its canonical owner; recommend a pointer.
7. **Emit the report** (SKILL §6): one table row per claim, then per-class counts and the
   top fixes ranked by blast radius (AGENTS.md / docs/\* drift first).

## Specific high-value probes (always run these)

- AGENTS.md "two S3 buckets" → grep bucket constructs in `lib/`; expect exactly two.
- AGENTS.md / docs/TESTING.md snapshot claims → grep `toMatchSnapshot`, check
  `test/unit/__snapshots__/` exists (the issue's regression case: the doc once _wrongly_
  said the snapshot was removed).
- "everything pinnable is pinned" → spot-check workflow `uses:` are SHAs, the MiniStack
  image is a digest, `mise.toml` is an exact patch; cross-check docs/PINNING.md.
- Pinned versions in prose (aws-cdk-lib, aws-cdk CLI, scanner versions) vs. `package.json` /
  lockfile / workflow YAML.
- Security-tooling prose vs. docs/SECURITY-TOOLING.md and the actual `security.yml` jobs.
- License/governance: list adopted tools/actions/deps and check each against the stated
  AGPL-avoidance / governance policy (the Renovate/PR #54 ↔ #80 class — a tool present that
  contradicts a documented decision).

## Output

Return the drift report as your final message (markdown). Do **not** edit docs in this run —
the fix loop (SKILL §7) is a separate, scoped follow-up. If asked to also fix, hand the
non-✅ rows to the fix loop / `resolve-open-issues` as a docs-only batch.
