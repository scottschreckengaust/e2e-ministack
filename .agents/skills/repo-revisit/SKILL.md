---
name: repo-revisit
description: Use this skill to run the recurring "Repo Revisit" documentation & posture-consistency audit — re-auditing the repo's prose and governance artifacts (AGENTS.md, README, docs/*, SECURITY.md, threat model, pinning/license claims) against the ACTUAL state of the code, config, and workflows to detect drift. Reach for it whenever the request is about checking that the docs still match reality — e.g. "audit the docs for drift," "are the docs stale," "run a repo revisit," "check that CLAUDE.md/AGENTS.md still matches the code," "verify the pinning claims still hold," "do a documentation consistency pass," or on a schedule (monthly cron / on-demand workflow_dispatch). The common thread: comparing descriptive/governance claims against ground truth and classifying each as accurate / stale / superseded / obsolete / wrong / update-necessary. Don't use it to FIX one known-wrong sentence (just edit it) or to resolve a batch of issues (use resolve-open-issues).
---

# Repo Revisit — documentation & posture drift audit

A repeatable audit that an agent runs to compare every **descriptive / governance claim**
in the repo's prose against the **actual** state of the code, config, and workflows, then
emits a **drift report** classifying each claim. It exists because this repo carries a lot
of truth _outside_ the code (`AGENTS.md`, `README.md`, `docs/*`, `SECURITY.md`, the threat
model, pinning/license statements) that drifts silently as code changes — and AI agents
treat `AGENTS.md` as ground truth, so stale prose actively misleads automation.

> The companion human-facing doc is **[docs/REPO-REVISIT.md](../../../docs/REPO-REVISIT.md)** —
> it owns the cadence, scope, taxonomy, and fix-loop narrative. This SKILL is the
> runnable runner; the doc is the policy. Keep them in sync.

---

## 1. When to run

- **Scheduled** — monthly (mirrors the weekly `security.yml` cron, but lower frequency
  since docs move slower than advisories). _Wiring a CI cron is a documented follow-up, not
  yet committed — see docs/REPO-REVISIT.md._
- **On-demand** — an agent runs this skill, or a human triggers `workflow_dispatch` once a
  workflow exists.
- **Opportunistically** — after a large refactor or a governance decision (a tool adopted,
  a pin policy changed) that several docs describe.

The **first pass is optional / documented** — running it is not required to land the
process. Execute it when convenient and file the findings.

## 2. Canonical sources (audit against ONE place per topic)

Every topic has a single source of truth. Compare claims against the canonical doc, and
flag any _other_ doc that duplicates and contradicts it as drift (prefer a pointer over a
copy). The registry:

| Topic                                                                                 | Canonical source             |
| ------------------------------------------------------------------------------------- | ---------------------------- |
| Project / build / test / security / pinning overview (agent ground truth)             | **AGENTS.md**                |
| Security & supply-chain tooling (scanners, gates, the produce→upload→enforce pattern) | **docs/SECURITY-TOOLING.md** |
| Test strategy / quality matrix                                                        | **docs/TESTING.md**          |
| Pinning inventory + update/floating policy                                            | **docs/PINNING.md**          |
| Threat model authoring + CI checks                                                    | **docs/THREAT-MODELING.md**  |
| This audit process (cadence/taxonomy/fix-loop)                                        | **docs/REPO-REVISIT.md**     |

`CLAUDE.md` is a Claude-specific _pointer_ to AGENTS.md, not a canonical source — if it
duplicates AGENTS.md content, that's drift.

## 3. Scope — artifacts to audit each pass

- `AGENTS.md` (highest priority — agents act on it as ground truth)
- `CLAUDE.md` and any other tool entrypoints (should only _point_ to AGENTS.md)
- `README.md` and any nested READMEs; `CONTRIBUTING.md`
- `docs/` — `REPO-REVISIT.md`, `SECURITY-TOOLING.md`, `TESTING.md`, `PINNING.md`, `THREAT-MODELING.md`
- `SECURITY.md` (vulnerability-disclosure policy)
- `threat-model.tc.json` (sections present + parses)
- Workflow/posture prose vs. the actual `.github/workflows/*.yml` jobs
- Pinning claims vs. actual pinned versions/digests (does "everything pinnable is pinned" still hold?)
- License/governance statements (e.g. the AGPL-tooling stance; tool/dep/action adopted vs. policy)
- In-code suppressions vs. the no-silent-suppression posture (#202 → #167): run
  `node .github/scripts/suppression-inventory.mjs` (the report-only `suppression-inventory`
  job in `security.yml`) and re-check its buckets — any **raw** hit (unregistered in-code
  suppression: `nosemgrep`, `eslint-disable`, `@ts-ignore`, `# shellcheck disable`,
  `--exclude-rule`, and — per the maintainer's binding decision — any `// Stryker disable`)
  is drift to burn down or migrate into #167; **registered** (checkov Metadata skip, gitleaks
  allowlist, dep-review license allow, `.vex/` OpenVEX records) is the tracked/allowed set;
  **wiring** (VEX-feed config, tool-defining docs) is expected.

## 4. The drift taxonomy

Classify **every** audited claim as exactly one of:

| Symbol | Class            | Meaning                                                |
| ------ | ---------------- | ------------------------------------------------------ |
| ✅     | accurate         | Claim still matches reality.                           |
| ⚠️     | stale            | Was true; the code/config moved and the doc didn't.    |
| 🔁     | superseded       | A newer decision overrides the documented one.         |
| 🗑️     | obsolete         | No longer applies at all (feature/tool gone).          |
| ❌     | wrong            | Never true, or no longer true and actively misleading. |
| ➕     | update-necessary | Code/config added something real that's undocumented.  |

## 5. How to run (the verification protocol)

**Golden rule (from the issue's first real drift case): never trust a summary, an agent's
recollection, or the doc's own prose. Verify every claim against the artifact.**

For each canonical source and audited artifact:

1. **Read the claim.** Note the asserted fact (a file path, a symbol, a version/digest, a
   job name, a count, a policy decision).
2. **Pick the ground-truth probe** and run it:
   - _Code/path/symbol claims_ → `grep`/`rg` for the asserted symbol or path; open the file.
     (e.g. "the full-template CDK snapshot was removed" → grep for `toMatchSnapshot` and
     check `test/unit/__snapshots__/`. In the issue's case the claim was **wrong** — the
     snapshot was still in use.)
   - _Version/pin claims_ → read the lockfile, `mise.toml`, workflow `uses:` SHAs, image
     digests; cross-check docs/PINNING.md.
   - _Workflow/posture claims_ → read the actual `.github/workflows/*.yml` job, not the prose.
   - _PR/issue-number references_ → `git log`/`gh` to confirm the referenced change is real
     and says what the doc claims.
   - _License/governance claims_ → list adopted tools/deps/actions and check each against the
     stated policy (e.g. the AGPL stance). Surface any tool present that contradicts a
     documented decision (the Renovate/PR #54 ↔ #80 class).
3. **Classify** with a taxonomy symbol and record evidence (the probe + what it showed).
4. **Cross-doc duplication check** — if two docs state the same topic, only the canonical one
   (§2) should; flag the duplicate as drift and recommend replacing it with a pointer.

## 6. Output — the drift report

Emit a single markdown report (to chat, or as a checklist issue / artifact). One row per
audited claim:

```markdown
### Repo Revisit — drift report (<date>, base <commit>)

| Artifact:claim             | Class | Evidence (probe → result) | Fix                    |
| -------------------------- | ----- | ------------------------- | ---------------------- |
| AGENTS.md "two S3 buckets" | ✅    | grep Bucket in lib/ → 2   | —                      |
| AGENTS.md "<some claim>"   | ⚠️    | <probe> → <reality>       | update prose / open PR |
```

End with a short summary: counts per class, and the top fixes ranked by blast radius
(AGENTS.md / docs/\* drift outranks README cosmetics because agents act on it).

## 7. Fix loop

Drift findings become checkboxes → PRs. Each non-✅ row is an action:

- **⚠️ stale / ❌ wrong / 🗑️ obsolete** → edit the doc to match reality (or delete the claim).
- **🔁 superseded** → repoint to the newer decision / canonical source.
- **➕ update-necessary** → document the undocumented behavior in its canonical source.
- **Duplication** → replace the non-canonical copy with a pointer to §2's owner.

Keep fixes scoped to docs (this is a documentation process). Batch them as one "Repo
Revisit findings" PR, or hand the checklist to the `resolve-open-issues` pipeline. After
fixes land, the report's claims should all re-classify ✅ on the next pass.

## 8. The prompt

`prompts/audit.md` is the parameterized, paste-ready prompt an agent runs to produce the
report. Edit that template, not ad-hoc copies. To run: read this SKILL, then follow
`prompts/audit.md` against the current `main`.
