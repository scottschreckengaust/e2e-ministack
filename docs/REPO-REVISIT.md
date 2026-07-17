# Repo Revisit — documentation & posture drift audit

This repo carries a lot of **descriptive and governance truth outside the code**:
[`AGENTS.md`](../AGENTS.md), [`README.md`](../README.md), `docs/*`, [`SECURITY.md`](../SECURITY.md),
the threat model, and pinning / license statements. These drift silently as the code and
config change — and because AI agents treat `AGENTS.md` as ground truth, stale prose
**actively misleads automation**, not just humans.

**Repo Revisit** is a recurring audit that re-checks every claim in the prose against the
_actual_ state of the code, config, and workflows, classifies each as drift or accurate,
and feeds the findings into a fix loop. This page is the **single source of truth** for the
process (cadence, scope, taxonomy, fix loop). The runnable runner is the
[`repo-revisit` agent skill](../.agents/skills/repo-revisit/SKILL.md).

## Why (concrete drift already observed)

- **Stale-vs-fabricated, both at once (PR #75):** a loaded `CLAUDE.md` snapshot predated the
  two-S3-bucket change, _and_ a subagent asserted "the full-template CDK snapshot was
  removed" and wrote a draft doc to match — without checking the file. Reality on disk:
  `test/unit/stack.test.ts` still ran `toMatchSnapshot` and the snapshot file existed. The
  doc claim was **wrong**, not stale. Lesson: a claim that something was removed/changed must
  be verified against the file/commit, never taken from a summary or recollection.
- **Policy-vs-config drift (Renovate, PR #54 → #80):** the repo adopted an AGPL tool while
  the stated policy avoids AGPL tooling; config and policy disagreed for ~6 days. No existing
  gate caught it — cdk-nag/checkov scan synth output, dependency-review scans _dependency_
  licenses, and nothing ties "tool introduced in a PR" back to a documented governance
  decision. This audit is designed to surface exactly that class.

## Cadence (when it runs)

- **Scheduled** — monthly. Lower frequency than the weekly `security.yml` cron because docs
  move slower than advisories. _Wiring a CI cron (`schedule:` + `workflow_dispatch`) is a
  documented follow-up — not yet committed; see "Follow-ups" below._
- **On-demand** — an agent runs the `repo-revisit` skill, or a human triggers
  `workflow_dispatch` once the workflow exists.
- **Opportunistically** — after a large refactor or a governance decision (a tool adopted, a
  pin policy changed) that several docs describe.

The **first pass is documented / optional**: standing up the process does not require
executing a full audit. Run it when convenient and file the findings.

## Scope (artifacts audited each pass)

- [`AGENTS.md`](../AGENTS.md) — highest priority; agents act on it as ground truth.
- [`CLAUDE.md`](../CLAUDE.md) and any other tool entrypoints — should only _point_ to AGENTS.md.
- [`README.md`](../README.md), nested READMEs, [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- `docs/` — this page, [`SECURITY-TOOLING.md`](SECURITY-TOOLING.md),
  [`TESTING.md`](TESTING.md), [`PINNING.md`](PINNING.md), [`THREAT-MODELING.md`](THREAT-MODELING.md).
- [`SECURITY.md`](../SECURITY.md) — vulnerability-disclosure policy.
- [`threat-model.tc.json`](../threat-model.tc.json) — sections present + parses.
- Workflow / posture prose vs. the actual `.github/workflows/*.yml` jobs.
- Pinning claims vs. actual pinned versions/digests ("everything pinnable is pinned").
- License / governance statements (the AGPL-avoidance stance; any tool/dep/action adopted
  vs. the documented decision).
- **In-code suppressions vs. the no-silent-suppression posture** (#202, the in-code-comment
  arm of the suppression-governance program #167). Run the inventory
  (`node .github/scripts/suppression-inventory.mjs`, also the report-only
  `suppression-inventory` job in `security.yml`) and re-check its three buckets: any **raw**
  hit (an unregistered in-code suppression — `nosemgrep`, `eslint-disable`, `@ts-ignore`,
  `# shellcheck disable`, a `--exclude-rule`, and — per the maintainer's binding decision —
  any `// Stryker disable`) is drift to burn down or migrate into the #167 registry; the
  **registered** bucket (checkov Metadata skip, gitleaks allowlist, dependency-review license
  allow, the `.vex/` OpenVEX records) is the tracked/allowed set; **wiring** (VEX-feed config,
  tool-defining docs) is expected. The point is that new silent suppressions cannot accrete
  between passes without being surfaced.

## Single source of truth (canonical sources)

Each topic has **one** canonical home. Audits compare against it, and any _other_ doc that
duplicates and contradicts it is itself drift — prefer a pointer over a copy.

| Topic                                                                     | Canonical source                                  |
| ------------------------------------------------------------------------- | ------------------------------------------------- |
| Project / build / test / security / pinning overview (agent ground truth) | [`AGENTS.md`](../AGENTS.md)                       |
| Security & supply-chain tooling (scanners, gates, produce→upload→enforce) | [`docs/SECURITY-TOOLING.md`](SECURITY-TOOLING.md) |
| Test strategy / quality matrix                                            | [`docs/TESTING.md`](TESTING.md)                   |
| Pinning inventory + update / floating policy                              | [`docs/PINNING.md`](PINNING.md)                   |
| Threat-model authoring + CI checks                                        | [`docs/THREAT-MODELING.md`](THREAT-MODELING.md)   |
| This audit process                                                        | [`docs/REPO-REVISIT.md`](REPO-REVISIT.md)         |

`CLAUDE.md` is a Claude-specific _pointer_ to `AGENTS.md`, not a canonical source.

## Drift taxonomy

Every audited claim is classified as exactly one of:

| Symbol | Class            | Meaning                                                |
| ------ | ---------------- | ------------------------------------------------------ |
| ✅     | accurate         | Claim still matches reality.                           |
| ⚠️     | stale            | Was true; the code/config moved and the doc didn't.    |
| 🔁     | superseded       | A newer decision overrides the documented one.         |
| 🗑️     | obsolete         | No longer applies at all (feature/tool gone).          |
| ❌     | wrong            | Never true, or no longer true and actively misleading. |
| ➕     | update-necessary | Code/config added something real that's undocumented.  |

## Run mechanism

The runner is the [`repo-revisit` agent skill](../.agents/skills/repo-revisit/SKILL.md),
mirroring the existing [`resolve-open-issues`](../.agents/skills/resolve-open-issues/SKILL.md)
skill structure (`SKILL.md` + a `prompts/` template). An agent reads the skill, follows
[`prompts/audit.md`](../.agents/skills/repo-revisit/prompts/audit.md) against the current
`main`, and emits a **drift report** — one row per claim with the ground-truth probe, the
result, and a taxonomy class — plus per-class counts and top fixes ranked by blast radius.

The operating rule the runner enforces: **verify every claim against the artifact** (grep
the symbol/path, read the lockfile / `mise.toml` / workflow SHAs / image digests, read the
actual workflow YAML, `git log` / `gh` the referenced PR/issue) — never trust a summary or a
recollection.

## Fix loop

Each non-✅ row becomes an action:

- **⚠️ stale / ❌ wrong / 🗑️ obsolete** → edit the doc to match reality (or remove the claim).
- **🔁 superseded** → repoint to the newer decision / canonical source.
- **➕ update-necessary** → document the undocumented behavior in its canonical source.
- **Duplication** → replace the non-canonical copy with a pointer to the canonical owner.

Fixes stay scoped to docs. Batch them as one "Repo Revisit findings" PR, or hand the
checklist to the [`resolve-open-issues`](../.agents/skills/resolve-open-issues/SKILL.md)
pipeline. After the fixes land, every row should re-classify ✅ on the next pass.

## Follow-ups

- **CI cron wiring** — a scheduled `repo-revisit.yml` (`schedule:` monthly +
  `workflow_dispatch`) that runs the skill and files the report as an artifact or checklist
  issue. Deferred to keep this change scoped to the process + runner + doc.
