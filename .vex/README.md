# `.vex/` — OpenVEX records

[OpenVEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) is a
machine-readable format for asserting, per vulnerability, whether a product is
actually **affected** by a CVE its scanners flag. A scanner that consumes VEX
can then suppress a finding we have honestly assessed as not reachable, instead
of leaving it as permanent red noise.

**This file is instructions, not an inventory.** It states how to author, scope,
and retire a record, and why each rule exists. It deliberately does **not**
transcribe the current record set, counts, or per-record notes — that data lives
in the records themselves, where it cannot drift out of sync with them. To see
what is accepted right now, read the ledger:

```bash
ls .vex/*.openvex.json                     # the whole ledger IS the inventory
node .github/scripts/vex-report.mjs        # rendered view (status, justification, revisit_by)
```

## The authoring contract

**`.vex/` is the single authoring surface (#251).** You edit only the
`.vex/*.openvex.json` records; every scanner's suppression dialect is a
**generated artifact**. `.github/scripts/vex-dialects.ts` (jest-gated at 100%
coverage + Stryker + fuzz) reads the ledger and emits both `trivy.yaml`'s
`vulnerability.vex` list and `osv-scanner.toml`'s `[[IgnoredVulns]]`; a hard-fail
CI job (`vex-dialects` in `security.yml`) regenerates them and fails if the
committed files drift. Regenerate after any record change with:

```bash
node .github/scripts/vex-dialects.mjs write   # regenerate trivy.yaml + osv-scanner.toml
```

Do **not** hand-edit `trivy.yaml` / `osv-scanner.toml` — they carry a
GENERATED-FILE banner. The generator honors the SAME `SUPPRESSING_STATUSES` set
(`not_affected`/`fixed`) as the SARIF injector (imported from
`vex-to-sarif-suppressions.ts`, not re-derived), so an `affected` record never
appears in any dialect.

## What reads these records

Each surface has its own feed channel, and **no two are the same** — this is the
most common authoring mistake, because a record can be perfectly valid and still
be inert on the surface you meant it for.

| surface                     | how it receives the ledger                                                        | gate                                                      |
| --------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------- |
| grype **image** (#84)       | `GRYPE_VEX_DOCUMENTS` env, glob `.vex/CVE-*`                                      | hard-fail @ high+, VEX-gated                              |
| grype **filesystem** (#226) | `GRYPE_VEX_DOCUMENTS` env, broad glob `.vex/*`                                    | hard-fail @ **all** severities, JSON-derived (#284)       |
| trivy **image** (#84)       | **generated** `trivy.yaml` `vulnerability.vex`                                    | hard-fail @ high+, VEX-gated                              |
| trivy **filesystem**        | **generated** `trivy.yaml` `vulnerability.vex`                                    | report-only                                               |
| OSV-Scanner (#251)          | **generated** `osv-scanner.toml` `[[IgnoredVulns]]`                               | hard-fail                                                 |
| `npm audit` (#295)          | broad glob `.vex/*` for the verdict; **scoped** `.vex/npm-*` for SARIF visibility | hard-fail, JSON-derived                                   |
| GitHub Security tab (#181)  | `vex-to-sarif-suppressions` + `advanced-security/dismiss-alerts`                  | dismisses covered alerts; re-opens if a record is dropped |

Two consequences worth internalizing:

- **Neither `--vex` flag accepts a bare directory.** Grype reads `.vex/`
  natively via the env var; trivy and OSV-Scanner can only be fed through their
  generated config files. That asymmetry is why the dialect generator exists —
  it used to be hand-maintained parity, the historical "two-feed gotcha".
- **The pinned `aquasecurity/trivy-action` forwards no `vex` input and no
  `TRIVY_VEX` env**, so `trivy.yaml` (auto-discovered from the CWD) is the only
  channel that actually loads records into trivy. See
  `docs/SECURITY-TOOLING.md` § MiniStack image scan.

### Why the FS gate is JSON-derived for BOTH statuses (#284)

The grype FS scan runs `fail-build: false` (SARIF still uploads, so findings stay
visible) and the verdict is computed from grype's JSON by
`.github/scripts/grype-fs-gate.ts`, which fails only on a finding **not covered
by any `.vex/` record** — an `affected` record is an explicit, reviewed
acceptance exactly as a `not_affected` one is.

This is not a preference; it is forced. Grype's go-vex moves only
`not_affected`/`fixed` into `ignoredMatches[]`; an `affected` record STAYS in
`matches[]` (its `AugmentMatches` re-surfaces it). So the first time a floating
vuln DB rated a deliberately-`affected` acceptance as high, the **required** FS
gate went red repo-wide with no authoring error at all. The JSON gate lets a
record stay honestly `affected` (#188), still hard-fails on a genuinely-new
uncovered finding, and handles GHSA↔CVE aliasing (grype may report the GHSA with
the CVE in `relatedVulnerabilities`, or vice versa; each record names the CVE and
aliases the GHSA).

**Strictest floor — the FS ratchet is complete (#284).** Per maintainer
directive, the FS gate floor is grype's **lowest** rung: **every** severity
counts (negligible → critical). This is safe _because_ the gate is VEX-aware —
anything with a record stays accepted at any severity, so lowering the floor only
adds genuinely-uncovered findings. The floor lives in the TS gate, not grype's
`severity-cutoff`: that flag only sets grype's exit code and does **not** filter
the JSON `matches[]`/SARIF (proven empirically), so `grype-fs-gate.ts` is
authoritative; `severity-cutoff: negligible` is set on the steps for explicit
intent.

## Why `not_affected` (not `affected`)

The maintainer's first instinct was `status: affected` + `action_statement`
(an honest "we accept this risk" record). **That does not suppress in either
scanner** — proven empirically against the pinned Grype (`anchore/scan-action`)
and Trivy (`aquasecurity/trivy-action`) at the SHAs in `security.yml`: Grype's
OpenVEX `FilterMatches` only moves `not_affected`/`fixed` to the ignored set, and
its `AugmentMatches` re-SURFACES `affected` matches; Trivy's
`pkg/vex/openvex.go` `Filter` likewise suppresses only `not_affected`/`fixed`.
So the honest, working path is **`status: not_affected`** with a truthful
justification enum, and the accepted-risk prose in `impact_statement`. See
`docs/SECURITY-TOOLING.md` § "MiniStack image scan".

## Status-honesty policy — which status, when (#188)

As the gate's severity floor **ratchets down** (`high` → `medium` → `low` → …),
more base-image CVEs cross the gate and need a decision. The rule for choosing a
`status` is dictated by the OpenVEX/CISA spec — it is **not** a preference, and
it is the guardrail against blanket-suppression:

| The finding is…                                               | Honest `status`                         | Suppresses in grype/trivy? | Use it for                                                                 |
| ------------------------------------------------------------- | --------------------------------------- | -------------------------- | -------------------------------------------------------------------------- |
| present but **adversary-unreachable** in this deployment      | `not_affected` + a `justification` enum | **yes**                    | the MiniStack image CVEs (loopback-only, ephemeral, never network-exposed) |
| present, **reachable**, upstream **won't-fix**, risk accepted | `affected` + `action_statement`         | **no** (by design)         | a genuinely-reachable below-floor CVE we tolerate                          |
| not yet assessed                                              | `under_investigation`                   | no                         | a triage placeholder; convert once assessed                                |
| fixed upstream / by a digest bump                             | `fixed` (or delete the record)          | yes                        | pruned by the #76 drift audit                                              |

The five `not_affected` justification enums (only these are valid, per CISA
"Status Justifications"): `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary` (CISA notes it is "difficult
to prove conclusively", so the `impact_statement` must carry the reachability
argument), `inline_mitigations_already_exist`.

**The guardrail:** never file `not_affected` on a **reachable** finding just to
silence a scanner — that misrepresents the record. `not_affected` means "no
remediation required"; each justification is an affirmative _non-exploitability_
claim. A reachable-but-tolerated item is honestly `affected` — and since grype/
trivy only suppress `not_affected`/`fixed`, an `affected` record deliberately
does **not** quiet the scanner. Below the floor that's fine: the record's value
is being a **durable, machine-readable, reviewable** decision, so we stop
rediscovering "nothing can be done" on every push — not suppression. CISA frames
VEX as "not a discussion-ending declaration"; it "does not specify, assume, or
imply any default status", so leaving a genuinely-open finding open is correct.

**Illustrative `affected` record** (authored only when the floor drops onto a
reachable, upstream-won't-fix CVE — do **not** commit one before there's a real
finding to accept; a speculative acceptance is the blanket-VEX anti-pattern):

```jsonc
{
  "vulnerability": { "name": "CVE-YYYY-NNNNN" },
  "products": [{ "@id": "pkg:deb/debian/<name>@<version>" }],
  "status": "affected",
  "action_statement": "No upstream fix (vendor won't-fix). Reachable but accepted: <why tolerated>. Revisit on upstream release.",
  "action_statement_timestamp": "YYYY-MM-DDT00:00:00Z",
}
```

## Every record MUST carry a reason and a timeline — `revisit_by` (#188)

OpenVEX has **no expiry field** — only `timestamp` (required), `last_updated`,
and a monotonic `version`, so a record can rot silently. To keep acceptances
**durable, not forgotten**, each record MUST carry a custom **`revisit_by`**
naming a trigger and a reason. `MUST`, not `MAY`: the whole point is that an
acceptance is never open-ended — an optional field would rot exactly like the
bare timestamp it replaces.

This is safe to add: go-vex parses records with the Go stdlib `json.Unmarshal`
(no `DisallowUnknownFields`), so an unknown top-level key is ignored by both
scanners while remaining readable by humans and by the drift audit. The
`affected` path also has the spec-native `action_statement_timestamp` for the
same purpose.

**Vocabulary — pick the form that matches how the acceptance actually ends:**

| form                              | ends when                 | use for                                             |
| --------------------------------- | ------------------------- | --------------------------------------------------- |
| `revisit <ISO-date>`              | **the date passes**       | override/bundled-dep "waiting for the vendor"       |
| `wait-for-image-rebuild`          | the pinned digest bumps   | base-image CVEs, re-verified by the reconcile below |
| `waiting-on-upstream-issue <url>` | that issue resolves       | a tracked upstream defect                           |
| `waiting-for-fix <advisory>`      | that advisory ships a fix | a known-fix-pending dependency                      |

**Only the dated form self-expires.** `vex-ledger.ts` drops a record from the
active set once its embedded ISO date is on/before today, so the finding re-reds
automatically instead of rotting (`revisitDate` / `activeRecordIds`; the same
date feeds `osv-scanner.toml`'s `ignoreUntil` via `vex-dialects.ts`). The
event-token forms never expire **by design** — they wait on an event, not a
clock, and their expiry mechanism is the reconcile procedure, not the calendar.
So: if an acceptance is genuinely time-boxed, use the **dated** form, because it
is the only one a machine can nag you about.

> **Known gap — presence is NOT yet enforced.** Nothing in CI fails a record that
> omits `revisit_by`: every consumer treats it as optional (`revisit_by?:
string`, and `revisitDate`/`ignoreUntilFrom` return `undefined` for a missing
> value), so the `MUST` above is currently a convention a reviewer has to catch.
> Most existing records predate the rule and lack the field. Closing this is a
> **gate**, not more prose — see #76.

## Vendor-vs-tool severity honesty (#188)

A CVE can be scored very differently by the **vendor/NVD body** and the
**scanner's gate severity** — e.g. a glibc CVE Debian's tracker rates
_Negligible_ (driving grype's gate) while NVD scores it _9.8 / Critical_
(driving the GitHub badge). As the floor drops, these collisions multiply. When
authoring a record for such an item, the `impact_statement` / `action_statement`
MUST **state the vendor body's assessment honestly** even when the tool's gate
severity is lower — e.g. _"NVD CVSS 9.8 (Critical); Debian tracker rates
Negligible (disputed / not-a-security-bug upstream). Accepted because …"_. Do
**not** launder a vendor-Critical into a silent low: record both, and say why we
act on the lower one. This keeps the acceptance auditable and feeds the VEX
report a truthful "vendor vs tool" view: the per-push report renders the ledger
severity as `badge / gate X` whenever the scanner's distro/gate rating diverges
from GitHub's NVD-derived badge (#208, sourced from the scanners' structured
JSON via `gate-findings.*` — never SARIF-scraped).

## Prefer a fix over an acceptance

**A record is the last resort, not the first tool.** Before writing one, exhaust
the remediation paths — a version bump leaves nothing to accept, needs no
reachability argument, and cannot rot. For npm specifically see AGENTS.md
§ Dependency notes on `npm update` vs `overrides` vs an `aws-cdk-lib` rebundle;
for the pinned pip scanner closures, an entry in
`.github/scanner-requirements/overrides/` that _fixes_ the version is
categorically stronger than a record that _accepts_ the finding.

The goal state for any surface is **zero acceptances**, and the surfaces that
have reached it should stay there. Keep the gate machinery documented even when a
surface has no active record — it is still wired, and it will be needed for the
next genuinely upstream-blocked advisory.

## Adding a record

A new `.vex/*.openvex.json` reaches the surfaces per the feed table above with no
extra wiring — but **the filename prefix selects the scope**, because several
surfaces glob a subset rather than all of `.vex/`.

**Record-name prefix = surface scope.**

| prefix          | surface(s) that inject its SARIF suppression | shape of the name              |
| --------------- | -------------------------------------------- | ------------------------------ |
| `CVE-*`         | grype **image** gate + suppression injector  | `CVE-YYYY-NNNNN`               |
| `npm-*`         | **npm-audit** SARIF suppression (#295)       | `npm-<package>-CVE-YYYY-NNNNN` |
| everything else | FS surface (broad `.vex/*` glob)             | `<package>-CVE-YYYY-NNNNN`     |

This scoping is why the SAME CVE can have TWO records with DIFFERENT statuses for
DIFFERENT products without colliding — e.g. a `CVE-…` record marking a
`pkg:deb/debian/<name>` component in the emulator image `not_affected`, coexisting
with an `npm-<name>-CVE-…` record marking `pkg:npm/<name>` `affected`. The
npm-audit injection is scoped to `.vex/npm-*` precisely so a deb record's
`not_affected` can NEVER suppress (hide) an npm `affected` finding — it stays a
visible open alert, per #188.

> **Caveat — the verdict matchers are id-only, and that leaks across surfaces.**
> The grype FS gate and the generated OSV dialect match a record to a finding by
> **identifier alone, never by purl**. So an image-scoped `CVE-*` record will
> suppress a _same-CVE_ finding on the repo tree (npm/pip), on a different
> product, silently. Trivy FS is purl-precise and still reports it, which is how
> the divergence becomes visible. Until this is fixed, treat a `CVE-*` record as
> potentially broader than its purl claims.

**Product-purl shape (non-obvious).** List the **direct product purl** for the
component the scanner catalogs — NOT a parent-subcomponent form. A filesystem
scan of a requirements/lock file catalogs a transitive dependency as a
**top-level** component, and go-vex only suppresses when the statement's product
purl equals the scanned component; a `parent → child` subcomponent statement does
**not** match an FS scan (verified against both grype and trivy). So a record for
a pip transitive dep uses `pkg:pypi/<name>@<version>`, not a checkov-subcomponent
form.

After adding or removing a record, regenerate the dialects and commit the result
(the hard-fail `vex-dialects` job fails on drift):

```bash
node .github/scripts/vex-dialects.mjs write
```

## Purl-matching method (the non-obvious part)

The `products[].@id` are **qualifier-less package purls**
(`pkg:deb/debian/<name>@<version>`, `pkg:generic/python@<version>`) — NOT the
scanner's full purl. This is deliberate: grype and trivy emit different
qualifiers for the same package (grype `?arch=amd64&distro=debian-13`, trivy
`?arch=all&distro=debian-13.5`), and
[go-vex](https://github.com/openvex/go-vex) only matches when the statement's
qualifiers equal the scanned component's. A base purl matches BOTH scanners
across arch / distro-minor differences.

For debian packages carrying an **epoch**, grype keeps it in the version
(`name@1:2.41-5`) while trivy strips it to a qualifier and uses the epoch-less
version (`name@2.41-5`); such records must list **both** version forms as
products.

## The MiniStack image base-CVE class (`CVE-*`, #84)

One record per accepted CVE on the pinned MiniStack image (pinned in
`services/_registry/ministack-pin.json`). These share one class-wide
justification: **`vulnerable_code_cannot_be_controlled_by_adversary`** — a
genuine adversary-reachability claim, because MiniStack is a local-only CI
emulator (binds port 4566 on loopback, ephemeral per-run container, never
network-exposed, exercised only by this repo's own CDK/SDK test traffic, not a
deployed or production artifact), so no adversary can supply crafted input
reaching the vulnerable code.

**The class-wide claim is not a licence to skip the per-CVE one.** Each record's
`impact_statement` must still carry its own reachability rationale and fix state,
naming what the vulnerable code actually is and which precondition this
deployment fails to meet. Two CVEs in the same package are two separate
arguments.

### Reconciling after a digest bump (the procedure)

A bump changes package versions, so the purl in every version-bearing record no
longer matches — **a version-bearing record must be repinned to the new version
or go-vex silently stops suppressing it** (most visible for the interpreter,
`pkg:generic/python@<v>`). This procedure IS the expiry mechanism for every
`wait-for-image-rebuild` acceptance:

1. Scan the new digest with **every** scanner in the gate — currently **both**
   grype (`GRYPE_VEX_DOCUMENTS=…`) and trivy (`trivy.yaml` vex, auto-discovered
   from cwd) — at the gate's floor.
2. For each surviving finding, **repin** its record to the new purl.
3. **Delete a record ONLY when ALL scanners agree** the CVE is gone or has
   dropped below the floor on the new image. The gate is the grype ∪ trivy
   **union**, and the two rate the same CVE differently (grype uses
   distro/vendor qualitative severity — often `low`/`negligible` for Debian
   no-fix base CVEs — while trivy leans NVD and rates them `HIGH`). Deleting on
   one scanner's say-so re-opens the gate on the other.
4. A CVE fixed upstream but not yet in the image stays as a record whose
   `impact_statement` says so; drop it when a later digest ships the fix.
5. Regenerate the dialects and commit `trivy.yaml` + `osv-scanner.toml` — the
   `vex-dialects` CI drift-check enforces they match `.vex/` (#251).

Verify BOTH scanners report **0 uncovered** at the floor locally before pushing;
CI's grype + trivy are the final arbiters.

Note that a digest bump also invalidates the compat registry: every
`services/_registry/provisioning.json` row whose `lastVerifiedDigest` no longer
equals the new pin is re-verified by the `ministack-compat` workflow. That field
is deliberately **excluded** from `scripts/update-ministack.ts` — it is a
semantic provenance record, not a blind pin, and the workflow never edits the
registry itself.

## Lessons that outlive their records

Retired records leave behind rules worth keeping. These were each learned the
hard way, from a record that has since been deleted:

- **Delete a record when its premise becomes false — don't re-date it.** An
  `action_statement` asserting "no fixed release exists" is _wrong_, not merely
  stale, the moment one does. Deleting it ahead of its `revisit_by` window is
  correct; pushing the date out launders a false claim into a live one.
- **A "no upstream fix" / "the vendor pins it" claim is only true on the day it
  is written.** One acceptance rested on a vendor "unconditionally hard-pins this
  version in every release" claim that was true when written and **silently
  expired** when the vendor shipped a newer pin. Re-verify such a claim against
  current upstream metadata before renewing any acceptance built on it.
- **A record is keyed to ONE identifier, not to a package.** Accepting CVE-X on
  package P gives **zero** cover for CVE-Y later disclosed against the same code,
  and nothing warns you the ledger has gone partial. Before concluding a package
  is handled, enumerate **all** open advisories against it, and name the in-scope
  ids in the `impact_statement`.
- **A fix may need two halves.** Bundled copies (`inBundle: true`) are
  unreachable by npm `overrides` and need a parent bump; non-bundled copies need
  `npm update`, because `npm install` is conservative and keeps any pin that
  still satisfies its parent's range. Clearing one half looks like success to a
  partial scan.

## Authored date

The `timestamp` in each record is the **authored date**, set deterministically
(not `Date.now()`) so the committed artifact is reproducible.

## Drift / lifecycle (#76)

The `.vex/` set must stay in lockstep with live findings: **#76** audits it —
every record must still match a current scan finding, and resolved ones (a digest
bump that drops the CVE, or an upstream-fixed CVE reaching the image) are pruned.
A new CVE the scanners surface at the floor without a record here fails the gate
until it is VEX-accepted (add a record) or the pin is bumped past it. Enforcing
`revisit_by` presence (see the gap noted above) belongs to this audit.

## Cross-references

- **#84** — the design issue: per-CVE OpenVEX for the MiniStack image base CVEs +
  the hard-fail flip. Start here for the rationale behind this whole directory.
- **#76** — the recurring `.vex/` drift/staleness audit (the ongoing process that
  keeps these records in lockstep with live findings).
- **`docs/SECURITY-TOOLING.md`** — the security posture this directory serves.
