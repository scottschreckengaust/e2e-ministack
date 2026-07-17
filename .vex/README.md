# `.vex/` — OpenVEX records

[OpenVEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) is a
machine-readable format for asserting, per vulnerability, whether a product is
actually **affected** by a CVE its scanners flag. A scanner that consumes VEX
can then suppress a finding we have honestly assessed as not reachable, instead
of leaving it as permanent red noise.

As of **#84** these records are **live**: the `security.yml` `ministack-image`
(Grype) and `trivy-image` (Trivy) jobs are **hard-fail, VEX-gated** and consume
the `.vex/CVE-*.openvex.json` set. The feed channel differs per scanner (neither
`--vex` accepts a bare directory): **Grype** reads them via the
`GRYPE_VEX_DOCUMENTS` env (a comma-separated file list the `anchore/scan-action`
forwards natively); **Trivy** reads them from the committed `trivy.yaml`
`vulnerability.vex` list, which trivy auto-discovers from the CWD — the
`aquasecurity/trivy-action` v0.36.0 has no `vex` input and does not forward a
`TRIVY_VEX` env, so the config file is the channel that actually loads them (see
`docs/SECURITY-TOOLING.md` § MiniStack image scan). The image gate fails on any
**new** high+ CVE not covered by a record here, and passes on the accepted set.

As of **#226** the **filesystem** SCA scans are also VEX-aware: the `grype` FS job
(hard-fail @ high) reads the whole `.vex/*.openvex.json` set via
`GRYPE_VEX_DOCUMENTS`, and `trivy-fs` (report-only) reads the same set from
`trivy.yaml`. go-vex only suppresses when a record's product purl matches the
scanned component, so each record is inert off its own surface: the image
`CVE-*` records (deb/generic purls) don't touch the FS scan, and the `ecdsa`
record (a pypi purl) suppresses only the FS finding and is excluded from the
image-gate `CVE-*` glob. This is what lit up the previously-staged `ecdsa`
record (see its note below) — it fires now because the pinned pip files were
relocated to `requirements.txt` (so grype/trivy catalog them by filename) and
the FS jobs were wired to the `.vex/` feed.

As of **#284** the `grype` FS gate is **JSON-derived and VEX-aware for BOTH
statuses**, mirroring the `ministack-image` job: the scan action runs
`fail-build: false` (SARIF still uploads to the Security tab, so findings stay
visible) and the gate is computed from grype's JSON by
`.github/scripts/grype-fs-gate.ts` — it FAILS only on a high+ finding **not
covered by any `.vex/` record** (an `affected` record is an explicit, reviewed
acceptance exactly as a `not_affected` one is). Why the change: grype's go-vex
only moves `not_affected`/`fixed` to `ignoredMatches[]`; an `affected` record
STAYS in `matches[]` (its `AugmentMatches` re-surfaces it — see below), so once
the floating DB began rating the 3 `mcp` GHSAs high, the deliberately-`affected`
`mcp` records could not suppress the finding and the **required** FS gate went
red repo-wide. The JSON gate keeps the `mcp` records honestly `affected`
(#188), still hard-fails on a genuinely-new uncovered high+, and handles
GHSA↔CVE aliasing (grype may report the GHSA with the CVE in
`relatedVulnerabilities`, or vice versa; each record names the CVE + aliases the
GHSA). The `GRYPE_VEX_DOCUMENTS`-fed SARIF is retained as the Security-tab
visibility view (a `not_affected` FS record like `ecdsa` is suppressed there; an
`affected` `mcp` record still shows — honest, just no longer gate-failing).

Beyond the CI gate, these records also drive the **GitHub Security-tab** state:
a covered CVE is surfaced as a _dismissed_ alert whose suppression is derived
from its record here, and it auto-re-opens if the record is dropped (issue #181;
`vex-to-sarif-suppressions` + `advanced-security/dismiss-alerts`, on the default
branch). See `docs/SECURITY-TOOLING.md` § "VEX → Code Scanning".

## Why `not_affected` (not `affected`)

The maintainer's first instinct was `status: affected` + `action_statement`
(an honest "we accept this risk" record). **That does not suppress in either
scanner** — proven empirically against the pinned Grype (`anchore/scan-action`)
and Trivy (`aquasecurity/trivy-action`) at the SHAs in `security.yml`: Grype's
OpenVEX `FilterMatches` only moves
`not_affected`/`fixed` to the ignored set, and its `AugmentMatches` re-SURFACES
`affected` matches; Trivy's `pkg/vex/openvex.go` `Filter` likewise suppresses
only `not_affected`/`fixed`. So the honest, working path is **`status:
not_affected`** with a truthful justification enum, and the accepted-risk prose
in `impact_statement`. See `docs/SECURITY-TOOLING.md` § "MiniStack image scan".

## Status-honesty policy — which status, when (#188)

As the gate's severity floor **ratchets down** (`high` → `medium` → `low` → …),
more base-image CVEs cross the gate and need a decision. The rule for choosing a
`status` is dictated by the OpenVEX/CISA spec — it is **not** a preference, and
it is the guardrail against blanket-suppression:

| The finding is…                                               | Honest `status`                         | Suppresses in grype/trivy? | Use it for                                                                       |
| ------------------------------------------------------------- | --------------------------------------- | -------------------------- | -------------------------------------------------------------------------------- |
| present but **adversary-unreachable** in this deployment      | `not_affected` + a `justification` enum | **yes**                    | the MiniStack image CVEs today (loopback-only, ephemeral, never network-exposed) |
| present, **reachable**, upstream **won't-fix**, risk accepted | `affected` + `action_statement`         | **no** (by design)         | a genuinely-reachable below-floor CVE we tolerate                                |
| not yet assessed                                              | `under_investigation`                   | no                         | a triage placeholder; convert once assessed                                      |
| fixed upstream / by a digest bump                             | `fixed` (or delete the record)          | yes                        | pruned by the #76 drift audit                                                    |

The five `not_affected` justification enums (only these are valid, per CISA
"Status Justifications"): `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary` (ours — CISA notes it is
"difficult to prove conclusively", so the `impact_statement` must carry the
reachability argument), `inline_mitigations_already_exist`.

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
  "action_statement_timestamp": "2026-07-14T00:00:00Z",
}
```

## Revisit cadence — `revisit_by` (#188)

OpenVEX has **no expiry field** — only `timestamp` (required), `last_updated`,
and a monotonic `version`, so a record can rot silently. To keep acceptances
**durable, not forgotten**, each record MUST carry a custom **`revisit_by`**
date + reason. `MUST`, not `MAY`: the whole point is that an acceptance is never
open-ended — an optional field would rot exactly like the bare timestamp it
replaces. This is safe to add: go-vex parses records with the Go stdlib
`json.Unmarshal` (no `DisallowUnknownFields`), so an unknown top-level key is
ignored by both scanners while remaining readable by humans and the #76 drift
audit. The `affected` path also has the spec-native
`action_statement_timestamp` for the same purpose.

Every record needs an authorable revisit trigger, so `MUST` is a real bar, not
an aspiration: the `not_affected` **image** CVEs revisit **on the next digest
bump** (`revisit_by: "wait-for-image-rebuild"`) — when the image changes, the
reachability claim is re-verified; a genuinely-open `affected` item revisits on
the upstream fix or a dated review. The **#76** drift audit **enforces presence**
(a record lacking `revisit_by` is flagged) and keys off `last_updated` /
`revisit_by` to force periodic re-review and prune resolved records.

Suggested `revisit_by` reason vocabulary (free text, but standardize):
`wait-for-image-rebuild` · `waiting-on-upstream-issue <url>` ·
`waiting-for-fix <advisory>` · `revisit <ISO-date>`. (Trivy also honors a
per-CVE `expired_at` + `statement` in `.trivyignore.yaml`, the only scanner with
first-class expiry — an option if a tool-enforced expiry is later wanted; grype
ignore-rules have neither.)

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

## Adding a record — the two-feed gotcha

A new image `.vex/CVE-*.openvex.json` reaches the **grype image gate**
automatically (its feed is a glob over `.vex/CVE-*.openvex.json`) and the
**suppression injector** the same way; the **grype FS gate** globs the broader
`.vex/*.openvex.json` (so it also picks up the pypi-surface `ecdsa` record).
Either way, **`trivy.yaml`'s `vulnerability.vex` is an explicit file list**, not
a glob, so a new record MUST be added there in lockstep or trivy won't see it.
Keep the feeds in sync (this is the existing #84 convention; #226 extended it to
the FS surface — the `ecdsa` record is now listed in `trivy.yaml` too).

## Records

### `ecdsa` (filesystem/lockfile surface — live as of #226)

- **`ecdsa-CVE-2024-23342.openvex.json`** — `not_affected` /
  `vulnerable_code_not_in_execute_path` for `ecdsa` (`pkg:pypi/ecdsa@0.19.2`, a
  transitive dependency of checkov pinned in
  `.github/scanner-requirements/iac/requirements.txt`). CVE-2024-23342
  ("Minerva") is a timing side-channel in ECDSA **signing**; we only run checkov
  to scan local CloudFormation templates offline (no signing, no private keys, no
  attacker-observable timing), so the vulnerable path is unreachable. Full
  accepted-risk rationale lives in `docs/SECURITY-TOOLING.md`; see **#155**.

  **Product-purl shape (non-obvious).** The record lists the **direct product
  purl** `pkg:pypi/ecdsa@0.19.2` — NOT a checkov-subcomponent form. A filesystem
  scan of the requirements file catalogs `ecdsa` as a **top-level** component, and
  go-vex only suppresses when the statement's product purl equals the scanned
  component; a `checkov → ecdsa` subcomponent statement does NOT match an FS scan
  (verified against both grype and trivy). #226 reshaped the record from the
  subcomponent form to this direct-product form for exactly this reason.

  **Now live (#226).** Formerly staged — this record now suppresses the `ecdsa`
  high+ finding on the VEX-aware `grype` FS gate (hard-fail) and `trivy-fs`
  (report-only), because the pinned pip files were relocated to
  `requirements.txt` (so grype/trivy catalog them by filename) and both FS jobs
  were wired to the `.vex/` feed. **Dependabot** (which does **not** read VEX)
  still flags ecdsa as alert #13, so the **API dismissal** of #13
  (`tolerable_risk`) remains the active control for THAT surface.

### `mcp` (server-transport CVEs — filesystem/lockfile surface, #226)

- **`mcp-CVE-2026-59950.openvex.json`** (GHSA-vj7q-gjh5-988w, WebSocket
  Host/Origin validation), **`mcp-CVE-2026-52869.openvex.json`**
  (GHSA-jpw9-pfvf-9f58, streamable-HTTP principal check), and
  **`mcp-CVE-2026-52870.openvex.json`** (GHSA-hvrp-rf83-w775, task-handler
  cancellation) — all `status: affected` + `action_statement` for `mcp`
  (`pkg:pypi/mcp@1.23.3`, a transitive dependency of Semgrep pinned in
  `.github/scanner-requirements/semgrep.txt`). Semgrep **hard-pins
  `mcp==1.23.3` unconditionally** in every release through the latest and bundles
  it to back the `semgrep mcp` server subcommand — it cannot be bumped without
  breaking `--require-hashes`, so this is a VEX acceptance, not a version bump
  (upstream [semgrep#11506](https://github.com/semgrep/semgrep/issues/11506)
  tracks making mcp an optional extra; open, won't-fix-soon).

  **Why `affected`, not `not_affected` (#188 status-honesty policy).** All three
  CVEs are in MCP's **server** transport, and that code IS present and loadable
  (it backs `semgrep mcp`); this repo runs semgrep only as a SAST CLI
  (`semgrep scan --config=auto`) and never starts the MCP server, so the code is
  **reachable-but-not-exercised**. Per the policy table above, a
  reachable-but-tolerated finding is honestly `affected` + `action_statement`,
  **not** `not_affected` — the guardrail is "never file `not_affected` on a
  reachable finding just to silence a scanner." Consequently these records
  deliberately do **not** suppress grype/trivy (that is the intended `affected`
  behavior); their value is being a durable, machine-readable, reviewable
  decision. Full accepted-risk rationale lives in `docs/SECURITY-TOOLING.md`;
  see **#226**.

  Note: like the `ecdsa` record above, these target a filesystem/lockfile
  surface — OSV.dev carries the advisories against `mcp`, but the grype/trivy
  DBs did not at time of writing. **Dependabot** is the surface that flags
  `mcp`, and Dependabot does **not** read VEX — the maintainer rejects a
  Dependabot dismissal here, so these records ARE the honest acceptance. Wiring
  the filesystem-surface VEX feed into a consuming scanner is tracked separately
  under **#226** (PR 2).

  **Update (#284): grype's DB now rates these three high.** When that happened,
  the deliberately-`affected` records could NOT suppress the finding (grype only
  suppresses `not_affected`/`fixed`), so the **required** Grype FS gate reddened
  on `main` and every PR. The fix (see the "As of #284" note near the top of this
  file) makes the FS gate **JSON-derived and VEX-aware for both statuses**: it no
  longer reds on any CVE covered by a `.vex/` record (an `affected` acceptance is
  as explicit and reviewed as a `not_affected` one), while still hard-failing on
  a genuinely-new uncovered high+. **These three records stay honestly
  `affected`** — the #188 status-honesty stance is unchanged; only the gate
  mechanism changed. They still show as (un-suppressed) findings in the
  Security-tab SARIF, so visibility is preserved.

### MiniStack image base CVEs (`CVE-*.openvex.json`, #84)

One record per accepted high+ CVE on the pinned MiniStack image. **The record
set IS the inventory** — `ls .vex/CVE-*.openvex.json` is the current list; the
pinned image is in `services/_registry/ministack-pin.json`. Each is
`status: not_affected` with justification
**`vulnerable_code_cannot_be_controlled_by_adversary`** — a genuine
adversary-reachability claim: MiniStack is a local-only CI emulator (binds port
4566 on loopback, ephemeral per-run container, never network-exposed, exercised
only by this repo's own CDK/SDK test traffic, not a deployed/production
artifact), so no adversary can supply crafted input reaching the vulnerable
code. Each record's `impact_statement` carries its own reachability rationale +
fix state (including any in-flight "awaiting an upstream/image fix" note).

**Purl-matching method (the non-obvious part).** The `products[].@id` are
**qualifier-less package purls** (`pkg:deb/debian/<name>@<version>`,
`pkg:generic/python@<version>`) — NOT the scanner's full purl. This is deliberate:
grype and trivy emit different qualifiers for the same package (grype
`?arch=amd64&distro=debian-13`, trivy `?arch=all&distro=debian-13.5`), and
[go-vex](https://github.com/openvex/go-vex) only matches when the statement's
qualifiers equal the scanned component's. A base purl matches BOTH scanners
across arch / distro-minor differences. For debian packages carrying an **epoch**,
grype keeps it in the version (`name@1:2.41-5`) while trivy strips it to a
qualifier and uses the epoch-less version (`name@2.41-5`); those records therefore
list **both** version forms as products.

**Reconciling after a digest bump (method).** A bump changes package versions,
so the purl in every affected record no longer matches — **a version-bearing
record must be repinned to the new version or go-vex silently stops suppressing
it** (most visible for the interpreter, `pkg:generic/python@<v>`). Procedure:

1. Scan the new digest with **every** scanner in the gate — currently **both**
   grype (`GRYPE_VEX_DOCUMENTS=…`) and trivy (`trivy.yaml` vex, auto-discovered
   from cwd) — at HIGH+ severity.
2. For each surviving high+ finding, **repin** its record to the new purl.
3. **Delete a record ONLY when ALL scanners agree** the CVE is gone or has
   dropped below the `high` floor on the new image. The gate is the grype ∪
   trivy **union**, and the two rate the same CVE differently (grype uses
   distro/vendor qualitative severity — often `low`/`negligible` for Debian
   no-fix base CVEs — while trivy leans NVD and rates them `HIGH`). Deleting on
   one scanner's say-so re-opens the gate on the other.
4. A CVE fixed upstream but not yet in the image stays as a record whose
   `impact_statement` says so; drop it when a later digest ships the fix.
5. Keep `.vex/` and `trivy.yaml`'s `vulnerability.vex` list in lockstep (a
   record count == list count parity check catches drift).

Verify BOTH scanners report **0 uncovered high+** locally before pushing; CI's
grype + trivy are the final arbiters.

## Authored date

The `timestamp` in each record is the **authored date**, set deterministically
(not `Date.now()`) so the committed artifact is reproducible.

## Drift / lifecycle (#76)

The `.vex/` set must stay in lockstep with live findings: **#76** audits it —
every record must still match a current scan finding, and resolved ones (a
digest bump that drops the CVE, or an upstream-fixed python CVE reaching the
image) are pruned. A new high+ CVE the scanners surface without a record here
fails the image gate until it is VEX-accepted (add a record) or the digest is
bumped past it.

## Cross-references

- **#84** — per-CVE OpenVEX for the MiniStack image base CVEs + the hard-fail
  flip (this section); the `ecdsa` record was the `not_affected` example #84
  built on.
- **#133** — Trivy adoption (a `--vex`-capable consumer); the report-only
  foundation this flip builds on.
- **#155** — the ecdsa accepted-risk decision + Dependabot #13 dismissal.
- **#160** — the proof that `affected` cannot suppress → `not_affected` is the
  honest working path.
- **#76** — `.vex/` drift/staleness audit.
