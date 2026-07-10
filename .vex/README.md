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
The `ecdsa` record targets a filesystem/lockfile surface not yet wired to a
`--vex` consumer, so it remains staged (see its note below) and is excluded from
both image-gate feeds.

## Why `not_affected` (not `affected`)

The maintainer's first instinct was `status: affected` + `action_statement`
(an honest "we accept this risk" record). **That does not suppress in either
scanner** — proven empirically at the pinned versions (Grype v0.110.0 via
`anchore/scan-action` v7.4.0; Trivy v0.70.0 via `aquasecurity/trivy-action`
v0.36.0) in **PR #160**: Grype's OpenVEX `FilterMatches` only moves
`not_affected`/`fixed` to the ignored set, and its `AugmentMatches` re-SURFACES
`affected` matches; Trivy's `pkg/vex/openvex.go` `Filter` likewise suppresses
only `not_affected`/`fixed`. So the honest, working path is **`status:
not_affected`** with a truthful justification enum, and the accepted-risk prose
in `impact_statement`. See `docs/SECURITY-TOOLING.md` § "MiniStack image scan".

## Records

### `ecdsa` (filesystem/lockfile surface — still staged)

- **`ecdsa-CVE-2024-23342.openvex.json`** — `not_affected` /
  `vulnerable_code_not_in_execute_path` for `ecdsa` (`pkg:pypi/ecdsa@0.19.2`, a
  transitive dependency of checkov pinned in
  `.github/scanner-requirements/iac.txt`). CVE-2024-23342 ("Minerva") is a
  timing side-channel in ECDSA **signing**; we only run checkov to scan local
  CloudFormation templates offline (no signing, no private keys, no
  attacker-observable timing), so the vulnerable path is unreachable. Full
  accepted-risk rationale lives in `docs/SECURITY-TOOLING.md`; see **#155**.

  Note: **Dependabot** is the surface that flags ecdsa (alert #13), and
  Dependabot does **not** read VEX — so the **API dismissal** of #13
  (`tolerable_risk`) remains the active control for that surface. This record's
  value is realized only once a VEX-consuming filesystem/lockfile scanner (#133
  Trivy over `iac.txt`, or an expanded grype filesystem scope) picks it up.

### MiniStack image base CVEs (`CVE-*.openvex.json`, #84)

51 records — one per accepted high+ CVE on the pinned MiniStack image
(`ministackorg/ministack:full@sha256:dd2cf4d…`), the union of Grype's (47) and
Trivy's (27) high+ findings from the report-only scans they replaced, plus a
newly-published CVE the Trivy DB surfaced later on the same unchanged digest (a
`.vex/` staleness add — #76). Each is
`status: not_affected` with justification
**`vulnerable_code_cannot_be_controlled_by_adversary`** — a genuine
adversary-reachability claim: MiniStack is a local-only CI emulator (binds port
4566 on loopback, ephemeral per-run container, never network-exposed, exercised
only by this repo's own CDK/SDK test traffic, not a deployed/production
artifact), so no adversary can supply crafted input reaching the vulnerable
code. The full rationale + fix state is in each record's `impact_statement`.

The `products[].@id` are **qualifier-less package purls** (`pkg:deb/debian/<name>@<version>`,
`pkg:generic/python@<version>`) — NOT the scanner's full purl. This is deliberate:
grype and trivy emit different qualifiers for the same package (grype
`?arch=amd64&distro=debian-13`, trivy `?arch=all&distro=debian-13.5`), and
[go-vex](https://github.com/openvex/go-vex) only matches when the statement's
qualifiers equal the scanned component's. A base purl matches BOTH scanners
across arch / distro-minor differences. For debian packages carrying an **epoch**,
grype keeps it in the version (`name@1:2.41-5`) while trivy strips it to a
qualifier and uses the epoch-less version (`name@2.41-5`); those records therefore
list **both** version forms as products. Verified against grype v0.110.0 (SBOM)
and trivy v0.70.0 (`trivy image <digest>`) — see `docs/SECURITY-TOOLING.md`.
Grouped by package (the record file is named for the CVE):

- **bsdutils** (1): CVE-2026-53615
- **gzip** (1): CVE-2026-41992
- **libacl1** (2): CVE-2026-54369, CVE-2026-54370
- **libattr1** (1): CVE-2026-54371
- **libc-bin / libc6 (glibc)** (3): CVE-2026-5435, CVE-2026-5450, CVE-2026-5928
- **libcares2 (c-ares)** (1): CVE-2026-33630
- **libncursesw6 (ncurses)** (1): CVE-2025-69720
- **libnode115 / nodejs** (6): CVE-2026-48615, CVE-2026-48617, CVE-2026-48619,
  CVE-2026-48930, CVE-2026-48933, CVE-2026-48937
- **libsqlite3-0 (sqlite3)** (2): CVE-2026-11822, CVE-2026-11824
- **node-brace-expansion** (4): CVE-2026-13149, CVE-2026-25547, CVE-2026-33750,
  CVE-2026-45149
- **node-minimatch** (3): CVE-2026-26996, CVE-2026-27903, CVE-2026-27904
- **node-undici** (8): CVE-2026-1525, CVE-2026-1526, CVE-2026-1528,
  CVE-2026-2229, CVE-2026-6734, CVE-2026-9697, CVE-2026-12151, CVE-2026-22036
- **perl-base** (9): CVE-2026-7017, CVE-2026-8376, CVE-2026-9538, CVE-2026-12087,
  CVE-2026-42496, CVE-2026-42497, CVE-2026-48959, CVE-2026-48961, CVE-2026-48962
- **python** (9): CVE-2026-11940, CVE-2026-11972 (no upstream fix), plus the 7
  **fixed-upstream** below.

**Fixed-upstream python CVEs (7)** — CVE-2026-3298, CVE-2026-3644,
CVE-2026-4224, CVE-2026-4786, CVE-2026-6100, CVE-2026-7210, CVE-2026-9669. A fix
exists upstream (python ≥ 3.13.13/3.13.14) but is **not yet shipped** in the
pinned image (which carries python 3.12.13, `pkg:generic/python@3.12.13`); we
don't build the image, so we can't remediate by bumping. Their `impact_statement`
carries the distinct "awaiting a MiniStack image rebuild" note + the upstream
advisory link. **Drop each of these the moment a rebuilt digest ships the
patched python** (tracked by the drift audit, #76).

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
