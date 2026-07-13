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
scanner** — proven empirically against the pinned Grype (`anchore/scan-action`)
and Trivy (`aquasecurity/trivy-action`) at the SHAs in `security.yml`: Grype's
OpenVEX `FilterMatches` only moves
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
