# `.vex/` — OpenVEX records (staged)

[OpenVEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) is a
machine-readable format for asserting, per vulnerability, whether a product is
actually **affected** by a CVE its scanners flag. A scanner that consumes VEX
can then suppress a finding we have honestly assessed as not reachable, instead
of leaving it as permanent red noise.

These files are **staged**: no scanner in this repo consumes them yet. Wiring a
VEX-aware consumer (grype's / Trivy's `--vex` input) is tracked under **#84**
(hard-fail the MiniStack image scan, base-lib CVEs accepted via OpenVEX) and
**#133** (add Trivy). Until then the records are inert documentation of intent —
they suppress nothing.

## Records

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
  Trivy, or an expanded grype filesystem scope over `iac.txt`) picks it up.

## Authored date

The `timestamp` in each record is the **authored date**, set deterministically
(not `Date.now()`) so the committed artifact is reproducible.

## Cross-references

- **#84** — per-CVE OpenVEX for the MiniStack image base-lib CVEs; this ecdsa
  record is the `not_affected` reference example #84 noted it lacked.
- **#133** — Trivy adoption (a `--vex`-capable consumer).
- **#155** — the ecdsa accepted-risk decision + Dependabot #13 dismissal.
