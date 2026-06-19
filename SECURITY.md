# Security Policy

## Scope

`e2e-ministack` is a **demo / reference project**. It exercises an AWS CDK
(TypeScript) stack against the [MiniStack](https://github.com/ministackorg/ministack)
local emulator entirely on a laptop or in CI. It is **not intended for
production use** and deploys **no real cloud infrastructure** — there is no AWS
account, no live endpoint, and no data behind it.

Please keep that context in mind when assessing impact: a finding here is
educational (it teaches a pattern worth fixing) rather than a live exposure.

## Supported versions

Only the `main` branch is maintained. There are no release branches or
backports.

| Version         | Supported |
| --------------- | --------- |
| `main` (latest) | ✅        |
| Older commits   | ❌        |

## Reporting a vulnerability

**For sensitive findings, please use GitHub Private Vulnerability Reporting
(PVR):** go to this repository's **Security** tab and choose **"Report a
vulnerability"**. This opens a private advisory visible only to the maintainer,
so you can share details without disclosing them publicly.

> [!NOTE]
> If the "Report a vulnerability" button is not visible, PVR has not yet been
> enabled. Maintainer: enable it under **Settings → Code security → Private
> vulnerability reporting**.

For **non-sensitive** issues (a hardening suggestion, a misconfiguration that
isn't exploitable, a question about the security tooling), opening a regular
[issue](https://github.com/scottschreckengaust/e2e-ministack/issues) is fine and
preferred — it keeps the discussion in the open where it's most useful for a
reference repo.

Please do **not** report security issues that you believe are sensitive in
public issues, pull requests, or discussions.

## Response expectations

This is a personal reference project maintained on a best-effort basis. There is
**no service-level agreement (SLA)** and no guaranteed response time. Reports are
reviewed when time allows; thanks in advance for your patience and for
disclosing responsibly.

## Existing security tooling

This repo already runs a layered set of automated checks in CI (see
[`README.md`](README.md) and the
[`security.yml`](.github/workflows/security.yml) workflow): cdk-nag, ESLint,
checkov + cfn-lint, npm audit, OSV-Scanner, Grype, Semgrep, CodeQL, Gitleaks,
zizmor + actionlint, and a hand-authored
[threat model](threat-model.tc.json). SARIF results surface in the GitHub
**Security** tab.

This policy closes the loop: the scanners catch what they can, and the channel
above is for reporting what they miss.
