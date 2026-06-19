<div align="center">

# 🪐 e2e-ministack

**End-to-end AWS CDK testing — no cloud account, no bill, no waiting.**

Deploy a real CDK stack and run integration tests against it entirely on your laptop (or in CI), using [MiniStack](https://github.com/ministackorg/ministack) as a local AWS emulator.

[![CI](https://github.com/scottschreckengaust/e2e-ministack/actions/workflows/ci.yml/badge.svg)](https://github.com/scottschreckengaust/e2e-ministack/actions/workflows/ci.yml)
[![Security](https://github.com/scottschreckengaust/e2e-ministack/actions/workflows/security.yml/badge.svg)](https://github.com/scottschreckengaust/e2e-ministack/actions/workflows/security.yml)
![AWS CDK](https://img.shields.io/badge/AWS_CDK-2.260-FF9900?logo=amazonaws&logoColor=white)
![Node](https://img.shields.io/badge/node-24-339933?logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

## ✨ What you get

- 🏗️ A minimal **CDK stack** (TypeScript): two S3 buckets + a Node.js 24 Lambda. The data bucket (`cdk-demo-bucket`) is what tests read/write; the second bucket (`cdk-demo-log-bucket`) just receives its server access logs to satisfy the access-logging security rules (cdk-nag `AwsSolutions-S1` / checkov `CKV_AWS_18`).
- 🧪 **Jest integration tests** that hit the _deployed_ resources through the AWS SDK v3 — not mocks.
- 🐳 **MiniStack** standing in for AWS locally: `bootstrap` → `deploy` → `test` → `destroy`, on port `4566`.
- 🤖 A **GitHub Actions workflow** that runs the exact same loop on every push.

## 🗺️ How it fits together

```mermaid
flowchart LR
    subgraph dev["🧑‍💻 Runner / laptop"]
        CDK["AWS CDK CLI<br/>(TypeScript app)"]
        JEST["Jest + AWS SDK v3"]
    end
    subgraph ms["🐳 MiniStack :4566"]
        CFN["CloudFormation"]
        S3["S3 data bucket<br/>cdk-demo-bucket"]
        LOG["S3 access-log bucket<br/>cdk-demo-log-bucket"]
        LAM["Lambda<br/>cdk-doubler"]
    end
    CDK -- "bootstrap + deploy" --> CFN
    CFN -- provisions --> S3 & LOG & LAM
    S3 -. "server access logs" .-> LOG
    JEST -- "invoke / put / get" --> LAM & S3
    LAM -. "runs in a sibling<br/>Docker container" .-> dev
```

## 🚀 Quickstart

> [!IMPORTANT]
> Requires **Docker** (Linux host) and **Node 24** (`mise install` reads [`mise.toml`](mise.toml)).

```bash
# 1️⃣ Start MiniStack (flags matter — see the table below)
docker run -d --name ministack --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e LAMBDA_EXECUTOR=docker -e MINISTACK_RDS_PUBLIC_ENDPOINT=1 -e MINISTACK_HOST=localhost \
  ministackorg/ministack:full@sha256:c5ce466eb2e73b5f3af86a5a1aea780c1e8fcf8f04ec0e2042a5cf759d6dcdd3

# 2️⃣ Point the AWS toolchain at MiniStack (both endpoint vars required)
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ENDPOINT_URL_S3=http://localhost:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=us-east-1

# 3️⃣ Build, fast unit checks, deploy, integration test
npm ci
npm run build
npm run test:unit          # synth-only — no emulator needed
npm run bootstrap
npm run deploy
npm run test:integration
```

> [!NOTE]
> The `CDK_DEFAULT_ACCOUNT`/`CDK_DEFAULT_REGION` exports above are belt-and-suspenders only — the app pins the MiniStack account/region unconditionally in [`lib/env.ts`](lib/env.ts), so it never deploys to a real account even if your shell has live AWS credentials.

```console
PASS test/integration/integration.test.ts
  ✓ invokes the deployed Lambda and gets the doubled value
  ✓ round-trips an object through the deployed S3 bucket
```

## 📦 npm scripts

| Script                     | Does                                                       |
| -------------------------- | ---------------------------------------------------------- |
| `npm run build`            | `tsc` compile                                              |
| `npm run bootstrap`        | `cdk bootstrap` the `CDKToolkit` stack into MiniStack      |
| `npm run deploy`           | `cdk deploy --require-approval never`                      |
| `npm run test:unit`        | Fast: Lambda logic + CDK assertions/snapshot (no emulator) |
| `npm run test:integration` | Jest + AWS SDK against deployed MiniStack resources        |
| `npm run test:e2e`         | Placeholder for a real-account stage (skipped)             |
| `npm run test:mutation`    | Stryker mutation testing of the Lambda logic (gate: >=80%) |
| `npm run fuzz`             | jazzer.js coverage-guided fuzzing (see `fuzz/README.md`)   |
| `npm run destroy`          | `cdk destroy --force`                                      |

Reset MiniStack state between runs (cheaper than restarting): `curl -X POST http://localhost:4566/_ministack/reset`

## 🧩 Project layout

```text
bin/app.ts                 # CDK entrypoint (fixed account/region)
lib/ministack-stack.ts     # the stack: two S3 buckets (data + access-log) + Lambda
lambda/index.js            # function under test (doubles event.n)
test/unit/                 # Lambda logic + CDK assertions/snapshot (no emulator)
test/integration/          # Jest + AWS SDK v3, points at AWS_ENDPOINT_URL
test/e2e/                  # placeholder for a real-account stage
.github/workflows/         # CI: unit → bootstrap → deploy → integration loop
```

### 🧪 Test pyramid

| Tier            | Needs                      | Speed   | Here                                                                |
| --------------- | -------------------------- | ------- | ------------------------------------------------------------------- |
| **Unit**        | nothing (pure synth)       | ms      | Lambda logic + CDK fine-grained assertions + full-template snapshot |
| **Integration** | MiniStack (local emulator) | seconds | AWS SDK against deployed resources                                  |
| **E2E**         | a real AWS account         | minutes | placeholder (skipped) — real deploy + smoke/CSPM                    |

## ⚠️ Gotchas worth knowing

These were learned by running it, not from docs — the defaults bite in non-obvious ways:

| Gotcha                                                         | Why / fix                                                                                                                                        |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 🚫 **Not** a GH Actions `services:` container                  | Lambda/ECS/RDS spawn _sibling_ Docker containers; a service container can't join the host network. Run MiniStack as a `docker run` step instead. |
| 🩺 Don't set a `curl` health check                             | The image has no `curl`/`wget` — it ships its own python `HEALTHCHECK`. A curl override goes `unhealthy` and blocks the job.                     |
| 🌐 `--network host` is required                                | Makes MiniStack's loopback the host so sibling RDS/Lambda ports resolve (Linux-only; fine on `ubuntu-latest`).                                   |
| 🔑 Set **both** `AWS_ENDPOINT_URL` _and_ `AWS_ENDPOINT_URL_S3` | Bare `cdk` (CLI ≥ 2.1000) needs the S3-specific var; S3 virtual-host addressing can't be inferred. No `cdklocal` wrapper needed.                 |
| 🪣 Avoid `autoDeleteObjects: true`                             | Its custom-resource Lambda stalls the deploy against the emulator. Use `cdk destroy` / reset.                                                    |

## 🔒 Security checks

A defense-in-depth set of gates runs in CI (see [`security.yml`](.github/workflows/security.yml)); most also run locally.

| Layer              | Tool                                      | Scope                                                          |
| ------------------ | ----------------------------------------- | -------------------------------------------------------------- |
| CDK best practices | **cdk-nag** (AwsSolutions)                | Fails `cdk synth` on violations — wired into the build         |
| Lint               | **ESLint** + typescript-eslint            | TypeScript construct code                                      |
| IaC                | **checkov** + **cfn-lint**                | Synthesized CloudFormation (`cdk.out`)                         |
| Dependencies       | **npm audit**, **OSV-Scanner**, **Grype** | Lockfile + filesystem CVEs                                     |
| SAST               | **Semgrep**, **CodeQL**                   | JS/TS source                                                   |
| Secrets            | **Gitleaks**                              | Full git history                                               |
| Actions hardening  | **zizmor** + **actionlint**               | The workflow files themselves                                  |
| Threat model       | **threat-composer**                       | `threat-model.tc.json` ([how to use](docs/THREAT-MODELING.md)) |

The stack is hardened to pass cdk-nag and checkov cleanly (TLS, encryption, least-privilege IAM, DLQ, KMS-encrypted logs). All GitHub Actions are pinned to commit SHAs with least-privilege `permissions`.

## 📚 References

- [MiniStack](https://github.com/ministackorg/ministack) — the local AWS emulator (MIT)
- [AWS CDK](https://docs.aws.amazon.com/cdk/v2/guide/home.html) · [GitHub Actions service containers](https://docs.github.com/en/actions/using-containerized-services/about-service-containers)

## 📄 License

[MIT](LICENSE) © Scott Schreckengaust
