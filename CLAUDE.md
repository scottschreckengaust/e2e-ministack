# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`e2e-ministack` — a minimal **AWS CDK (TypeScript) app exercised by end-to-end integration tests against [MiniStack](https://github.com/ministackorg/ministack)**, a free local AWS emulator (LocalStack alternative, port 4566). A trivial stack (an S3 bucket + a Node.js Lambda) is deployed into MiniStack with `cdk deploy`, then Jest tests invoke the deployed resources through the AWS SDK. The whole loop runs locally and in CI with no real AWS account.

## Commands

Node is pinned to 24 via `mise.toml` (`mise install` to set up). MiniStack must be running before bootstrap/deploy/test.

```bash
# 1. Start MiniStack (see "Why these flags" below — all are required for
#    Lambda/RDS/ECS to work):
docker run -d --name ministack --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e LAMBDA_EXECUTOR=docker -e MINISTACK_RDS_PUBLIC_ENDPOINT=1 -e MINISTACK_HOST=localhost \
  ministackorg/ministack:full

# 2. Point the AWS toolchain at MiniStack (BOTH endpoint vars are required):
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ENDPOINT_URL_S3=http://localhost:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=us-east-1

npm ci                 # install (use `npm install` when changing deps)
npm run build          # tsc compile
npm run bootstrap      # cdk bootstrap aws://000000000000/us-east-1
npm run deploy         # cdk deploy --require-approval never
npm test               # jest integration tests against deployed resources
npm run destroy        # cdk destroy --force

# Reset MiniStack state between runs (faster than restarting the container):
curl -X POST http://localhost:4566/_ministack/reset

# Run a single test:
npx jest -t "invokes the deployed Lambda"
```

CI runs this same sequence — see `.github/workflows/aws-integration-tests.yml`.

## Architecture / layout

- `bin/app.ts` — CDK entrypoint; instantiates the stack with a fixed account/region (`000000000000`/`us-east-1`) so the bootstrap environment matches locally and in CI.
- `lib/ministack-stack.ts` — the stack: S3 bucket `cdk-demo-bucket` + Lambda `cdk-doubler`. **Resource names are hard-coded** so tests address them directly without reading CloudFormation outputs.
- `lambda/index.js` — the function under test (doubles `event.n`, returns `process.version`).
- `test/integration.test.ts` — Jest + AWS SDK v3 clients pointed at `AWS_ENDPOINT_URL`. Assumes `cdk deploy` already ran (the workflow deploys before testing).

## Why these flags / non-obvious constraints

These were established by running the stack, not from docs alone — don't "simplify" them away:

- **MiniStack runs as a `docker run` step, NOT a GitHub Actions `services:` container.** Lambda/ECS/RDS/ElastiCache work by MiniStack spawning *sibling* containers via the host Docker socket. A `services:` container can mount the socket but cannot join the host network, so RDS readiness probes hit the wrong loopback and the DB hangs in `creating` forever.
- **`--network host`** is what makes sibling containers reachable: MiniStack's loopback becomes the host, so the host-published ports of RDS/etc. (and `MINISTACK_RDS_PUBLIC_ENDPOINT=1`'s reported `localhost:PORT`) actually resolve. Linux-only — fine on `ubuntu-latest`.
- **`-v /var/run/docker.sock` + `LAMBDA_EXECUTOR=docker`** — required for real Lambda/RDS/ECS containers.
- **Health check: do NOT pass `--health-cmd`.** The image ships its own python-based `HEALTHCHECK` (it has no `curl`/`wget`). A `curl`-based override goes `unhealthy` (exit 127) and blocks the job. Poll `docker inspect -f '{{.State.Health.Status}}'` instead.
- **Both `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` must be set** for `cdk`. The modern bare CDK CLI (>= 2.1000) honors `AWS_ENDPOINT_URL` natively (no `cdklocal` wrapper needed), but it *requires* the S3-specific var too because S3 virtual-host addressing can't be inferred from the generic endpoint. Omitting it throws "If specifying 'AWS_ENDPOINT_URL' then 'AWS_ENDPOINT_URL_S3' must be specified".
- **No `autoDeleteObjects: true` on buckets** — that synthesizes a custom-resource Lambda that doesn't complete cleanly against the emulator and stalls the deploy. Clean up with `cdk destroy` / `_ministack/reset` instead.

## Version coupling

- `aws-cdk-lib` is pinned to **2.260.0**. Note `lambda.Runtime.NODEJS_24_X` requires >= 2.230.0 (2.220.0 and earlier lack it), so don't downgrade below that.
- `aws-cdk` (CLI) is **2.1128.0**. Post-2.179 the CLI versions diverged from the library (CLI is numbered `2.10xx.x`/`2.11xx.x`), so they are pinned independently and are not expected to match.

## Security checks

Two workflows. `aws-integration-tests.yml` lints, runs the cdk-nag synth gate, then deploys/tests. `security.yml` runs the scanners (also on a weekly cron).

- **cdk-nag (AwsSolutions)** — runs *inside* `cdk synth` (wired in `bin/app.ts` via `Validations.of(app).addPlugins(...)`, the v3 API — NOT the v2 `Aspects` API). Any unsuppressed finding fails synth. The stack is hardened to pass cleanly. Suppressions use CDK-native `Validations.of(construct).acknowledge({ id, reason })` — but note cdk-nag v3 **removed `NagSuppressions`**, and granular rule IDs containing `::` (e.g. `IAM5[Resource::arn:<AWS::Partition>:...]`) **cannot be acknowledged** (CDK reserves `::`), so such findings must be fixed structurally, not suppressed.
- **ESLint** (`npm run lint`) — flat config, typescript-eslint.
- **checkov + cfn-lint** — scan synthesized `cdk.out` templates. checkov hard-fails (43 pass / 0 fail / 1 skip). `CKV_AWS_117` (Lambda-in-VPC) is skipped via CloudFormation `Metadata` (`checkov: { skip: [...] }`) injected with `cfnFn.addMetadata(...)` — the only way to suppress on CDK-generated templates. cfn-lint's two `W` warnings (`AccessControl` legacy prop, redundant dependency) are expected and not failed on.
- **Dependency/supply-chain** — `npm audit --audit-level=high`, OSV-Scanner (lockfile), Grype (filesystem).
- **SAST/secrets** — Semgrep (`--config=auto --error`), Gitleaks (full history), CodeQL (JS/TS).
- **zizmor** — audits the workflow files themselves. To keep it clean: pin every action to a **commit SHA** (not a tag), set top-level `permissions: contents: read`, and `persist-credentials: false` on every checkout.

## Dependency notes

- `package.json` has an `overrides` forcing **`js-yaml ^4.2.0`**. The Jest/Istanbul coverage toolchain pulls `js-yaml@^3` transitively, which carries a moderate DoS (GHSA-h67p-54hq-rp68). v4 is safe here because the only consumer (`@istanbuljs/load-nyc-config`) calls `js-yaml.load()`, which still exists in v4 (only `safeLoad` was removed). `npm audit` should report 0 vulnerabilities — don't accept `npm audit fix`'s suggestion to downgrade `ts-jest`.
- The GitHub-side Dependabot "npm_and_yarn … js-yaml" updates fail because the fix lives in this override, not a direct-dep bump; that's expected, not a CI regression.

## Repository conventions

- `.remember/` is local session/memory tooling, not project code — ignore it when reasoning about the application.
