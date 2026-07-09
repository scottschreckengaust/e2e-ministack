#!/usr/bin/env bash
# Accept a new integ-runner snapshot baseline (deploy + assertions on MiniStack).
# Requires MiniStack running and the same AWS env as cdk deploy (see AGENTS.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${AWS_ENDPOINT_URL:?Set AWS_ENDPOINT_URL (see AGENTS.md)}"
: "${AWS_ENDPOINT_URL_S3:?Set AWS_ENDPOINT_URL_S3 (see AGENTS.md)}"
: "${CDK_DEFAULT_ACCOUNT:?Set CDK_DEFAULT_ACCOUNT}"
: "${CDK_DEFAULT_REGION:?Set CDK_DEFAULT_REGION}"

npm run build

exec npx integ-runner \
  --directory integ \
  --parallel-regions us-east-1 \
  --update-on-failed \
  --disable-update-workflow \
  "$@"
