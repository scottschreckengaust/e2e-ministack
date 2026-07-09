#!/usr/bin/env bash
# Run @aws-cdk/integ-runner snapshot diff for integ/*.integ.js.
# Requires `npm run build` first (runner discovers compiled *.integ.js files).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f integ/integ.ministack-stack.js ]]; then
  echo "run-integ-snapshot: run npm run build first (missing integ/integ.ministack-stack.js)" >&2
  exit 1
fi

exec npx integ-runner \
  --directory integ \
  --parallel-regions us-east-1 \
  "$@"
