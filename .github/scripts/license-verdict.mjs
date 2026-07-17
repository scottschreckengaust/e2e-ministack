#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — declare
// them inline rather than widening eslint.config.mjs.)
//
// Thin CLI shim for the SPDX allow-list satisfiability verdict (#127 Leg B2).
// The `isAcceptable` logic lives in the jest-visible `license-verdict.ts` so it
// flows through the repo's 100% coverage gate (#124) + Stryker mutation (#122)
// + fuzz-regression tier; this file is only argv/exit-code plumbing. The verdict
// delegates to the vetted `spdx-satisfies` library (#222), so the poller job now
// runs `npm ci` before invoking this shim. Node 24 imports the `.ts` natively
// (stable, unflagged type-stripping — no build step), so the poller's
// `node .github/scripts/license-verdict.mjs "<expr>" "<allow,list>"` call is
// unchanged.
//
// CLI: node license-verdict.mjs "<spdx-expression>" "<allow,list,ids>"
//   exit 0 = ACCEPTABLE, exit 1 = UNACCEPTABLE, exit 2 = usage error.
// The allow-list is an argument, not a constant: the single source of truth
// is security.yml's `allow-licenses:` value, extracted at runtime by the
// caller (license-review-poller.yml).
import { isAcceptable } from './license-verdict.ts';

const [expression, allowList] = process.argv.slice(2);
let acceptable;
try {
  acceptable = isAcceptable(expression ?? '', allowList ?? '');
} catch (err) {
  console.error(`usage error: ${err instanceof Error ? err.message : err}`);
  console.error(
    'usage: license-verdict.mjs "<spdx-expression>" "<allow,list,ids>"',
  );
  process.exit(2);
}
console.log(
  `${acceptable ? 'ACCEPTABLE' : 'UNACCEPTABLE'}: ${JSON.stringify(
    expression ?? '',
  )}`,
);
process.exit(acceptable ? 0 : 1);
