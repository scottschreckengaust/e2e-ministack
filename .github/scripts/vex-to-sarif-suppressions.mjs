#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// sonar-to-sarif.mjs / license-verdict.mjs and declare them inline rather than
// widening eslint.config.mjs.)
//
// Thin CLI shim for the VEX -> SARIF suppression injector. The transform logic
// lives in the jest-visible `vex-to-sarif-suppressions.ts` so it flows through
// the repo's 100% coverage gate (#124) + Stryker mutation (#122) + fuzz-
// regression tier; this file is only argv/read/write plumbing. Node 24 imports
// the `.ts` natively (stable, unflagged type-stripping — no build step), so the
// workflow call is unchanged.
//
// Usage:
//   node vex-to-sarif-suppressions.mjs <in.sarif> <out.sarif> <vex.json...>
// Exits non-zero (2) on bad args. The transform itself never throws; a
// non-empty uncovered-CVE set is REPORTED (not failed here) — the workflow's
// existing produce->always-upload->enforce gate owns the hard-fail decision.
import { readFileSync, writeFileSync } from 'node:fs';
import { injectSuppressions } from './vex-to-sarif-suppressions.ts';

const [, , infile, outfile, ...vexFiles] = process.argv;
if (!infile || !outfile) {
  console.error(
    'usage: vex-to-sarif-suppressions.mjs <in.sarif> <out.sarif> <vex.json...>',
  );
  process.exit(2);
}

const sarif = JSON.parse(readFileSync(infile, 'utf8'));
const vexDocs = vexFiles.map((f) => JSON.parse(readFileSync(f, 'utf8')));

const {
  sarif: out,
  covered,
  uncoveredCves,
} = injectSuppressions(sarif, vexDocs);
writeFileSync(outfile, JSON.stringify(out, null, 2));

console.error(
  `vex-to-sarif-suppressions: injected ${covered} suppression(s) from ${vexFiles.length} VEX doc(s); ` +
    `${uncoveredCves.length} uncovered CVE(s)${uncoveredCves.length ? ': ' + uncoveredCves.join(', ') : ''}`,
);
