#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// license-verdict.mjs and declare them inline rather than widening
// eslint.config.mjs.)
//
// Thin CLI shim for the SonarQube issues → SARIF converter. The mapping logic
// lives in the jest-visible `sonar-to-sarif.ts` so it flows through the repo's
// 100% coverage gate (#124) + Stryker mutation (#122) + fuzz-regression tier;
// this file is only argv/read/write plumbing. Node 24 imports the `.ts`
// natively (stable, unflagged type-stripping — no build step), so the workflow
// call `node .github/scripts/sonar-to-sarif.mjs <in> <out>` is unchanged.
import { readFileSync, writeFileSync } from 'node:fs';
import { toSarif } from './sonar-to-sarif.ts';

// CLI: node sonar-to-sarif.mjs <issues.json> <out.sarif>
const [, , infile, outfile] = process.argv;
if (!infile || !outfile) {
  console.error('usage: sonar-to-sarif.mjs <issues.json> <out.sarif>');
  process.exit(2);
}
const response = JSON.parse(readFileSync(infile, 'utf8'));
writeFileSync(outfile, JSON.stringify(toSarif(response), null, 2));
