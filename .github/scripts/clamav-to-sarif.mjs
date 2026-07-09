#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// license-verdict.mjs and declare them inline rather than widening
// eslint.config.mjs.)
//
// Thin CLI shim for the clamdscan-log → SARIF converter. The parser logic lives
// in the jest-visible `clamav-to-sarif.ts` so it flows through the repo's 100%
// coverage gate (#124) + Stryker mutation (#122) + fuzz-regression tier; this
// file is only argv/read/write plumbing. Node 24 imports the `.ts` natively
// (stable, unflagged type-stripping — no build step), so the workflow call
// `node .github/scripts/clamav-to-sarif.mjs <in> <out>` is unchanged.
import { readFileSync, writeFileSync } from 'node:fs';
import { toSarif } from './clamav-to-sarif.ts';

// CLI: node clamav-to-sarif.mjs <infile> <outfile>
const [, , infile, outfile] = process.argv;
if (!infile || !outfile) {
  console.error('usage: clamav-to-sarif.mjs <infile> <outfile>');
  process.exit(2);
}
const text = readFileSync(infile, 'utf8');
writeFileSync(outfile, JSON.stringify(toSarif(text), null, 2));
