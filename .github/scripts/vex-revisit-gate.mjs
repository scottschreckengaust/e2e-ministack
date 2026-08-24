#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling npm-audit-gate.mjs / grype-fs-gate.mjs / vex-dialects.mjs shims and
// declare them inline.)
//
// Thin CLI shim: fail CI when a `.vex/` record does not carry a sanctioned
// `revisit_by` (issue #336). ALL decision logic lives in the jest-visible
// `vex-revisit-gate.ts` (+ `vex-ledger.ts`), which flow through the 100%
// coverage gate, Stryker and the fuzz tier. This shim is ONLY
// readdir/read/parse/write/exit — it holds NO logic of its own (the #165
// contract: `.mjs` shims are not coverage-instrumented, so every decision must
// sit in a tested `.ts` and the shim just renders the result). Node 24 strips the
// `.ts` on import — no build step.
//
// Usage: node .github/scripts/vex-revisit-gate.mjs
//
// The ledger directory is NOT an argument: a shell-expanded file list can go
// silently empty (a bad glob, a moved directory) and take the gate green with
// it, so the shim reads `.vex/` itself and the logic fails closed on an empty
// ledger. Writes the report to `vex-revisit.txt` and the verdict to
// `vex-revisit.outcome` (KEY=VALUE the enforce step `source`s), prints the report,
// and always exits 0 — the produce → always-upload → ENFORCE pattern reads the
// `.outcome` after the artifact upload.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gateResult, renderReport } from './vex-revisit-gate.ts';

const VEX_DIR = '.vex';
const SUFFIX = '.openvex.json';

// A missing/unreadable directory degrades to an empty list; the logic then fails
// closed rather than passing vacuously.
function ledgerFiles() {
  try {
    return readdirSync(VEX_DIR)
      .filter((name) => name.endsWith(SUFFIX))
      .sort()
      .map((name) => join(VEX_DIR, name));
  } catch {
    return [];
  }
}

// An unparseable record degrades to `undefined`, which the logic reports as an
// `unreadable` violation — never fatal, never silently skipped.
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

const result = gateResult(
  ledgerFiles().map((path) => ({ path, doc: readJson(path) })),
);
const report = renderReport(result);

console.log(report.trimEnd());
writeFileSync('vex-revisit.txt', report);
writeFileSync('vex-revisit.outcome', `outcome=${result.outcome}\n`);
process.exit(0);
