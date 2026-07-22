#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling clamav-to-sarif.mjs / vex-report.mjs shims and declare them inline.)
//
// Thin CLI shim for the `npm audit --json` → SARIF converter (issue #295). The
// transform logic lives in the jest-visible `npm-audit-to-sarif.ts` (100%
// coverage + Stryker + fuzz); this file is only argv/read/parse/write plumbing
// and holds NO logic (the #165 contract). Node 24 strips the `.ts` on import —
// no build step.
//
// Usage:
//   node npm-audit-to-sarif.mjs <npm-audit.json> <out.sarif> [vex1.json ...]
//
// The `.vex/*.openvex.json` args supply the GHSA→CVE map so a GHSA-only npm
// advisory gets a CVE-carrying ruleId that reconciles to its `.vex/` record
// (and is dismissible by vex-to-sarif-suppressions). A missing/invalid audit or
// vex file degrades to a valid empty-results / bare-GHSA SARIF — never fatal.
import { readFileSync, writeFileSync } from 'node:fs';
import { toSarif } from './npm-audit-to-sarif.ts';

const [, , auditFile, outFile, ...vexFiles] = process.argv;
if (!auditFile || !outFile) {
  console.error(
    'usage: npm-audit-to-sarif.mjs <npm-audit.json> <out.sarif> [vex1.openvex.json ...]',
  );
  process.exit(2);
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

const sarif = toSarif(readJson(auditFile), vexFiles.map(readJson));
writeFileSync(outFile, JSON.stringify(sarif, null, 2));
