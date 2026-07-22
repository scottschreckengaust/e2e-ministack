#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling grype-fs-gate.mjs / *-to-sarif.mjs / vex-report.mjs shims and declare
// them inline.)
//
// Thin CLI shim: derive the `npm audit` gate from its JSON output, VEX-aware
// against the canonical `.vex/` ledger (issue #295). ALL decision logic lives in
// the jest-visible `npm-audit-gate.ts` + shared `vex-ledger.ts` (both 100%
// coverage + Stryker + fuzz). This shim is ONLY argv/read/parse/write/exit — it
// holds NO logic of its own (the repo's #165 contract: `.mjs` shims are not
// coverage-instrumented, so every branch/decision must sit in a tested `.ts`
// and the shim just renders `gateResult`'s output). Node 24 strips the `.ts` on
// import — no build step.
//
// Usage:
//   node npm-audit-gate.mjs <npm-audit.json> <today> <vex1.openvex.json> [vex2 ...]
//
//   npm-audit.json  the `npm audit --json` output
//   today           ISO date (YYYY-MM-DD) for dated-revisit_by expiry; the
//                   workflow passes "$(date -u +%Y-%m-%d)". '' disables expiry.
//
// Writes the outcome to `npm-audit.outcome` (KEY=VALUE the enforce step
// `source`s) and prints BOTH the uncovered advisories (FAIL signal) AND the
// accepted-but-present ones (the transparency view — npm audit has no Security
// tab, so this log + the uploaded npm-audit.json ARE the visibility surface; an
// `affected` acceptance passes the gate but stays printed). Exit is always 0 —
// the produce → always-upload → ENFORCE pattern reads the `.outcome` later.
import { readFileSync, writeFileSync } from 'node:fs';
import { gateResult, resolveNow } from './npm-audit-gate.ts';

const [auditFile, todayArg, ...vexFiles] = process.argv.slice(2);
if (!auditFile) {
  console.error(
    'usage: npm-audit-gate.mjs <npm-audit.json> <today YYYY-MM-DD|""> <vex1.openvex.json> [vex2 ...]',
  );
  process.exit(2);
}

// Read + JSON-parse a file; a missing/invalid file degrades to `undefined` (the
// logic treats an undefined audit as fail-closed, a non-object vex doc as
// contributing nothing) — never fatal.
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

const result = gateResult(
  readJson(auditFile),
  vexFiles.map(readJson),
  resolveNow(todayArg),
);

if (result.failedClosed) {
  console.error('npm-audit-gate: no readable npm-audit JSON — failing closed');
}

// TRANSPARENCY: print every accepted-but-present advisory so an `affected`
// acceptance stays visible in the log even though it passes the gate.
if (result.covered.length > 0) {
  console.error(
    `npm-audit-gate: ${result.covered.length} advisory(ies) present but ACCEPTED by a .vex/ record (visible, not gating):`,
  );
  for (const { pkg, ids } of result.covered) {
    console.error(`  - ${pkg} [${ids.join(', ')}]`);
  }
}

if (result.outcome === 'success') {
  console.error(
    `npm-audit-gate: 0 uncovered advisories (${result.acceptedCount} active VEX-accepted id(s)) — PASS`,
  );
} else if (!result.failedClosed) {
  console.error(
    `npm-audit-gate: ${result.uncovered.length} advisory(ies) NOT covered by any active .vex/ record — FAIL:`,
  );
  for (const pkg of result.uncovered) console.error(`  - ${pkg}`);
}

writeFileSync('npm-audit.outcome', `outcome=${result.outcome}\n`);
process.exit(0);
