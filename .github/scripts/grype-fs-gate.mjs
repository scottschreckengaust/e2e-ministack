#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling *-to-sarif.mjs / vex-report.mjs / sarif-cve-ids.mjs shims and declare
// them inline.)
//
// Thin CLI shim: derive the Grype FILESYSTEM scan's gate from its JSON output,
// VEX-aware for BOTH `affected` and `not_affected` records (issue #284). Logic
// lives in the jest-visible `grype-fs-gate.ts` (100% coverage + Stryker + fuzz);
// this is only argv/read/write/exit plumbing. Node 24 strips the `.ts` on import
// — no build step.
//
// Usage:
//   node grype-fs-gate.mjs <grype.json> <vex1.openvex.json> [vex2 ...]
//
// Reads the grype JSON and every `.vex/` record, then writes the gate outcome to
// `grype-fs.outcome` (KEY=VALUE lines the enforce step `source`s) and prints the
// uncovered ids. The floor is grype's STRICTEST rung — EVERY severity counts
// (#284, "drop it the most strict") — so any finding not covered by a `.vex/`
// record fails. Coverage is SURFACE-SCOPED (#337): a record covers a finding only
// when an identifier AND the product purl agree, so an image-scoped record cannot
// suppress a same-CVE finding on the repo tree. Exit is always 0 — the workflow's
// produce → always-upload → ENFORCE pattern reads the `.outcome` file in a later
// `if: always()` step, so this shim never fails the job directly (the SARIF must
// always upload first).
import { readFileSync, writeFileSync } from 'node:fs';
import { uncoveredVulns } from './grype-fs-gate.ts';
// The acceptance builder comes straight from the shared ledger — the ONE place
// that decides what a `.vex/` record covers (#295/#337). Imported here rather
// than re-exported through the gate module so no logic hides behind an alias.
import { recordAcceptances } from './vex-ledger.ts';

const [grypeFile, ...vexFiles] = process.argv.slice(2);
if (!grypeFile) {
  console.error(
    'usage: grype-fs-gate.mjs <grype.json> <vex1.openvex.json> [vex2 ...]',
  );
  process.exit(2);
}

// Read + JSON-parse a file; a missing/invalid file degrades to `undefined`
// (the logic tolerates a non-object — it contributes nothing) — never fatal.
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

const grype = readJson(grypeFile);
const acceptances = recordAcceptances(vexFiles.map(readJson));
const uncovered = uncoveredVulns(grype, acceptances);

// HONEST fail-closed: if the grype JSON could not be read at all, we cannot
// prove the scan was clean — fail so a broken scan never passes silently
// (mirrors the image job's "no gate JSON produced → outcome=failure").
if (grype === undefined) {
  console.error('grype-fs-gate: no readable grype JSON — failing closed');
  writeFileSync('grype-fs.outcome', 'outcome=failure\n');
  process.exit(0);
}

if (uncovered.length === 0) {
  console.error(
    `grype-fs-gate: 0 uncovered findings at any severity (${acceptances.length} surface-scoped VEX acceptance(s)) — PASS`,
  );
  writeFileSync('grype-fs.outcome', 'outcome=success\n');
} else {
  console.error(
    `grype-fs-gate: ${uncovered.length} uncovered finding(s) NOT covered by any .vex/ record — FAIL:`,
  );
  for (const id of uncovered) console.error(`  - ${id}`);
  writeFileSync('grype-fs.outcome', 'outcome=failure\n');
}
process.exit(0);
