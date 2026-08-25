#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling *-to-sarif.mjs / vex-report.mjs / sarif-cve-ids.mjs shims and declare
// them inline.)
//
// Thin CLI shim: read the scanners' structured JSON (grype `-o json`, trivy
// `--format json`) and emit a CVE-id -> GATE (distro-adjusted) severity JSON
// object — the input for the VEX report's gate-vs-badge divergence column
// (#208). Logic lives in the jest-visible `gate-findings.ts` (100% coverage +
// Stryker + fuzz); this is only argv/read/detect/write plumbing. Node 24 strips
// the `.ts` on import — no build step.
//
// Usage:
//   node gate-findings.mjs <out.json> <scan1.json> [scan2.json ...]
//
// Each input is auto-detected as grype (`{matches:[…]}`) or trivy
// (`{Results:[…]}`) by shape, so callers pass the grype + trivy image JSON of
// the SAME run (no re-scan). A missing/invalid/unknown-shape file contributes
// nothing (the report still renders from the badge severity alone). The merged
// map (higher gate rank wins per CVE across scanners) is written to <out.json>
// as a plain `{ "CVE-…": "SEVERITY" }` object.
import { readFileSync, writeFileSync } from 'node:fs';
import {
  parseGrypeGate,
  parseTrivyGate,
  mergeGateSeverities,
} from './gate-findings.ts';

const [outFile, ...scanFiles] = process.argv.slice(2);
if (!outFile || scanFiles.length === 0) {
  console.error(
    'usage: gate-findings.mjs <out.json> <scan1.json> [scan2.json ...]',
  );
  process.exit(2);
}

// Read + JSON-parse one scan file, then parse BOTH ways and keep whichever
// yielded findings. Shape auto-detect: a grype doc has `matches`, a trivy doc
// has `Results` — the other parser returns an empty map on a foreign shape, so
// merging both is safe and order-independent. A missing/invalid file yields two
// empty maps (contributes nothing) — never fatal.
function gateMapFor(file) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return new Map();
  }
  return mergeGateSeverities([parseGrypeGate(doc), parseTrivyGate(doc)]);
}

const merged = mergeGateSeverities(scanFiles.map(gateMapFor));
// Serialize the Map as a plain object (JSON has no Map); the report shim reads
// it back into a Map. Sorted keys for a deterministic, diff-friendly artifact.
const obj = {};
for (const cve of [...merged.keys()].sort()) obj[cve] = merged.get(cve);
writeFileSync(outFile, JSON.stringify(obj));
console.error(
  `gate-findings: ${Object.keys(obj).length} CVE gate-severities across ${scanFiles.length} scan file(s)`,
);
