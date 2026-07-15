#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling *-to-sarif.mjs / vex-report.mjs shims and declare them inline.)
//
// Thin CLI shim: read a GitHub Code Scanning Alerts API response (as fetched by
// `gh api .../code-scanning/alerts`) and emit the normalized findings JSON that
// `vex-report.mjs` consumes (#189) — in the report's `ScannerFinding` shape
// (`toScannerFindings` maps the alert's `badgeSeverity` onto the report's
// `severity`; without it every CI severity renders UNKNOWN). Logic lives in the
// jest-visible `alerts-findings.ts` (100% coverage + Stryker + fuzz); this is
// only argv/read/filter/write plumbing.
//
// Usage:
//   node alerts-findings.mjs <alerts.json> <out.json> [category ...]
// `category` args (optional) restrict to specific scan categories — pass the
// image-scan categories (e.g. grype-ministack-image, trivy-image) so unrelated
// code-scanning alerts (SonarQube, CodeQL) don't leak into the VEX report.
import { readFileSync, writeFileSync } from 'node:fs';
import {
  parseAlerts,
  filterByCategory,
  toScannerFindings,
} from './alerts-findings.ts';

const [, , alertsFile, outFile, ...categories] = process.argv;
if (!alertsFile || !outFile) {
  console.error(
    'usage: alerts-findings.mjs <alerts.json> <out.json> [category ...]',
  );
  process.exit(2);
}

let alerts = [];
try {
  alerts = JSON.parse(readFileSync(alertsFile, 'utf8'));
} catch {
  // No/invalid alerts file -> no findings; the report still renders from `.vex/`
  // alone (e.g. a fresh branch whose scans haven't uploaded yet).
}

// Normalize -> filter by scan category -> adapt to the report's ScannerFinding
// shape (maps badgeSeverity -> severity; see toScannerFindings). Emitting the
// consumed shape here keeps the field-name bridge in tested logic, not plumbing.
const findings = toScannerFindings(
  filterByCategory(parseAlerts(alerts), categories),
);
writeFileSync(outFile, JSON.stringify(findings));
console.error(
  `alerts-findings: ${findings.length} finding(s)` +
    (categories.length ? ` in categories [${categories.join(', ')}]` : ''),
);
