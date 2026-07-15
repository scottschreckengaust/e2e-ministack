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
//   node alerts-findings.mjs <alerts.json> <out.json> [--main <mainAlerts.json>] [category ...]
// `category` args (optional) restrict to specific scan categories — pass the
// image-scan categories (e.g. grype-ministack-image, trivy-image) so unrelated
// code-scanning alerts (SonarQube, CodeQL) don't leak into the VEX report.
//
// `--main <file>`: a SECOND alerts response fetched for `refs/heads/main`. The
// `fixed`/`dismissed` alert state lives on the DEFAULT BRANCH, so on a PR merge
// ref those are absent; merging the default-branch set back in (open findings
// still come from the run ref) restores the "recently resolved" + drift signals
// (#210, `mergeAlertLedgers`). Omit it on default-branch runs (the run ref IS
// main), or when unavailable — the report then reflects the run ref alone.
import { readFileSync, writeFileSync } from 'node:fs';
import {
  parseAlerts,
  filterByCategory,
  mergeAlertLedgers,
  toScannerFindings,
} from './alerts-findings.ts';

// Pull out the optional `--main <file>` pair, leaving positionals intact.
const argv = process.argv.slice(2);
let mainFile;
const rest = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--main') {
    mainFile = argv[++i];
  } else {
    rest.push(argv[i]);
  }
}
const [alertsFile, outFile, ...categories] = rest;
if (!alertsFile || !outFile) {
  console.error(
    'usage: alerts-findings.mjs <alerts.json> <out.json> [--main <mainAlerts.json>] [category ...]',
  );
  process.exit(2);
}

// Read + normalize an alerts JSON file; a missing/invalid file yields [] (the
// report still renders — e.g. a fresh branch whose scans haven't uploaded yet).
function loadFindings(file) {
  if (!file) return [];
  try {
    return filterByCategory(
      parseAlerts(JSON.parse(readFileSync(file, 'utf8'))),
      categories,
    );
  } catch {
    return [];
  }
}

// Merge run-ref (open findings, digest-bump-correct) with the default-branch set
// (fixed/dismissed history the run ref lacks), then adapt to the report's
// ScannerFinding shape (maps badgeSeverity -> severity; see toScannerFindings).
// Keeping the merge + field-name bridge in tested logic, not plumbing.
const findings = toScannerFindings(
  mergeAlertLedgers(loadFindings(alertsFile), loadFindings(mainFile)),
);
writeFileSync(outFile, JSON.stringify(findings));
console.error(
  `alerts-findings: ${findings.length} finding(s)` +
    (categories.length ? ` in categories [${categories.join(', ')}]` : '') +
    (mainFile ? ' (merged with default-branch ledger)' : ''),
);
