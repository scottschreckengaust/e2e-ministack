#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling *-to-sarif.mjs shims and declare them inline.)
//
// Thin CLI shim for the per-push VEX report (#189). The pure transform lives in
// the jest-visible `vex-report.ts` (100% coverage gate #124 + Stryker #122 +
// fuzz-regression); this file is only argv/read/write/glob plumbing. Node 24
// strips the `.ts` on import — no build step.
//
// Usage:
//   node vex-report.mjs <vexDir> <findings.json> [today] [gateFloor] [out.md] [resolvedSince] [--scan-cves <cves.json>]
//
//   vexDir        directory of `.vex/CVE-*.openvex.json` records (the source of truth)
//   findings.json a JSON array of {id, scanner, severity, pkg, state, fixedAt} —
//                 the Code-Scanning alerts normalized by `alerts-findings.mjs`
//                 (tool-agnostic; `state`/`fixedAt` carry the second-ledger signal)
//   today         ISO date (YYYY-MM-DD) for overdue detection; '' to skip
//   gateFloor     CRITICAL|HIGH|MEDIUM|LOW (default HIGH)
//   out.md        optional output path; else stdout
//   resolvedSince ISO date boundary for the "recently resolved" window — a
//                 Resolved alert older than this falls off the report. The
//                 workflow passes the LAST RELEASE's published date ("resolved
//                 since users last saw a release"); '' (default) drops all
//                 Resolved rows (no release baseline yet). The workflow supplies
//                 a rolling-window fallback when there is no prior release.
//   --scan-cves   OPTIONAL JSON array of the CVE ids the CURRENT image scan
//                 (Grype ∪ Trivy SARIFs of this run) reports, from
//                 `sarif-cve-ids.mjs`. Enables the #210 cross-check: an alert
//                 `open` in the API but ABSENT from this set (high+) becomes
//                 "Scanner-cleared" instead of a false "Decision needed". Omit
//                 it to disable the cross-check (pre-#210 behavior).
//
// The transform never throws; malformed inputs degrade to empty sets.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { buildReport, renderMarkdown } from './vex-report.ts';

// Pull out the optional `--scan-cves <file>` pair (a JSON array of the CVE ids
// the CURRENT image scan reports, produced by `sarif-cve-ids.mjs`), leaving the
// positional args intact. Its presence enables the #210 stale-open cross-check;
// its absence leaves the scan set `null` (pre-#210 behavior — no demotion).
const rawArgv = process.argv.slice(2);
let scanCvesFile;
const argv = [];
for (let i = 0; i < rawArgv.length; i++) {
  if (rawArgv[i] === '--scan-cves') {
    scanCvesFile = rawArgv[++i];
  } else {
    argv.push(rawArgv[i]);
  }
}
const [
  vexDir,
  findingsFile,
  today = '',
  gateFloor = 'HIGH',
  outFile,
  resolvedSince = '',
] = argv;
if (!vexDir || !findingsFile) {
  console.error(
    'usage: vex-report.mjs <vexDir> <findings.json> [today] [gateFloor] [out.md] [resolvedSince] [--scan-cves <cves.json>]',
  );
  process.exit(2);
}

// Read each `.vex/CVE-*.openvex.json` into the {cve,status,justification,revisitBy}
// shape the logic module expects (one statement per record, as the repo authors them).
function loadVexRecords(dir) {
  let entries;
  try {
    entries = readdirSync(dir).filter(
      (f) => f.startsWith('CVE-') && f.endsWith('.openvex.json'),
    );
  } catch {
    return [];
  }
  const out = [];
  for (const f of entries) {
    try {
      const doc = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      const st = (doc.statements && doc.statements[0]) || {};
      const vuln = st.vulnerability;
      const cve = typeof vuln === 'object' && vuln ? vuln.name : vuln;
      out.push({
        cve,
        status: st.status,
        justification: st.justification,
        // `revisit_by` may live at the document or statement level.
        revisitBy: doc.revisit_by ?? st.revisit_by,
      });
    } catch {
      // A malformed record is skipped, not fatal — the report must still render.
    }
  }
  return out;
}

const vexRecords = loadVexRecords(vexDir);
let findings = [];
try {
  const parsed = JSON.parse(readFileSync(findingsFile, 'utf8'));
  if (Array.isArray(parsed)) findings = parsed;
} catch {
  // no/!invalid findings file -> empty; report still renders from .vex/ alone.
}

// Load the current-scan CVE set when `--scan-cves` was given. `null` (flag
// absent) DISABLES the stale-open cross-check — buildReport then behaves exactly
// as before #210. A present-but-unreadable/invalid file degrades to `null` too:
// we must not treat "couldn't read the scan" as "the scan found nothing" (which
// would falsely demote every open alert to Scanner-cleared).
let scanCves = null;
if (scanCvesFile) {
  try {
    const parsed = JSON.parse(readFileSync(scanCvesFile, 'utf8'));
    if (Array.isArray(parsed)) scanCves = parsed;
  } catch {
    // leave null — no reliable scan ledger, so don't cross-check.
  }
}

const rows = buildReport(
  vexRecords,
  findings,
  gateFloor,
  today,
  resolvedSince,
  scanCves,
);
const md = renderMarkdown(rows);

if (outFile) writeFileSync(outFile, md);
else process.stdout.write(md + '\n');
