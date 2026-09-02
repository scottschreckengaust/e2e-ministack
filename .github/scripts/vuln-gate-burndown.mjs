#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling shims and declare them inline.)
//
// Thin CLI shim: render the ABSOLUTE view of every vulnerability surface into the
// sticky `review:vuln` burndown issue body (issue #334, option 2 — the split
// between what BLOCKS and what stays VISIBLE). ALL decision logic lives in the
// jest-visible `vuln-gate.ts`; this shim holds only argv/read/parse/write/exit.
//
// Usage:
//   node vuln-gate-burndown.mjs <today YYYY-MM-DD|""> <findings1.json> [findings2 ...]
//
// The findings files are the `vuln-gate-<surface>.findings.json` artifacts the
// six per-surface gate runs uploaded. An unreadable one is NOT skipped — the
// logic counts it as UNKNOWN and refuses to report clean, because "I could not
// read the surface" must never render as "the surface is clean" (the #364 shape:
// a misrouted artifact made a corroboration arm read no-data 64/64 times and
// still look green).
//
// Writes `vuln-gate-burndown.md` (the issue body) and `vuln-gate-burndown.outcome`
// with `clean=` and `total=` for the workflow to branch on. Also writes
// `vuln-gate-burndown.meta.json` carrying the sticky issue's TITLE and body
// MARKER, so `security.yml` never restates either literal — the workflow reads
// them from the same tested constants the body is built from, and a rename can
// never leave the poller hunting for an issue that no longer matches. (Kept out
// of the `.outcome` file on purpose: that one is `source`d as shell KEY=VALUE and
// the title contains spaces and an em dash.)
import { readFileSync, writeFileSync } from 'node:fs';
import {
  BURNDOWN_MARKER,
  BURNDOWN_TITLE,
  burndown,
  observedAt,
} from './vuln-gate.ts';

const [todayArg, ...files] = process.argv.slice(2);

// A missing/unparseable file degrades to `undefined`, which the logic counts as
// an UNREADABLE surface (not-clean), never as an absent one.
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

const result = burndown(files.map(readJson), observedAt(todayArg));

console.error(
  `vuln-gate-burndown: ${files.length} surface file(s), ${result.total} finding(s), clean=${result.clean}`,
);
console.error(result.body);

writeFileSync('vuln-gate-burndown.md', result.body);
writeFileSync(
  'vuln-gate-burndown.outcome',
  `clean=${result.clean}\ntotal=${result.total}\n`,
);
writeFileSync(
  'vuln-gate-burndown.meta.json',
  `${JSON.stringify({ title: BURNDOWN_TITLE, marker: BURNDOWN_MARKER }, null, 2)}\n`,
);
process.exit(0);
