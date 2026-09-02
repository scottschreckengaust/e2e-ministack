#!/usr/bin/env node
/* global process, console, fetch */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling vex-revisit-gate.mjs / npm-audit-gate.mjs shims and declare them
// inline. `fetch` is a Node 24 global, so the one HTTPS GET below needs no
// dependency.)
//
// Thin CLI shim: report Debian's OWN verdict for every `pkg:deb/debian/*`
// acceptance in the `.vex/` ledger (issue #352). ALL decision logic lives in the
// jest-visible `vex-debian-tracker.ts` (+ `vex-ledger.ts`), which flow through
// the 100% coverage gate and Stryker. This shim is ONLY
// fetch/readdir/read/parse/write — it holds NO logic of its own (the #165
// contract). Node 24 strips the `.ts` on import — no build step.
//
// Usage:
//   node .github/scripts/vex-debian-tracker.mjs <out.txt> [grype.json] [trivy.json]
//
// The two scanner JSONs are OPTIONAL fix-state corroboration (grype
// `matches[].vulnerability.fix.state`, trivy `Results[].Vulnerabilities[].Status`);
// an absent/unreadable one simply contributes no claims.
//
// REPORT-ONLY, never a gate: this performs one HTTPS GET of an ~86 MB
// third-party file, so making a required check depend on it would put an
// external service on CI's critical path (#335 C1). It exits 0 on success and
// writes no `.outcome` file — there is no verdict to enforce. It also edits
// nothing under `.vex/` (#322).
//
// `DEBIAN_TRACKER_FILE` reads a already-downloaded payload instead of fetching —
// for local iteration only. NEVER commit that payload, whole or sliced.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import {
  DEBIAN_SUITE,
  DEBIAN_TRACKER_URL,
  classifyTriples,
  debTriples,
  fixStateIndex,
  grypeFixStates,
  indexTracker,
  renderReport,
  standingPremises,
  trivyFixStates,
} from './vex-debian-tracker.ts';
import { vexRecordPaths } from './vex-ledger.ts';

const VEX_DIR = '.vex';
const [out = 'vex-debian-tracker.txt', grypeJson, trivyJson] =
  process.argv.slice(2);

// An unreadable/absent/unparseable file degrades to `undefined`, which every
// reader in the `.ts` treats as "contributes nothing" — never fatal.
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

// A missing/unreadable directory degrades to an empty listing; discovery itself
// is `vexRecordPaths` in the tested core (the #342 lesson — a shim-local filter
// is a filter no gate can see).
function listDir(dir) {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

async function trackerPayload() {
  const local = process.env.DEBIAN_TRACKER_FILE;
  if (local !== undefined) return readJson(local);
  const response = await fetch(DEBIAN_TRACKER_URL);
  // Loud on a bad response: a silently-empty payload would classify every
  // triple as "Debian has no opinion", the one failure mode this join must
  // never have.
  if (!response.ok)
    throw new Error(`GET ${DEBIAN_TRACKER_URL} -> HTTP ${response.status}`);
  return response.json();
}

const entries = vexRecordPaths(listDir(VEX_DIR), VEX_DIR).map((path) => ({
  path,
  doc: readJson(path),
}));
const rows = classifyTriples(
  indexTracker(await trackerPayload(), DEBIAN_SUITE),
  debTriples(entries),
);
const report = renderReport(
  DEBIAN_SUITE,
  rows,
  fixStateIndex([
    ...grypeFixStates(readJson(grypeJson)),
    ...trivyFixStates(readJson(trivyJson)),
  ]),
  standingPremises(DEBIAN_SUITE, entries, rows),
);

console.log(report.trimEnd());
writeFileSync(out, report);
