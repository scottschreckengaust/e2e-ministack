#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match the
// sibling npm-audit-gate.mjs / grype-fs-gate.mjs / vex-revisit-gate.mjs shims and
// declare them inline.)
//
// Thin CLI shim: score ONE vulnerability surface as a DELTA on a change and as an
// ABSOLUTE on the default branch (issue #334). ALL decision logic lives in the
// jest-visible `vuln-gate.ts` (100% coverage + Stryker + fuzz); this shim holds
// only env/read/parse/write/exit — NO logic of its own (the repo's #165 contract:
// a `.mjs` is not coverage-instrumented, so every branch must sit in a tested
// `.ts`). Node 24 strips the `.ts` on import — no build step.
//
// Inputs arrive by ENVIRONMENT, never argv, because several of them are
// attacker-influencable on a public repo (a branch name, a base ref, a PR-set
// event payload). An env var is handed to the process as one opaque value, so
// there is no shell word-splitting, glob expansion or `$(...)` for a crafted
// branch name to reach — and the `.ts` then validates each one against a closed
// allow-list (`normSurface`, `normEnforcement`, `laneFor`), treating anything
// unrecognized as fail-closed rather than guessing.
//
//   VG_SURFACE         grype-fs | trivy-fs | osv | npm-audit | grype-image | trivy-image
//   VG_EVENT           github.event_name
//   VG_REF             github.ref
//   VG_DEFAULT_BRANCH  the repository default branch
//   VG_ENFORCE         'blocking' (default) | 'report-only'
//   VG_HEAD_JSON       path to the HEAD-side scanner output (JSON or SARIF)
//   VG_BASE_JSON       path to the BASE-side scanner output (may be absent)
//   VG_BASE_REASON     '' when the base side is usable; else WHY it is not
//   VG_BASE_WORKFLOW   image surfaces: base-side workflow file (digest pin)
//   VG_HEAD_WORKFLOW   image surfaces: head-side workflow file (digest pin)
//   VG_TODAY           ISO date for dated-revisit_by expiry ('' disables)
//
// Writes THREE files, all named for the surface so six jobs never collide:
//   vuln-gate-<surface>.outcome       KEY=VALUE the enforce step `source`s
//   vuln-gate-<surface>.txt           the human report (uploaded artifact)
//   vuln-gate-<surface>.findings.json the machine view the absolute burndown unions
//
// Exit is ALWAYS 0 — the produce → always-upload → ENFORCE pattern reads the
// `.outcome` in a later `if: always()` step, so the artifact exists precisely
// when the job fails.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import {
  findingsDocument,
  gate,
  normSurface,
  renderReport,
} from './vuln-gate.ts';
import { vexRecordPaths } from './vex-ledger.ts';

// Read + JSON-parse; a missing/unparseable file degrades to `undefined`, which
// the logic treats as fail-closed (an unread scan is NOT a clean one).
function readJson(file) {
  if (typeof file !== 'string' || file === '') return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

// Read as text; a missing file degrades to `undefined`, which makes the digest
// probe answer "unknown" and the gate fall back to the absolute verdict.
function readText(file) {
  if (typeof file !== 'string' || file === '') return undefined;
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
}

// The `.vex/` ledger is listed HERE rather than passed in as a shell-expanded
// glob: an unmatched glob silently yields an EMPTY list, which would drop every
// acceptance and false-red the gate — or, worse, a partially-expanded one would
// silently narrow it. Listing the directory is the only decision this shim makes,
// and it is the same one `vex-revisit-gate.mjs` makes for the same reason.
function readLedger() {
  try {
    return vexRecordPaths(readdirSync('.vex'), '.vex').map(readJson);
  } catch {
    return [];
  }
}

const env = process.env;
const surface = normSurface(env.VG_SURFACE);
if (surface === null) {
  // Still produce the report below — a bad surface name must FAIL, and it must
  // fail with an artifact explaining why, not with a bare non-zero exit.
  console.error(
    `vuln-gate: VG_SURFACE="${String(env.VG_SURFACE)}" is not a known surface — failing closed`,
  );
}

const result = gate({
  surface: env.VG_SURFACE,
  event: env.VG_EVENT,
  ref: env.VG_REF,
  defaultBranch: env.VG_DEFAULT_BRANCH,
  enforcement: env.VG_ENFORCE,
  headDoc: readJson(env.VG_HEAD_JSON),
  baseDoc: readJson(env.VG_BASE_JSON),
  baseReason: env.VG_BASE_REASON,
  baseWorkflow: readText(env.VG_BASE_WORKFLOW),
  headWorkflow: readText(env.VG_HEAD_WORKFLOW),
  vexDocs: readLedger(),
  today: env.VG_TODAY,
});

const report = renderReport(result);
// The report goes to the LOG as well as the artifact: #335 C2 — the delta lane
// narrows what BLOCKS, never what is printed, and the log is the surface a
// reviewer actually reads.
console.error(report);

const name = surface ?? 'unknown';
writeFileSync(`vuln-gate-${name}.txt`, report);
writeFileSync(
  `vuln-gate-${name}.findings.json`,
  `${JSON.stringify(findingsDocument(result), null, 2)}\n`,
);
writeFileSync(`vuln-gate-${name}.outcome`, `outcome=${result.outcome}\n`);
process.exit(0);
