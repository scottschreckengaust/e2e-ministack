#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// vex-to-sarif-suppressions.mjs / suppression-inventory.mjs and declare them
// inline rather than widening eslint.config.mjs.)
//
// Thin CLI shim for the VEX dialect generator (#251). The pure transform logic
// lives in the jest-visible `vex-dialects.ts` so it flows through the repo's
// 100% coverage gate (#124) + Stryker mutation (#122) + fuzz-regression tier;
// this file is only the `.vex/` glob + read/write/compare plumbing. Node 24
// imports the `.ts` natively (stable type-stripping — no build step).
//
// Usage:
//   node .github/scripts/vex-dialects.mjs write   # (re)generate the dialects
//   node .github/scripts/vex-dialects.mjs check   # fail if committed != generated
//
// `check` is the CI drift gate: it regenerates trivy.yaml / osv-scanner.toml
// from `.vex/` in memory and diffs against the committed files, exiting 1 (with
// the offending path + a hint) on any drift so a hand-edit or a forgotten
// regenerate can never silently desync a scanner's suppression set from the
// canonical ledger. Bad args exit 2.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { renderTrivyYaml, renderOsvToml } from './vex-dialects.ts';

const VEX_DIR = '.vex';
const TRIVY_PATH = 'trivy.yaml';
const OSV_PATH = 'osv-scanner.toml';

// Load every `.vex/*.openvex.json` record as { path, doc }. The path is the
// repo-relative form trivy.yaml lists; sorting here is cosmetic (the generator
// re-sorts), but keeps the read order stable.
function loadVexFiles() {
  return readdirSync(VEX_DIR)
    .filter((name) => name.endsWith('.openvex.json'))
    .sort()
    .map((name) => {
      const path = `${VEX_DIR}/${name}`;
      return { path, doc: JSON.parse(readFileSync(path, 'utf8')) };
    });
}

// Read a committed file, or '' if it does not exist yet (first `check` before a
// generated file is committed → reported as drift, which is correct).
function readOrEmpty(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

const mode = process.argv[2];
if (mode !== 'write' && mode !== 'check') {
  console.error('usage: vex-dialects.mjs <write|check>');
  process.exit(2);
}

const files = loadVexFiles();
const generated = {
  [TRIVY_PATH]: renderTrivyYaml(files),
  [OSV_PATH]: renderOsvToml(files),
};

if (mode === 'write') {
  for (const [path, content] of Object.entries(generated)) {
    writeFileSync(path, content);
    console.error(`vex-dialects: wrote ${path}`);
  }
  process.exit(0);
}

// mode === 'check'
let drift = false;
for (const [path, content] of Object.entries(generated)) {
  if (readOrEmpty(path) !== content) {
    drift = true;
    console.error(
      `vex-dialects: DRIFT — ${path} does not match the generator output ` +
        `from ${VEX_DIR}/. Run \`node .github/scripts/vex-dialects.mjs write\` ` +
        `and commit the result.`,
    );
  }
}
if (drift) process.exit(1);
console.error(
  `vex-dialects: OK — ${TRIVY_PATH} and ${OSV_PATH} match the ${VEX_DIR}/ ledger ` +
    `(${files.length} record(s)).`,
);
process.exit(0);
