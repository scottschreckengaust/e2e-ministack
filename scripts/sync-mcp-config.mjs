#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// vex-dialects.mjs / suppression-inventory.mjs and declare them inline rather
// than widening eslint.config.mjs.)
//
// Thin CLI shim for the per-agent MCP config generator (#111, Phase 2 of #72).
// The pure transform logic lives in the jest-visible `sync-mcp-config.ts` so it
// flows through the repo's 100% coverage gate (#124) + Stryker mutation (#122);
// this file is only the read/write/compare plumbing. Node 24 imports the `.ts`
// natively (stable type-stripping — no build step).
//
// Usage:
//   node scripts/sync-mcp-config.mjs write   # (re)generate every per-agent file
//   node scripts/sync-mcp-config.mjs check   # fail if committed != generated (drift gate)
//
// `check` is the CI drift gate (unit job + pre-commit): it regenerates every
// target from the canonical `.mcp.json` in memory and diffs against the committed
// files, exiting 1 (with the offending path + a hint) on any drift so a hand-edit
// or a forgotten regenerate can never silently desync a per-agent MCP config from
// the canonical block. Bad args exit 2.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseCanonical, TARGETS } from './sync-mcp-config.ts';

const CANONICAL_PATH = '.mcp.json';

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
  console.error('usage: sync-mcp-config.mjs <write|check>');
  process.exit(2);
}

const canonical = parseCanonical(readFileSync(CANONICAL_PATH, 'utf8'));
const generated = TARGETS.map((t) => ({
  path: t.path,
  content: t.render(canonical),
}));

if (mode === 'write') {
  for (const { path, content } of generated) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    console.error(`sync-mcp-config: wrote ${path}`);
  }
  process.exit(0);
}

// mode === 'check'
let drift = false;
for (const { path, content } of generated) {
  if (readOrEmpty(path) !== content) {
    drift = true;
    console.error(
      `sync-mcp-config: DRIFT — ${path} does not match the generator output ` +
        `from ${CANONICAL_PATH}. Run \`node scripts/sync-mcp-config.mjs write\` ` +
        `and commit the result.`,
    );
  }
}
if (drift) process.exit(1);
console.error(
  `sync-mcp-config: OK — ${generated.length} per-agent MCP config(s) match ` +
    `the canonical ${CANONICAL_PATH}.`,
);
process.exit(0);
