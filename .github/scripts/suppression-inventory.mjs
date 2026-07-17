#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// clamav-to-sarif.mjs / license-verdict.mjs and declare them inline rather than
// widening eslint.config.mjs.)
//
// Thin CLI shim for the suppression-token inventory (#202). ripgrep does the
// fast tree walk + pre-filter (one alternation of every catalog pattern, with
// the documented exclude globs); the pure classifier/report/SARIF builders live
// in the jest-visible `suppression-inventory.ts` so they flow through the repo's
// 100% coverage gate (#124) + Stryker mutation (#122) + fuzz-regression tier.
// This file is only spawn/read/write/exit plumbing. Node 24 imports the `.ts`
// natively (stable type-stripping — no build step), so the workflow call
// `node .github/scripts/suppression-inventory.mjs [--sarif out] [--text out]`
// is unchanged.
//
// REPORT-ONLY: exits 0 even when the `raw` bucket is non-empty — it mirrors the
// trivy-fs / sonarqube report-first posture. The ratchet to fail on `raw` lands
// after the reason-bearing suppressions are triaged into #167.
import { spawnSync } from 'node:child_process';
import { readdirSync, writeFileSync } from 'node:fs';
import {
  TOKENS,
  scanLine,
  buildReport,
  toSarif,
  formatText,
} from './suppression-inventory.ts';

// Directories/files that never hold a real suppression: vendored/generated
// output, VCS internals, report/coverage trees, snapshots, and lockfiles. The
// `.vex/` tree is intentionally NOT excluded — its records are classified as
// `registered`, not hidden.
const EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'cdk.out',
  'coverage',
  'reports',
  '.stryker-tmp',
  '**/*.snapshot/**',
  '**/__snapshots__/**',
  'package-lock.json',
];

// One ripgrep alternation over every catalog pattern. ripgrep only pre-filters
// (finds candidate lines fast); `scanLine` in the .ts is the authoritative
// per-token matcher + classifier, so a slightly loose union here is harmless.
function ripgrepCandidates() {
  // `--hidden` so dotfiles/dirs are searched (the suppressions live in
  // `.github/`, `.gitleaks.toml`, `.vex/`); `.git` stays excluded via EXCLUDES.
  // `--no-ignore-vcs`/default gitignore honoring: we WANT gitignored report
  // trees skipped, so leave gitignore active and list the rest in EXCLUDES.
  const args = ['--json', '--no-config', '--hidden', '-i'];
  for (const g of EXCLUDES) args.push('-g', `!${g}`);
  for (const t of TOKENS) args.push('-e', t.pattern);
  args.push('.');
  const res = spawnSync('rg', args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  // FAIL-SAFE (report-only contract, must NEVER red CI): if ripgrep isn't
  // spawnable — not installed (ENOENT), or killed by a signal — `res.error` is
  // set and/or `res.status` is null. A missing tool is an infra gap, not a
  // finding, so treat it as an EMPTY inventory (caller writes a valid
  // empty-results SARIF + text report) rather than failing the step. This is
  // deliberately distinct from a genuine ripgrep RUNTIME error (the process ran
  // and exited with a numeric code >= 2, e.g. a bad pattern), which is a real
  // bug in THIS tool and still exits non-zero below.
  if (res.error || res.status === null) {
    console.error(
      `ripgrep unavailable (${res.error ? res.error.code || res.error.message : 'no exit status'}); ` +
        'emitting empty report (report-only — not failing CI)',
    );
    return [];
  }
  // rg exits 1 when there are no matches — that is a clean tree, not an error.
  if (res.status !== 0 && res.status !== 1) {
    console.error(`ripgrep failed (status ${res.status}): ${res.stderr}`);
    process.exit(2);
  }
  const hits = [];
  for (const raw of (res.stdout || '').split('\n')) {
    if (!raw) continue;
    let ev;
    try {
      ev = JSON.parse(raw);
    } catch {
      continue;
    }
    if (ev.type !== 'match') continue;
    const path = ev.data.path.text.replace(/^\.\//, '');
    const line = ev.data.line_number;
    const text = ev.data.lines.text ?? '';
    hits.push(...scanLine(path, line, text));
  }
  return hits;
}

function countVexRecords() {
  try {
    return readdirSync('.vex').filter((f) => /\.openvex\.json$/.test(f)).length;
  } catch {
    return 0;
  }
}

// CLI: node suppression-inventory.mjs [--sarif <out>] [--text <out>]
const argv = process.argv.slice(2);
function optVal(flag) {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

const report = buildReport(ripgrepCandidates(), countVexRecords());

const sarifOut = optVal('--sarif');
if (sarifOut)
  writeFileSync(sarifOut, JSON.stringify(toSarif(report.raw), null, 2));

const textOut = optVal('--text');
const text = formatText(report);
if (textOut) writeFileSync(textOut, text);

console.log(text);
// Report-only: always exit 0. (Ratchet to `process.exit(report.counts.raw ? 1
// : 0)` once the reason-bearing suppressions are triaged into #167.)
process.exit(0);
