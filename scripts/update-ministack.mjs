#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — declare
// the globals inline rather than widening eslint.config.mjs.)
//
// `mise run update:ministack` — resolve the current MiniStack image digest and
// fan it out to every pin site (#152, the ergonomics surface of the #78
// pin-sync updater).
//
// CLI + THIN I/O SHIM. Every PURE function (digest validation, literal
// substitution, the pin-site set, the fan-out + report formatting) lives in the
// jest-visible `update-ministack.ts` so it flows through the repo's 100%
// coverage gate (#124) + Stryker mutation (#122). This file keeps only the
// plumbing that CANNOT be gated in-process:
//   - RESOLVE the current multi-arch OCI *index* digest via
//     `docker buildx imagetools inspect` (network + docker — unavailable in the
//     unit CI job, so this task is exercised by humans / a scheduled workflow,
//     exactly like `ministack-upstream.mjs`),
//   - READ/WRITE the pin-site files,
//   - run the drift guard to SELF-VERIFY.
// Node 24 imports the `.ts` natively (no build step), so
// `node scripts/update-ministack.mjs` is unchanged. Same split as
// `ministack-upstream.{ts,mjs}`.
//
// SINGLE SOURCE OF TRUTH: the canonical digest is
// `services/_registry/ministack-pin.json` (`.digest`). The old digest to
// replace is read from there; the new digest is resolved from the registry
// (`docker buildx imagetools inspect`). The fan-out rewrites the SAME set of
// pin sites the drift guard (#212) verifies, so after this runs
// `.github/scripts/check-ministack-digest-drift.sh` MUST pass — which the task
// then runs to self-verify (fail closed).
//
// Node built-ins only — no npm deps (repo governance line, #73/#80).
//
// CLI:
//   node update-ministack.mjs           resolve + fan out + self-verify
//   node update-ministack.mjs --dry-run resolve + REPORT only (no writes)
//
//   --digest sha256:<64hex>  use this digest instead of resolving via docker
//                            (for testing / an already-known index digest;
//                            still fails closed if it isn't a legal digest).
//
// Exit codes: 0 success (fan-out written + guard green, or dry-run), 2 usage
// error, 3 resolve/verify failure (fail closed).

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MINISTACK_IMAGE,
  PIN_SITE_FILES,
  fanOut,
  formatReport,
  isValidDigest,
  resolveBin,
} from './update-ministack.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const PIN_PATH = path.join(REPO_ROOT, 'services/_registry/ministack-pin.json');
const DRIFT_GUARD = path.join(
  REPO_ROOT,
  '.github/scripts/check-ministack-digest-drift.sh',
);

// ── Thin I/O (NOT unit-tested; needs docker / network / the filesystem) ──────

/** Read the current (old) pinned digest from the single source of truth. */
function readPinnedDigest() {
  const pin = JSON.parse(readFileSync(PIN_PATH, 'utf8'));
  return pin.digest;
}

/**
 * Resolve the current multi-arch OCI *index* digest of the MiniStack image via
 * `docker buildx imagetools inspect`. CI runs amd64 and dev machines are arm64,
 * so the pin MUST be the platform-agnostic index digest — `.Manifest.Digest`
 * from imagetools is exactly that top-level index digest (a per-arch manifest
 * digest would break the other architecture). Argv array → execFileSync (no
 * shell); the `docker` binary is resolved to an ABSOLUTE path via `resolveBin`
 * (no `$PATH` lookup — S4036), honoring an absolute `DOCKER_BIN` override.
 * Throws on any docker/network failure so the caller can fail closed.
 * @returns {string} `sha256:<64hex>`
 */
function resolveIndexDigest() {
  const dockerBin = resolveBin('docker', process.env.DOCKER_BIN, existsSync);
  const out = execFileSync(
    dockerBin,
    [
      'buildx',
      'imagetools',
      'inspect',
      MINISTACK_IMAGE,
      '--format',
      '{{json .Manifest.Digest}}',
    ],
    { encoding: 'utf8' },
  );
  // `--format '{{json .Manifest.Digest}}'` prints a JSON string (quoted).
  return JSON.parse(out.trim());
}

/** Read every pin-site file's current contents (repo-root-relative paths). */
function readPinSites() {
  return PIN_SITE_FILES.map((rel) => ({
    path: rel,
    content: readFileSync(path.join(REPO_ROOT, rel), 'utf8'),
  }));
}

/** Run the #212 drift guard; throw (non-zero exit) if the sites disagree. */
function runDriftGuard() {
  if (!existsSync(DRIFT_GUARD)) {
    throw new Error(`drift guard not found at ${DRIFT_GUARD}`);
  }
  // Inherit stdio so the guard's own OK/DRIFT report is visible to the operator.
  // `bash` is resolved to an ABSOLUTE path via `resolveBin` (no `$PATH` lookup —
  // S4036), honoring an absolute `BASH_BIN` override.
  const bashBin = resolveBin('bash', process.env.BASH_BIN, existsSync);
  execFileSync(bashBin, [DRIFT_GUARD], { stdio: 'inherit' });
}

// ── CLI entry (skipped when imported as a module) ────────────────────────────

function usage(stream = console.error) {
  stream(
    [
      'usage: update-ministack.mjs [--dry-run] [--digest sha256:<64hex>]',
      '',
      '  (default)               resolve the current index digest, fan it out',
      '                          to every pin site, then run the drift guard',
      '  --dry-run               resolve + report the diff only; write nothing',
      '  --digest sha256:<hex>   use this digest instead of resolving via docker',
    ].join('\n'),
  );
}

/**
 * Parse argv into `{ dryRun, explicitDigest }`. Exits 2 on an unknown flag.
 */
function parseArgs(argv) {
  let dryRun = false;
  let explicitDigest;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dry-run') dryRun = true;
    else if (arg === '--digest') explicitDigest = argv[++i];
    else {
      console.error(`unknown argument: ${arg}`);
      usage();
      process.exit(2);
    }
  }
  return { dryRun, explicitDigest };
}

/**
 * Return the validated new digest: the explicit `--digest` if given, otherwise
 * the resolved index digest. Fails closed (exit 3) if resolution throws or the
 * result isn't a legal `sha256:<64hex>`.
 */
function resolveNewDigest(explicitDigest) {
  let newDigest = explicitDigest;
  if (newDigest === undefined) {
    try {
      newDigest = resolveIndexDigest();
    } catch (err) {
      console.error(
        `failed to resolve the MiniStack index digest via ` +
          `\`docker buildx imagetools inspect ${MINISTACK_IMAGE}\` ` +
          `(is docker/buildx installed and online?): ${
            err instanceof Error ? err.message : err
          }`,
      );
      process.exit(3);
    }
  }
  if (!isValidDigest(newDigest)) {
    console.error(
      `resolved digest is not a legal sha256:<64hex>: ${JSON.stringify(
        newDigest,
      )}`,
    );
    process.exit(3);
  }
  return newDigest;
}

/**
 * Write the substituted pin sites, then self-verify with the drift guard.
 * Fails closed (exit 3) if the guard reports drift after the fan-out.
 */
function applyAndVerify(results, total) {
  if (total === 0) {
    console.log('\nNothing to write (0 replacements).');
  } else {
    for (const r of results) {
      if (r.replacements > 0) {
        writeFileSync(path.join(REPO_ROOT, r.path), r.content);
      }
    }
    console.log(`\nWrote ${total} replacement(s) across the pin sites.`);
  }

  // Self-verify: after the fan-out every pin site must agree, or the guard
  // fails and we fail closed.
  console.log('\nSelf-verifying with the drift guard…');
  try {
    runDriftGuard();
  } catch (err) {
    console.error(
      `drift guard FAILED after fan-out — pin sites disagree: ${
        err instanceof Error ? err.message : err
      }`,
    );
    process.exit(3);
  }
}

function main(argv) {
  const { dryRun, explicitDigest } = parseArgs(argv);

  const oldDigest = readPinnedDigest();
  if (!isValidDigest(oldDigest)) {
    console.error(
      `pinned digest in ${PIN_PATH} is not a legal sha256:<64hex>: ${JSON.stringify(
        oldDigest,
      )}`,
    );
    process.exit(3);
  }

  const newDigest = resolveNewDigest(explicitDigest);

  const files = readPinSites();
  const { results, total } = fanOut(files, oldDigest, newDigest);
  console.log(formatReport(results, oldDigest, newDigest));

  if (dryRun) {
    console.log('\n--dry-run: nothing written.');
    return;
  }

  applyAndVerify(results, total);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2));
}
