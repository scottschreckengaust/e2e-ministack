#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — declare
// the globals inline rather than widening eslint.config.mjs.)
//
// Upstream MiniStack tracking (#137, sub-issue C of epic #117).
//
// CLI + THIN I/O SHIM. Every PURE function (ranking, formatting, the
// AUTO_POST_UPSTREAM gate) now lives in the jest-visible `ministack-upstream.ts`
// so it flows through the repo's 100% coverage gate (#124) + Stryker mutation
// (#122) + fuzz-regression tier (#165). This file keeps only the plumbing that
// CANNOT be gated in-process — the network-touching `gh search` and the
// registry read/write — plus the CLI. Node 24 imports the `.ts` natively
// (stable, unflagged type-stripping — no build step), so
// `node scripts/ministack-upstream.mjs <cmd> <service>` is unchanged.
//
// CORE PRINCIPLE — query = automated, comment/watch = HUMAN-GATED.
// Commenting on the foreign OSS repo `ministackorg/ministack` is an
// outward-facing, hard-to-reverse action into a community we don't control.
// This script may READ upstream freely (search issues/PRs via the
// already-authenticated `gh` CLI) and WRITE to OUR OWN registry file, but it
// MUST NEVER post/comment/subscribe to the upstream repo automatically. It
// only DRAFTS a comment body and PRINTS the exact copy-pasteable command (and
// a one-click URL) for a maintainer to run manually.
//
// The never-auto-post property is locked by a unit test
// (test/unit/ministack-upstream.test.ts) against the AUTO_POST_UPSTREAM export
// in ministack-upstream.ts.
//
// Node built-ins only — no npm deps (repo governance line, #73/#80). The
// GitHub search reuses `gh` via node:child_process (no secrets committed, no
// @octokit). All child_process calls pass argv arrays to execFileSync (never a
// shell string), so a service name can't inject shell metacharacters.
//
// CLI:
//   node ministack-upstream.mjs query <service>
//     — search ministackorg/ministack issues+PRs for <service>, pick the best
//       match, and WRITE its ref into ministack-support.json's ministackRef.
//       exit 0 on success (match written or confirmed-none), 2 on usage error,
//       3 if the network/gh call fails.
//   node ministack-upstream.mjs draft-comment <service>
//     — PRINT a structured comment body + the exact `gh issue comment` command
//       (or a new-issue URL when there is no ref yet). NEVER posts. exit 0.
//
// See docs/MINISTACK-COMPAT.md for the query/comment/watch flow.

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AUTO_POST_UPSTREAM,
  UPSTREAM_REPO,
  draftCommentBody,
  formatOneClickUrl,
  formatPostCommand,
  formatRef,
  isValidServiceName,
  selectBestMatch,
} from './ministack-upstream.ts';

// Re-export the single gate so importers that read it via the .mjs still see it
// (the value lives in the tested .ts module).
export { AUTO_POST_UPSTREAM };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REGISTRY_PATH = path.resolve(
  __dirname,
  '../services/_registry/ministack-support.json',
);
const PIN_PATH = path.resolve(
  __dirname,
  '../services/_registry/ministack-pin.json',
);

// ── Thin I/O (NOT unit-tested; needs network / gh auth) ─────────────────────

/**
 * Run `gh search {issues,prs}` against the upstream repo for a service and
 * return parsed JSON. Argv array → execFileSync (no shell); the service name
 * is validated by the caller before it reaches here.
 * @param {string} kind 'issues' | 'prs'
 * @param {string} service
 * @returns {Array<object>}
 */
function ghSearch(kind, service) {
  const out = execFileSync(
    'gh',
    [
      'search',
      kind,
      '--repo',
      UPSTREAM_REPO,
      service,
      '--json',
      'number,title,url,state',
      '--limit',
      '20',
    ],
    { encoding: 'utf8' },
  );
  return JSON.parse(out || '[]');
}

/** Read the Axis-1 support registry. @returns {{services:Array<object>}} */
function readRegistry() {
  return JSON.parse(readFileSync(REGISTRY_PATH, 'utf8'));
}

/** Read the pinned MiniStack image digest, or a placeholder if unavailable. */
function readDigest() {
  try {
    const pin = JSON.parse(readFileSync(PIN_PATH, 'utf8'));
    return pin.digest ?? pin.imageDigest ?? '(unpinned)';
  } catch {
    return '(unpinned)';
  }
}

/** Find the registry row for a service, or throw a clear error. */
function findRow(registry, service) {
  const row = registry.services.find((r) => r.service === service);
  if (!row) {
    throw new Error(
      `service "${service}" is not in the registry (services/_registry/ministack-support.json)`,
    );
  }
  return row;
}

// ── Subcommands ─────────────────────────────────────────────────────────────

function cmdQuery(service) {
  const registry = readRegistry();
  const row = findRow(registry, service);

  let issues = [];
  let prs = [];
  try {
    issues = ghSearch('issues', service);
    prs = ghSearch('prs', service);
  } catch (err) {
    console.error(
      `query: upstream search failed (is gh authenticated?): ${
        err instanceof Error ? err.message : err
      }`,
    );
    process.exit(3);
  }

  const match = selectBestMatch(issues, prs, service);
  const ref = formatRef(match);

  if (ref === row.ministackRef) {
    console.log(
      `query: ${service} → ${ref ?? 'none'} (unchanged; registry already current)`,
    );
    return;
  }

  const previous = row.ministackRef;
  row.ministackRef = ref;
  writeFileSync(REGISTRY_PATH, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(
    `query: ${service} → ${ref ?? 'none'} (was ${previous ?? 'none'}); wrote ministack-support.json`,
  );
}

function cmdDraftComment(service) {
  const registry = readRegistry();
  const row = findRow(registry, service);
  const digest = readDigest();
  const body = draftCommentBody(row, digest);
  const ref = row.ministackRef;

  console.log('─'.repeat(72));
  console.log(`DRAFT upstream comment for "${service}" — NOT posted.`);
  console.log('─'.repeat(72));
  console.log('');
  console.log(body);
  console.log('');
  console.log('─'.repeat(72));
  if (ref) {
    console.log('To post it (copy-paste), a maintainer runs:');
    console.log('');
    console.log(`  ${formatPostCommand(ref, body)}`);
    console.log('');
    console.log(`Or open in a browser: ${formatOneClickUrl(ref)}`);
  } else {
    console.log(
      `No upstream ref yet for "${service}". A maintainer may open a new issue:`,
    );
    console.log('');
    console.log(`  Open in a browser: ${formatOneClickUrl(ref)}`);
    console.log(
      `  Then run \`ministack-upstream.mjs query ${service}\` to record the ref.`,
    );
  }
  console.log('─'.repeat(72));
  // The safety statement the test asserts on. This never auto-posts: the
  // AUTO_POST_UPSTREAM gate (default off) is the single point that would ever
  // enable it, and it is NOT read on this path.
  console.log(
    'This is human-gated: the harness will never auto-post to the upstream ' +
      'repo. Nothing was posted; a maintainer must run the command above.',
  );
}

// ── CLI entry (skipped when imported as a module) ────────────────────────────

function usage(stream = console.error) {
  stream(
    [
      'usage: ministack-upstream.mjs <command> <service>',
      '',
      '  query <service>         search upstream & write ministackRef (automated)',
      '  draft-comment <service> print a comment + post command (human-gated; NEVER posts)',
    ].join('\n'),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, service] = process.argv.slice(2);

  if (!command || !['query', 'draft-comment'].includes(command)) {
    usage();
    process.exit(2);
  }
  if (!isValidServiceName(service)) {
    console.error(`invalid service name: ${JSON.stringify(service ?? '')}`);
    usage();
    process.exit(2);
  }

  try {
    if (command === 'query') cmdQuery(service);
    else cmdDraftComment(service);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  }
}
