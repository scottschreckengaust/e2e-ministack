#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — this and
// .github/scripts/license-verdict.mjs are the only standalone Node scripts it
// lints, so declare the globals inline rather than widening eslint.config.mjs.)
//
// Upstream MiniStack tracking (#137, sub-issue C of epic #117).
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
// The maintainer has explicitly chosen to START GATED and expand
// write-automation later once comfortable. So the write path is structured so
// that enabling auto-post later is a SINGLE, well-marked flag flip:
// `AUTO_POST_UPSTREAM` below (default off). Do NOT flip it without maintainer
// sign-off; the never-auto-post property is locked by a unit test
// (test/unit/ministack-upstream.test.ts).
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

// ── The single gate ────────────────────────────────────────────────────────
// #137: this is the ONE place a future maintainer would flip to enable
// auto-posting to the foreign repo. Flipping to true is a deliberate,
// documented policy change — do NOT flip it without maintainer sign-off.
// While false, `draft-comment` only PRINTS a command for a human to run.
export const AUTO_POST_UPSTREAM = false;

const UPSTREAM_REPO = 'ministackorg/ministack';

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

// ── Pure helpers (unit-tested offline; no network) ──────────────────────────

/**
 * A service key must be a safe, stable token so it can never inject shell
 * metacharacters into a child_process call (defense-in-depth — we already use
 * argv arrays, not a shell). Matches the registry's `service` convention:
 * lowercase letters, digits and single dashes (e.g. `lambda`, `rds-postgres`).
 * @param {unknown} name
 * @returns {boolean}
 */
export function isValidServiceName(name) {
  return typeof name === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name);
}

/**
 * Format a single `gh search` result as an `owner/repo#N` tracking ref, or
 * null when there is no match.
 * @param {{ number: number } | null | undefined} match
 * @returns {string | null}
 */
export function formatRef(match) {
  if (!match || typeof match.number !== 'number') return null;
  return `${UPSTREAM_REPO}#${match.number}`;
}

/**
 * Choose the best upstream match for a service from `gh search` payloads.
 * Ranking (higher wins): a title hit outranks a non-title hit; among equal
 * title-hits an OPEN item outranks a CLOSED one; ties break to the LOWEST issue
 * number (the earliest/canonical tracking item). Returns null when nothing
 * mentions the service at all.
 *
 * The inputs are the parsed JSON of
 *   gh search issues --repo <repo> "<service>" --json number,title,url,state
 *   gh search prs    --repo <repo> "<service>" --json number,title,url,state
 * kept OUT of this function (thin I/O lives in fetchUpstreamMatches) so the
 * ranking is unit-tested offline against a fixture.
 *
 * @param {Array<{number:number,title:string,url:string,state:string}>} issues
 * @param {Array<{number:number,title:string,url:string,state:string}>} prs
 * @param {string} service
 * @returns {{number:number,title:string,url:string,state:string} | null}
 */
export function selectBestMatch(issues, prs, service) {
  const needle = String(service).toLowerCase();
  const candidates = [...(issues ?? []), ...(prs ?? [])].filter(
    (r) => r && typeof r.number === 'number',
  );
  if (candidates.length === 0) return null;

  const scored = candidates
    .map((r) => {
      const title = String(r.title ?? '').toLowerCase();
      // A candidate must actually mention the service to count as a match.
      const titleHit = title.includes(needle);
      return { r, titleHit, open: String(r.state).toLowerCase() === 'open' };
    })
    // gh already searched for the term, but be defensive: require a title hit.
    .filter((c) => c.titleHit);

  if (scored.length === 0) return null;

  scored.sort((a, b) => {
    if (a.open !== b.open) return a.open ? -1 : 1; // OPEN first
    return a.r.number - b.r.number; // then lowest (earliest) number
  });
  return scored[0].r;
}

/**
 * Draft the structured comment body for a service: what MiniStack digest it
 * was verified against, the current registry verdict, and the ask. This is the
 * text a maintainer would post — the script only PRINTS it.
 * @param {{service:string,status:string,ministackRef:string|null}} row
 * @param {string} digest the pinned MiniStack image digest
 * @returns {string}
 */
export function draftCommentBody(row, digest) {
  const ref = row.ministackRef;
  const ask = ref
    ? `Is there an ETA or a way we can help move ${row.service} forward? We track it against your issue ${ref}.`
    : `Would you consider tracking ${row.service} emulation? We didn't find an existing issue/PR for it.`;
  return [
    `Hi from the [e2e-ministack](https://github.com/scottschreckengaust/e2e-ministack) compatibility harness 👋`,
    ``,
    `- **Service:** \`${row.service}\``,
    `- **Our verdict:** \`${row.status}\``,
    `- **Verified against MiniStack digest:** \`${digest}\``,
    ref ? `- **Upstream ref:** ${ref}` : `- **Upstream ref:** none found yet`,
    ``,
    `**Ask:** ${ask}`,
    ``,
    `_This message was drafted by an automated harness but posted manually by a maintainer — replies are read by a human._`,
  ].join('\n');
}

/**
 * The exact copy-pasteable command a maintainer runs to post the drafted
 * comment on an EXISTING upstream ref. The script PRINTS this; it never runs
 * it (while AUTO_POST_UPSTREAM is false).
 * @param {string} ref owner/repo#N
 * @param {string} body the drafted comment body
 * @returns {string}
 */
export function formatPostCommand(ref, body) {
  // Single-quote the body for a POSIX shell so the maintainer can paste it
  // verbatim; escape embedded single quotes the standard way.
  const quoted = `'${String(body).replace(/'/g, `'\\''`)}'`;
  return `gh issue comment ${ref} --repo ${UPSTREAM_REPO} --body ${quoted}`;
}

/**
 * A one-click browser URL: the existing upstream issue (to comment on) when a
 * ref exists, otherwise the "new issue" page on the upstream repo.
 * @param {string|null} ref owner/repo#N
 * @returns {string}
 */
export function formatOneClickUrl(ref) {
  if (ref) {
    const n = ref.split('#')[1];
    return `https://github.com/${UPSTREAM_REPO}/issues/${n}`;
  }
  return `https://github.com/${UPSTREAM_REPO}/issues/new`;
}

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
