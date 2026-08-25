// Derive the Grype FILESYSTEM scan's gate from its JSON output, VEX-aware for
// BOTH `affected` and `not_affected` records (issue #284).
//
// WHY (#284): the `Grype FS scan` job was `fail-build: true` and fed the whole
// `.vex/` set via `GRYPE_VEX_DOCUMENTS`. Grype only moves `not_affected`/`fixed`
// records to `ignoredMatches[]`; an `affected` record STAYS in `matches[]` (its
// `AugmentMatches` even re-surfaces it — proven in #160). So once grype's
// floating DB began rating the 3 mcp GHSAs high, the 3 deliberately-`affected`
// `.vex/mcp-CVE-*.openvex.json` records (#188 status-honesty: the MCP
// server-transport code is reachable-but-not-exercised) could not suppress the
// finding, and the REQUIRED FS gate went red on `main` and every PR.
//
// THE FIX (Option 3, maintainer-recommended) mirrors the `ministack-image`
// Grype job: run the action with `fail-build: false` (SARIF still uploads to the
// Security tab, so findings stay VISIBLE) and derive the gate from the JSON
// here. But the image job's gate is a bare "count high+ in `matches[]`" — that
// works there ONLY because every accepted image CVE is `not_affected` and thus
// already in `ignoredMatches[]`. On the FS surface the accepted mcp records are
// `affected`, so this module must ADDITIONALLY exclude the `.vex/`-accepted id
// set: an `affected` record is an explicit, REVIEWED acceptance exactly as a
// `not_affected` one is. The gate then fails ONLY on a high+ finding NOT covered
// by ANY `.vex/` record — the genuinely-new, actionable signal — which does NOT
// weaken security: it makes the FS scan consistent with the image scan.
//
// GHSA↔CVE ALIASING (the crux): grype may report the GHSA as the primary
// `vulnerability.id` and carry the CVE in `relatedVulnerabilities[]` (or vice
// versa). The `.vex/` records name the CVE in `vulnerability.name` and alias the
// GHSA in `vulnerability.aliases[]`. So we (a) build the accepted set as the
// UNION of every record's name + aliases, and (b) test a match against the UNION
// of its own primary id + related ids. A match is covered iff those two sets
// intersect — mapping either aliasing direction onto the accepted set.
//
// SURFACE SCOPING (#337): an id match alone is NOT coverage. Every `.vex/`
// record argues about ONE product, and matching by identifier alone let an
// image-scoped record (e.g. the Debian `node-brace-expansion` inside the pinned
// MiniStack image) silently suppress a same-CVE finding on a DIFFERENT surface —
// the `pkg:npm/brace-expansion` copy in this repo's own tree. That is
// over-suppression, the one direction this repo's posture forbids (#335 C2). So
// the gate now compares the record's product purl against each match's
// `artifact.purl` via the shared ledger's `isCovered`. A match whose purl is
// missing or unparseable is NEVER covered (fail-closed): without a purl the
// surface is unprovable, and the honest verdict is to surface the finding.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `grype-fs-gate.mjs` shim. TOTAL: malformed input yields an empty (pass)
// result, never throws.

// EXPLICIT `.ts` extension: a runtime VALUE cross-import between two
// `.github/scripts` siblings (as in vex-dialects.ts → vex-to-sarif-suppressions.ts
// and npm-audit-gate.ts → vex-ledger.ts). The `.mjs` shim runs this under Node
// 24's type-stripping loader, which resolves ONLY an explicit specifier naming an
// existing file — a `.js` sibling does not exist on a clean checkout (it's a
// gitignored tsc artifact) and an extensionless specifier fails. tsc accepts the
// `.ts` under `allowImportingTsExtensions` (tsconfig.scripts.json, noEmit); the
// emitting tsconfig.json excludes `.github/scripts/**/*.ts` AND this module's
// test importers, so no shadowing `.js` is ever emitted.
import {
  asArray,
  asRecord,
  normId,
  parsePurl,
  isCovered,
  type Purl,
  type Acceptance,
} from './vex-ledger.ts';

// The total coercions this module used to carry its own copies of now come from
// the shared ledger (the migration its header promised, #295) — re-exported here
// so the unit/fuzz tiers keep asserting this module's contract directly and the
// two surfaces can never drift apart on what a record id even is.
export { asArray, asRecord, normId };

/**
 * Every id a single grype `matches[]` entry is known by: its primary
 * `vulnerability.id` plus every `relatedVulnerabilities[].id`, normalized. This
 * is what carries the GHSA↔CVE aliasing — grype routinely lists the CVE as a
 * related vulnerability of a GHSA primary (and vice versa). Malformed structures
 * contribute nothing; never throws.
 */
export function matchVulnIds(match: unknown): Set<string> {
  const ids = new Set<string>();
  const m = asRecord(match);
  if (m === null) return ids;
  const vuln = asRecord(m.vulnerability);
  if (vuln !== null) {
    const primary = normId(vuln.id);
    if (primary !== null) ids.add(primary);
  }
  for (const rawRel of asArray(m.relatedVulnerabilities)) {
    const rel = asRecord(rawRel);
    if (rel === null) continue;
    const id = normId(rel.id);
    if (id !== null) ids.add(id);
  }
  return ids;
}

/**
 * Whether a grype `matches[]` entry has a real (string) severity — i.e. is a
 * bona-fide finding the STRICTEST gate should evaluate (#284, "drop it the most
 * strict"). The gate floor is grype's LOWEST rung (`negligible`), so EVERY
 * severity counts (negligible/low/medium/high/critical) — there is no
 * severity-membership test to mutate. WHY the floor lives here, not in grype's
 * `severity-cutoff`: proven empirically (PR #285 review) that grype's
 * `--fail-on`/`severity-cutoff` only sets the process EXIT CODE — it does NOT
 * filter the JSON `matches[]` or the SARIF results (a Medium finding is present
 * at `--fail-on high` and `--fail-on critical` alike). Since the gate reads
 * `fail-build: false` and derives the verdict from the JSON, this predicate is
 * the operative floor. Only a missing/non-string severity is excluded (a
 * degenerate record that isn't an actionable finding), which keeps the function
 * total and the `typeof` guard observable.
 */
export function hasSeverity(match: unknown): boolean {
  const m = asRecord(match);
  if (m === null) return false;
  const vuln = asRecord(m.vulnerability);
  if (vuln === null) return false;
  return typeof vuln.severity === 'string';
}

/**
 * The purl of the package a grype `matches[]` entry was found on — the SURFACE
 * a `.vex/` record must argue about to cover it (#337). Grype builds this with
 * packageurl-go, so it is already canonical: `pkg:npm/brace-expansion@2.0.1` for
 * a lockfile entry, `pkg:pypi/ecdsa@0.19.2` for a pip requirement,
 * `pkg:deb/debian/...` for an image package. Returns null when the match carries
 * no artifact or no parseable purl, which callers must treat as NOT coverable.
 */
export function matchPurl(match: unknown): Purl | null {
  const m = asRecord(match);
  if (m === null) return null;
  const artifact = asRecord(m.artifact);
  if (artifact === null) return null;
  return parsePurl(artifact.purl);
}

/**
 * The GATE DECISION: the sorted, de-duplicated list of vulnerability ids in a
 * grype JSON document (`grype -o json`), AT ANY SEVERITY (strictest floor,
 * #284), that are NOT covered by any `.vex/` record. An empty list means the
 * gate PASSES; a non-empty list means it FAILS (each id is a genuinely-new,
 * uncovered finding — VEX-accept it with a truthful record or fix it).
 *
 * A match is COVERED iff some SINGLE acceptance both (a) shares one of the
 * match's ids (primary or related, so an `affected` mcp record reported by its
 * GHSA with the CVE in `relatedVulnerabilities` still counts) and (b) names a
 * product purl that matches the match's `artifact.purl` (#337, so an
 * image-scoped record cannot reach a repo-tree finding on the same CVE).
 *
 * The reported id for an uncovered match is its primary `vulnerability.id`
 * (falling back to the first related id, then `(unknown)`), so the workflow log
 * names the actionable CVE/GHSA. TOTAL: malformed JSON yields an empty list.
 */
export function uncoveredVulns(
  grypeJson: unknown,
  acceptances: readonly Acceptance[],
): string[] {
  const uncovered = new Set<string>();
  const doc = asRecord(grypeJson);
  if (doc === null) return [];
  for (const rawMatch of asArray(doc.matches)) {
    if (!hasSeverity(rawMatch)) continue;
    const ids = matchVulnIds(rawMatch);
    if (isCovered(acceptances, ids, matchPurl(rawMatch))) continue;
    // Report the primary id when known (the first inserted), else "(unknown)".
    const [first] = ids;
    uncovered.add(first ?? '(unknown)');
  }
  return [...uncovered].sort();
}
