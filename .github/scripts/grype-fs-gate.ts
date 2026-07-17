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
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `grype-fs-gate.mjs` shim. TOTAL: malformed input yields an empty (pass)
// result, never throws.

// -- small total coercions (exported + unit-tested directly, mutation-tight,
//    mirroring the identical helpers in gate-findings.ts / sarif-cve-ids.ts) --

/** The value if it's an array, else an empty array. */
export function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** A plain object, or null. Arrays and primitives are NOT records. */
export function asRecord(v: unknown): Record<string, unknown> | null {
  if (typeof v !== 'object') return null;
  if (Array.isArray(v)) return null;
  return v as Record<string, unknown> | null;
}

/**
 * A vulnerability identifier normalized for set membership: upper-cased and
 * trimmed. Non-strings and empty/whitespace-only values yield null (totality) —
 * matching by an empty token would falsely equate unrelated blank ids. We do
 * NOT restrict to a CVE regex: grype's primary id and the `.vex/` aliases are
 * frequently GHSAs, and the whole point of #284 is to map GHSA↔CVE, so both id
 * shapes must survive normalization.
 */
export function normId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const t = value.trim().toUpperCase();
  return t.length > 0 ? t : null;
}

/**
 * The set of vulnerability ids ACCEPTED by the `.vex/` records — the union of
 * every statement's `vulnerability.name` AND its `vulnerability.aliases[]`,
 * normalized. Includes BOTH `affected` and `not_affected` records: each is an
 * explicit, reviewed risk acceptance (#188), so both should keep the FS gate
 * green. Malformed docs/statements/vulns are skipped; never throws.
 */
export function vexAcceptedIds(docs: readonly unknown[]): Set<string> {
  const ids = new Set<string>();
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    for (const rawStmt of asArray(doc.statements)) {
      const stmt = asRecord(rawStmt);
      if (stmt === null) continue;
      const vuln = asRecord(stmt.vulnerability);
      if (vuln === null) continue;
      const name = normId(vuln.name);
      if (name !== null) ids.add(name);
      for (const rawAlias of asArray(vuln.aliases)) {
        const alias = normId(rawAlias);
        if (alias !== null) ids.add(alias);
      }
    }
  }
  return ids;
}

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

// Severities at or above the gate's `high` floor. A Set (not a comparison
// operator) so there is no `>=`/`>` boundary for Stryker to flip into an
// equivalent survivor — membership is the honest test.
const HIGH_PLUS = new Set(['HIGH', 'CRITICAL']);

/**
 * Whether a grype `matches[]` entry is at or above the `high` severity floor.
 * Reads `vulnerability.severity` (grype Title-case: High/Critical/…),
 * case-insensitively. Missing/garbage severity is below the floor (false).
 */
export function isHighPlus(match: unknown): boolean {
  const m = asRecord(match);
  if (m === null) return false;
  const vuln = asRecord(m.vulnerability);
  if (vuln === null) return false;
  const sev = vuln.severity;
  if (typeof sev !== 'string') return false;
  return HIGH_PLUS.has(sev.toUpperCase());
}

/**
 * The GATE DECISION: the sorted, de-duplicated list of high+ vulnerability ids
 * in a grype JSON document (`grype -o json`) that are NOT covered by any `.vex/`
 * record. An empty list means the gate PASSES; a non-empty list means it FAILS
 * (each id is a genuinely-new, uncovered high+ finding — VEX-accept it or fix
 * it). A match is COVERED iff any of its ids (primary + related) is in the
 * accepted set, so an `affected` mcp record (reported by its GHSA, CVE in
 * related) is correctly treated as accepted.
 *
 * The reported id for an uncovered match is its primary `vulnerability.id`
 * (falling back to the first related id, then `(unknown)`), so the workflow log
 * names the actionable CVE/GHSA. TOTAL: malformed JSON yields an empty list.
 */
export function uncoveredHighVulns(
  grypeJson: unknown,
  accepted: ReadonlySet<string>,
): string[] {
  const uncovered = new Set<string>();
  const doc = asRecord(grypeJson);
  if (doc === null) return [];
  for (const rawMatch of asArray(doc.matches)) {
    if (!isHighPlus(rawMatch)) continue;
    const ids = matchVulnIds(rawMatch);
    // Covered iff ANY of the match's ids (primary or related) is accepted.
    let covered = false;
    for (const id of ids) {
      if (accepted.has(id)) {
        covered = true;
        break;
      }
    }
    if (covered) continue;
    // Report the primary id when known (the first inserted), else "(unknown)".
    const [first] = ids;
    uncovered.add(first ?? '(unknown)');
  }
  return [...uncovered].sort();
}
