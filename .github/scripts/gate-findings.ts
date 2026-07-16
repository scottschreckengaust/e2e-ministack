// Extract each scanner's GATE (distro-adjusted) severity per CVE from its
// structured JSON output — the input for the VEX report's gate-vs-badge
// severity column (#208).
//
// WHY (#208, #181): the report's existing severity is the BADGE severity —
// GitHub's `rule.security_severity_level`, which is NVD-derived. That diverges
// sharply from a scanner's own DISTRO/GATE rating for exactly the base-image
// CVEs this repo VEX-accepts: e.g. CVE-2019-1010022 on libc6 is NVD `Critical`
// but grype/trivy (following Debian's tracker) rate it `Negligible`/`LOW`.
// Showing only the badge overstates risk; showing both makes the acceptance
// legible at a glance. The gate severity has NO union API (unlike the badge,
// which the Code Scanning Alerts API already merges across scanners) — it is
// inherently per-tool JSON, so this module carries tool-shaped parsers.
//
// SOURCED FROM STRUCTURED JSON (a real field), NEVER SARIF-message-scraping
// (a rejected dead-end — version-brittle, the opposite of the tool-agnostic
// design). grype: `matches[].vulnerability.{id, severity}` (Title-case:
// High/Negligible/…). trivy: `Results[].Vulnerabilities[].{VulnerabilityID,
// Severity}` (UPPER-case: HIGH/…). Both normalize to the report's shared
// severity vocabulary.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `gate-findings.mjs` shim. TOTAL: malformed input yields an empty map, never
// throws.

// The report's severity vocabulary (mirrors vex-report.ts's SEV_RANK keys).
// Normalization is case-insensitive; anything unrecognized becomes UNKNOWN.
const SEV_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NEGLIGIBLE: 1,
  UNKNOWN: 0,
};

/** A gate severity normalized to a known keyword, or UNKNOWN. Case-insensitive
 *  so grype's `Negligible` and trivy's `HIGH` both land on the shared vocab. */
export function normGateSeverity(s: unknown): string {
  if (typeof s !== 'string') return 'UNKNOWN';
  const up = s.toUpperCase();
  return up in SEV_RANK ? up : 'UNKNOWN';
}

/** Rank of an ALREADY-NORMALIZED severity. Total by construction. */
function rankOf(normalizedSev: string): number {
  return SEV_RANK[normalizedSev];
}

// Reverse of SEV_RANK: rank index -> canonical severity name. Lets `addSeverity`
// pick the higher rating with `Math.max` (no comparison OPERATOR to mutate) and
// map the winning rank straight back to its name — sidestepping the equivalent
// `>`/`>=` mutant a string comparison would carry (rank<->name is a bijection,
// so equal ranks always write the same string; Stryker can't observe the
// boundary, leaving a false-positive survivor).
const RANK_NAME = [
  'UNKNOWN',
  'NEGLIGIBLE',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
];

// A CVE identifier. Each logic module carries its OWN copy of this regex rather
// than importing one at runtime — the repo convention (vex-report.ts,
// alerts-findings.ts, sarif-cve-ids.ts each define their own) that keeps every
// module self-contained so its thin `.mjs` shim resolves under bare Node with
// no cross-`.ts` runtime import to break.
const CVE_RE = /CVE-\d{4}-\d+/i;

/** The canonical (upper-case) CVE token inside an arbitrary value, or null.
 *  Non-string input yields null (totality) — the typeof guard is load-bearing:
 *  a `['CVE-2026-1']` array would otherwise coerce through `RegExp.exec`. */
export function extractCve(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const m = CVE_RE.exec(value);
  return m !== null ? m[0].toUpperCase() : null;
}

// -- small total coercions (exported + unit-tested directly, mutation-tight,
//    mirroring the identical helpers in alerts-findings.ts / sarif-cve-ids.ts) --

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

// Fold one CVE-to-severity observation into the accumulator, keeping the HIGHER
// rank when a CVE is seen more than once (across scanners, or across a CVE's
// multiple package matches). MAX so the report shows the worst gate rating any
// scanner assigned — the honest ceiling, never diluted by a lower duplicate.
function addSeverity(
  into: Map<string, string>,
  cve: string,
  normalized: string,
): void {
  // On first sight the "previous" rank defaults to the INCOMING rank, so
  // `Math.max` yields the incoming (the value always wins on first insert); on a
  // duplicate the higher of stored-vs-incoming is kept. Both branches of the
  // `has` guard are observable — forcing it true corrupts the first insert
  // (into.get is undefined -> NaN rank), forcing it false loses the max-keeping
  // on a lower-later duplicate. `Math.max` carries no comparison OPERATOR to
  // mutate, and RANK_NAME maps the winning rank back to its canonical string.
  const incoming = rankOf(normalized);
  const prevRank = into.has(cve) ? rankOf(into.get(cve) as string) : incoming;
  into.set(cve, RANK_NAME[Math.max(prevRank, incoming)]);
}

/**
 * Parse a GRYPE JSON document (`grype -o json`) into CVE-to-gate-severity.
 * Reads `matches[].vulnerability.{id, severity}`. Malformed structures are
 * skipped; never throws.
 */
export function parseGrypeGate(grype: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const doc = asRecord(grype);
  if (doc === null) return out;
  for (const rawMatch of asArray(doc.matches)) {
    const match = asRecord(rawMatch);
    if (match === null) continue;
    const vuln = asRecord(match.vulnerability);
    if (vuln === null) continue;
    const cve = extractCve(vuln.id);
    if (cve === null) continue;
    addSeverity(out, cve, normGateSeverity(vuln.severity));
  }
  return out;
}

/**
 * Parse a TRIVY JSON document (`trivy image --format json`) into
 * CVE-to-gate-severity. Reads `Results[].Vulnerabilities[].{VulnerabilityID,
 * Severity}`. Malformed structures are skipped; never throws.
 */
export function parseTrivyGate(trivy: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const doc = asRecord(trivy);
  if (doc === null) return out;
  for (const rawResult of asArray(doc.Results)) {
    const result = asRecord(rawResult);
    if (result === null) continue;
    for (const rawVuln of asArray(result.Vulnerabilities)) {
      const vuln = asRecord(rawVuln);
      if (vuln === null) continue;
      const cve = extractCve(vuln.VulnerabilityID);
      if (cve === null) continue;
      addSeverity(out, cve, normGateSeverity(vuln.Severity));
    }
  }
  return out;
}

/**
 * Merge several already-parsed gate-severity maps into one, keeping the HIGHER
 * rank per CVE (so the union reflects the worst gate rating across scanners).
 * The single place grype's + trivy's maps combine into what `buildReport`
 * joins by CVE id.
 */
export function mergeGateSeverities(
  maps: readonly (ReadonlyMap<string, string> | null | undefined)[],
): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of asArray(maps) as (ReadonlyMap<string, string> | null)[]) {
    // `m?.forEach` covers null/undefined AND anything lacking a forEach (a
    // non-Map junk entry) in ONE guard — no redundant `m === null` clause (that
    // was an unkillable-equivalent mutant, since optional chaining already
    // short-circuits null to `undefined !== 'function'`).
    if (typeof m?.forEach !== 'function') continue;
    m.forEach((sev, cve) => addSeverity(out, cve, sev));
  }
  return out;
}
