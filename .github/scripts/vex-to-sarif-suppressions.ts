// Inject OpenVEX-derived `suppressions[]` into a scanner's SARIF 2.1.0 document,
// so a VEX-accepted CVE surfaces in the GitHub Security tab as a *dismissed*
// alert coupled to its `.vex/` record — not as permanent red noise, and not as
// a manual "Dismiss" that silently outlives the record (issue #181).
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `vex-to-sarif-suppressions.mjs` shim, which imports `injectSuppressions` from
// here — Node 24 strips the `.ts` on import, so the workflow call
// `node .github/scripts/vex-to-sarif-suppressions.mjs <sarif> <out> <.vex/*.json...>`
// works with no build step.
//
// WHY this exists (see docs/SECURITY-TOOLING.md § "VEX -> Code Scanning"):
//   - Grype/Trivy, when fed VEX, DROP the covered CVE from their SARIF entirely
//     (verified: grype's SARIF presenter iterates only `Matches`, never
//     `IgnoredMatches`; trivy's `--show-suppressed` is JSON/table only). So a
//     VEX-covered CVE simply vanishes from the Security tab — no audit trail.
//   - GitHub does NOT act on `result.suppressions[]` at ingest (proven live on
//     issue #181: an uploaded suppression left the alert OPEN). The post-upload
//     `advanced-security/dismiss-alerts` Action reads `suppressions[]` and
//     PATCHes matching alerts to dismissed / re-opens ones whose suppression
//     disappeared. This module produces the `suppressions[]` that Action needs.
//   - kind:"external" is the SARIF §3.35.2 value for "suppressed in an external,
//     persistent store" — which is exactly what a `.vex/` OpenVEX record is.
//   - SARIF §3.27.23 is ALL-OR-NOTHING per run: every result must carry the
//     `suppressions` array (possibly empty) or none may. We therefore emit
//     `suppressions: []` on non-covered results so that DROPPING a `.vex/`
//     record cleanly flips a result from suppressed->unsuppressed on the next
//     scan, which `dismiss-alerts` turns into a re-opened alert.
//
// The transform is TOTAL: it never throws on malformed SARIF/VEX input (the
// fuzz-regression tier enforces this) and always returns a well-formed document.

/** The subset of an OpenVEX statement this module reads. */
export interface VexStatement {
  vulnerability?: { name?: string } | string;
  status?: string;
  justification?: string;
  impact_statement?: string;
}

/** The subset of an OpenVEX document this module reads. */
export interface VexDoc {
  statements?: VexStatement[];
}

/** A SARIF suppression object (SARIF §3.35), the subset we emit. */
export interface SarifSuppression {
  kind: 'external';
  justification: string;
}

/** Minimal shape of the SARIF pieces we read/write. Unknown fields pass through. */
export interface SarifResultLike {
  ruleId?: unknown;
  suppressions?: SarifSuppression[];
  [k: string]: unknown;
}
export interface SarifRunLike {
  results?: unknown;
  [k: string]: unknown;
}
export interface SarifLogLike {
  runs?: unknown;
  [k: string]: unknown;
}

// A CVE identifier: `CVE-<year>-<digits>`. Used to pull the CVE token out of a
// scanner rule id (grype: `CVE-2026-0864-python`; trivy: bare `CVE-2026-0864`)
// and out of a VEX `vulnerability.name`, so matching is scanner-agnostic and
// immune to package-suffix / purl-qualifier differences.
const CVE_RE = /CVE-\d{4}-\d+/i;

/**
 * Extract the canonical (upper-case) CVE token from an arbitrary string, or
 * null if none is present. Non-string input yields null (totality).
 */
export function extractCve(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const m = CVE_RE.exec(value);
  return m ? m[0].toUpperCase() : null;
}

// A VEX statement suppresses a finding only when its status is one GitHub's
// consumers (and grype/trivy) treat as "not a live finding". Mirrors the
// scanner filters: `not_affected` and `fixed` (see .vex/README.md § "Why
// not_affected"). Any other status (e.g. `affected`, `under_investigation`)
// does NOT suppress.
const SUPPRESSING_STATUSES = new Set(['not_affected', 'fixed']);

/**
 * Build a map of CVE -> suppression justification text from the given VEX docs.
 * Only `not_affected`/`fixed` statements contribute. The justification string
 * combines the VEX `justification` enum and `impact_statement` prose so the
 * dismissed alert carries the honest, per-CVE accepted-risk rationale.
 * Later docs win on a duplicate CVE (deterministic, last-wins).
 */
export function collectSuppressions(
  vexDocs: readonly VexDoc[],
): Map<string, string> {
  const map = new Map<string, string>();
  if (!Array.isArray(vexDocs)) return map;
  for (const doc of vexDocs) {
    // Stryker disable ArrayDeclaration: the `: []` fallback is EQUIVALENT to any
    // other array here — a non-array `doc.statements` yields an iterable whose
    // elements are all skipped by the `!st || typeof st !== 'object'` guard
    // below, so the output is identical regardless of the array's contents.
    const statements =
      doc && Array.isArray(doc.statements) ? doc.statements : [];
    // Stryker restore ArrayDeclaration
    for (const st of statements) {
      // Stryker disable next-line ConditionalExpression: the `typeof st !== 'object'`
      // half is EQUIVALENT — a truthy NON-object statement (string/number) has no
      // `.status`/`.vulnerability`, so dropping this half still yields no
      // suppression. The `!st` half IS load-bearing (killed by the null-statement
      // test); only the object-typecheck is unobservable.
      if (!st || typeof st !== 'object') continue;
      if (!SUPPRESSING_STATUSES.has(String(st.status))) continue;
      const name =
        typeof st.vulnerability === 'string'
          ? st.vulnerability
          : // Stryker disable next-line ConditionalExpression: forcing this
            // typeof-object check to `true` is EQUIVALENT — it is reached only
            // when `st.vulnerability` is truthy and not a string; a truthy
            // non-object (number/boolean) has an `undefined` `.name` either way.
            st.vulnerability && typeof st.vulnerability === 'object'
            ? st.vulnerability.name
            : undefined;
      const cve = extractCve(name);
      if (!cve) continue;
      const justification =
        typeof st.justification === 'string' && st.justification !== ''
          ? st.justification
          : 'vex_not_affected';
      const impact =
        typeof st.impact_statement === 'string' && st.impact_statement !== ''
          ? ` — ${st.impact_statement}`
          : '';
      map.set(cve, `VEX ${String(st.status)} (${justification})${impact}`);
    }
  }
  return map;
}

/**
 * Return a SARIF document with `suppressions[]` injected on every result whose
 * rule id carries a CVE covered by a suppressing VEX statement, and an EMPTY
 * `suppressions: []` on every other result (SARIF §3.27.23 all-or-nothing).
 *
 * The input is not mutated. Malformed structures are tolerated: a run without a
 * results array is passed through unchanged; every result is normalized to the
 * VEX-derived suppression when covered, else forced to `[]`.
 *
 * Returns `{ sarif, covered, uncoveredCves }` — `covered` counts injected
 * suppressions; `uncoveredCves` lists the distinct CVEs still un-suppressed
 * (the gate signal: a non-empty list means a high+ CVE lacks a `.vex/` record).
 */
export function injectSuppressions(
  sarif: SarifLogLike,
  vexDocs: readonly VexDoc[],
): { sarif: SarifLogLike; covered: number; uncoveredCves: string[] } {
  const suppMap = collectSuppressions(vexDocs);
  // Structured-clone so callers' input is never mutated (totality/safety).
  //
  // Stryker disable ConditionalExpression,ObjectLiteral: two EQUIVALENT mutants
  // live in this expression. (1) forcing `typeof sarif === 'object'` to `true`:
  // for a truthy non-object, non-array input (string/number) both branches
  // yield a document normalized to `runs: []` by the guard just below, so the
  // output is identical — the `sarif` (null/undefined) and `!Array.isArray`
  // halves ARE load-bearing (killed by the totality test's null / array cases).
  // (2) `{}` vs `{ runs: [] }`: `out.runs` is unconditionally normalized to an
  // array on the next lines, so the initial `runs` value is overwritten anyway.
  const out: SarifLogLike =
    sarif && typeof sarif === 'object' && !Array.isArray(sarif)
      ? structuredClone(sarif)
      : { runs: [] };
  // Stryker restore ConditionalExpression,ObjectLiteral
  // Normalize `runs` to an array so the OUTPUT is always a well-formed SARIF
  // document that uploads (a producer must not pass through a missing/garbage
  // `runs`). A non-array `runs` on input is replaced with an empty array.
  const runs: SarifRunLike[] = Array.isArray(out.runs)
    ? (out.runs as SarifRunLike[])
    : [];
  out.runs = runs;
  let covered = 0;
  const uncovered = new Set<string>();
  for (const run of runs) {
    // Stryker disable next-line ConditionalExpression: the `typeof run !==
    // 'object'` half is EQUIVALENT — a truthy non-object run element
    // (string/number) has a non-array `.results`, so the very next
    // `!Array.isArray(run.results)` guard `continue`s on it regardless. The
    // `!run` half IS load-bearing (killed by the null-run totality case).
    if (!run || typeof run !== 'object') continue;
    if (!Array.isArray(run.results)) continue;
    for (const res of run.results as SarifResultLike[]) {
      if (!res || typeof res !== 'object') continue;
      const cve = extractCve(res.ruleId);
      const justification = cve ? suppMap.get(cve) : undefined;
      if (justification) {
        res.suppressions = [{ kind: 'external', justification }];
        covered += 1;
      } else {
        // Not covered -> explicit empty array so a later scan can flip it back
        // to suppressed (and dismiss-alerts can re-open) deterministically.
        res.suppressions = [];
        if (cve) uncovered.add(cve);
      }
    }
  }
  return { sarif: out, covered, uncoveredCves: [...uncovered].sort() };
}
