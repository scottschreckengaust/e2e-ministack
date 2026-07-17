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
//
// EXPORTED as the single source of truth for the suppression predicate: the
// scanner-dialect generator (`vex-dialects.ts`, #251) imports THIS set rather
// than re-deriving it, so trivy.yaml / osv-scanner.toml / the SARIF injector
// can never disagree on which statuses suppress (the `affected` mcp records
// must stay visible in every dialect — #188).
export const SUPPRESSING_STATUSES = new Set(['not_affected', 'fixed']);

/**
 * The vulnerability NAME from a statement's `vulnerability` field, which OpenVEX
 * allows as either a bare string or an object `{ name }`. A string is returned
 * as-is; anything else is read via `(v as {name?})?.name`, which yields the name
 * for an object and `undefined` for a primitive/null alike — so there is no
 * `typeof === 'object'` branch to leave an equivalent mutant. Returns undefined
 * when no usable name is present; `extractCve` then rejects it.
 */
function vulnerabilityName(v: VexStatement['vulnerability']): unknown {
  if (typeof v === 'string') return v;
  return (v as { name?: unknown } | undefined)?.name;
}

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
    // GUARD the statements loop with Array.isArray rather than a `: []` fallback
    // literal — no array literal to spawn an equivalent ArrayDeclaration mutant,
    // and the guard's false branch (a non-array `doc.statements` contributes
    // nothing) stays observable.
    if (!doc || !Array.isArray(doc.statements)) continue;
    for (const st of doc.statements) {
      // Only `!st` is load-bearing here: a primitive (string/number) statement
      // is truthy but reading `.status`/`.vulnerability` off it yields
      // `undefined`, so it's dropped by the checks below anyway — no separate
      // `typeof st !== 'object'` guard (that was the equivalent mutant).
      if (!st) continue;
      if (!SUPPRESSING_STATUSES.has(String(st.status))) continue;
      const name = vulnerabilityName(st.vulnerability);
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
 * A mutable SARIF-shaped base for `injectSuppressions` to write into: a
 * structured CLONE of a real SARIF object (so the caller's input is never
 * mutated), or a fresh `{ runs: [] }` for degenerate input (null/undefined, a
 * primitive, or an array — none of which is a SARIF log). Exported + unit-tested
 * directly so BOTH outcomes are observable: the clone is a distinct object that
 * still round-trips `runs`, and the fallback carries an empty `runs` array — so
 * neither the object-guard nor the `{ runs: [] }` literal leaves an equivalent
 * mutant (the previous inline form did, hence the disable this removes).
 */
export function sarifBase(sarif: unknown): SarifLogLike {
  if (sarif && typeof sarif === 'object' && !Array.isArray(sarif)) {
    return structuredClone(sarif) as SarifLogLike;
  }
  return { runs: [] };
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
  // A mutable SARIF-shaped base to write into — either a structured clone of a
  // real SARIF object (so the caller's input is never mutated) or a fresh
  // document for degenerate input. Extracted + tested directly (`sarifBase`)
  // so both the guard and the fallback are OBSERVABLE — no equivalent mutant.
  const out = sarifBase(sarif);
  // Normalize `runs` to an array so the OUTPUT is always a well-formed SARIF
  // document that uploads (a producer must not pass through a missing/garbage
  // `runs`). A non-array `runs` on input is replaced with an empty array.
  const runs: SarifRunLike[] = Array.isArray(out.runs)
    ? (out.runs as SarifRunLike[])
    : [];
  out.runs = runs;
  // A SARIF producer's output must be a valid SARIF 2.1.0 document — `version`
  // is schema-required (#187). Grype always sets it, but on degenerate input
  // (a non-SARIF object, or one missing `version`) the normalized result would
  // otherwise be schema-invalid and rejected at upload. Only fill it when
  // absent, so we never overwrite a producer's own value.
  if (typeof out.version !== 'string') out.version = '2.1.0';
  let covered = 0;
  const uncovered = new Set<string>();
  for (const run of runs) {
    // Only `!run` is load-bearing (a null run would throw on `.results`). A
    // primitive run is truthy but its `.results` is undefined, so the next
    // `!Array.isArray` guard drops it — no separate `typeof run !== 'object'`
    // check (that was the equivalent mutant).
    if (!run) continue;
    if (!Array.isArray(run.results)) continue;
    for (const res of run.results as SarifResultLike[]) {
      // BOTH halves are load-bearing here (unlike the `run` guard above): a
      // primitive `res` reaches the `res.suppressions = []` write below, which
      // THROWS on a number/string — so the `typeof res !== 'object'` half is
      // observable (killed by the null/non-object-result test), not equivalent.
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
