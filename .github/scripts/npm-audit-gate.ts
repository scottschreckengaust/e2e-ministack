// Derive the `npm audit` gate from its JSON output, VEX-aware against the ONE
// canonical `.vex/` ledger (issue #295). The npm-audit sibling of
// `grype-fs-gate.ts` (#284) — same JSON-derived-gate model, so an advisory this
// repo cannot fix (e.g. a dep BUNDLED inside aws-cdk-lib, which `overrides`
// provably cannot rewrite) can be honestly accepted with a `.vex/` record
// instead of leaving `npm audit` permanently red or reaching for a per-ID
// blanket-ignore (the anti-pattern AGENTS.md forbids).
//
// WHY a JSON-derived gate (not a native suppression): `npm audit` has NO native
// VEX/allowlist/exception channel. Today CI runs raw `npm audit
// --audit-level=high; test exit=0`. This module replaces that verdict: run
// `npm audit --json`, then fail ONLY on an advisory not covered by any `.vex/`
// record — the produce → always-upload → enforce pattern.
//
// IDENTIFIER MATCHING (the crux — differs from grype): `npm audit --json` keys
// each advisory by the vulnerable PACKAGE name and carries the id ONLY as a
// GitHub advisory URL in `via[].url` (`…/advisories/GHSA-xxxx`). It does NOT
// carry a CVE. So the matchable identifier is the GHSA. The shared ledger
// (vex-ledger.ts) accepts BOTH the record's CVE `name` and its GHSA `aliases`,
// so a base-image record naming the CVE + aliasing the GHSA covers here too. An
// advisory with NO extractable GHSA is treated as UNCOVERED (fail-closed): we
// cannot prove it is an accepted one.
//
// TRANSPARENCY (the maintainer-flagged invariant): an `affected` record makes
// the advisory PASS the gate but it is NOT hidden — npm audit has no
// Security-tab surface, so the CI log + the uploaded `npm-audit.json` artifact
// ARE the visibility view. `coveredAdvisories` lets the shim PRINT every
// accepted-but-present advisory, preserving the two-tier model: gate-green, but
// the accepted risk stays on the record AND in the log, never silently dropped.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transforms live here so
// they flow through the 100% coverage gate (#124), Stryker mutation (#122), and
// the fuzz-regression tier. TOTAL: malformed input yields an empty (pass) list,
// never throws. The runnable CLI is the thin `npm-audit-gate.mjs` shim.

// EXPLICIT `.ts` extension: this is a runtime VALUE cross-import between two
// `.github/scripts` siblings (like vex-dialects.ts → vex-to-sarif-suppressions.ts,
// #251). The `.mjs` shim runs this under Node 24's type-stripping loader, which
// resolves ONLY an explicit specifier naming an existing file — a `.js` sibling
// does not exist on a clean checkout (it's a gitignored tsc artifact) and an
// extensionless specifier fails. tsc accepts the `.ts` under
// `allowImportingTsExtensions` (tsconfig.scripts.json, noEmit); the emitting
// tsconfig.json excludes `.github/scripts/**/*.ts`, so no shadowing `.js`.
import { asArray, asRecord, normId, activeRecordIds } from './vex-ledger.ts';

// A GHSA identifier: `GHSA-xxxx-xxxx-xxxx`, three groups of four base36 chars.
// DELIBERATELY permissive (`[0-9a-z]`, not GitHub's tighter random-id alphabet):
// an over-tight alphabet is a fragility for a SECURITY gate — if a real GHSA
// ever carried a char outside a restricted set, `extractGhsa` would return null,
// the advisory would be treated as uncovered, and the gate would FALSE-RED on a
// legitimately-accepted finding. The permissive shape cannot cause a false
// ACCEPT (membership in the `.vex/` set is what accepts — this only lifts the id
// string out of the URL), and the rigid `GHSA-` prefix + 4-4-4 structure makes a
// false MATCH on non-GHSA text effectively impossible. Case-insensitive.
const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

/**
 * The canonical (upper-case) GHSA token in a string, or null. Delegates to
 * `normId` for the upper-case/trim so the id shape matches the ledger's set
 * exactly. Non-strings and GHSA-free strings yield null (totality).
 */
export function extractGhsa(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const m = GHSA_RE.exec(value);
  if (m === null) return null;
  return normId(m[0]);
}

/**
 * Every GHSA one `npm audit` advisory is known by: pulled from each `via[]`
 * entry's `url`. A string `via` entry is a package cross-reference (npm points
 * one vulnerable package at another), not an advisory, so it contributes
 * nothing. Malformed structures contribute nothing; never throws.
 */
export function advisoryGhsaIds(advisory: unknown): Set<string> {
  const ids = new Set<string>();
  const adv = asRecord(advisory);
  if (adv === null) return ids;
  for (const rawVia of asArray(adv.via)) {
    const via = asRecord(rawVia);
    if (via === null) continue;
    const ghsa = extractGhsa(via.url);
    if (ghsa !== null) ids.add(ghsa);
  }
  return ids;
}

/**
 * The GATE DECISION: the sorted, de-duplicated vulnerable PACKAGE names in an
 * `npm audit --json` document whose advisory is NOT covered by any accepted id.
 * Empty ⇒ PASS; non-empty ⇒ FAIL (each is a live advisory needing a `.vex/`
 * record or a fix). An advisory is COVERED iff any of its GHSAs is accepted (an
 * `affected` record covers exactly as `not_affected` does — the acceptance set
 * is built by the shared ledger, which unions both). An advisory with no
 * extractable GHSA is UNCOVERED (fail-closed). Reports the package name (npm
 * audit's natural key) so the log names the actionable dependency. TOTAL:
 * malformed JSON yields an empty list.
 */
export function uncoveredAdvisories(
  auditJson: unknown,
  accepted: ReadonlySet<string>,
): string[] {
  const uncovered = new Set<string>();
  const doc = asRecord(auditJson);
  if (doc === null) return [];
  const vulns = asRecord(doc.vulnerabilities);
  if (vulns === null) return [];
  for (const [pkgName, rawAdv] of Object.entries(vulns)) {
    const ghsaIds = advisoryGhsaIds(rawAdv);
    let covered = false;
    for (const id of ghsaIds) {
      if (accepted.has(id)) {
        covered = true;
        break;
      }
    }
    if (!covered) uncovered.add(pkgName);
  }
  return [...uncovered].sort();
}

/** One accepted-but-present advisory: the package and the covered GHSA ids. */
export interface CoveredAdvisory {
  pkg: string;
  ids: string[];
}

/**
 * The accepted-but-present advisories — package → the GHSA ids a `.vex/` record
 * covered, sorted — so the shim can PRINT them (the transparency guarantee: an
 * accepted advisory stays visible in the log even though it passes the gate).
 * Only advisories with at least one covered GHSA appear. TOTAL; never throws.
 */
export function coveredAdvisories(
  auditJson: unknown,
  accepted: ReadonlySet<string>,
): CoveredAdvisory[] {
  const out: CoveredAdvisory[] = [];
  const doc = asRecord(auditJson);
  if (doc === null) return out;
  const vulns = asRecord(doc.vulnerabilities);
  if (vulns === null) return out;
  for (const [pkgName, rawAdv] of Object.entries(vulns)) {
    const ids = [...advisoryGhsaIds(rawAdv)].filter((id) => accepted.has(id));
    if (ids.length > 0) out.push({ pkg: pkgName, ids: ids.sort() });
  }
  return out;
}

/**
 * The "now" for dated-`revisit_by` expiry, from the shim's `today` CLI arg. A
 * real ISO date → that UTC-midnight instant; an empty/absent arg → the epoch,
 * which makes NO dated record overdue (every acceptance stays active) — the safe
 * default for a local run that omits the date. The workflow always passes a real
 * date, so expiry is enforced in CI. Kept here (not in the shim) so it is tested.
 */
export function resolveNow(todayArg: unknown): Date {
  return typeof todayArg === 'string' && todayArg !== ''
    ? new Date(todayArg)
    : new Date(0);
}

/** The whole gate decision, as data the shim renders/exits on. */
export interface GateResult {
  outcome: 'success' | 'failure';
  /** True only when the audit JSON was unreadable (fail-closed). */
  failedClosed: boolean;
  /** Vulnerable package names with no active covering record (the FAIL signal). */
  uncovered: string[];
  /** Accepted-but-present advisories (the transparency signal). */
  covered: CoveredAdvisory[];
  /** Size of the active accepted-id set (for the log line). */
  acceptedCount: number;
}

/**
 * The ENTIRE gate decision as a pure function, so the `.mjs` shim is left with
 * nothing but read/parse/write/exit (the repo's `.ts`-holds-all-logic contract,
 * #165 — the `.mjs` is not coverage-instrumented, so it must carry NO logic).
 *
 * `audit` is the parsed `npm audit --json` (or `undefined` if unreadable →
 * fail-closed: we cannot prove the audit was clean). `vexDocs` are the parsed
 * `.vex/*.openvex.json` docs; `now` is `resolveNow(todayArg)`. The active
 * accepted set drops any record whose dated `revisit_by` is on/before `now`
 * (self-expiry, #295). The gate fails iff there is an uncovered advisory; the
 * `covered` list is always returned so an `affected` acceptance stays VISIBLE in
 * the shim's log even on a pass. TOTAL: never throws.
 */
export function gateResult(
  audit: unknown,
  vexDocs: readonly unknown[],
  now: Date,
): GateResult {
  if (audit === undefined) {
    return {
      outcome: 'failure',
      failedClosed: true,
      uncovered: [],
      covered: [],
      acceptedCount: 0,
    };
  }
  const accepted = activeRecordIds(vexDocs, now);
  const uncovered = uncoveredAdvisories(audit, accepted);
  const covered = coveredAdvisories(audit, accepted);
  return {
    outcome: uncovered.length === 0 ? 'success' : 'failure',
    failedClosed: false,
    uncovered,
    covered,
    acceptedCount: accepted.size,
  };
}
