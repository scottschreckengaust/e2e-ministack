// Parse the GitHub Code Scanning Alerts API response into the finding shape the
// VEX report reconciles against `.vex/` (#189). The Alerts API — not SARIF — is
// the right "second ledger" for the report because:
//   - it is the UNION of every scanner (GitHub already merged grype + trivy +
//     …), normalized, so the report is genuinely tool-agnostic — no per-scanner
//     file, no message-scraping, survives a scanner swap;
//   - it carries ALERT STATE (open / dismissed / fixed) + dismissed_reason,
//     which SARIF cannot express — that state is exactly what lets the report
//     detect the #181 drift (a VEX record whose alert is still open) and the
//     inverse (a dismissed alert with no backing `.vex/` record, #167);
//   - it is one `gh api` call, no re-scan.
//
// Caveat (documented, not hidden): the API reflects the LAST upload for the
// ref, so on a brand-new branch it can lag a push; the report job runs after
// the scan/upload jobs so this is normally current.
//
// The severity is GitHub's `rule.security_severity_level` — the BADGE severity
// (NVD-derived). It is NOT the scanner's distro/gate rating; the gate-vs-badge
// divergence column is a fast-follow fed by structured scanner JSON (a real
// field), never by scraping. This module is honest about carrying badge only.
//
// LOGIC MODULE (jest-visible, gate-eligible): pure parser, 100% coverage (#124)
// + Stryker mutation (#122, zero survivors) + fuzz. Runnable CLI is the thin
// `alerts-findings.mjs` shim. TOTAL: malformed input yields `[]`, never throws.

import type { ScannerFinding } from './vex-report';

/** One Code Scanning alert, reduced to what the VEX report reconciles. */
export interface AlertFinding {
  id: string; // CVE-… extracted from the rule id (or the raw rule id if none)
  scanner: string; // tool.name (e.g. "Grype" | "Trivy")
  badgeSeverity: string; // rule.security_severity_level: CRITICAL|HIGH|… |UNKNOWN
  state: string; // open | dismissed | fixed
  dismissedReason: string; // e.g. "won't fix" | "" when not dismissed
  category: string; // most_recent_instance.category (which scan produced it)
  htmlUrl: string; // alert's Security-tab URL, so the report can link to it
  fixedAt: string; // `fixed_at` ISO timestamp when state==='fixed', else '' — bounds the "recently resolved" window (#210)
}

// A CVE token inside a rule id (grype `CVE-2026-1-python`, trivy `CVE-2026-1`),
// case-insensitive. Rules without one (e.g. a SonarQube `typescript:S1848`) keep
// their raw id — the report can then filter non-CVE rules out by category.
const CVE_RE = /CVE-\d{4}-\d+/i;

/** The canonical CVE token in a rule id, else the raw id (or '' if unusable). */
export function idFromRule(ruleId: unknown): string {
  const s = str(ruleId);
  const m = s.match(CVE_RE);
  return m !== null ? m[0].toUpperCase() : s;
}

const SEV_KEYWORDS = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

/** GitHub's `security_severity_level` uppercased to a known keyword, else UNKNOWN. */
export function badgeSeverity(level: unknown): string {
  const up = str(level).toUpperCase();
  return SEV_KEYWORDS.has(up) ? up : 'UNKNOWN';
}

/**
 * Parse the Alerts API array into findings. Each alert must carry a usable rule
 * id; malformed elements are skipped. `state`/`dismissed_reason` are preserved
 * so the report can reconcile the two ledgers.
 */
export function parseAlerts(alerts: unknown): AlertFinding[] {
  const out: AlertFinding[] = [];
  for (const raw of asArray(alerts)) {
    const a = asRecord(raw);
    if (a === null) continue;
    // A missing/malformed rule (or one with no CVE-ish id) is unusable — skip.
    // Guarding `rule` here narrows it to a real record for the rest of the body,
    // so `rule.security_severity_level` needs no (dead) optional-chaining.
    const rule = asRecord(a.rule);
    if (rule === null) continue;
    const id = idFromRule(rule.id);
    if (id === '') continue;
    out.push({
      id,
      scanner: str(asRecord(a.tool)?.name),
      badgeSeverity: badgeSeverity(rule.security_severity_level),
      state: str(a.state),
      dismissedReason: str(a.dismissed_reason),
      category: str(asRecord(a.most_recent_instance)?.category),
      htmlUrl: str(a.html_url),
      fixedAt: str(a.fixed_at),
    });
  }
  return out;
}

/**
 * Keep only alerts from the given scan categories (e.g. the image-scan
 * categories), so unrelated code-scanning alerts (SonarQube, CodeQL) don't
 * leak into a VEX/image report. An empty `categories` keeps everything.
 */
export function filterByCategory(
  findings: readonly AlertFinding[],
  categories: readonly string[],
): AlertFinding[] {
  if (categories.length === 0) return [...findings];
  const wanted = new Set(categories);
  return findings.filter((f) => wanted.has(f.category));
}

/**
 * Merge the run-ref alert set with the default-branch (`main`) set (#210).
 *
 * WHY: the Alerts API `state` (open / dismissed / fixed) is anchored per ref,
 * but `fixed`/`dismissed` history lives on the DEFAULT BRANCH — a PR merge ref
 * reports 0 fixed and 0 dismissed even when many exist on `main` (dismissal +
 * auto-fix are repo-global, like the #186 dismiss-alerts step which is
 * default-branch-only). So on a PR the "recently resolved" and drift signals
 * would silently vanish. This merges both: OPEN findings come from the RUN ref
 * (correct on a digest-bump PR, where the new image's open set differs from
 * main), while `main` supplies the fixed/dismissed history the run ref lacks.
 *
 * Keyed by `id|scanner` (one alert per CVE per scanner). The RUN-ref entry wins
 * when a key exists on both (its open/severity/url reflect what THIS ref scans);
 * a key present only on `main` is added (the resolved/dismissed history). Order
 * is deterministic: run-ref entries first (in their order), then main-only ones.
 */
export function mergeAlertLedgers(
  runRef: readonly AlertFinding[],
  mainRef: readonly AlertFinding[],
): AlertFinding[] {
  const key = (f: AlertFinding): string => `${f.id}|${f.scanner}`;
  const seen = new Set(runRef.map(key));
  const out = [...runRef];
  for (const f of mainRef) {
    if (!seen.has(key(f))) out.push(f);
  }
  return out;
}

/**
 * Adapt Alert findings to the `ScannerFinding` shape the VEX report consumes.
 * The two ledgers name the same concepts differently — the alert's
 * `badgeSeverity` is the report's `severity` — so this is the ONE place the
 * contract is bridged (a typed seam, not an untested `.mjs` field rename). The
 * report has no `pkg` source from the Alerts API (it omits the package), so it
 * is left undefined; `state`/`htmlUrl` carry the second-ledger signal + link.
 */
export function toScannerFindings(
  findings: readonly AlertFinding[],
): ScannerFinding[] {
  return findings.map((f) => ({
    id: f.id,
    scanner: f.scanner,
    severity: f.badgeSeverity,
    state: f.state,
    htmlUrl: f.htmlUrl,
    fixedAt: f.fixedAt,
  }));
}

// -- small total coercions (exported + unit-tested directly, mutation-tight) --

/** A plain object, or null. Arrays and primitives are NOT records. */
export function asRecord(v: unknown): Record<string, unknown> | null {
  if (typeof v !== 'object') return null;
  if (Array.isArray(v)) return null;
  return v as Record<string, unknown> | null;
}

/** The value if it's an array, else an empty array. */
export function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** A string value, or '' for anything else. */
export function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}
