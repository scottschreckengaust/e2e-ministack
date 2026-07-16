// Build a per-push "VEX report" — a human-readable table reconciling the
// committed `.vex/` records (the durable governance ledger) against the GitHub
// Code Scanning ALERTS (the live Security-tab ledger), so every accepted/known
// base-image CVE is visible with its status, badge severity, suggested
// justification, and revisit cadence (#189).
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `vex-report.mjs` shim, which reads `.vex/*.json` + the alerts normalized by
// `alerts-findings.*` and writes the markdown.
//
// DESIGN:
//   - `.vex/`-DIRECTORY-DRIVEN, tool-agnostic: the report reflects OUR durable
//     decisions, reconciled against the Alerts API (already the UNION of all
//     scanners) — it does NOT depend on a specific scanner staying in the stack.
//   - TWO-LEDGER reconciliation: the unified status is the product of the VEX
//     verdict AND the alert state (open/dismissed/fixed). "Suppressed" is not a
//     GitHub state, so drift between the ledgers is surfaced as a status:
//       * VEX drift — VEX-accepted but the alert is still OPEN (dismiss it);
//       * Undocumented dismissal — alert dismissed with NO backing `.vex/`
//         record (justify or reopen; the #167 inverse-drift).
//   - Severity is the BADGE severity (GitHub's NVD-derived
//     `security_severity_level`); it can diverge from a scanner's distro/gate
//     rating (#181). When the optional `gateSeverities` map (from
//     `gate-findings.*`, the scanners' structured JSON) is supplied, the ledger
//     renders `badge / gate X` on exactly the rows where the two differ (#208) —
//     surfacing the overstated-badge base-image CVEs this repo VEX-accepts.
//   - CURRENT-SCAN CROSS-CHECK (#210): GitHub only auto-closes an alert when a
//     newer analysis for the same ref omits it, so an alert can be `open` in the
//     API yet ABSENT from the current image scan (e.g. after the pinned image
//     dropped a batch of CVEs). Fed the current scan's CVE set (the optional
//     `currentScanCves` param), the report demotes such a stale-open high+
//     finding from a false `Decision needed` to the non-actionable
//     `Scanner-cleared`, and never mistakes it for real `VEX drift`. Passing
//     `null` (the default) disables the cross-check (pre-#210 behavior).
//   - Flags: the `vulnerable_code_not_in_execute_path` (never-run tools) class,
//     and un-CVE'd `TEMP-…`/GHSA pseudo-ids that a CVE-keyed record can't match.

/** A committed OpenVEX record's essentials (one statement per record here). */
export interface VexRecord {
  /** CVE id from statements[].vulnerability.name. */
  cve: string;
  status: string; // not_affected | affected | fixed | under_investigation
  justification?: string; // the not_affected enum, when present
  /** custom revisit_by field (#188) — may be absent on legacy records. */
  revisitBy?: string;
}

/**
 * One finding the report reconciles against `.vex/`. Sourced from the GitHub
 * Code Scanning Alerts API (the union of all scanners), so it carries the
 * SECOND LEDGER's state — that's what lets the report detect drift between the
 * durable `.vex/` decision and what the Security tab actually shows.
 */
export interface ScannerFinding {
  id: string; // CVE-… or a TEMP-…/GHSA pseudo-id
  scanner: string; // e.g. "Grype" | "Trivy" (alert tool.name)
  severity: string; // the BADGE severity (NVD-derived): CRITICAL|…|UNKNOWN
  pkg?: string; // package name when known (Alerts API often omits it)
  /** Alert state: open | dismissed | fixed. Absent => treat as open. */
  state?: string;
  /** The alert's Security-tab URL, so the report can link the scanner to it. */
  htmlUrl?: string;
  /** `fixed_at` ISO timestamp (when the alert auto-fixed) — bounds the
   *  "recently resolved" window. Absent/empty on non-fixed findings. */
  fixedAt?: string;
}

/** A scanner that reported this CVE, with a link to its own alert. */
export interface ScannerLink {
  scanner: string; // e.g. "Grype"
  htmlUrl: string; // that scanner's alert URL ('' if none — rendered unlinked)
}

export interface ReportRow {
  item: string;
  isCve: boolean; // false => un-CVE'd TEMP-/GHSA pseudo-id (needs manual tracking)
  /** Scanners reporting this CVE, each linked to its own Code-Scanning alert. */
  scanners: ScannerLink[];
  /** How many Code-Scanning alerts collapsed into this one CVE row (dedup count). */
  alertCount: number;
  maxSeverity: string; // the badge (NVD) severity shown in the report
  /** The scanner's GATE (distro-adjusted) severity for this CVE, when known
   *  (#208). Null when no gate map was supplied, or the CVE isn't in it. The
   *  render shows it alongside `maxSeverity` ONLY when the two differ. */
  gateSeverity: string | null;
  status: UnifiedStatus;
  suggestedJustification: string | null; // for uncovered items, else the recorded one
  /** The revisit_by value as authored: an ISO date OR an event token. */
  revisitBy: string | null;
  /** True only when revisitBy is a DATE that is on/before `today` (overdue). */
  revisitOverdue: boolean;
  /** True when this row needs a human decision/action (drives the signal). */
  actionNeeded: boolean;
  /** Prioritization rank (0 = most urgent). Drives the report sort so
   *  act-now rows lead and settled Accepted/Tracked sink. See `priorityRank`. */
  priorityRank: number;
  /** For a `Resolved` row, the alert's `fixed_at` ISO timestamp (else null) —
   *  bounds the recency window and orders the "recently resolved" block. */
  resolvedAt: string | null;
}

// Human-readable, action-oriented status labels. The reviewer should be able to
// tell "do I need to do something?" from the word alone.
export type UnifiedStatus =
  | 'Accepted' // VEX not_affected/fixed + alert dismissed (or n/a) — nothing to do
  | 'Tracked' // below floor / reachable-accepted — visible, no action now
  | 'Decision needed' // uncovered at/above the gate floor — must VEX or fix (blocks gate)
  | 'Revisit overdue' // an accepted record whose revisit_by DATE has passed
  | 'Stale record' // a VEX record with no matching current finding — prune?
  | 'Investigating' // under_investigation record
  | 'VEX drift' // VEX-accepted, but its Code-Scanning alert is still OPEN (dismiss it)
  | 'Undocumented dismissal' // alert DISMISSED (a human hid it) with NO backing .vex/ record
  | 'Scanner-cleared' // alert still OPEN in the API but ABSENT from the current scan — stale, no action (#210)
  | 'Resolved'; // alert auto-FIXED (finding gone), no .vex/ record — informational, no action

// A status is "actionable" (gets the 🔴 signal) iff it asks a human to do
// something. SINGLE source of truth — every `actionNeeded` derives from this,
// so a row can never disagree with its own status.
export function isActionable(status: UnifiedStatus): boolean {
  return (
    status === 'Decision needed' ||
    status === 'Revisit overdue' ||
    status === 'Stale record' ||
    status === 'VEX drift' ||
    status === 'Undocumented dismissal'
  );
}

// Prioritization rank per status — lower sorts higher (top of the report). The
// tiers, most-urgent first (#210): things that block the gate or represent a
// missed commitment lead; ledger-reconciliation next; the harvest/prune signal;
// then the bounded "recently resolved" news; then in-progress; then the settled
// Accepted/Tracked bulk (which sinks to the collapsed ledger). Total by
// construction — every UnifiedStatus has an entry, so there is no fallback.
const PRIORITY: Record<UnifiedStatus, number> = {
  'Decision needed': 0, // gate is/goes RED — must VEX or fix
  'Revisit overdue': 1, // accepted, but the revisit_by date passed
  'Undocumented dismissal': 2, // hidden with NO .vex/ record — governance hole
  'VEX drift': 3, // justified, but the Security-tab alert lags — reconcile
  'Stale record': 4, // .vex/ record with no finding — the real PRUNE signal
  Resolved: 5, // auto-fixed this window — news, not work
  'Scanner-cleared': 6, // open in the API but gone from the current scan — stale news (#210)
  Investigating: 7, // under_investigation — no action yet
  Accepted: 8, // VEX'd + dismissed — settled noise
  Tracked: 9, // below floor — settled noise
};

/** The prioritization rank for a status (0 = most urgent). */
export function priorityRank(status: UnifiedStatus): number {
  return PRIORITY[status];
}

/**
 * True iff a `Resolved` row is INSIDE the recency window — its `fixed_at`
 * calendar day is on/after the `resolvedSince` boundary day. The boundary is
 * INJECTED (not computed here) so the policy lives with the caller: the CLI shim
 * passes the last release's `published_at` ("resolved since users last saw a
 * release" — the governance-aligned default), falling back to a rolling window
 * (`today − N days`) when there is no prior release or the lookup fails. Keeping
 * the boundary a parameter leaves this transform pure/reproducible and lets the
 * report's retention policy change without touching gated logic.
 *
 * Both operands become a `YYYYMMDD` integer via `isoDayNumber`; the single `>=`
 * is false whenever EITHER side is NaN — so a missing/malformed `fixedAt` (an
 * undated resolved row) or an absent/malformed `resolvedSince` reads as OUTSIDE
 * the window (dropped), never surfaced without a real date behind it.
 */
export function isRecentlyResolved(
  fixedAt: string | null,
  resolvedSince: string,
): boolean {
  return isoDayNumber(fixedAt) >= isoDayNumber(resolvedSince);
}

const SEV_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NEGLIGIBLE: 1,
  UNKNOWN: 0,
};
const RANK_NAME = [
  'UNKNOWN',
  'NEGLIGIBLE',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
];

// Normalize a scanner severity to a known keyword or 'UNKNOWN'. A single guard,
// not two: a non-string returns early (the `.toUpperCase()` below would throw on
// it, which is exactly why the guard is load-bearing — dropping it is observable).
function normSev(s: unknown): string {
  if (typeof s !== 'string') return 'UNKNOWN';
  const up = s.toUpperCase();
  return up in SEV_RANK ? up : 'UNKNOWN';
}

// Rank of an ALREADY-NORMALIZED severity. Total by construction — `normSev`
// only ever yields a key present in SEV_RANK, so there is no fallback branch.
function rankOf(normalizedSev: string): number {
  return SEV_RANK[normalizedSev];
}

// A present, non-empty string. Used at every input boundary so "is this a
// usable key/label?" is defined once (not re-spelled as `typeof x==='string'
// && x` at each site, which split into a hard-to-test compound condition).
function nonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v !== '';
}

// A real CVE id (vs. a Debian/GHSA `TEMP-…` placeholder a CVE-keyed record
// can't match). Case-insensitive; anchored so `TEMP-…`/`GHSA-…` are excluded.
// The typeof guard is load-bearing: a non-string that stringifies to a
// CVE-shaped value (e.g. the 1-element array `['CVE-2026-1']`) would otherwise
// coerce through `RegExp.test` and falsely match — so it is NOT a CVE id.
const CVE_RE = /^CVE-\d{4}-\d+$/i;
export function isCveId(id: unknown): boolean {
  return typeof id === 'string' && CVE_RE.test(id);
}

// Packages whose code the emulator never invokes at runtime (tools, not linked
// libs) → the tighter `vulnerable_code_not_in_execute_path` enum. Everything
// else present-but-not-adversary-reachable → `..cannot_be_controlled..`. In this
// loopback-only ephemeral emulator NOTHING is `affected` (no attacker surface).
const NEVER_RUN_PKGS = new Set([
  'bsdutils',
  'mount',
  'util-linux',
  'login.defs',
  'login',
  'apt',
  'tar',
  'gzip',
  'coreutils',
  'sysvinit-utils',
  'bash',
  'libbz2-1.0',
  'libpam-modules',
]);

/** Suggested justification enum for an as-yet-uncovered finding. */
export function suggestJustification(pkgs: readonly string[]): string {
  const set = new Set(pkgs);
  let anyNeverRun = false;
  let anyOther = false;
  for (const p of set) {
    if (NEVER_RUN_PKGS.has(p)) anyNeverRun = true;
    else anyOther = true;
  }
  // Only claim not-in-execute-path when EVERY package is a never-run tool.
  if (anyNeverRun && !anyOther) return 'vulnerable_code_not_in_execute_path';
  return 'vulnerable_code_cannot_be_controlled_by_adversary';
}

// A leading ISO calendar day as a comparable integer `YYYYMMDD`, or NaN when
// `value` has no such day. Accepts any value and matches on its string form:
// only a genuine `YYYY-MM-DD` prefix produces a number, so absent values, event
// tokens (e.g. "wait-for-image-rebuild"), and non-strings all yield NaN. NaN
// makes the overdue comparison (`<=`) definitively false — no string/null
// sentinel to coerce, no fallback literal, no guard that can go dead. The
// typeof guard is load-bearing: a `['2026-07-14']` array would otherwise coerce
// to a matching string, so a non-string is NaN by contract.
const ISO_DAY_CAPTURE_RE = /^(\d{4})-(\d{2})-(\d{2})/;
export function isoDayNumber(value: unknown): number {
  const m = typeof value === 'string' ? ISO_DAY_CAPTURE_RE.exec(value) : null;
  if (m === null) return NaN;
  return Number(m[1] + m[2] + m[3]);
}

/**
 * The leading `YYYY-MM-DD` day of an ISO timestamp for DISPLAY, or the input
 * unchanged when it has no ISO-day prefix (e.g. an event token) — so the report
 * shows `2026-07-15`, not the noisy `2026-07-15T20:08:43Z` the Alerts API emits.
 * A null yields '—' (nothing to show). Reuses the same anchored day regex.
 */
export function isoDay(value: string | null): string {
  if (value === null) return '—';
  const m = ISO_DAY_CAPTURE_RE.exec(value);
  return m === null ? value : `${m[1]}-${m[2]}-${m[3]}`;
}

/**
 * True iff `revisitBy` is a calendar day on/before `today`'s calendar day.
 * Both operands become a `YYYYMMDD` integer (NaN when not a date). The single
 * `due <= now` is false whenever EITHER side is NaN — so a missing/event
 * revisit_by, or a malformed today, all read as "not overdue".
 */
export function isRevisitOverdue(
  revisitBy: string | null | undefined,
  today: string,
): boolean {
  return isoDayNumber(revisitBy) <= isoDayNumber(today);
}

/**
 * Build report rows from `.vex/` records + scanner findings. Tool-agnostic:
 * findings may come from any scanner set.
 *
 * (The GitHub Code-Scanning alert ledger — for the inverse-drift check, a
 * dismissed alert with no backing `.vex/` record — is a deferred follow-up
 * tracked in #167; it will add an `alertStates` parameter when consumed, not
 * before, so this signature carries no unused input today.)
 *
 * @param gateFloor the current hard-fail floor — an uncovered finding at/above
 *   it needs a decision; below it is tracked.
 * @param today ISO date (YYYY-MM-DD) for overdue detection. Injected (not
 *   `Date.now()`) so the transform stays pure/reproducible. Both params are
 *   REQUIRED — a default would be an arbitrary sentinel (for `today`, any
 *   non-date behaves identically), so callers must state their intent.
 * @param resolvedSince ISO date boundary for the "recently resolved" window: a
 *   `Resolved` row survives only if its `fixed_at` day is on/after this. The
 *   shim passes the last release's date (rolling-window fallback when none).
 *   Injected for the same purity reason as `today`; a non-date drops all
 *   Resolved rows (nothing is "recent" relative to an unknown boundary).
 * @param currentScanCves the CVE-id set the CURRENT image scan (Grype ∪ Trivy
 *   SARIFs of THIS run) actually reports — the ground truth the report
 *   cross-checks the Alerts API against (#210). GitHub only auto-closes an alert
 *   when a newer analysis for the same ref omits it, so an alert can be `open`
 *   in the API yet ABSENT from the current scan (a scanner-cleared finding, e.g.
 *   after the pinned image dropped a batch of CVEs). Passing `null` (the
 *   DEFAULT) disables the cross-check entirely — the engine behaves exactly as
 *   before, which is why every legacy caller and the fuzz harness stay valid.
 *   The check only DEMOTES an uncovered at/above-floor finding from `Decision
 *   needed` to `Scanner-cleared`; it never invents a finding or hides one the
 *   scan still reports. Floor-gated because the scan SARIFs carry only high+
 *   findings, so a CVE's absence is conclusive only at/above the gate floor.
 * @param gateSeverities a CVE-id -> scanner GATE (distro-adjusted) severity map
 *   (from `gate-findings.*`, the union of grype+trivy JSON), joined by CVE id
 *   onto each row so the report can surface gate-vs-badge divergence (#208).
 *   Passing `null` (the DEFAULT) leaves every row's `gateSeverity` null — the
 *   engine behaves exactly as before, so legacy callers and the fuzz harness
 *   stay valid. A CVE absent from the map (or a non-CVE row) gets a null
 *   gateSeverity — the report then shows the badge alone, tool-agnostically.
 */
export function buildReport(
  vexRecords: readonly VexRecord[],
  findings: readonly ScannerFinding[],
  gateFloor: string,
  today: string,
  resolvedSince: string,
  currentScanCves: readonly string[] | null = null,
  gateSeverities: ReadonlyMap<string, string> | null = null,
): ReportRow[] {
  // `vexRecords`/`findings` are arrays by contract — the CLI shim (the only
  // untrusted-input boundary) parses JSON and passes arrays. ELEMENT-level junk
  // is tolerated below (each loop skips malformed rows); non-array TOTALITY is
  // the shim's responsibility, not re-litigated here.
  const vexByCve = new Map<string, VexRecord>();
  for (const r of vexRecords) {
    if (r && nonEmptyString(r.cve)) vexByCve.set(r.cve.toUpperCase(), r);
  }
  const floorRank = rankOf(normSev(gateFloor));

  // The CURRENT-scan CVE set, upper-cased for a case-insensitive membership test
  // matching the finding keys (#210). `null` means "no scan ledger supplied" —
  // the cross-check below is then skipped entirely and every code path behaves
  // as it did before this parameter existed. An EMPTY set is DIFFERENT from
  // null: it means the scan ran and found nothing, so every uncovered open alert
  // is scanner-cleared. Collapsing the two would either resurrect phantoms or
  // hide real findings, so the distinction is load-bearing.
  const scanSet =
    currentScanCves === null
      ? null
      : new Set(currentScanCves.map((c) => String(c).toUpperCase()));

  // Look up a CVE's scanner GATE severity (#208), keyed the same upper-case way
  // as the finding ids. Returns null when no gate map was supplied OR this CVE
  // isn't in it (the report then shows the badge alone). A single helper so both
  // row-push sites (found findings + stale records) join gate severity the same
  // way, and a `null` map cleanly disables the whole feature.
  const gateSevOf = (id: string): string | null =>
    gateSeverities === null ? null : (gateSeverities.get(id) ?? null);

  // Group findings by id. The second-ledger (alert-state) signals are set only
  // on POSITIVE evidence — an absent `state` means "no alert-ledger opinion"
  // (the caller didn't supply one), leaving the pure `.vex/`+severity logic in
  // charge (so the engine behaves identically when no alerts are fed). The
  // three alert states are kept DISTINCT because they mean different things:
  //   anyOpen      — an alert is `open`      => a human decision is still due
  //   anyDismissed — an alert is `dismissed` => a HUMAN hid it (drift-relevant)
  //   anyFixed     — an alert is `fixed`     => it genuinely went away (resolved)
  // Conflating dismissed with fixed would flag auto-resolved findings as
  // "undocumented dismissal" — a false alarm; they are separate signals.
  const byId = new Map<
    string,
    {
      // scanner -> that scanner's alert URL (last non-empty wins). One entry per
      // scanner; each is a distinct Code-Scanning alert the report links to.
      scannerUrls: Map<string, string>;
      maxRank: number; // highest badge severity across this CVE's alerts
      pkgs: Set<string>; // affected package(s) — for the justification suggestion
      alertCount: number; // how many alerts collapsed into this CVE
      anyOpen: boolean;
      anyDismissed: boolean;
      anyFixed: boolean;
      // The latest `fixed_at` ISO day-string across this CVE's fixed alerts
      // ('' if none) — bounds/orders the "recently resolved" block.
      fixedAt: string;
    }
  >();
  for (const f of findings) {
    if (!f || !nonEmptyString(f.id)) continue;
    const key = f.id.toUpperCase();
    const g = byId.get(key) ?? {
      scannerUrls: new Map<string, string>(),
      maxRank: 0,
      pkgs: new Set<string>(),
      alertCount: 0,
      anyOpen: false,
      anyDismissed: false,
      anyFixed: false,
      fixedAt: '',
    };
    g.alertCount += 1; // every finding is one Code-Scanning alert
    // `nonEmptyString` is load-bearing: it excludes both non-strings (which
    // would label the row with garbage) and '' (an empty scanner name).
    if (nonEmptyString(f.scanner)) {
      // Keep this scanner's alert URL (a later empty url must not clobber a
      // real one — only overwrite when we actually have a url).
      const url = nonEmptyString(f.htmlUrl)
        ? f.htmlUrl
        : (g.scannerUrls.get(f.scanner) ?? '');
      g.scannerUrls.set(f.scanner, url);
      g.maxRank = Math.max(g.maxRank, rankOf(normSev(f.severity)));
    }
    if (nonEmptyString(f.pkg)) g.pkgs.add(f.pkg);
    if (f.state === 'open') g.anyOpen = true;
    if (f.state === 'dismissed') g.anyDismissed = true;
    if (f.state === 'fixed') g.anyFixed = true;
    // Record this CVE's fixed_at (last non-empty wins). GitHub stamps `fixed_at`
    // per ANALYSIS — all of one CVE's alerts fix in the same run — so every
    // fixed alert for a CVE carries the same date; "last wins" == "any", with no
    // order comparison that could go wrong (a `>`-max here would be an EQUIVALENT
    // mutant: `>`/`>=` differ only on equal values, which write the same string).
    if (nonEmptyString(f.fixedAt)) g.fixedAt = f.fixedAt;
    byId.set(key, g);
  }

  const rows: ReportRow[] = [];
  const seenCves = new Set<string>();

  for (const [id, g] of byId) {
    seenCves.add(id);
    const maxRank = g.maxRank;
    const maxSeverity = RANK_NAME[maxRank];
    const vex = vexByCve.get(id);
    const isCve = isCveId(id);

    // Cross-check the (possibly stale) Alerts API against the CURRENT scan
    // (#210): an alert is SCANNER-CLEARED when we were given a scan set, the
    // finding is a real CVE at/above the gate floor, and the current scan does
    // NOT report it. Floor-gated because the scan SARIFs carry only high+ CVEs,
    // so a CVE's absence is conclusive only at/above the floor; `isCve` because
    // only CVE ids can appear in the scan set (a GHSA/TEMP pseudo-id never
    // would, so absence there proves nothing). A `null` scan set (no ledger
    // supplied) disables the demotion entirely — pre-#210 behavior.
    const clearedByScan =
      scanSet !== null && isCve && maxRank >= floorRank && !scanSet.has(id);

    const overdue = isRevisitOverdue(vex?.revisitBy, today);
    let status: UnifiedStatus;
    let suggested: string | null;
    if (vex) {
      const st = String(vex.status);
      const suppressing = st === 'not_affected' || st === 'fixed';
      if (overdue) {
        // Revisit takes precedence — the acceptance itself is due for review.
        status = 'Revisit overdue';
      } else if (suppressing && g.anyOpen && !clearedByScan) {
        // Ledger drift: VEX-accepted, yet an alert is still OPEN *and the current
        // scan still reports it*. The dismiss-alerts wiring (#186) should have
        // closed it — flag to reconcile. If the scan has since cleared the CVE,
        // the open alert is merely stale (not real drift) → fall through to
        // Accepted; the .vex/ record is still valid, nothing to reconcile.
        status = 'VEX drift';
      } else if (suppressing) {
        status = 'Accepted';
      } else if (st === 'affected') {
        status = 'Tracked';
      } else {
        status = 'Investigating';
      }
      suggested = vex.justification ?? null;
    } else if (g.anyOpen) {
      // Uncovered + open. If the current scan no longer reports this high+ CVE,
      // the API's `open` is stale — surface it as the non-actionable
      // Scanner-cleared (#210), NOT a false Decision needed. Otherwise: at/above
      // floor needs a decision; below floor is tracked.
      status = clearedByScan
        ? 'Scanner-cleared'
        : maxRank >= floorRank
          ? 'Decision needed'
          : 'Tracked';
      suggested = suggestJustification([...g.pkgs]);
    } else if (g.anyDismissed) {
      // No `.vex/` record, yet a HUMAN dismissed the alert — a suppression with
      // no durable justification (inverse drift, #167). Actionable.
      status = 'Undocumented dismissal';
      suggested = suggestJustification([...g.pkgs]);
    } else if (g.anyFixed) {
      // No `.vex/` record and the alert auto-FIXED (finding gone) — resolved,
      // NOT a dismissal to document. Informational only.
      status = 'Resolved';
      suggested = suggestJustification([...g.pkgs]);
    } else {
      // Uncovered with no alert-ledger opinion: severity decides.
      status = maxRank >= floorRank ? 'Decision needed' : 'Tracked';
      suggested = suggestJustification([...g.pkgs]);
    }

    rows.push({
      item: id,
      isCve,
      scanners: [...g.scannerUrls]
        .map(([scanner, htmlUrl]) => ({ scanner, htmlUrl }))
        .sort((x, y) => x.scanner.localeCompare(y.scanner)),
      alertCount: g.alertCount,
      maxSeverity,
      gateSeverity: gateSevOf(id),
      status,
      suggestedJustification: suggested,
      revisitBy: vex?.revisitBy ?? null,
      revisitOverdue: overdue,
      actionNeeded: isActionable(status),
      priorityRank: priorityRank(status),
      // The CVE's fixed date if any alert reported one, else null — a pure data
      // field (NOT status-gated: gating on `status === 'Resolved'` would be an
      // equivalent mutant, since an undated Resolved row is always dropped by the
      // recency filter, so its null could never be observed). Display is gated
      // in render/filter, which key on `status`; this just carries the date.
      resolvedAt: nonEmptyString(g.fixedAt) ? g.fixedAt : null,
    });
  }

  // VEX records with no matching current finding = a stale record (prune?).
  for (const [cve, vex] of vexByCve) {
    if (seenCves.has(cve)) continue;
    rows.push({
      item: cve,
      isCve: isCveId(cve),
      scanners: [],
      alertCount: 0,
      maxSeverity: 'UNKNOWN',
      // A stale record has no CURRENT finding, so by definition no current-scan
      // gate rating — but if the gate map still lists the CVE, surface it (the
      // gate map is the current scan's view; a match here is itself signal the
      // record may not be as stale as the alert ledger suggests).
      gateSeverity: gateSevOf(cve),
      status: 'Stale record',
      suggestedJustification: vex.justification ?? null,
      revisitBy: vex.revisitBy ?? null,
      revisitOverdue: isRevisitOverdue(vex.revisitBy, today),
      actionNeeded: isActionable('Stale record'),
      priorityRank: priorityRank('Stale record'),
      resolvedAt: null,
    });
  }

  // Drop `Resolved` rows whose alert fixed OUTSIDE the recency window (or with
  // no fixed date) — otherwise the ever-growing all-history pile of fixed alerts
  // would swamp the report (#210). Non-Resolved rows always survive.
  const kept = rows.filter(
    (r) =>
      r.status !== 'Resolved' ||
      isRecentlyResolved(r.resolvedAt, resolvedSince),
  );

  // Prioritized order (#210): rank asc (act-now leads, settled sinks), then
  // severity desc, then most-recently-resolved first (resolvedAt desc — nulls
  // last), then item asc for a fully deterministic, test-pinnable order.
  kept.sort((a, b) => {
    if (a.priorityRank !== b.priorityRank)
      return a.priorityRank - b.priorityRank;
    const d = rankOf(b.maxSeverity) - rankOf(a.maxSeverity);
    if (d !== 0) return d;
    const ra = a.resolvedAt ?? '';
    const rb = b.resolvedAt ?? '';
    if (ra !== rb) return rb.localeCompare(ra); // newer resolvedAt first
    return a.item.localeCompare(b.item);
  });
  return kept;
}

/** Count rows by unified status (for the summary line). */
export function summarize(
  rows: readonly ReportRow[],
): Record<UnifiedStatus, number> {
  const acc: Record<UnifiedStatus, number> = {
    Accepted: 0,
    Tracked: 0,
    'Decision needed': 0,
    'Revisit overdue': 0,
    'Stale record': 0,
    Investigating: 0,
    'VEX drift': 0,
    'Undocumented dismissal': 0,
    'Scanner-cleared': 0,
    Resolved: 0,
  };
  for (const r of rows) acc[r.status] += 1;
  return acc;
}

/** Shorten a justification enum to a compact, no-scroll label. */
function shortJust(j: string | null): string {
  if (!j) return '—';
  if (j === 'vulnerable_code_not_in_execute_path') return 'not-in-execute-path';
  if (j === 'vulnerable_code_cannot_be_controlled_by_adversary')
    return 'adversary-unreachable';
  return j;
}

// A legend defining every vocabulary the tables use — so no status, severity,
// or revisit_by cell needs its own footnote (#206 item 2). Rendered as a
// scannable status TABLE (one row per label) plus two short definition lines,
// all inside a collapsed <details> so it stays out of the way. (The previous
// single dense italic run-on was unreadable — maintainer feedback on PR #207.)
const LEGEND =
  '<details>\n' +
  '<summary>Legend — status vocabulary, severity, revisit_by</summary>\n\n' +
  '| status | meaning |\n' +
  '| --- | --- |\n' +
  '| Accepted | VEX `not_affected`/`fixed` + alert dismissed — gated, nothing to do |\n' +
  '| Tracked | below the gate floor, tolerated — no action now |\n' +
  '| Decision needed | uncovered at/above the gate floor — must VEX or fix |\n' +
  '| VEX drift | VEX-accepted but the alert is still open — dismiss it |\n' +
  '| Undocumented dismissal | alert dismissed with no `.vex/` record — justify or reopen |\n' +
  '| Scanner-cleared | alert still open in the API but gone from the current scan — stale, no action |\n' +
  '| Resolved | alert auto-fixed (finding gone) — informational |\n' +
  '| Revisit overdue | accepted record past its `revisit_by` date |\n' +
  '| Stale record | `.vex/` record with no current alert — prune? |\n' +
  '| Investigating | `under_investigation` record |\n\n' +
  "**severity** — GitHub's badge (NVD) severity. Shown as `badge / gate X` when " +
  "the scanner's distro/gate rating differs (e.g. NVD Critical vs Debian Negligible).\n\n" +
  '**revisit_by** — an ISO date (overdue-checkable) or an event token (e.g. `wait-for-image-rebuild`).\n\n' +
  '</details>';

// GitHub advisory-database search for a CVE. GitHub does NOT autolink a CVE id
// inside a markdown TABLE cell (it does in prose), so a bare id is dead text —
// we link it ourselves. A search URL (not a per-CVE page) because the CVE→GHSA
// mapping isn't known here; GitHub resolves the query to the advisory. Below-
// floor / un-alerted CVEs have no scanner-alert link, so this is often the ONLY
// way to click through to what a CVE actually is (#210 maintainer feedback).
function advisoryUrl(cve: string): string {
  return `https://github.com/advisories?query=${encodeURIComponent(cve)}`;
}

/**
 * Render `item`: a real CVE id becomes a link to its GitHub advisory (always
 * available, independent of whether a scanner alert exists); an un-CVE'd
 * `TEMP-…`/GHSA pseudo-id stays plain text with a flag (a CVE-query link would
 * be misleading — it isn't a CVE the advisory search resolves).
 */
function renderItem(r: ReportRow): string {
  return r.isCve
    ? `[${r.item}](${advisoryUrl(r.item)})`
    : `${r.item} ⚠️ un-CVE'd`;
}

/** Scanners linked to their own alerts, e.g. `[grype](url), [trivy](url)`. */
function renderScanners(r: ReportRow): string {
  if (r.scanners.length === 0) return '—';
  return r.scanners
    .map((sc) => (sc.htmlUrl ? `[${sc.scanner}](${sc.htmlUrl})` : sc.scanner))
    .join(', ');
}

/**
 * Render the severity cell: the badge (NVD) severity alone, OR `badge / gate`
 * when the scanner's gate rating is known AND DIFFERS (#208). Showing both only
 * on divergence keeps the common case (they agree) uncluttered while surfacing
 * exactly the overstated-badge rows this repo VEX-accepts (e.g. libc CVEs the
 * badge scores Critical but the distro rates Negligible). A null/equal gate
 * severity shows the badge alone — tool-agnostic (a scanner emitting no gate
 * rating simply contributes nothing).
 */
function renderSeverity(r: ReportRow): string {
  if (r.gateSeverity === null || r.gateSeverity === r.maxSeverity) {
    return r.maxSeverity;
  }
  return `${r.maxSeverity} / gate ${r.gateSeverity}`;
}

/**
 * Render the report as GitHub-flavored markdown, in reader-priority order (#210):
 *   1. a summary line stating the two denominators (distinct CVEs vs. alerts),
 *   2. NEEDS ATTENTION — the actionable rows (item · status · why), the top slot,
 *   3. RECENTLY RESOLVED — a bounded "what cleared this window" block (news, not
 *      work), sitting just below the action table,
 *   4. the FULL ledger in a DEFAULT-COLLAPSED <details> (rows in priority order,
 *      so Accepted/Tracked sink to the bottom), scanners linked to their alerts,
 *   5. the legend.
 * `rows` is assumed already priority-sorted by `buildReport`.
 */
export function renderMarkdown(rows: readonly ReportRow[]): string {
  const s = summarize(rows);
  const action = rows.filter((r) => r.actionNeeded);
  const resolved = rows.filter((r) => r.status === 'Resolved');
  const alertTotal = rows.reduce((n, r) => n + r.alertCount, 0);

  // (1) Header: distinct CVEs (rows) vs. the alerts they collapse (the #206
  // "170 vs 125" legibility fix — say both denominators explicitly).
  const summary =
    `**VEX report** — ${rows.length} CVE(s) across ${alertTotal} image-scan alert(s): ` +
    `${s['Decision needed']} decision needed · ${s['VEX drift']} vex drift · ` +
    `${s['Undocumented dismissal']} undocumented dismissal · ` +
    `${s['Revisit overdue']} revisit overdue · ${s['Stale record']} stale · ` +
    `${s['Accepted']} accepted · ${s['Tracked']} tracked` +
    (s['Investigating'] ? ` · ${s['Investigating']} investigating` : '') +
    (s['Scanner-cleared'] ? ` · ${s['Scanner-cleared']} scanner-cleared` : '') +
    (s['Resolved'] ? ` · ${s['Resolved']} resolved` : '');

  // (2) Narrow action table — only rows needing attention; the reviewer's focus.
  let actionBlock: string;
  if (action.length === 0) {
    actionBlock =
      '✅ **No action needed** — every finding is accepted, tracked, or resolved.';
  } else {
    const head = '| item | status | why |\n| --- | --- | --- |';
    const body = action
      .map(
        (r) =>
          `| ${renderItem(r)} | ${r.status} | ${shortJust(r.suggestedJustification)} |`,
      )
      .join('\n');
    actionBlock = `**Needs attention (${action.length}):**\n\n${head}\n${body}`;
  }

  // (3) Recently resolved — bounded "what cleared" block, below the action table
  // and only when there's something to show (buildReport already dropped
  // out-of-window Resolved rows). Non-actionable news, not work.
  let resolvedBlock = '';
  if (resolved.length > 0) {
    const head = '| item | severity | resolved |\n| --- | --- | --- |';
    const body = resolved
      .map(
        (r) =>
          `| ${renderItem(r)} | ${r.maxSeverity} | ${isoDay(r.resolvedAt)} |`,
      )
      .join('\n');
    resolvedBlock = `ℹ️ **Recently resolved (${resolved.length}):**\n\n${head}\n${body}\n\n`;
  }

  // (4) Full ledger — default-collapsed. Scanners link to their own alerts.
  const fHead =
    '| item | status | severity | scanners | revisit_by |\n' +
    '| --- | --- | --- | --- | --- |';
  const fBody = rows
    .map(
      (r) =>
        `| ${renderItem(r)} | ${r.status} | ${renderSeverity(r)} | ${renderScanners(r)} | ${r.revisitBy ?? '—'} |`,
    )
    .join('\n');

  return (
    `${summary}\n\n` +
    `${actionBlock}\n\n` +
    `${resolvedBlock}` +
    `<details>\n<summary>Full VEX ledger (${rows.length} CVEs) — click to expand</summary>\n\n` +
    `${fHead}\n${fBody}\n\n` +
    `</details>\n\n` +
    `${LEGEND}`
  );
}
