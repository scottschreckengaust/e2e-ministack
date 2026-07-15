// Build a per-push "VEX report" — a human-readable table reconciling the
// committed `.vex/` records against current scanner findings, so every accepted
// or known base-image CVE is visible with its status, severity (per scanner),
// suggested justification, and revisit cadence (#189).
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `vex-report.mjs` shim, which reads `.vex/*.json` + normalized scanner
// findings and writes the markdown.
//
// DESIGN (validated by the #189 full-ratchet enumeration):
//   - `.vex/`-DIRECTORY-DRIVEN, tool-agnostic: the report reflects OUR durable
//     decisions (`.vex/` records), enriched by which scanners corroborate each
//     item — it does NOT depend on a specific scanner staying in the stack.
//   - Two-ledger STATUS (CI-gate x GitHub-alert). "Suppressed" is not a GitHub
//     state; the unified status is the product of the two ledgers.
//   - Option A: only `not_affected`/`fixed` are dismissed; a reachable
//     `affected` item is WATCH-BELOW-FLOOR (visible, not hidden).
//   - Severity is SCANNER-RELATIVE — show every scanner's rating (they diverge).
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

/** One scanner's view of one finding. `severity` is that scanner's rating. */
export interface ScannerFinding {
  id: string; // CVE-… or a TEMP-…/GHSA pseudo-id
  scanner: string; // e.g. "grype" | "trivy"
  severity: string; // CRITICAL|HIGH|MEDIUM|LOW|NEGLIGIBLE|UNKNOWN (any case)
  pkg?: string;
}

export interface ReportRow {
  item: string;
  isCve: boolean; // false => un-CVE'd TEMP-/GHSA pseudo-id (needs manual tracking)
  packages: string[]; // affected package name(s) — triage aid in the full ledger
  tools: string[]; // scanners that report it
  severities: Record<string, string>; // scanner -> severity (diverges)
  maxSeverity: string; // union max across scanners (kept in data; not a rendered column)
  status: UnifiedStatus;
  suggestedJustification: string | null; // for uncovered items, else the recorded one
  /** The revisit_by value as authored: an ISO date OR an event token. */
  revisitBy: string | null;
  /** True only when revisitBy is a DATE that is on/before `today` (overdue). */
  revisitOverdue: boolean;
  /** True when this row needs a human decision/action (drives the signal). */
  actionNeeded: boolean;
}

// Human-readable, action-oriented status labels. The reviewer should be able to
// tell "do I need to do something?" from the word alone.
export type UnifiedStatus =
  | 'Accepted' // VEX not_affected/fixed — gated, nothing to do
  | 'Tracked' // below floor / reachable-accepted — visible, no action now
  | 'Decision needed' // uncovered at/above the gate floor — must VEX or fix (blocks gate)
  | 'Revisit overdue' // an accepted record whose revisit_by DATE has passed
  | 'Stale record' // a VEX record with no matching current finding — prune?
  | 'Investigating'; // under_investigation record

// A status is "actionable" (gets the 🔴 signal) iff it asks a human to do
// something. SINGLE source of truth — every `actionNeeded` derives from this,
// so a row can never disagree with its own status.
export function isActionable(status: UnifiedStatus): boolean {
  return (
    status === 'Decision needed' ||
    status === 'Revisit overdue' ||
    status === 'Stale record'
  );
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
 */
export function buildReport(
  vexRecords: readonly VexRecord[],
  findings: readonly ScannerFinding[],
  gateFloor: string,
  today: string,
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

  // Group findings by id.
  const byId = new Map<
    string,
    { tools: Set<string>; sevs: Record<string, string>; pkgs: Set<string> }
  >();
  for (const f of findings) {
    if (!f || !nonEmptyString(f.id)) continue;
    const key = f.id.toUpperCase();
    const g = byId.get(key) ?? { tools: new Set(), sevs: {}, pkgs: new Set() };
    // `nonEmptyString` is load-bearing: it excludes both non-strings (which
    // would index/label the row with garbage) and '' (an empty scanner/pkg
    // name). Both halves are observable — see the adversarial finding tests.
    if (nonEmptyString(f.scanner)) {
      g.tools.add(f.scanner);
      g.sevs[f.scanner] = normSev(f.severity);
    }
    if (nonEmptyString(f.pkg)) g.pkgs.add(f.pkg);
    byId.set(key, g);
  }

  const rows: ReportRow[] = [];
  const seenCves = new Set<string>();

  for (const [id, g] of byId) {
    seenCves.add(id);
    const severities = g.sevs;
    const maxRank = Math.max(
      0,
      ...Object.values(severities).map((s) => rankOf(s)),
    );
    const maxSeverity = RANK_NAME[maxRank];
    const vex = vexByCve.get(id);
    const isCve = isCveId(id);

    const overdue = isRevisitOverdue(vex?.revisitBy, today);
    let status: UnifiedStatus;
    let suggested: string | null;
    if (vex) {
      const st = String(vex.status);
      if (st === 'not_affected' || st === 'fixed') {
        status = overdue ? 'Revisit overdue' : 'Accepted';
      } else if (st === 'affected') {
        status = overdue ? 'Revisit overdue' : 'Tracked';
      } else {
        status = 'Investigating';
      }
      suggested = vex.justification ?? null;
    } else {
      // Uncovered: at/above floor needs a decision; below floor is tracked.
      status = maxRank >= floorRank ? 'Decision needed' : 'Tracked';
      suggested = suggestJustification([...g.pkgs]);
    }

    rows.push({
      item: id,
      isCve,
      packages: [...g.pkgs].sort(),
      tools: [...g.tools].sort(),
      severities,
      maxSeverity,
      status,
      suggestedJustification: suggested,
      revisitBy: vex?.revisitBy ?? null,
      revisitOverdue: overdue,
      actionNeeded: isActionable(status),
    });
  }

  // VEX records with no matching current finding = a stale record (prune?).
  for (const [cve, vex] of vexByCve) {
    if (seenCves.has(cve)) continue;
    rows.push({
      item: cve,
      isCve: isCveId(cve),
      packages: [],
      tools: [],
      severities: {},
      maxSeverity: 'UNKNOWN',
      status: 'Stale record',
      suggestedJustification: vex.justification ?? null,
      revisitBy: vex.revisitBy ?? null,
      revisitOverdue: isRevisitOverdue(vex.revisitBy, today),
      actionNeeded: isActionable('Stale record'),
    });
  }

  // Stable order: severity desc, then item.
  rows.sort((a, b) => {
    const d = rankOf(b.maxSeverity) - rankOf(a.maxSeverity);
    return d !== 0 ? d : a.item.localeCompare(b.item);
  });
  return rows;
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

/**
 * Render the report as GitHub-flavored markdown:
 *   1. a one-line summary,
 *   2. a NARROW "action needed" table (item · status · justification · signal) —
 *      always visible, ≤4 columns so a reviewer never scrolls horizontally,
 *   3. the FULL ledger inside a DEFAULT-COLLAPSED <details> (no `open` attr).
 * `signal`: 🔴 = needs a human decision/action; ⏰ = revisit date passed;
 * ⚠️ = un-CVE'd (manual tracking). Empty otherwise.
 */
export function renderMarkdown(rows: readonly ReportRow[]): string {
  const s = summarize(rows);
  const action = rows.filter((r) => r.actionNeeded);

  const summary =
    `**VEX report** — ${rows.length} item(s): ` +
    `${s['Decision needed']} decision needed · ${s['Revisit overdue']} revisit overdue · ` +
    `${s['Stale record']} stale · ${s['Accepted']} accepted · ${s['Tracked']} tracked` +
    (s['Investigating'] ? ` · ${s['Investigating']} investigating` : '');

  const signal = (r: ReportRow): string => {
    const bits: string[] = [];
    if (r.actionNeeded) bits.push('🔴');
    if (r.revisitOverdue) bits.push('⏰');
    if (!r.isCve) bits.push('⚠️');
    return bits.join(' ') || '';
  };

  // (2) Narrow action table — only rows needing attention; the reviewer's focus.
  let actionBlock: string;
  if (action.length === 0) {
    actionBlock =
      '✅ **No action needed** — every finding is accepted or tracked.';
  } else {
    const head =
      '| item | status | justification | signal |\n| --- | --- | --- | --- |';
    const body = action
      .map(
        (r) =>
          `| ${r.item} | ${r.status} | ${shortJust(r.suggestedJustification)} | ${signal(r)} |`,
      )
      .join('\n');
    actionBlock = `**Needs attention (${action.length}):**\n\n${head}\n${body}`;
  }

  // (3) Full ledger — default-collapsed. Wider columns live here, out of the way.
  const fHead =
    '| item | status | justification | package(s) | tools (severity) | revisit_by | signal |\n' +
    '| --- | --- | --- | --- | --- | --- | --- |';
  const fBody = rows
    .map((r) => {
      const tools = r.tools.length
        ? r.tools.map((t) => `${t}=${r.severities[t]}`).join(', ')
        : '—';
      const pkgs = r.packages.length ? r.packages.join(', ') : '—';
      return `| ${r.item} | ${r.status} | ${shortJust(r.suggestedJustification)} | ${pkgs} | ${tools} | ${r.revisitBy ?? '—'} | ${signal(r)} |`;
    })
    .join('\n');

  return (
    `${summary}\n\n` +
    `${actionBlock}\n\n` +
    `<details>\n<summary>Full VEX ledger (${rows.length} items) — click to expand</summary>\n\n` +
    `${fHead}\n${fBody}\n\n` +
    `</details>`
  );
}
