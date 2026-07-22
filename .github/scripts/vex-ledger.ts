// The SHARED VEX ledger core (issue #295): one identifier-matcher + one expiry
// mechanism for EVERY scanner surface that reads `.vex/*.openvex.json`.
//
// WHY (the unification #295 asked for): the accept/ignore DECISION is already
// single-sourced in `.vex/`, but the *matching* was re-implemented per surface:
// `grype-fs-gate.ts` unions `name` ∪ `aliases[]` (CVE and GHSA alike), while the
// dialect generators (`vex-dialects.ts`) match a CVE-only regex on the name and
// silently drop the aliases. An npm-audit gate is the first consumer that must
// match on the GHSA (npm audit carries no CVE — only a GHSA URL), so the
// CVE-only path would make it invisible to every base-image record. This module
// is the ONE matcher those consumers import, so a record covers identically on
// every surface. `recordIds` is the promoted form of grype-fs-gate's
// `vexAcceptedIds`; the coercions (`asArray`/`asRecord`/`normId`) consolidate
// here (grype-fs-gate re-exports them from this module in a later migration).
//
// AND the dated-`revisit_by` EXPIRY decided on #295 (the `.nsprc`-parity edge):
// an acceptance whose record embeds a dated `revisit_by` on/before today stops
// covering — `activeRecordIds` drops it — so the finding re-reds automatically
// instead of rotting. The event-token vocabulary (`wait-for-image-rebuild`,
// `waiting-on-upstream-issue <url>`) never expires (it waits on an event, not a
// clock); a genuinely time-boxed acceptance (override/bundled-dep "wait for the
// vendor") should use the DATED form so this nag fires. This generalizes the
// `ignoreUntilFrom` date-extraction already in `vex-dialects.ts`.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transforms live here so
// they flow through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. TOTAL: malformed input yields an empty
// set / undefined, never throws.

// -- small total coercions (the single home for the copies that grype-fs-gate.ts
//    / gate-findings.ts / sarif-cve-ids.ts each carry today) --

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
 * trimmed. Non-strings and empty/whitespace-only values yield null (totality).
 * NOT restricted to a CVE regex: the `.vex/` name is frequently a CVE while the
 * aliases are GHSAs, and #295's whole point is to match either shape, so both
 * id forms must survive normalization.
 */
export function normId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const t = value.trim().toUpperCase();
  return t.length > 0 ? t : null;
}

/**
 * Every id ONE OpenVEX statement is known by: its `vulnerability.name` plus
 * every `vulnerability.aliases[]` entry, normalized, in that order and without
 * blanks. This is the atom the whole ledger matches on — the CVE the record
 * names AND the GHSA(s) it aliases. Malformed structures contribute nothing;
 * never throws.
 */
export function statementIds(statement: unknown): string[] {
  const ids: string[] = [];
  const stmt = asRecord(statement);
  if (stmt === null) return ids;
  const vuln = asRecord(stmt.vulnerability);
  if (vuln === null) return ids;
  const name = normId(vuln.name);
  if (name !== null) ids.push(name);
  for (const rawAlias of asArray(vuln.aliases)) {
    const alias = normId(rawAlias);
    if (alias !== null) ids.push(alias);
  }
  return ids;
}

// A calendar date embedded in a `revisit_by` string (the "revisit <ISO-date>"
// vocabulary from .vex/README.md). The event-token vocabulary
// (`wait-for-image-rebuild`, `waiting-on-upstream-issue <url>`) yields no match.
const ISO_DATE_RE = /\d{4}-\d{2}-\d{2}/;

/**
 * The `Date` a `revisit_by` string embeds, or undefined. A match on the ISO
 * shape is parsed as UTC midnight; a structurally-ISO but invalid calendar date
 * (e.g. `2026-13-45`) yields undefined (via the Invalid-Date guard), so callers
 * never compare against `NaN`. Non-strings yield undefined (totality).
 */
export function revisitDate(revisitBy: unknown): Date | undefined {
  if (typeof revisitBy !== 'string') return undefined;
  const m = revisitBy.match(ISO_DATE_RE);
  if (m === null) return undefined;
  const d = new Date(m[0]);
  if (Number.isNaN(d.getTime())) return undefined;
  return d;
}

/**
 * Whether a `revisit_by` names a DATE that is on/before `now` — i.e. the
 * acceptance is time-boxed and its window has passed, so it must stop covering
 * (the finding re-reds). An event-token `revisit_by` (no date) is NEVER overdue.
 * `now` is injected (the repo's scripts can't call `Date.now()` in the fuzz/
 * Stryker sandbox) so the decision is deterministic and testable.
 */
export function isRevisitOverdue(revisitBy: unknown, now: Date): boolean {
  const due = revisitDate(revisitBy);
  if (due === undefined) return false;
  return due.getTime() <= now.getTime();
}

/**
 * The set of every id ACCEPTED by the given `.vex/` docs — the union of every
 * statement's `statementIds` across every doc. Includes BOTH `affected` and
 * `not_affected` statements: each is an explicit, reviewed acceptance (#188), so
 * both keep a gate green (an `affected` finding stays VISIBLE via the SARIF
 * dialect's separate `not_affected`/`fixed` filter — this set is only about
 * gate pass/fail). Malformed docs/statements are skipped; never throws. This is
 * the promoted form of grype-fs-gate.ts's `vexAcceptedIds`.
 */
export function recordIds(docs: readonly unknown[]): Set<string> {
  const ids = new Set<string>();
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    for (const rawStmt of asArray(doc.statements)) {
      for (const id of statementIds(rawStmt)) ids.add(id);
    }
  }
  return ids;
}

/**
 * Like `recordIds`, but EXCLUDES any doc whose `revisit_by` names a date on/
 * before `now` — the dated-expiry mechanism (#295). An overdue record's ids are
 * dropped from the accepted set, so a gate that was passing on that acceptance
 * re-reds until the record is renewed (a fresh date) or the finding is fixed.
 * Records with no `revisit_by`, or an event-token one, are always active.
 * Malformed input yields an empty set; never throws.
 */
export function activeRecordIds(
  docs: readonly unknown[],
  now: Date,
): Set<string> {
  const ids = new Set<string>();
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    if (isRevisitOverdue(doc.revisit_by, now)) continue;
    for (const rawStmt of asArray(doc.statements)) {
      for (const id of statementIds(rawStmt)) ids.add(id);
    }
  }
  return ids;
}
