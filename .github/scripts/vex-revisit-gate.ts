// Enforce the `.vex/` ledger's `revisit_by` MUST (issue #336): every OpenVEX
// record has to name HOW its acceptance ends, in one of the five sanctioned
// forms, or CI fails.
//
// WHY a gate and not more prose: `.vex/README.md` has said `MUST` since #188,
// but every CONSUMER treats the field as optional (`revisit_by?: string`;
// `revisitDate`/`ignoreUntilFrom` return `undefined` when it is absent), so the
// rule was only ever a convention a reviewer had to catch — and most records
// predate it. An un-triggered acceptance is exactly the rot the field exists to
// prevent, so the rule needs a machine that says no.
//
// WHY this gate is safe to make HARD (the Gate Atomicity Law, #335): it asserts
// an invariant over a set this repo OWNS. Unlike the vuln gates — whose finding
// sets move when an upstream DB updates, so a snapshot assertion can deadlock —
// `.vex/` changes only when someone edits it in a PR, so the gate can never go
// red on its own, and any red is fixable in the same PR that caused it.
//
// WHAT is checked, per record:
//   1. PRESENCE — a `revisit_by` exists (doc-level, or on every statement).
//   2. VOCABULARY — the value's first word is one of the five sanctioned form
//      tokens, and the argument that form requires is well-formed.
//   3. EVIDENCE — `standing-acceptance` (#352) additionally carries a complete,
//      well-formed `evidence` object. It is the ONE form that names no future
//      event, so it is the one form that cannot be falsified by waiting; the
//      evidence object is what makes it falsifiable instead (re-run the cited
//      lookup and see whether the verdict still holds). A `standing-acceptance`
//      without evidence is a bare "we decided not to care", which is exactly
//      the blanket-ignore the ledger exists to forbid — so it FAILS.
// Argument well-formedness is the part a reviewer reliably misses: `revisit
// 2026-02-30` LOOKS like a date and even parses (see `isCalendarDate`), and
// `waiting-on-upstream-issue soon` names no tracker at all.
//
// NOT checked here (deliberate, single-responsibility): whether a dated
// `revisit_by` is already PAST. That is `activeRecordIds`' job — an overdue
// record stops covering, so the consuming scanner gate re-reds on the finding
// itself. Duplicating it here would red twice for one cause.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure decision lives here so it
// flows through the 100% coverage gate (#124), Stryker mutation (#122) and the
// fuzz tier. TOTAL: malformed input yields a violation, never a throw. The
// runnable CLI is the thin `vex-revisit-gate.mjs` shim.

// EXPLICIT `.ts` extensions: runtime VALUE cross-imports between
// `.github/scripts` siblings, resolvable by Node 24's type-stripping loader (the
// #251 convention — see the same note in npm-audit-gate.ts).
//
// `extractCve`/`extractGhsa` are REUSED rather than re-derived: the repo already
// carries the two vetted identifier matchers, and a `waiting-for-fix` argument
// must be one of exactly those two id namespaces. (`extractGhsa` sits in
// npm-audit-gate.ts only because that was its first consumer; promoting it into
// vex-ledger.ts next to the other id helpers is a follow-up, not this PR's
// scope.)
import { asArray, asRecord, isCalendarDate } from './vex-ledger.ts';
import { extractCve } from './vex-to-sarif-suppressions.ts';
import { extractGhsa } from './npm-audit-gate.ts';

/**
 * The five sanctioned `revisit_by` forms (`.vex/README.md` § the MUST), which
 * fall into three CLASSES: `date` is time-boxed (class A), `image-rebuild` /
 * `upstream-issue` / `advisory` are event-triggered (class B), and `standing`
 * is a standing acceptance whose trigger is a periodic re-check rather than an
 * event (class C, #352) — see `.vex/README.md` § "Three classes of acceptance".
 */
export type RevisitForm =
  | 'date'
  | 'image-rebuild'
  | 'upstream-issue'
  | 'advisory'
  | 'standing';

/** Rendered in the failure report so the fix is obvious without opening docs. */
const SANCTIONED_FORMS =
  'revisit <ISO-date> | wait-for-image-rebuild | waiting-on-upstream-issue <https url> | waiting-for-fix <CVE|GHSA> | standing-acceptance (requires evidence)';

/**
 * An `https` absolute URL. `URL.canParse` + `new URL` are the vetted parser (no
 * hand-rolled URL regex, and no `try`/`catch` to swallow); `http:` is rejected on
 * purpose — a `revisit_by` tracker link is a durable citation, so it must not be
 * a downgradeable one. Non-URL text (`soon`) yields false.
 */
function isHttpsUrl(value: string): boolean {
  return URL.canParse(value) && new URL(value).protocol === 'https:';
}

/**
 * A vulnerability-advisory identifier, i.e. EXACTLY a CVE or a GHSA — the two id
 * namespaces the ledger already matches on (a npm-only advisory has no CVE,
 * which is why the GHSA shape must be accepted too, #295). Reuses the vetted
 * extractors and then demands a LOSSLESS match, so an id-shaped substring inside
 * other text (`xCVE-2026-13149`) is not mistaken for an identifier.
 */
function isAdvisoryId(value: string): boolean {
  const id = value.toUpperCase();
  return extractCve(value) === id || extractGhsa(value) === id;
}

/**
 * Which sanctioned form a `revisit_by` value uses, or null if it uses none.
 *
 * Grammar: the FIRST word is the form token; the SECOND word is that form's
 * argument; anything after is free-text and ignored. The README asks each record
 * to name a trigger AND a reason, so trailing prose is encouraged — only the
 * token and its argument are machine-checked. Whitespace-insensitive. Non-string,
 * empty and unknown-token values yield null (totality).
 */
export function revisitForm(value: unknown): RevisitForm | null {
  if (typeof value !== 'string') return null;
  const [token, arg] = value.trim().split(/\s+/);
  // The two argument-free forms. `standing-acceptance` takes no argument in the
  // STRING because its argument is structured — the sibling `evidence` object,
  // checked by `evidenceDefect` (a URL + a dated lookup + a verdict do not fit
  // in one whitespace-delimited word).
  if (token === 'wait-for-image-rebuild') return 'image-rebuild';
  if (token === 'standing-acceptance') return 'standing';
  if (arg === undefined) return null;
  if (token === 'revisit') return isCalendarDate(arg) ? 'date' : null;
  if (token === 'waiting-on-upstream-issue')
    return isHttpsUrl(arg) ? 'upstream-issue' : null;
  if (token === 'waiting-for-fix') return isAdvisoryId(arg) ? 'advisory' : null;
  return null;
}

/**
 * The `revisit_by` in force for one statement: the doc-level value if the record
 * carries one, else the statement's own. Mirrors `doc.revisit_by ??
 * st.revisit_by` in vex-report.mjs, so the gate accepts a record exactly where
 * the report renders a trigger for it. A non-record statement contributes
 * nothing (never throws).
 */
export function effectiveRevisitBy(
  doc: Record<string, unknown>,
  statement: unknown,
): unknown {
  return doc.revisit_by ?? asRecord(statement)?.revisit_by;
}

/**
 * The `evidence` in force for one statement. Resolved EXACTLY like
 * `effectiveRevisitBy` (doc-level wins, else the statement's own) so a record can
 * declare `standing-acceptance` + `evidence` once at the document level and have
 * it cover every statement, rather than repeating the citation per product.
 */
export function effectiveEvidence(
  doc: Record<string, unknown>,
  statement: unknown,
): unknown {
  return doc.evidence ?? asRecord(statement)?.evidence;
}

/**
 * The `evidence` fields a `standing-acceptance` MUST carry, in report order.
 *
 * Every one of them answers a question a reader of the record would otherwise
 * have to take on trust: WHO says so (`source`), WHERE to re-check it (`url`),
 * WHAT was looked up (`source_package` — Debian keys on source packages, so this
 * is NOT the purl's binary package name), against which release (`suite`), what
 * the answer was (`verdict`), how far it reaches (`scope`), and WHEN it was last
 * confirmed (`checked_at`, the field the periodic re-check in #354 reads).
 */
export const EVIDENCE_FIELDS = [
  'source',
  'url',
  'source_package',
  'suite',
  'verdict',
  'scope',
  'checked_at',
] as const;

/** One member of `EVIDENCE_FIELDS`. */
export type EvidenceField = (typeof EVIDENCE_FIELDS)[number];

/**
 * Per-field well-formedness. Two fields carry a machine-checkable shape — `url`
 * must be a durable https citation (same rule as `waiting-on-upstream-issue`)
 * and `checked_at` a real calendar date (so "when was this last confirmed" can be
 * compared, not just read) — and the rest must be non-blank text. A whitespace
 * string is treated as absent on purpose: `suite: " "` is not a citation.
 */
function evidenceFieldWellFormed(field: EvidenceField, value: string): boolean {
  if (field === 'url') return isHttpsUrl(value);
  if (field === 'checked_at') return isCalendarDate(value);
  return value.trim() !== '';
}

/**
 * The FIRST defect in a `standing-acceptance`'s evidence, or null when it is
 * complete and well-formed. The string is a report line, not a type — one
 * actionable defect per record keeps the failure output one line long.
 *
 * TOTAL: any non-object (including `undefined` for an absent field) is a defect,
 * never a throw. Fails CLOSED — an unreadable evidence block is a missing one.
 */
export function evidenceDefect(evidence: unknown): string | null {
  const record = asRecord(evidence);
  if (record === null) return 'no evidence object';
  for (const field of EVIDENCE_FIELDS) {
    const value = record[field];
    if (value === undefined) return `evidence.${field} absent`;
    if (typeof value !== 'string')
      return `evidence.${field} not a string (${typeof value})`;
    if (!evidenceFieldWellFormed(field, value))
      return `evidence.${field} malformed: ${value}`;
  }
  return null;
}

/** One `.vex/` file as the shim hands it over (`doc` is undefined if unreadable). */
export interface LedgerEntry {
  path: string;
  doc: unknown;
}

/**
 * Why a record fails: unparseable, no field, a value outside the vocabulary, or
 * a `standing-acceptance` whose required `evidence` is missing/malformed.
 */
export type ViolationReason =
  | 'unreadable'
  | 'missing'
  | 'unsanctioned'
  | 'evidence';

/**
 * One failing record. `value` is the offending text ('' when there is none) — for
 * an `evidence` violation it is the defect from `evidenceDefect`.
 */
export interface Violation {
  path: string;
  reason: ViolationReason;
  value: string;
}

/** The `revisit_by` + `evidence` pair in force for one statement. */
export interface InForce {
  value: unknown;
  evidence: unknown;
}

/**
 * Every (`revisit_by`, `evidence`) pair in force across a record — one per
 * statement, or the doc-level pair alone when a record carries no statements.
 *
 * EXPORTED so the class-C premise check (`vex-debian-tracker.ts`, #353) resolves
 * "which form is in force" through the SAME reader this gate enforces with.
 * Re-deriving it there would let the two modules disagree about whether a record
 * is a standing acceptance — the gate demanding evidence for a record the premise
 * check never re-verifies, which is precisely the silent gap class C exists to
 * close. Same argument the joiner already makes for reusing `statementName` /
 * `statementPurls`.
 */
export function inForcePairs(record: Record<string, unknown>): InForce[] {
  const statements = asArray(record.statements);
  if (statements.length === 0)
    return [{ value: record.revisit_by, evidence: record.evidence }];
  return statements.map((statement) => ({
    value: effectiveRevisitBy(record, statement),
    evidence: effectiveEvidence(record, statement),
  }));
}

/**
 * The violation for one record, or null when it complies. A record complies iff
 * EVERY statement has a sanctioned `revisit_by` in force (doc-level covers them
 * all at once) — plus complete `evidence` where that form demands it; a record
 * with no statements must carry the doc-level fields. Only the first failing
 * statement is reported — one record, one actionable line.
 *
 * TOTAL by construction: anything that is not a JSON object (including the
 * `undefined` the shim yields for an unparseable file) is a violation, so a
 * broken record can never pass as "nothing to check".
 */
export function recordViolation({ path, doc }: LedgerEntry): Violation | null {
  const record = asRecord(doc);
  if (record === null) return { path, reason: 'unreadable', value: '' };
  for (const { value, evidence } of inForcePairs(record)) {
    const form = revisitForm(value);
    // A standing acceptance is the only form whose validity depends on data
    // OUTSIDE the `revisit_by` string, so it is checked here and not in
    // `revisitForm` (which sees the string alone).
    if (form === 'standing') {
      const defect = evidenceDefect(evidence);
      if (defect === null) continue;
      return { path, reason: 'evidence', value: defect };
    }
    if (form !== null) continue;
    if (value === undefined || value === null)
      return { path, reason: 'missing', value: '' };
    return {
      path,
      reason: 'unsanctioned',
      // `String(value)` would throw on a symbol and JSON.stringify can return
      // undefined; the type name is enough for a human to find the typo.
      value: typeof value === 'string' ? value : `<non-string ${typeof value}>`,
    };
  }
  return null;
}

/** The whole gate decision, as data the shim renders/exits on. */
export interface GateResult {
  outcome: 'success' | 'failure';
  violations: Violation[];
  checked: number;
}

/**
 * The ENTIRE gate decision as a pure function, so the `.mjs` shim keeps no logic
 * of its own (#165 — the shim is not coverage-instrumented).
 *
 * Fails on any violating record AND on an EMPTY ledger: a presence gate that
 * passes because it found no records to check would recreate the very hole it
 * exists to close (a broken glob, a moved directory). Fail-closed is the repo's
 * convention for "cannot prove the invariant holds".
 */
export function gateResult(entries: readonly LedgerEntry[]): GateResult {
  const violations: Violation[] = [];
  for (const entry of entries) {
    const violation = recordViolation(entry);
    if (violation !== null) violations.push(violation);
  }
  return {
    outcome:
      violations.length === 0 && entries.length > 0 ? 'success' : 'failure',
    violations,
    checked: entries.length,
  };
}

/** The human-readable line for one violation. */
const REASON_TEXT: Record<ViolationReason, string> = {
  unreadable: 'unreadable record (not a JSON object)',
  missing: 'no revisit_by',
  unsanctioned: 'unsanctioned revisit_by',
  evidence: 'standing-acceptance without complete evidence',
};

/**
 * The gate's text report — the uploaded artifact AND the CI log surface (the
 * produce → always-upload → enforce pattern), so it must be self-explanatory:
 * what failed, where, and which forms are allowed.
 */
export function renderReport(result: GateResult): string {
  const lines = [
    '.vex/ revisit_by gate (#336/#352) — presence + vocabulary + evidence',
    `records checked: ${result.checked}`,
    `violations: ${result.violations.length}`,
    '',
  ];
  if (result.checked === 0) {
    lines.push(
      'FAIL — no readable .vex/ record was checked; failing closed (a vacuously-green',
      'presence gate is exactly the hole this gate closes).',
    );
  } else if (result.violations.length === 0) {
    lines.push('PASS — every record carries a sanctioned revisit_by.');
  } else {
    lines.push(
      'FAIL — every .vex/ record MUST carry a revisit_by naming how the acceptance ends',
      '(see .vex/README.md § "Every record MUST carry a reason and a timeline").',
      `sanctioned forms: ${SANCTIONED_FORMS}`,
    );
    // Only spell the evidence contract out when a record actually tripped it —
    // the common failure is a typo'd token, and an unconditional field list would
    // bury it.
    if (result.violations.some((violation) => violation.reason === 'evidence'))
      lines.push(
        `standing-acceptance evidence fields: ${EVIDENCE_FIELDS.join(', ')}`,
      );
    for (const violation of result.violations) {
      const detail = violation.value === '' ? '' : ` ("${violation.value}")`;
      lines.push(
        `  - ${violation.path}: ${REASON_TEXT[violation.reason]}${detail}`,
      );
    }
  }
  return `${lines.join('\n')}\n`;
}
