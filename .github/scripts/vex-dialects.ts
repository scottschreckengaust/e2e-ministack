// Generate every scanner's VEX suppression DIALECT from the ONE canonical
// `.vex/*.openvex.json` ledger (issue #251).
//
// WHY (see .vex/README.md § "Adding a record — the two-feed gotcha" and
// docs/SECURITY-TOOLING.md): a single accept/ignore decision lives in
// `.vex/*.openvex.json`, but each scanner speaks a different suppression
// dialect. Grype reads the OpenVEX files natively via `GRYPE_VEX_DOCUMENTS`
// (a glob — already single-sourced). Trivy needs an explicit FILE list in
// `trivy.yaml` `vulnerability.vex`, and OSV-Scanner has NO OpenVEX channel at
// all — only `osv-scanner.toml` `[[IgnoredVulns]]`. Hand-maintaining those two
// against `.vex/` is the drift smell #251 kills: this module GENERATES both, and
// a CI drift-check asserts the committed files match the generator output.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the repo's 100% coverage gate (#124), Stryker mutation
// (#122), and the fuzz-regression tier. The runnable CLI is the thin
// `vex-dialects.mjs` shim (glob `.vex/`, write/compare files) — Node 24 strips
// the `.ts` on import, so `node .github/scripts/vex-dialects.mjs <write|check>`
// works with no build step.
//
// INVARIANT (the #188 status semantics, uniform across dialects): only
// `not_affected`/`fixed` generate a suppression in ANY dialect; `affected`
// NEVER suppresses anywhere (the mcp records — #226/#227 — must stay visible in
// grype/trivy/OSV/Code-Scanning alike). We import the EXACT `SUPPRESSING_STATUSES`
// set from `vex-to-sarif-suppressions.ts` rather than re-deriving it, so the
// dialects can never disagree with the SARIF injector on which statuses suppress.

import { stringify as tomlStringify } from 'smol-toml';
import {
  SUPPRESSING_STATUSES,
  extractCve,
} from './vex-to-sarif-suppressions.js';

// Re-export the shared predicate so this module is the single import surface for
// the dialect generator AND so a test can assert both modules agree on the set.
export { SUPPRESSING_STATUSES };

/** The subset of an OpenVEX statement this generator reads. */
export interface VexStatement {
  vulnerability?: { name?: string } | string;
  status?: string;
  justification?: string;
  impact_statement?: string;
}

/** The subset of an OpenVEX document this generator reads. */
export interface VexDoc {
  /** Document-level custom field (#188) — a revisit trigger; may embed a date. */
  revisit_by?: string;
  statements?: VexStatement[];
}

/** A `.vex/` record: its repo-relative path (the trivy file-list entry) + doc. */
export interface VexFile {
  path: string;
  doc: VexDoc;
}

/** One `osv-scanner.toml` `[[IgnoredVulns]]` row. */
export interface IgnoredVuln {
  id: string;
  reason: string;
  ignoreUntil?: Date;
}

/**
 * True when a document has at least one statement whose status suppresses
 * (`not_affected`/`fixed`). A malformed doc (no statements array, primitive
 * statements) contributes nothing — totality, never throws.
 */
function docSuppresses(doc: VexDoc | undefined): boolean {
  if (!doc || !Array.isArray(doc.statements)) return false;
  for (const st of doc.statements) {
    if (!st) continue;
    if (SUPPRESSING_STATUSES.has(String(st.status))) return true;
  }
  return false;
}

/**
 * The subset of `.vex/` records that generate a suppression — i.e. those with a
 * `not_affected`/`fixed` statement — sorted by path (deterministic output). An
 * `affected` record (e.g. mcp) is dropped so it stays a visible finding in every
 * dialect (#188). Tolerates a non-array input and null elements (returns []).
 */
export function suppressingRecords(files: readonly VexFile[]): VexFile[] {
  if (!Array.isArray(files)) return [];
  // `.filter` already returns a fresh array, so the later `.sort` never mutates
  // the caller's array — no defensive `.slice()` needed. `localeCompare` is a
  // single, total string comparator (no hand-rolled `< / >` ternary whose
  // boundary mutants are equivalent for distinct paths).
  return files
    .filter((f) => f && docSuppresses(f.doc))
    .sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Human-readable reason for a suppressing statement: the VEX status, the
 * justification enum, and the impact prose — identical in spirit to the SARIF
 * injector's `collectSuppressions` justification, so the OSV alert carries the
 * same honest, per-CVE accepted-risk rationale. Falls back to a default enum
 * when `justification` is absent/empty; omits the impact suffix when absent.
 */
export function reasonFor(st: VexStatement): string {
  const justification =
    typeof st.justification === 'string' && st.justification !== ''
      ? st.justification
      : 'vex_not_affected';
  const impact =
    typeof st.impact_statement === 'string' && st.impact_statement !== ''
      ? ` — ${st.impact_statement}`
      : '';
  return `VEX ${String(st.status)} (${justification})${impact}`;
}

// A calendar date embedded in a `revisit_by` string (the "revisit <ISO-date>"
// vocabulary from .vex/README.md). The non-date vocabulary
// (`wait-for-image-rebuild`, `waiting-on-upstream-issue <url>`) yields no match.
const ISO_DATE_RE = /\d{4}-\d{2}-\d{2}/;

/**
 * Extract a `Date` from a `revisit_by` string when it embeds an ISO calendar
 * date, else undefined — used to derive OSV's `ignoreUntil` (a self-expiring
 * ignore). Non-string / date-free input yields undefined (totality). A bare
 * `YYYY-MM-DD` parses as UTC midnight.
 */
export function ignoreUntilFrom(revisitBy: unknown): Date | undefined {
  if (typeof revisitBy !== 'string') return undefined;
  const m = revisitBy.match(ISO_DATE_RE);
  if (!m) return undefined;
  return new Date(m[0]);
}

/**
 * The vulnerability NAME from a statement's `vulnerability` field, which OpenVEX
 * allows as either a bare string or an object `{ name }`. A string is returned
 * as-is; anything else is read via `?.name`, which yields the name for an object
 * and `undefined` for a primitive/null alike.
 */
function vulnerabilityName(v: VexStatement['vulnerability']): unknown {
  if (typeof v === 'string') return v;
  return (v as { name?: unknown } | undefined)?.name;
}

/**
 * The `osv-scanner.toml` `[[IgnoredVulns]]` rows derived from `.vex/`: one row
 * per suppressing statement carrying a CVE id, with the reason and (when the
 * record's `revisit_by` embeds a date) an `ignoreUntil`. Records are processed
 * in path order (deterministic); a non-suppressing statement, or one whose
 * vulnerability name has no CVE token, is skipped (OSV keys on the CVE id).
 */
export function ignoredVulns(files: readonly VexFile[]): IgnoredVuln[] {
  const rows: IgnoredVuln[] = [];
  for (const rec of suppressingRecords(files)) {
    const ignoreUntil = ignoreUntilFrom(rec.doc.revisit_by);
    // `suppressingRecords` only keeps records whose `doc.statements` is an
    // array (docSuppresses requires it), so the cast is safe and there is no
    // `?? []` fallback branch to leave uncovered.
    for (const st of rec.doc.statements as VexStatement[]) {
      if (!st) continue;
      if (!SUPPRESSING_STATUSES.has(String(st.status))) continue;
      const id = extractCve(vulnerabilityName(st.vulnerability));
      if (!id) continue;
      const row: IgnoredVuln = { id, reason: reasonFor(st) };
      if (ignoreUntil) row.ignoreUntil = ignoreUntil;
      rows.push(row);
    }
  }
  return rows;
}

// The GENERATED-file banner shared by both dialects; `<tool>` and the comment
// leader are filled per dialect. Kept terse: the authoring surface + rationale
// live in .vex/README.md; more prose here would just rot.
function generatedHeader(
  leader: string,
  tool: string,
  ledgerGlob: string,
): string {
  return [
    `${leader} GENERATED FILE — do NOT edit by hand.`,
    `${leader}`,
    `${leader} ${tool}'s VEX suppression dialect, generated from the canonical`,
    `${leader} ${ledgerGlob} ledger by .github/scripts/vex-dialects.ts (#251).`,
    `${leader} Add/remove an acceptance by editing a .vex/*.openvex.json record,`,
    `${leader} then regenerate: \`node .github/scripts/vex-dialects.mjs write\`.`,
    `${leader} CI (security.yml) fails if this file drifts from the generator.`,
    `${leader} Only not_affected/fixed records suppress; affected records (e.g.`,
    `${leader} the mcp CVEs, #226/#227) are omitted so they stay visible. See`,
    `${leader} .vex/README.md — the single authoring surface.`,
  ].join('\n');
}

/**
 * Render the full `trivy.yaml`: the generated banner, the non-VEX `scan`
 * policy (skip generated/vendored trees — mirrors the committed file), and the
 * `vulnerability.vex` FILE list of every suppressing record path. Trivy reads
 * this natively from the CWD (the trivy-action forwards no `--vex`/`TRIVY_VEX`),
 * and the list takes explicit paths (no glob), which is exactly why it must be
 * generated in lockstep with `.vex/`. Deterministic; ends with a newline.
 */
export function renderTrivyYaml(files: readonly VexFile[]): string {
  const records = suppressingRecords(files);
  const lines = [
    generatedHeader('#', 'Trivy', '.vex/*.openvex.json'),
    '',
    'scan:',
    '  skip-dirs:',
    '    - node_modules',
    '    - cdk.out',
    '',
    'vulnerability:',
    '  vex:',
  ];
  for (const rec of records) lines.push(`    - ${rec.path}`);
  return lines.join('\n') + '\n';
}

/**
 * Render the full `osv-scanner.toml`: the generated banner plus an
 * `[[IgnoredVulns]]` block per suppressing CVE. Reason/date escaping is
 * delegated to the vetted `smol-toml` serializer (BSD-3-Clause) so arbitrary
 * impact-statement prose (quotes, newlines, unicode) can never corrupt the
 * file. When there are no suppressing records the banner alone is emitted (a
 * valid empty config). Deterministic; ends with a newline.
 */
export function renderOsvToml(files: readonly VexFile[]): string {
  const rows = ignoredVulns(files);
  const header = generatedHeader('#', 'OSV-Scanner', '.vex/*.openvex.json');
  // smol-toml terminates its last line with a single `\n` and adds no extra
  // blank line, so its output is already a well-formed POSIX text block ending
  // in exactly one newline — use it verbatim (no trailing-newline fix-up that
  // would only differ from an equivalent mutant on input smol-toml never
  // produces). A blank line separates the banner from the first block.
  const body = rows.length ? tomlStringify({ IgnoredVulns: rows }) : '';
  return body ? `${header}\n\n${body}` : `${header}\n`;
}
