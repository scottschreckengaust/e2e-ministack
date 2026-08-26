// Generate every scanner's VEX suppression DIALECT from the ONE canonical
// `.vex/*.openvex.json` ledger (issue #251).
//
// WHY (see .vex/README.md § "What reads these records" / "Adding a record" and
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
//
// SECOND INVARIANT — SURFACE SCOPE (#337): a record suppresses only on the
// product it argues about. Trivy enforces that itself (it reads the OpenVEX
// document and matches the product purl), but OSV's `[[IgnoredVulns]]` keys on
// the vulnerability id ALONE, so the ONLY lever is what we emit: a statement is
// written into `osv-scanner.toml` only when its own product purl is a type OSV
// scans here (see `OSV_SCANNED_PURL_TYPES`). Without that filter an image-scoped
// `pkg:deb/...` record silently suppressed the same CVE on the repo tree's
// npm/pip packages — over-suppression, the one direction this repo's posture
// forbids (#335 C2).

import { stringify as tomlStringify } from 'smol-toml';
// EXPLICIT `.ts` extension (NOT `.js`, NOT extensionless): this is the repo's
// FIRST runtime VALUE cross-import between two `.github/scripts` siblings (every
// other cross-import here is `import type`, erased at runtime). The `.mjs` shim
// runs this under Node 24's type-stripping loader with NO build step, and that
// loader only resolves an EXPLICIT specifier that names an existing file — a
// `.js` sibling does NOT exist on a clean checkout (it is a gitignored tsc
// artifact), and an extensionless specifier fails too, so only
// `./vex-to-sarif-suppressions.ts` resolves at runtime. tsc accepts the `.ts`
// extension under `allowImportingTsExtensions` (set in the noEmit
// tsconfig.scripts.json that type-checks these modules); the EMITTING
// tsconfig.json never sees this file — both it and its only test importer are
// excluded there (mirroring the existing `fuzz/**` exclusion), so tsc never
// tries to emit a `.js` sibling that would shadow the `.ts` under jest/Stryker.
import {
  SUPPRESSING_STATUSES,
  extractCve,
} from './vex-to-sarif-suppressions.ts';
// Same explicit-`.ts` rule as above (#337): the surface a record argues about is
// read with the SHARED purl reader from the ledger core, so the OSV emission
// filter and the grype-FS coverage decision can never disagree about which
// product a `.vex/` statement covers.
import { statementPurls } from './vex-ledger.ts';

// Re-export the shared predicate so this module is the single import surface for
// the dialect generator AND so a test can assert both modules agree on the set.
export { SUPPRESSING_STATUSES };

/** The subset of an OpenVEX statement this generator reads. */
export interface VexStatement {
  vulnerability?: { name?: string } | string;
  status?: string;
  justification?: string;
  impact_statement?: string;
  /**
   * The product(s) the statement argues about — its SURFACE (#337). Typed
   * `unknown` because it is only ever handed to the ledger's total
   * `statementPurls` reader, which validates the shape itself.
   */
  products?: unknown;
}

/** The subset of an OpenVEX document this generator reads. */
export interface VexDoc {
  /**
   * Document-level custom field (#188) — a revisit trigger naming how the
   * acceptance ends; may embed a date.
   *
   * REQUIRED, not optional (#352). It was `revisit_by?: string` from #188 until
   * #336 made presence a hard CI gate (`vex-revisit-gate.ts`) — after which the
   * `?` was simply false: no committed record can lack the field, and typing it
   * optional invited exactly the "may be absent, so tolerate it" reflex the gate
   * exists to kill. The runtime readers below stay total anyway (this is
   * hand-authored JSON, so a type is a claim about the ledger, not a
   * guarantee about a file on disk) — but a NEW tolerance of `undefined` should
   * now have to argue with the compiler first.
   */
  revisit_by: string;
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
// vocabulary from .vex/README.md). The other four forms take no date argument —
// `wait-for-image-rebuild`, `waiting-on-upstream-issue <url>`,
// `waiting-for-fix <CVE|GHSA>` and `standing-acceptance` (the closed set is
// `RevisitForm` in vex-revisit-gate.ts, which is the gate on it) — so none of
// them yields an `ignoreUntil` unless its free-text tail happens to carry a date.
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
 * The purl types OSV-Scanner can actually report on THIS repo's OSV scan surface
 * — `osv-scanner scan source --lockfile=package-lock.json` (npm) plus the three
 * `.github/scanner-requirements/**` pip files (pypi). See the `osv-scanner` job
 * in `.github/workflows/security.yml`.
 *
 * WHY AN ALLOW-LIST AT ALL (#337): OSV's ignore entry is `{id, ignoreUntil,
 * reason}` and its matcher keys on the id ALONE (`ShouldIgnore(vulnID)` in
 * osv-scanner v2.5.1) — the dialect has NO package/ecosystem field, and
 * `[[PackageOverrides]]`'s `vulnerability.ignore` is an all-vulns-for-a-package
 * blanket, not a per-CVE scope. So a row for an IMAGE-scoped `pkg:deb/...`
 * record could never suppress the emulator finding it was written for (OSV never
 * scans the image here) — it could ONLY ever silence a same-CVE finding on the
 * repo TREE, which is exactly the over-suppression #337 closes. Emission is
 * therefore the only lever, and it is fail-closed: a statement is emitted only
 * when it affirmatively proves its surface is in scope.
 *
 * The coupling to the workflow is deliberate and its failure mode is LOUD: add a
 * lockfile in a new ecosystem to the OSV job without adding its purl type here
 * and a legitimate acceptance simply stops suppressing, so the gate reds and a
 * human reconciles — never the reverse.
 *
 * RESIDUAL, disclosed not hidden: this is as tight as OSV's dialect can express.
 * An emitted row is still id-keyed WITHIN the OSV scan, so a `pkg:pypi/...`
 * acceptance could in principle silence the same CVE on an npm package. That is
 * a strictly narrower leak than the one #337 closes (an IMAGE record silencing
 * the whole tree), and the only tighter lever is per-directory `osv-scanner.toml`
 * files — OSV discovers its config NEXT TO the scanned lockfile, not at the repo
 * root — which is its own reviewable change, not a silent tweak here.
 */
export const OSV_SCANNED_PURL_TYPES: ReadonlySet<string> = new Set([
  'npm',
  'pypi',
]);

/**
 * True when a statement's surface is inside OSV's scan scope — i.e. it names at
 * least one product purl and EVERY one of them is a type OSV can report here.
 *
 * Fail-closed in both directions: a statement with no (or no parseable) product
 * purl proves nothing about its surface and is not emitted, and one mixed purl
 * off the allow-list disqualifies the whole statement. Not emitting can only
 * make the OSV gate louder, never quieter (#335 C2).
 */
export function osvEmittable(st: VexStatement): boolean {
  const purls = statementPurls(st);
  if (purls.length === 0) return false;
  return purls.every((purl) => OSV_SCANNED_PURL_TYPES.has(purl.type));
}

/**
 * The `osv-scanner.toml` `[[IgnoredVulns]]` rows derived from `.vex/`: one row
 * per suppressing statement whose SURFACE is in OSV's scan scope (see
 * `osvEmittable`) and which carries a CVE id, with the reason and (when the
 * record's `revisit_by` embeds a date) an `ignoreUntil`. Records are processed
 * in path order (deterministic); a non-suppressing statement, one arguing about
 * a surface OSV never scans, or one whose vulnerability name has no CVE token,
 * is skipped (OSV keys on the CVE id).
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
      if (!osvEmittable(st)) continue;
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
 * Render the full `osv-scanner.toml`: the generated banner (plus the #337
 * surface-scoping note, which is OSV-specific — trivy scopes by product purl
 * natively) and an `[[IgnoredVulns]]` block per emitted CVE. Reason/date
 * escaping is delegated to the vetted `smol-toml` serializer (BSD-3-Clause) so
 * arbitrary impact-statement prose (quotes, newlines, unicode) can never corrupt
 * the file. When there are no suppressing records the banner alone is emitted (a
 * valid empty config). Deterministic; ends with a newline.
 */
export function renderOsvToml(files: readonly VexFile[]): string {
  const rows = ignoredVulns(files);
  const header = [
    generatedHeader('#', 'OSV-Scanner', '.vex/*.openvex.json'),
    '#',
    '# ALSO omitted (#337): a record whose product purl names a surface OSV does',
    '# not scan here (e.g. the pkg:deb/... MiniStack IMAGE records). OSV has no',
    '# package field on an ignore entry, so such a row could never suppress the',
    '# finding it was written for — only a same-CVE finding on the repo TREE.',
    `# Emitted purl types: ${[...OSV_SCANNED_PURL_TYPES].join(', ')}.`,
  ].join('\n');
  // smol-toml terminates its last line with a single `\n` and adds no extra
  // blank line, so its output is already a well-formed POSIX text block ending
  // in exactly one newline — use it verbatim (no trailing-newline fix-up that
  // would only differ from an equivalent mutant on input smol-toml never
  // produces). A blank line separates the banner from the first block.
  const body = rows.length ? tomlStringify({ IgnoredVulns: rows }) : '';
  return body ? `${header}\n\n${body}` : `${header}\n`;
}
