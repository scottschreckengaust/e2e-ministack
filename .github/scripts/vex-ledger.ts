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
// here — grype-fs-gate re-exports them from this module (that migration landed
// with #337, when the gate started importing the purl matcher below).
//
// AND the SURFACE SCOPING of #337: matching a finding to a record by identifier
// alone let an image-scoped record suppress a same-CVE finding on the repo tree.
// `parsePurl`/`purlMatches`/`recordAcceptances`/`isCovered` add the missing
// half — a record covers a finding only when an id AND the product purl agree.
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
// vocabulary from .vex/README.md). The other four forms take no date argument —
// `wait-for-image-rebuild`, `waiting-on-upstream-issue <url>`,
// `waiting-for-fix <CVE|GHSA>` and `standing-acceptance` (the closed set is
// `RevisitForm` in vex-revisit-gate.ts) — so a record on one of those has no
// expiry to check, which is precisely why `standing-acceptance` must instead
// carry a dated `evidence.checked_at` (#352).
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
 * Whether `iso` is EXACTLY one real calendar day in `YYYY-MM-DD` form — the
 * authoring contract for the dated `revisit <ISO-date>` form (#336).
 *
 * WHY this is not just `revisitDate(iso) !== undefined`: `new Date` accepts a
 * day that OVERFLOWS its month and silently rolls it forward
 * (`new Date('2026-02-30')` is 2026-03-02, NOT Invalid Date), so the
 * Invalid-Date guard in `revisitDate` only catches an out-of-range MONTH
 * (`2026-13-45`). A typo'd `revisit 2026-02-30` would therefore parse — and
 * expire the acceptance on a date nobody authored. Rather than re-deriving
 * calendar arithmetic (leap years, month lengths), this delegates the parse to
 * `revisitDate` and then requires the round-trip to be LOSSLESS: a date-only
 * string is specified to parse as UTC midnight, so a faithfully-parsed
 * `YYYY-MM-DD` must serialize back to exactly `<iso>T00:00:00.000Z`. Any
 * rollover, extra text, or truncation breaks that equality.
 */
export function isCalendarDate(iso: string): boolean {
  const parsed = revisitDate(iso);
  if (parsed === undefined) return false;
  return parsed.toISOString() === `${iso}T00:00:00.000Z`;
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

// -- SURFACE SCOPING: the product purl a record actually argues about (#337) --
//
// WHY an id is not enough: a `.vex/` record's accepted-risk argument is made
// about ONE product — `.vex/CVE-2026-13149.openvex.json` argues reachability for
// the Debian `node-brace-expansion` package inside the pinned MiniStack image,
// and says nothing about the separately-installed `pkg:npm/brace-expansion` copy
// in this repo's own tree. Matching a finding to a record by IDENTIFIER ALONE
// let that image record silently suppress the npm finding on the filesystem
// surface: OVER-suppression, the one direction this repo's posture forbids
// (#335 C2 — nothing may get quieter). A verdict matcher must therefore compare
// the record's own product purl against the finding's artifact purl.
//
// SEMANTICS: faithful to the reference implementation this repo's records were
// authored against — openvex/go-vex `PurlMatches` (pkg/vex/vex.go), where the
// RECORD purl is a PATTERN and the finding purl is the component: type,
// namespace and name must be equal; a pattern version that is set must equal the
// component's (an EMPTY pattern version is a wildcard, matching any version);
// every qualifier the pattern names must be present with an equal value in the
// component, while qualifiers the pattern omits are IGNORED; the subpath is not
// compared. That qualifier-subset rule is exactly why `.vex/README.md` mandates
// QUALIFIER-LESS product purls: grype and trivy emit different arch/distro/epoch
// qualifiers for the same package, so a qualifier-less record matches both while
// an exact string compare would match neither.
//
// CONFORMANCE: the parser below is checked against the purl spec's OWN
// conformance suite (package-url/purl-spec `tests/spec/specification-test.json`)
// — every `test_type: parse` case in its `required` group, all of which are
// expected FAILURES (no scheme, no type, an encoded scheme colon, a type with an
// invalid character / leading digit / colon, an invalid qualifier key, a missing
// name). Those inputs are replayed verbatim in test/unit/vex-ledger.test.ts, so
// this hand-rolled parser is measured against the authority rather than against
// its author's intuition. WHY hand-rolled at all: the CI `grype` FS job runs this
// gate on a bare `actions/checkout` with NO `npm ci`, so the module may import
// nothing outside Node's built-ins — a purl library is not installable there, and
// adopting one would also be a governance/license decision. The mitigation for
// going bespoke is this conformance corpus plus the fail-closed direction below.
//
// DELIBERATE DEVIATIONS, each chosen so the failure direction is LOUDER (a
// record goes inert and the gate reds) and never quieter:
//   - No purl-type-specific case folding (packageurl-go lowercases the
//     namespace/name of deb/rpm/apk/pypi/… and maps `_`→`-` for pypi). Both
//     sides of a real comparison are already canonical — grype builds its purls
//     with packageurl-go itself, and `.vex/README.md` mandates the canonical
//     form — so folding would only ever ADD matches. A case-mismatched record
//     simply fails to cover, which reds the gate and names the CVE.
//   - `pkg://type/...` (leading slashes, which the spec tolerates) is REJECTED
//     rather than normalized: as a record purl it goes inert, as a finding purl
//     it is unprovable, and both outcomes are fail-closed.
//   - An empty qualifier value is RETAINED, where packageurl-go drops it.
//     Dropping would widen the pattern; retaining can only narrow it.
//   - The subpath is discarded rather than validated (go-vex never compares it).

/** A parsed, comparison-ready purl. Qualifier keys are lower-cased. */
export interface Purl {
  type: string;
  namespace: string;
  name: string;
  /** Empty when the purl names no version — a wildcard on the pattern side. */
  version: string;
  qualifiers: ReadonlyMap<string, string>;
}

/**
 * Percent-decode one purl component. Go's `url.PathUnescape` (what
 * packageurl-go uses) leaves `+` literal, and so does `decodeURIComponent` —
 * unlike form decoding, which would turn `+` into a space and corrupt a Debian
 * epoch/revision version like `2.0.1+~1.1.0-2`. A malformed escape (`%zz`)
 * degrades to the raw text rather than throwing, so both sides of a comparison
 * still normalize identically.
 */
function decodePurl(component: string): string {
  try {
    return decodeURIComponent(component);
  } catch {
    return component;
  }
}

// The spec's charsets. A type is `[a-zA-Z][a-zA-Z0-9.+-]*` (checked after
// lower-casing, since the type is case-insensitive); a qualifier key is
// `[a-zA-Z0-9.-_]+`. Both are anchored: a purl carrying an out-of-charset type or
// qualifier key is REJECTED outright, as packageurl-go does — the spec's
// conformance suite lists exactly those inputs as expected parse failures.
const PURL_TYPE_RE = /^[a-z][a-z0-9.+-]*$/;
const QUALIFIER_KEY_RE = /^[a-z0-9._-]+$/;

/**
 * Parse `key=value&…` into a lower-cased-key map, or null when any key is not a
 * legal qualifier key (which invalidates the whole purl). An empty `&`-separated
 * segment is skipped and a key with no `=` carries no constraint, both matching
 * packageurl-go; an empty VALUE is kept (see the deviations above).
 */
function parseQualifiers(raw: string): Map<string, string> | null {
  const qualifiers = new Map<string, string>();
  for (const pair of raw.split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const key = (eq === -1 ? pair : pair.slice(0, eq)).toLowerCase();
    if (!QUALIFIER_KEY_RE.test(key)) return null;
    if (eq === -1) continue;
    qualifiers.set(key, decodePurl(pair.slice(eq + 1)));
  }
  return qualifiers;
}

/**
 * Parse a purl string into its comparison-ready parts, or null when it is not a
 * purl this matcher can reason about. Follows the purl spec's parse order —
 * scheme, subpath, qualifiers, type, version, namespace/name — percent-decoding
 * each component. TOTAL: non-strings and malformed input yield null, never
 * throws; a null on EITHER side means "cannot prove the same surface", which
 * every caller must treat as NOT covered.
 */
export function parsePurl(value: unknown): Purl | null {
  if (typeof value !== 'string') return null;
  let rest = value.trim();
  // The scheme is case-insensitive per the spec; everything after it is not.
  if (rest.slice(0, 4).toLowerCase() !== 'pkg:') return null;
  rest = rest.slice(4);
  // Subpath: split off and DISCARDED — go-vex does not compare it.
  const hash = rest.indexOf('#');
  if (hash !== -1) rest = rest.slice(0, hash);
  let qualifierPart = '';
  const question = rest.indexOf('?');
  if (question !== -1) {
    qualifierPart = rest.slice(question + 1);
    rest = rest.slice(0, question);
  }
  const qualifiers = parseQualifiers(qualifierPart);
  if (qualifiers === null) return null;
  // Type is everything up to the first `/`, so a purl with NO `/` at all has no
  // type and is rejected. The EMPTY type (`pkg:/npm/x`) and the leading-slash
  // form (`pkg://npm/x`, a documented deviation above) need no separate guard:
  // both leave `type` empty, which the anchored charset below rejects — writing
  // `slash <= 0` here instead would state that same rejection twice, and the
  // second statement would be unfalsifiable (no input could tell the two spellings
  // apart, which is exactly what Stryker reports as a surviving mutant).
  const slash = rest.indexOf('/');
  if (slash === -1) return null;
  const type = rest.slice(0, slash).toLowerCase();
  if (!PURL_TYPE_RE.test(type)) return null;
  let path = rest.slice(slash + 1);
  // Version is after the RIGHTMOST `@`, exactly as packageurl-go's `FromString`
  // splits it — which is why a scoped npm name keeps its `@scope` (the last `@`
  // in `@scope/name@1.0.0` is the version's) while `pkg:maven/@1.3.4` leaves an
  // EMPTY name and is rejected below (a spec conformance case).
  let version = '';
  const at = path.lastIndexOf('@');
  if (at !== -1) {
    version = decodePurl(path.slice(at + 1));
    path = path.slice(0, at);
  }
  // The last non-empty segment is the name; any earlier ones are the namespace.
  const segments = path.split('/').filter((segment) => segment !== '');
  const name = segments.pop();
  if (name === undefined) return null;
  return {
    type,
    namespace: segments.map(decodePurl).join('/'),
    name: decodePurl(name),
    version,
    qualifiers,
  };
}

/**
 * Whether a RECORD purl (`pattern`) covers a FINDING purl (`component`) — the
 * go-vex `PurlMatches` relation described above. Asymmetric on purpose: the
 * pattern may be broader than the component (omitted version/qualifiers act as
 * wildcards) but never the reverse.
 */
export function purlMatches(pattern: Purl, component: Purl): boolean {
  if (pattern.type !== component.type) return false;
  if (pattern.namespace !== component.namespace) return false;
  if (pattern.name !== component.name) return false;
  // An empty pattern version is a wildcard; a set one must match exactly (which
  // also rejects a component that names no version at all).
  if (pattern.version !== '' && pattern.version !== component.version) {
    return false;
  }
  for (const [key, value] of pattern.qualifiers) {
    if (component.qualifiers.get(key) !== value) return false;
  }
  return true;
}

/**
 * Every product purl ONE OpenVEX statement argues about: each `products[]`
 * entry's `@id` and its `identifiers.purl` (OpenVEX allows either, and this
 * repo's records set both to the same value — go-vex likewise tries the `@id`
 * before the identifiers map). Unparseable entries are dropped.
 *
 * `subcomponents` are deliberately NOT read: `.vex/README.md` mandates the
 * DIRECT product-purl shape, so a record that instead nested its purl under
 * `subcomponents` would yield no purls here, go inert, and red the gate — a
 * loud, discoverable authoring failure rather than a silent broad match.
 * Malformed structures contribute nothing; never throws.
 */
export function statementPurls(statement: unknown): Purl[] {
  const purls: Purl[] = [];
  const stmt = asRecord(statement);
  if (stmt === null) return purls;
  for (const rawProduct of asArray(stmt.products)) {
    const product = asRecord(rawProduct);
    if (product === null) continue;
    const candidates: unknown[] = [product['@id']];
    const identifiers = asRecord(product.identifiers);
    if (identifiers !== null) candidates.push(identifiers.purl);
    for (const candidate of candidates) {
      const purl = parsePurl(candidate);
      if (purl !== null) purls.push(purl);
    }
  }
  return purls;
}

/**
 * One statement's acceptance, SCOPED to the surface it argues about: the ids it
 * is known by AND the product purls it covers. `purls` is guaranteed non-empty
 * (`recordAcceptances` drops a statement with no parseable product purl), so an
 * acceptance can never degenerate into "covers everything".
 */
export interface Acceptance {
  ids: ReadonlySet<string>;
  purls: readonly Purl[];
}

/**
 * The `.vex/` docs as SURFACE-SCOPED acceptances — one per statement, since
 * `products` live on the statement, not the document. Includes BOTH `affected`
 * and `not_affected` statements for the same reason `recordIds` does (each is an
 * explicit, reviewed acceptance, #188).
 *
 * FAIL-CLOSED: a statement with no matchable id, or no parseable product purl,
 * yields NO acceptance at all — it cannot suppress anything. That is the whole
 * point of #337: an acceptance with no provable surface must be inert, not
 * universal. Malformed input yields an empty list; never throws.
 */
export function recordAcceptances(docs: readonly unknown[]): Acceptance[] {
  const acceptances: Acceptance[] = [];
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    for (const rawStmt of asArray(doc.statements)) {
      const ids = statementIds(rawStmt);
      if (ids.length === 0) continue;
      const purls = statementPurls(rawStmt);
      if (purls.length === 0) continue;
      acceptances.push({ ids: new Set(ids), purls });
    }
  }
  return acceptances;
}

/**
 * Whether a finding is covered by some acceptance: an id in common AND a product
 * purl that matches the finding's. Both conditions on the SAME acceptance — an
 * id from one record plus a purl from another proves nothing.
 *
 * A finding whose purl could not be parsed (or that carries none) is NEVER
 * covered: without a purl the surface is unprovable, and the honest verdict is
 * to surface the finding. Never throws.
 */
export function isCovered(
  acceptances: readonly Acceptance[],
  findingIds: ReadonlySet<string>,
  findingPurl: Purl | null,
): boolean {
  if (findingPurl === null) return false;
  for (const acceptance of acceptances) {
    let idMatch = false;
    for (const id of findingIds) {
      if (acceptance.ids.has(id)) {
        idMatch = true;
        break;
      }
    }
    if (!idMatch) continue;
    for (const purl of acceptance.purls) {
      if (purlMatches(purl, findingPurl)) return true;
    }
  }
  return false;
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

// -- LEDGER DISCOVERY + RECORD PROJECTION: the ONE way from a `.vex/` directory
//    listing to per-statement records (#342) --
//
// WHY this is here and not in each shim: the `.mjs` CLI shims are the one layer
// NO gate can see — per #165 they hold argv/read/write plumbing only, and on
// that premise they are outside the coverage (#124) and mutation (#122) gates.
// DECISIONS had leaked in anyway and then drifted: `vex-report.mjs` discovered
// records with `startsWith('CVE-') && endsWith('.openvex.json')` while
// `vex-dialects.mjs` used the suffix alone, so over ONE directory the report
// read 46 of the 48 committed records. The two it dropped were exactly the
// surface-prefixed ones (`ecdsa-…`, `pytest-…`) — the only records carrying a
// DATED `revisit_by` — so the report's whole `Revisit overdue` pathway was
// unreachable. Single-sourcing discovery here makes that divergence impossible
// by construction, rather than relying on two filters staying aligned.
//
// The SYSCALLS stay in the shims (`readdirSync`/`readFileSync`): this module is
// a pure-transform core (jest imports it in-process, and the grype-FS gate runs
// it on a bare checkout with no `npm ci`). What moves is every DECISION — which
// entries are records, which id a statement is known by, where `revisit_by` is
// read from, and how many statements a document contributes.

/** The filename suffix every `.vex/` record carries. */
export const VEX_RECORD_SUFFIX = '.openvex.json';

/**
 * Whether a directory entry names a `.vex/` record. The suffix is the WHOLE
 * rule. A leading `<surface>-` prefix (`ecdsa-`, `pytest-`, `npm-`) says which
 * scanner surface the record argues about (`.vex/README.md`) — that is a SCOPE
 * claim, decided by `purlMatches` above against the finding's purl, and it must
 * never narrow DISCOVERY: a record the reader cannot see is a record nobody can
 * reconcile. Non-strings yield false (totality).
 */
export function isVexRecordName(name: unknown): name is string {
  return typeof name === 'string' && name.endsWith(VEX_RECORD_SUFFIX);
}

/**
 * Every `.vex/` record in a directory listing, as `dir`-joined paths, sorted.
 * `entries` is a raw `readdirSync(dir)` result — listing the directory is all
 * the shim decides. Joined with a literal `/` rather than `path.join` because
 * the generated dialect files (`trivy.yaml`, `osv-scanner.toml`) EMBED these
 * paths and are committed, so they must be POSIX-form on every host; sorted so
 * those generated artifacts are byte-stable whatever order the filesystem
 * reports. A non-array listing yields an empty list; never throws.
 */
export function vexRecordPaths(
  entries: readonly unknown[],
  dir: string,
): string[] {
  const paths: string[] = [];
  for (const entry of asArray(entries)) {
    if (isVexRecordName(entry)) paths.push(`${dir}/${entry}`);
  }
  return paths.sort();
}

/**
 * The PRIMARY id one OpenVEX statement is known by — its `vulnerability.name`,
 * normalized — accepting BOTH shapes the spec allows: the object form
 * (`{"name": "CVE-…"}`, what this repo authors) and the bare-string form
 * (`"CVE-…"`). Aliases are deliberately NOT included: this identifies the ONE
 * record, where `statementIds` enumerates everything it may MATCH. Null when
 * the statement names nothing usable.
 *
 * DELIBERATELY MORE TOLERANT than `statementIds`, which reads the object form
 * only — the two have opposite fail-directions and must not be merged.
 * `statementIds` feeds the SUPPRESSION matcher, where an unreadable shape must
 * leave the record INERT (fail-closed: it cannot quiet a gate). This feeds the
 * report's VISIBILITY projection, where an unreadable shape must still be SHOWN
 * (fail-open: dropping it would hide a committed acceptance from review).
 * Widening `statementIds` to the bare-string form would instead make a record
 * that is inert today start suppressing findings — the one direction #335 C2
 * forbids.
 */
export function statementName(statement: unknown): string | null {
  const stmt = asRecord(statement);
  if (stmt === null) return null;
  const vuln = stmt.vulnerability;
  const asObject = asRecord(vuln);
  return normId(asObject === null ? vuln : asObject.name);
}

/**
 * The `revisit_by` governing ONE statement: the DOCUMENT-level value whenever
 * the document carries the key at all, else the statement-level one. Every
 * record in this ledger sets it at the document level (#340 backfilled all of
 * them), so this precedence is live logic, not a hypothesis.
 *
 * `!== undefined` — NOT `??` — is the load-bearing detail: `??` treats an
 * explicit document-level `null` as ABSENT and falls through to the statement,
 * so a record that deliberately BLANKS the document cadence would silently
 * inherit a stale statement-level date, and a dated-expiry mechanism that reads
 * the wrong date is worse than none. A non-string result (null, a number, a
 * nested object) yields undefined — "no readable cadence" — which every
 * consumer treats as not-overdue. Never throws.
 */
export function recordRevisitBy(
  doc: unknown,
  statement: unknown,
): string | undefined {
  const docLevel = asRecord(doc) ?? {};
  const stmtLevel = asRecord(statement) ?? {};
  const raw =
    docLevel.revisit_by !== undefined
      ? docLevel.revisit_by
      : stmtLevel.revisit_by;
  return typeof raw === 'string' ? raw : undefined;
}

/**
 * One `.vex/` statement's essentials, as the reconciliation report consumes
 * them. Structurally the `VexRecord` of `vex-report.ts` — kept as its own type
 * so this module stays dependency-free (the report imports nothing from here at
 * runtime), with the call site's assignment the compile-time drift check.
 */
export interface LedgerRecord {
  /** The vulnerability id the statement names (`statementName`). */
  cve: string;
  /** The authored status: not_affected | affected | fixed | under_investigation. */
  status: string;
  /** The `not_affected` justification enum, when the statement carries one. */
  justification?: string;
  /** The governing `revisit_by` — a dated form or an event token (#340). */
  revisitBy?: string;
}

/**
 * Parsed `.vex/` documents projected to per-STATEMENT records.
 *
 * EVERY statement is read, not just `statements[0]`: OpenVEX allows a document
 * to carry many, and the shim this replaced read only the first — so a
 * multi-statement record would have had its 2nd..nth acceptances invisible in
 * the report while still suppressing scanner findings, which is precisely the
 * asymmetry (suppressed but unreviewable) the ledger exists to prevent.
 *
 * A statement whose vulnerability id is unusable is skipped — it can be neither
 * keyed nor displayed — and its siblings are kept. Everything else passes
 * through as AUTHORED (an unset status reads as `'undefined'`, exactly what the
 * report renders as `Investigating`) so the report shows what the ledger SAYS
 * rather than a normalized guess. Malformed input yields an empty list; never
 * throws.
 */
export function ledgerRecords(docs: readonly unknown[]): LedgerRecord[] {
  const records: LedgerRecord[] = [];
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    for (const rawStmt of asArray(doc.statements)) {
      const stmt = asRecord(rawStmt);
      if (stmt === null) continue;
      // Unpack the statement's own fields FIRST, then require a usable id. The
      // order matters: `statementName` is total (it answers `null` for a
      // non-record), so checking it first would make the `stmt === null` guard
      // above merely redundant rather than load-bearing — an equivalent mutant
      // Stryker can't kill. Destructuring a non-record statement throws here
      // instead, which is what the guard is for (mirrors `doc.statements` doing
      // the same job for the doc-level guard).
      const { status, justification } = stmt;
      const revisitBy = recordRevisitBy(doc, stmt);
      const cve = statementName(stmt);
      if (cve === null) continue;
      records.push({
        cve,
        status: String(status),
        justification:
          typeof justification === 'string' ? justification : undefined,
        revisitBy,
      });
    }
  }
  return records;
}
