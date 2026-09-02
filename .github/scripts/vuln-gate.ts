// The DELTA/ABSOLUTE vulnerability gate (issue #334).
//
// THE BUG THIS FIXES: the filesystem and image vuln gates answered "is the
// repo's TOTAL uncovered set empty?" — a snapshot question — while being asked,
// as REQUIRED status checks, "is this PR safe to merge?" — a delta question. The
// two diverge the moment the set moves for a reason no PR caused: a freshly
// disclosed CVE, the floating vuln DB (#183), an upstream-blocked transitive, a
// third-party image nobody can patch. Then EVERY PR in the repo goes red,
// including a docs-only one, and the snapshot gate becomes a single point of
// failure for all merges (the Gate Atomicity Law, #335 C1).
//
// THE SHAPE (the approved combination on #334):
//   * option 4 — SAME-JOB MERGE-BASE DELTA for the filesystem surfaces. The
//     merge-base tree and the PR head are scored by the SAME scanner, in the
//     SAME job, at the SAME moment, so the floating DB is identical on both
//     sides. That is precisely why no STORED baseline is needed (option 1 was
//     dropped): a persisted base result would have been taken with a different
//     DB and would drift into exactly the false verdicts it was meant to fix.
//   * option 5 — CAUSAL ATTRIBUTION for the image surfaces. There is no "base
//     image tree" to diff; the honest question is whether the PR CHANGED the
//     pinned digest. Only a change that moves the pin can be responsible for
//     what the new digest contains, so attribution is decided from the pin
//     itself — no second scan.
//   * option 2 — the DELTA verdict decides what BLOCKS; the ABSOLUTE verdict
//     stays visible (on the default branch, on schedule, and in the sticky
//     `review:vuln` burndown issue this module also renders).
//
// TWO INVARIANTS THIS MODULE EXISTS TO HOLD, both learned the hard way:
//
// 1. FAIL CLOSED, AND PROVE IT. A delta gate's dangerous failure is not a false
//    red, it is a false GREEN: if the base side silently yields nothing, every
//    head finding looks "not newly introduced" and the gate passes — a silencer
//    indistinguishable from a legitimate pass. This repo has been bitten by that
//    exact shape three times (#347 a fabricated-clean SARIF; #364 an artifact
//    rooted at `/` making a corroboration arm read `no-scanner-data` 64/64
//    times; GitHub's silent alert auto-dismissals). So: an undeterminable base
//    side NEVER reads as "nothing new" — it degrades to the ABSOLUTE verdict and
//    says so. And `BaseSide` distinguishes `scanned{count:0}` (the base
//    genuinely had none) from `no-data{reason}` (we could not look) as separate
//    VARIANTS, not as one number that happens to be zero, so the two can never
//    render identically.
//
// 2. NOTHING GETS QUIETER (#335 C2). The delta lane narrows what BLOCKS; it must
//    not narrow what is PRINTED. Every finding — attributed or not — lands in
//    `informational` when it does not block, and the report prints it, exactly as
//    the VEX-aware `npm audit` gate already prints the `affected` records it does
//    not fail on. The report is the uploaded artifact AND the CI log, so it is
//    the visibility surface: it must be self-explanatory on its own.
//
// LOGIC MODULE (jest-visible, gate-eligible): every decision lives here so it
// flows through the 100% coverage gate (#124), Stryker mutation (#122) and the
// fuzz tier. The runnable CLIs are the thin `vuln-gate.mjs` /
// `vuln-gate-burndown.mjs` shims, which hold argv/read/parse/write/exit only
// (#165 — a `.mjs` is not coverage-instrumented, so it may carry NO decision).
// TOTAL: every entry point tolerates arbitrary malformed input without throwing.

// EXPLICIT `.ts` extensions: runtime VALUE cross-imports between
// `.github/scripts` siblings, resolvable by Node 24's type-stripping loader (the
// #251 convention — see the same note in npm-audit-gate.ts / vex-revisit-gate.ts).
import {
  asArray,
  asRecord,
  normId,
  isCovered,
  recordAcceptances,
  activeRecordIds,
  type Acceptance,
} from './vex-ledger.ts';
import { normGateSeverity } from './gate-findings.ts';
import { matchVulnIds, matchPurl } from './grype-fs-gate.ts';
import { advisoryGhsaIds, extractGhsa, resolveNow } from './npm-audit-gate.ts';

// ── vocabulary ─────────────────────────────────────────────────────────────

/** Which gate is being scored. One surface == one required status check. */
export type Surface =
  | 'grype-fs'
  | 'trivy-fs'
  | 'osv'
  | 'npm-audit'
  | 'grype-image'
  | 'trivy-image';

/** The canonical surface names, in the order the burndown lists them. */
export const SURFACES: readonly Surface[] = [
  'grype-fs',
  'trivy-fs',
  'osv',
  'npm-audit',
  'grype-image',
  'trivy-image',
];

/**
 * The surface name from the workflow, or null. Deliberately EXACT (no trim, no
 * case folding): the value is a literal in `security.yml`, so a near-miss is a
 * typo, and a typo must fail the gate loudly rather than be guessed at.
 *
 * Matching by identity against the vocabulary needs NO `typeof` pre-check — a
 * non-string cannot equal any member — and the narrowed return type comes from
 * the array element, so there is no cast either.
 */
export function normSurface(value: unknown): Surface | null {
  return SURFACES.find((surface) => surface === value) ?? null;
}

/** `delta` scores what the change ADDS; `absolute` scores the whole set. */
export type Lane = 'delta' | 'absolute';

/** Whether a non-empty blocking set may fail the job. */
export type Enforcement = 'blocking' | 'report-only';

/**
 * Only the exact token opts out of blocking. Anything else — a typo, an unset
 * variable — means BLOCKING: the fail-closed direction for a gate.
 */
export function normEnforcement(value: unknown): Enforcement {
  return value === 'report-only' ? 'report-only' : 'blocking';
}

/** The severity vocabulary, lowest rung first, so the index IS the rank. */
export const SEVERITY_ORDER: readonly string[] = [
  'UNKNOWN',
  'NEGLIGIBLE',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
];

/**
 * A finding's severity rank, or null when it carries no severity STRING at all
 * (a degenerate scanner record that is not an actionable finding — the same
 * `typeof` guard `grype-fs-gate.hasSeverity` applies). An unrecognized keyword
 * ranks as UNKNOWN (0) rather than being dropped: the strictest floor is 0, so
 * an unfamiliar rating must still count.
 */
export function severityRank(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  return SEVERITY_ORDER.indexOf(normGateSeverity(value));
}

/**
 * How a fix would REACH this repo, which is what makes the C1 predicate
 * decidable (see `fixClass`). npm/PyPI are consumed DIRECTLY; the MiniStack
 * emulator is consumed as a PUBLISHED IMAGE DIGEST — one indirection this repo
 * does not control.
 */
export type FixChannel = 'registry' | 'image-digest';

/**
 * The image surfaces scan a third-party digest; everything else scans the tree.
 * An UNNAMED surface (`null`, i.e. the workflow passed a typo) takes the
 * `registry` channel — it is the conservative default: it never grants an image
 * finding the `rebuild-blocked` excuse, and the unknown surface is already
 * failing closed for a separate reason.
 */
export function channelFor(surface: Surface | null): FixChannel {
  return surface === 'grype-image' || surface === 'trivy-image'
    ? 'image-digest'
    : 'registry';
}

/**
 * The severity floor per surface, preserving each gate's SHIPPED floor exactly:
 * the filesystem gates run at grype's lowest rung — EVERY severity counts (#284
 * "drop it the most strict") — and the image gates at `high` (#84, a documented
 * ratchet). Changing a floor is its own reviewable change, not a side effect of
 * this one.
 */
export function floorFor(surface: Surface): number {
  return channelFor(surface) === 'image-digest'
    ? SEVERITY_ORDER.indexOf('HIGH')
    : 0;
}

/** Whether an upstream fix exists at all, as the scanners report it. */
export type FixState = 'fixed' | 'unfixed' | 'unknown';

/**
 * The C1 REACHABILITY CLASS (#334, #335 C1). The predicate a hard gate may
 * assert is NOT "does a fix exist?" but "is the fix reachable through a channel
 * THIS REPO consumes?" — and `fix.state: fixed` alone does not answer it:
 *
 *   * npm deps      — the repo consumes the npm registry directly, so a fixed
 *                     advisory is reachable the same day (`npm update`).
 *   * pip closures  — same, PyPI plus an overrides pin.
 *   * MiniStack image — the repo consumes PUBLISHED IMAGE DIGESTS, not Debian
 *                     packages. Debian shipping the patch does NOT put it in any
 *                     digest this repo can pin; that needs an upstream rebuild.
 *                     So `fixed` here means `rebuild-blocked`, NOT actionable —
 *                     UNLESS the change under review is itself moving the pin, in
 *                     which case the digest it moves to IS the reachability
 *                     probe and its residual belongs to the mover.
 */
export type FixClass = 'reachable' | 'rebuild-blocked' | 'no-upstream-fix';

export function fixClass(
  channel: FixChannel,
  fix: FixState,
  pinMovable: boolean,
): FixClass {
  if (fix !== 'fixed') return 'no-upstream-fix';
  if (channel === 'registry') return 'reachable';
  return pinMovable ? 'reachable' : 'rebuild-blocked';
}

/** Human wording for each class, used by the report and the burndown. */
const FIX_CLASS_TEXT: Record<FixClass, string> = {
  reachable: 'fix reachable through a channel this repo consumes',
  'rebuild-blocked':
    'fixed upstream but NOT in any published digest this repo can pin — needs an image rebuild',
  'no-upstream-fix': 'no upstream fix exists yet',
};

// ── findings ───────────────────────────────────────────────────────────────

/**
 * One normalized finding. `id` is what a human acts on; `key` is the DELTA
 * IDENTITY — it must be stable across the base and head evaluations of the same
 * finding, and distinct for two findings a reviewer would treat separately.
 */
export interface Finding {
  readonly id: string;
  readonly key: string;
  readonly severity: string;
  readonly fix: FixState;
}

/** De-duplicate by `key`, preserving first-seen order (the report's order). */
function dedupe(findings: readonly Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const finding of findings) {
    if (!byKey.has(finding.key)) byKey.set(finding.key, finding);
  }
  return [...byKey.values()];
}

const NO_PURL = '(no-purl)';
const NO_ID = '(unknown)';

/**
 * A purl reduced to its IDENTITY without the version — `pkg:npm/left-pad`. The
 * version is deliberately stripped: a PR that bumps an already-flagged package
 * from 1.0.0 to 1.0.1 while the CVE persists has introduced NOTHING, and a
 * version-bearing key would score it as a brand-new finding and false-red the
 * PR. Qualifiers are dropped for the same reason (grype and trivy emit
 * different arch/distro/epoch qualifiers for the same package — the divergence
 * already documented for the `.vex/` purls).
 */
function purlIdentity(match: unknown): string {
  const purl = matchPurl(match);
  if (purl === null) return NO_PURL;
  const namespace = purl.namespace === '' ? '' : `${purl.namespace}/`;
  return `pkg:${purl.type}/${namespace}${purl.name}`;
}

/**
 * grype's `fix.state` vocabulary → ours (`wont-fix` is an unfixed finding).
 * Takes the ALREADY-NARROWED `vulnerability` record rather than the raw match,
 * so it re-derives nothing and carries no unreachable defensive guard.
 */
function grypeFixState(vuln: Record<string, unknown>): FixState {
  const state = asRecord(vuln.fix)?.state;
  if (state === 'fixed') return 'fixed';
  if (typeof state !== 'string') return 'unknown';
  return state === 'unknown' ? 'unknown' : 'unfixed';
}

/**
 * Findings from a grype JSON document (`grype -o json`), for BOTH grype
 * surfaces. VEX-aware through the shared purl-scoped ledger, exactly as the
 * shipped FS gate is (#284/#337): an id match alone is not coverage, the
 * record's product purl must match the finding's too, and a finding with no
 * parseable purl is NEVER covered (fail-closed).
 *
 * Applying `acceptances` on the IMAGE surface as well is deliberate and cannot
 * over-suppress: grype's own go-vex pass has already moved every record it
 * matched into `ignoredMatches[]`, so this is a strictly-additional safety net
 * for a record whose purl grype's matcher spelled differently — and it can only
 * ever honour an explicit, reviewed `.vex/` record.
 */
export function findingsFromGrype(
  doc: unknown,
  acceptances: readonly Acceptance[],
  floor: number,
): Finding[] {
  const found: Finding[] = [];
  const parsed = asRecord(doc);
  if (parsed === null) return found;
  for (const match of asArray(parsed.matches)) {
    // Settle the shape ONCE: a match that carries no `vulnerability` record at
    // all is not a finding, and narrowing here (rather than optional-chaining at
    // each use) means every later access is unconditional.
    const vuln = asRecord(asRecord(match)?.vulnerability);
    if (vuln === null) continue;
    const rank = severityRank(vuln.severity);
    if (rank === null || rank < floor) continue;
    const ids = matchVulnIds(match);
    if (isCovered(acceptances, ids, matchPurl(match))) continue;
    const [primary] = ids;
    const id = primary ?? NO_ID;
    found.push({
      id,
      key: `${id}|${purlIdentity(match)}`,
      severity: normGateSeverity(vuln.severity),
      fix: grypeFixState(vuln),
    });
  }
  return dedupe(found);
}

const NO_PACKAGE = '(no-package)';

/**
 * Findings from a trivy JSON document (`trivy … --format json`).
 *
 * NO extra VEX filtering here, on purpose: trivy's VEX arrives through the
 * committed `trivy.yaml` `vulnerability.vex` list (the only channel the pinned
 * action actually forwards), so the document is already gated. Re-filtering by
 * IDENTIFIER alone would reintroduce the #337 cross-surface leak, because trivy
 * reports a bare `PkgName` and no purl — there is nothing to scope a record to.
 */
export function findingsFromTrivy(doc: unknown, floor: number): Finding[] {
  const found: Finding[] = [];
  const parsed = asRecord(doc);
  if (parsed === null) return found;
  for (const rawResult of asArray(parsed.Results)) {
    const result = asRecord(rawResult);
    if (result === null) continue;
    for (const rawVuln of asArray(result.Vulnerabilities)) {
      const vuln = asRecord(rawVuln);
      if (vuln === null) continue;
      const id = normId(vuln.VulnerabilityID);
      if (id === null) continue;
      const rank = severityRank(vuln.Severity);
      if (rank === null || rank < floor) continue;
      const pkg =
        typeof vuln.PkgName === 'string' && vuln.PkgName !== ''
          ? vuln.PkgName
          : NO_PACKAGE;
      found.push({
        id,
        key: `${id}|${pkg}`,
        severity: normGateSeverity(vuln.Severity),
        fix:
          typeof vuln.FixedVersion === 'string' && vuln.FixedVersion !== ''
            ? 'fixed'
            : 'unfixed',
      });
    }
  }
  return dedupe(found);
}

/**
 * Findings from a SARIF document (the OSV and trivy-fs surfaces), keyed on the
 * `ruleId` ALONE.
 *
 * WHY not also the location: the base side is scanned from a different root
 * (`.vuln-base/package-lock.json` vs `package-lock.json`), so every location URI
 * differs between the two sides and a location-bearing key would score EVERY
 * finding as newly introduced — a gate that is red for all PRs, which is the bug
 * being fixed. On a lockfile surface the vulnerability id is also the actionable
 * unit: it is what you would fix or record. The residual granularity gap (the
 * same id appearing on a SECOND package) is covered by the grype-FS surface,
 * which scans the same lockfile and IS purl-granular.
 */
export function findingsFromSarif(doc: unknown): Finding[] {
  const found: Finding[] = [];
  const parsed = asRecord(doc);
  if (parsed === null) return found;
  for (const rawRun of asArray(parsed.runs)) {
    const run = asRecord(rawRun);
    if (run === null) continue;
    for (const rawResult of asArray(run.results)) {
      const result = asRecord(rawResult);
      if (result === null) continue;
      const id = normId(result.ruleId);
      if (id === null) continue;
      found.push({ id, key: id, severity: 'UNKNOWN', fix: 'unknown' });
    }
  }
  return dedupe(found);
}

const NO_ADVISORY = '(no-advisory-id)';

/**
 * Whether `npm audit` says a patched version is reachable from the registry.
 *
 * `fixAvailable` is `false`, `true`, or a `{name, version, isSemVerMajor}`
 * object — npm uses the object when it can name the bump and the bare `true`
 * when it cannot, so BOTH truthy forms mean a fix exists. Only an explicit
 * `false` (or an absent/malformed field) reads as unfixed, which is the
 * fail-closed direction here: on this surface `fixed` is what makes the C1
 * predicate answer "reachable", so guessing `fixed` would overstate what the
 * repo can actually do about the finding.
 */
function npmFixState(advisory: unknown): FixState {
  const fixAvailable = asRecord(advisory)?.fixAvailable;
  return fixAvailable === undefined || fixAvailable === false
    ? 'unfixed'
    : 'fixed';
}

/**
 * Findings from `npm audit --json`, keyed on `<package>|<GHSA>`.
 *
 * WHY the pair and not the package alone: `npm audit` keys by vulnerable
 * PACKAGE, so a package that already carries one advisory would absorb a SECOND,
 * genuinely-new one behind an unchanged key — a silencer. The pair makes the new
 * advisory a new key.
 *
 * COVERAGE stays ADVISORY-level and ID-ONLY, matching the shipped
 * `npm-audit-gate` exactly (its header explains why a purl compare is
 * impossible here — npm audit emits no purl, ecosystem or version-qualified id,
 * so a purl match would never fire and the gate would false-red on every
 * legitimate acceptance). If ANY of an advisory's ids is accepted, the whole
 * advisory drops, as it does today.
 */
export function findingsFromNpmAudit(
  doc: unknown,
  accepted: ReadonlySet<string>,
): Finding[] {
  const found: Finding[] = [];
  const parsed = asRecord(doc);
  if (parsed === null) return found;
  const vulns = asRecord(parsed.vulnerabilities);
  if (vulns === null) return found;
  for (const [pkg, rawAdvisory] of Object.entries(vulns)) {
    const ids = advisoryGhsaIds(rawAdvisory);
    let covered = false;
    for (const id of ids) {
      if (accepted.has(id)) {
        covered = true;
        break;
      }
    }
    if (covered) continue;
    const fix = npmFixState(rawAdvisory);
    if (ids.size === 0) {
      found.push({
        id: NO_ADVISORY,
        key: `${pkg}|${NO_ADVISORY}`,
        severity: 'UNKNOWN',
        fix,
      });
      continue;
    }
    // Iterating the ENTRIES, not `ids` with a `.get()`: the map's keys are the
    // same set (`advisorySeverities` and `advisoryGhsaIds` traverse the same
    // `via[]` with the same extractor — asserted by a parity test), so a
    // `.get(id) ?? 'UNKNOWN'` fallback would be a branch no input can reach.
    // Unreachable code cannot be tested, and an untestable fallback is a place
    // for a bug to hide; the entry loop removes it by construction.
    for (const [id, severity] of advisorySeverities(rawAdvisory)) {
      found.push({ id, key: `${pkg}|${id}`, severity, fix });
    }
  }
  return dedupe(found);
}

/**
 * Each of an advisory's ids mapped to the severity npm reported alongside it, so
 * the log can rank findings. Display-only: the gate floor for this surface is 0,
 * so a missing severity never changes a verdict — hence an id npm rated
 * inconsistently across `via[]` entries keeps the FIRST rating rather than
 * needing a tie-break policy.
 *
 * Its key set is exactly `advisoryGhsaIds`'s output; the parity is asserted by a
 * test rather than assumed, because `findingsFromNpmAudit` relies on it to emit
 * one finding per accepted-check id.
 */
export function advisorySeverities(advisory: unknown): Map<string, string> {
  const severities = new Map<string, string>();
  const adv = asRecord(advisory);
  if (adv === null) return severities;
  for (const rawVia of asArray(adv.via)) {
    const via = asRecord(rawVia);
    if (via === null) continue;
    const id = extractGhsa(via.url);
    if (id === null) continue;
    if (!severities.has(id)) severities.set(id, normGateSeverity(via.severity));
  }
  return severities;
}

// ── the pinned-digest probe (option 5) ─────────────────────────────────────

// The pinned MiniStack image reference. A LOOKBEHIND (not a capture group) so
// the match itself IS the digest — `match[0]` is always a string, leaving no
// undefined-capture branch that no input could ever exercise.
const PIN_RE =
  /(?<=ministackorg\/ministack:[A-Za-z0-9._-]+@)sha256:[0-9a-f]{64}/g;

/**
 * The single MiniStack digest a workflow file pins, or null when it pins none —
 * or DISAGREES WITH ITSELF. Refusing to guess on disagreement matters: the
 * digest appears at several pin sites, and `check-ministack-digest-drift.sh` is
 * what keeps them equal. If they have drifted, this probe cannot say what "the"
 * pinned digest is, so it must report unknown and let the gate fail closed
 * rather than attribute findings to an arbitrary one of them.
 */
export function pinnedDigest(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  const digests = [...text.matchAll(PIN_RE)].map((match) => match[0]);
  const first = digests[0];
  if (first === undefined) return null;
  return digests.every((digest) => digest === first) ? first : null;
}

/** Whether the change under review moves the pinned image digest. */
export type DigestChange =
  | { readonly kind: 'changed'; readonly from: string; readonly to: string }
  | { readonly kind: 'unchanged'; readonly digest: string }
  | { readonly kind: 'unknown'; readonly reason: string };

export function digestChange(
  baseText: unknown,
  headText: unknown,
): DigestChange {
  const base = pinnedDigest(baseText);
  if (base === null)
    return {
      kind: 'unknown',
      reason: 'the base-side pinned digest could not be read',
    };
  const head = pinnedDigest(headText);
  if (head === null)
    return {
      kind: 'unknown',
      reason: 'the head-side pinned digest could not be read',
    };
  if (base === head) return { kind: 'unchanged', digest: head };
  return { kind: 'changed', from: base, to: head };
}

// ── lanes ──────────────────────────────────────────────────────────────────

/**
 * Which lane a run scores in.
 *
 * `push` to a FEATURE branch takes the DELTA lane, and that is load-bearing:
 * both `push` and `pull_request` fire for a PR branch push, and both report
 * under the SAME required context name, so an absolute red on the push-event run
 * would block the PR just as effectively as a red on the pull_request run.
 *
 * An unreadable ref or default branch falls back to ABSOLUTE — deliberately the
 * LOUD direction. The quiet failure would be worse: a `push` to the default
 * branch mis-classified as delta would diff `main` against itself, find every
 * finding "pre-existing", and take `main` permanently green.
 */
export function laneFor(
  event: unknown,
  ref: unknown,
  defaultBranch: unknown,
): Lane {
  if (typeof defaultBranch !== 'string' || defaultBranch === '')
    return 'absolute';
  if (typeof ref !== 'string') return 'absolute';
  if (event === 'push')
    return ref === `refs/heads/${defaultBranch}` ? 'absolute' : 'delta';
  if (event === 'pull_request') return 'delta';
  return 'absolute';
}

// ── the base side ──────────────────────────────────────────────────────────

/**
 * What the base side of the comparison yielded. `scanned` and `no-data` are
 * SEPARATE VARIANTS rather than a count that might be zero, precisely so "the
 * base genuinely had none" can never render, or be reasoned about, as "we could
 * not look".
 */
export type BaseSide =
  /** The base side was evaluated and held this many findings (possibly zero). */
  | { readonly kind: 'scanned'; readonly count: number }
  /** Image surfaces: nothing is causally attributable to this change. */
  | { readonly kind: 'unattributable'; readonly detail: string }
  /**
   * Image surfaces: the pin MOVED, so the whole head set is attributable. Its own
   * variant rather than `scanned{count:0}` for the same reason `scanned` and
   * `no-data` are separate — no base image is scanned on this path, and rendering
   * it as "the base scan found none" would state something the job never did.
   */
  | { readonly kind: 'attributed'; readonly detail: string }
  /** The base side could not be evaluated → fall back to the absolute verdict. */
  | { readonly kind: 'no-data'; readonly reason: string }
  /** Absolute lane: there is no base side to consult by design. */
  | { readonly kind: 'not-consulted'; readonly detail: string };

/** A base side plus the key set to subtract (null ⇒ subtract nothing). */
interface BaseEvaluation {
  side: BaseSide;
  keys: ReadonlySet<string> | null;
}

/** Map the digest probe onto a base side (option 5's whole decision). */
function imageBase(change: DigestChange): BaseEvaluation {
  if (change.kind === 'unchanged')
    return {
      side: {
        kind: 'unattributable',
        detail: `pinned digest unchanged (${change.digest})`,
      },
      keys: null,
    };
  if (change.kind === 'changed')
    // The pin MOVED, so nothing on the new digest pre-existed for this change:
    // an empty base set makes every finding attributable to the mover.
    return {
      side: {
        kind: 'attributed',
        detail:
          'the pinned digest MOVED — no base image is scanned, so the whole finding set on the new digest belongs to this change',
      },
      keys: new Set(),
    };
  return { side: { kind: 'no-data', reason: change.reason }, keys: null };
}

// ── the verdict ────────────────────────────────────────────────────────────

/** Everything the gate needs, as the shim hands it over (all values untrusted). */
export interface GateInput {
  /** The surface literal from `security.yml`. */
  surface: unknown;
  /** `github.event_name`. */
  event: unknown;
  /** `github.ref`. */
  ref: unknown;
  /** The repository default branch. */
  defaultBranch: unknown;
  /** `blocking` or `report-only`. */
  enforcement: unknown;
  /** The parsed HEAD scan output (`undefined` when unreadable). */
  headDoc: unknown;
  /** The parsed BASE scan output (`undefined` when unreadable/absent). */
  baseDoc: unknown;
  /** Why the workflow already knows the base side is unusable ('' when it is). */
  baseReason: unknown;
  /** Image surfaces: the base-side workflow text to read the digest pin from. */
  baseWorkflow: unknown;
  /** Image surfaces: the head-side workflow text. */
  headWorkflow: unknown;
  /** The parsed `.vex/*.openvex.json` documents. */
  vexDocs: readonly unknown[];
  /** Today, ISO — dated `revisit_by` expiry. */
  today: unknown;
}

/** The whole gate decision, as data the shim renders and exits on. */
export interface GateResult {
  outcome: 'success' | 'failure';
  /** null ⇒ the surface name was not recognized (fail-closed). */
  surface: Surface | null;
  /** The lane the event asked for. */
  lane: Lane;
  /** The lane actually applied (`absolute` after a fail-closed degrade). */
  effectiveLane: Lane;
  enforcement: Enforcement;
  channel: FixChannel;
  /** True iff this change moves the pinned image digest (option 5). */
  pinMovable: boolean;
  /** The digest probe, or null on a non-image surface / the absolute lane. */
  digest: DigestChange | null;
  headRead: boolean;
  base: BaseSide;
  /** The findings the verdict is derived from. */
  blocking: Finding[];
  /** Present but not blocking — PRINTED, never hidden (#335 C2). */
  informational: Finding[];
  /** Size of the active accepted-id set, for the log line. */
  acceptedCount: number;
  /** Fail-closed / degradation notes, printed loudly. */
  notes: string[];
}

/** Route a surface to its extractor. */
function findingsFor(
  surface: Surface,
  doc: unknown,
  acceptances: readonly Acceptance[],
  acceptedIds: ReadonlySet<string>,
): Finding[] {
  if (surface === 'grype-fs' || surface === 'grype-image')
    return findingsFromGrype(doc, acceptances, floorFor(surface));
  if (surface === 'trivy-image')
    return findingsFromTrivy(doc, floorFor(surface));
  if (surface === 'npm-audit') return findingsFromNpmAudit(doc, acceptedIds);
  return findingsFromSarif(doc);
}

const CLOSED = 'failing CLOSED';

/**
 * The ENTIRE gate decision as a pure function.
 *
 * Order matters: the two fail-closed conditions (unrecognized surface,
 * unreadable head scan) are settled BEFORE any diffing, because in both cases we
 * cannot prove anything about the head set — and "cannot prove clean" must never
 * be spelled the same way as "is clean".
 */
export function gate(input: GateInput): GateResult {
  const notes: string[] = [];
  const surface = normSurface(input.surface);
  const enforcement = normEnforcement(input.enforcement);
  const lane = laneFor(input.event, input.ref, input.defaultBranch);
  const channel = channelFor(surface);

  // Two acceptance views over ONE ledger, each matching its surface's shipped
  // gate exactly rather than quietly unifying them: purl-scoped acceptances for
  // grype (#337) and the expiry-filtered id set for npm audit (#295).
  const acceptances = recordAcceptances(input.vexDocs);
  const acceptedIds = activeRecordIds(input.vexDocs, resolveNow(input.today));

  // Only the image surfaces have a pin to probe, and only the delta lane cares
  // WHO introduced a finding — the absolute lane scores the whole set either way.
  // (No `surface !== null` conjunct: an unnamed surface takes the `registry`
  // channel, so the channel test already excludes it.)
  const digest =
    channel === 'image-digest' && lane === 'delta'
      ? digestChange(input.baseWorkflow, input.headWorkflow)
      : null;
  const pinMovable = digest !== null && digest.kind === 'changed';

  const headRead = input.headDoc !== undefined;
  const all =
    surface === null
      ? []
      : findingsFor(surface, input.headDoc, acceptances, acceptedIds);

  let evaluation: BaseEvaluation;
  if (surface === null) {
    notes.push(
      `unknown surface "${String(input.surface)}" — ${CLOSED}: the gate will not score a finding set it cannot name.`,
    );
    evaluation = {
      side: { kind: 'no-data', reason: 'the surface name is not recognized' },
      keys: null,
    };
  } else if (!headRead) {
    notes.push(
      `the head scan produced no readable output — ${CLOSED}: an unread scan is not a clean one.`,
    );
    evaluation = {
      side: {
        kind: 'no-data',
        reason: 'the head scan produced no readable output',
      },
      keys: null,
    };
  } else if (lane === 'absolute') {
    evaluation = {
      side: {
        kind: 'not-consulted',
        detail: 'absolute lane — the whole uncovered set is scored',
      },
      keys: null,
    };
  } else if (digest !== null) {
    evaluation = imageBase(digest);
    if (digest.kind === 'changed')
      notes.push(
        `this change MOVES the pinned image digest (${digest.from} -> ${digest.to}), so every finding on the new digest is attributable to it.`,
      );
  } else {
    evaluation = filesystemBase(input, surface, acceptances, acceptedIds);
  }

  if (evaluation.side.kind === 'no-data' && lane === 'delta')
    notes.push(
      `the base side yielded NO DATA (${evaluation.side.reason}) — ${CLOSED} to the ABSOLUTE verdict rather than reading it as "nothing new".`,
    );

  const baseKeys = evaluation.keys;
  const unattributable = evaluation.side.kind === 'unattributable';
  const blocking = unattributable
    ? []
    : baseKeys === null
      ? all
      : all.filter((finding) => !baseKeys.has(finding.key));
  const blockingKeys = new Set(blocking.map((finding) => finding.key));
  const informational = all.filter((finding) => !blockingKeys.has(finding.key));

  const failClosed = surface === null || !headRead;
  const outcome =
    enforcement === 'report-only'
      ? 'success'
      : failClosed || blocking.length > 0
        ? 'failure'
        : 'success';

  return {
    outcome,
    surface,
    lane,
    effectiveLane:
      lane === 'delta' && evaluation.side.kind !== 'no-data'
        ? 'delta'
        : 'absolute',
    enforcement,
    channel,
    pinMovable,
    digest,
    headRead,
    base: evaluation.side,
    blocking,
    informational,
    acceptedCount: acceptedIds.size,
    notes,
  };
}

/**
 * The filesystem base side (option 4). A reason from the workflow WINS over any
 * document: if the workflow could not materialize the merge-base tree, whatever
 * the base scanner then wrote is not a base result.
 */
function filesystemBase(
  input: GateInput,
  surface: Surface,
  acceptances: readonly Acceptance[],
  acceptedIds: ReadonlySet<string>,
): BaseEvaluation {
  const reason =
    typeof input.baseReason === 'string' ? input.baseReason : 'unreadable';
  if (reason !== '') return { side: { kind: 'no-data', reason }, keys: null };
  if (input.baseDoc === undefined)
    return {
      side: {
        kind: 'no-data',
        reason: 'the base scan produced no readable output',
      },
      keys: null,
    };
  const findings = findingsFor(
    surface,
    input.baseDoc,
    acceptances,
    acceptedIds,
  );
  return {
    side: { kind: 'scanned', count: findings.length },
    keys: new Set(findings.map((finding) => finding.key)),
  };
}

// ── the report ─────────────────────────────────────────────────────────────

/** The base-side line — the anti-silencer surface, so it is explicit. */
function baseLine(side: BaseSide): string {
  if (side.kind === 'scanned')
    return `base side: merge-base evaluated with the SAME scanner in this job — ${side.count} finding(s)`;
  if (side.kind === 'unattributable')
    return `base side: ${side.detail} — no finding here is causally attributable to this change`;
  if (side.kind === 'attributed') return `base side: ${side.detail}`;
  if (side.kind === 'not-consulted')
    return `base side: not consulted (${side.detail})`;
  return `base side: NO DATA (${side.reason}) — falling back to the ABSOLUTE verdict`;
}

function findingLines(
  findings: readonly Finding[],
  channel: FixChannel,
  pinMovable: boolean,
): string[] {
  return findings.map((finding) => {
    const klass = fixClass(channel, finding.fix, pinMovable);
    return `  - ${finding.id}  severity=${finding.severity}  fix=${finding.fix}  class=${klass} (${FIX_CLASS_TEXT[klass]})  key=${finding.key}`;
  });
}

/**
 * The gate's text report — the uploaded artifact AND the CI log surface (the
 * produce → always-upload → enforce pattern), so it must be self-explanatory
 * without opening the docs: which lane ran, what the base side yielded, what
 * blocks, and what is present-but-not-blocking.
 */
export function renderReport(result: GateResult): string {
  const name = result.surface ?? NO_ID;
  const lines = [
    `vuln gate — ${name} (#334: delta on changes, absolute on the default branch)`,
    `lane: ${result.lane} requested / ${result.effectiveLane} applied`,
    `enforcement: ${result.enforcement}`,
    `fix channel: ${result.channel}${result.pinMovable ? ' (this change moves the pin)' : ''}`,
    `active .vex/ acceptance ids: ${result.acceptedCount}`,
    baseLine(result.base),
    `verdict: ${result.outcome === 'success' ? 'PASS' : 'FAIL'}`,
    '',
  ];
  for (const note of result.notes) lines.push(`! ${note}`);
  if (result.notes.length > 0) lines.push('');
  lines.push(
    `blocking (${result.blocking.length}) — attributable to this change:`,
    ...findingLines(result.blocking, result.channel, result.pinMovable),
    `informational (${result.informational.length}) — present but NOT attributable; printed, never hidden (#335 C2):`,
    ...findingLines(result.informational, result.channel, result.pinMovable),
  );
  return `${lines.join('\n')}\n`;
}

// ── the findings document (input to the absolute burndown) ──────────────────

/** One finding as the burndown consumes it. */
export interface FindingRecord extends Finding {
  class: FixClass;
}

/** The per-surface artifact the `vuln-gate-absolute` job unions. */
export interface FindingsDocument {
  surface: string;
  lane: Lane;
  effectiveLane: Lane;
  outcome: 'success' | 'failure';
  enforcement: Enforcement;
  base: BaseSide;
  notes: string[];
  blocking: FindingRecord[];
  informational: FindingRecord[];
}

export function findingsDocument(result: GateResult): FindingsDocument {
  const record = (finding: Finding): FindingRecord => ({
    ...finding,
    class: fixClass(result.channel, finding.fix, result.pinMovable),
  });
  return {
    surface: result.surface ?? NO_ID,
    lane: result.lane,
    effectiveLane: result.effectiveLane,
    outcome: result.outcome,
    enforcement: result.enforcement,
    base: result.base,
    notes: result.notes,
    blocking: result.blocking.map(record),
    informational: result.informational.map(record),
  };
}

// ── the absolute burndown (option 2's visibility half) ─────────────────────

/** Identifies the sticky issue so the poller updates instead of duplicating. */
export const BURNDOWN_MARKER = '<!-- vuln-gate-absolute -->';

/** The sticky issue title (the `review:vuln` burndown queue, #297). */
export const BURNDOWN_TITLE =
  'review:vuln — uncovered vulnerability findings (absolute lane)';

export interface Burndown {
  /** Every finding across every surface. */
  total: number;
  /** True ONLY when every surface reported and none had a finding. */
  clean: boolean;
  /** The issue body. */
  body: string;
}

function text(value: unknown): string {
  return typeof value === 'string' && value !== '' ? value : NO_ID;
}

/**
 * The burndown's observation date from the workflow's `today` argument, or null
 * when there isn't a usable one.
 *
 * DELIBERATELY NOT `npm-audit-gate.resolveNow`, whose contract is expiry
 * semantics: it maps an ABSENT date to the epoch, precisely so no dated record is
 * ever overdue. That sentinel is right for expiry and wrong for a timestamp — it
 * would print `1970-01-01` as if it were an observation. And a MALFORMED date
 * yields an Invalid Date, whose `toISOString()` THROWS, which would break this
 * module's totality guarantee from the one place a human typo can reach it. Both
 * become null here, and null renders as an explicit unknown.
 *
 * The empty string needs no separate test: `new Date('')` IS an Invalid Date, so
 * the finiteness check already rejects it.
 */
export function observedAt(todayArg: unknown): Date | null {
  if (typeof todayArg !== 'string') return null;
  const parsed = new Date(todayArg);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

/**
 * The `review:vuln` burndown body from the per-surface findings documents.
 *
 * `clean` requires POSITIVE evidence: at least one surface reported AND nothing
 * was unreadable AND no finding was listed. An empty or unreadable input set is
 * NOT clean — the same fail-closed rule as `vex-revisit-gate`'s empty ledger,
 * for the same reason (a report that goes quiet because it found no data to read
 * recreates the hole it exists to close). TOTAL: never throws.
 */
export function burndown(docs: readonly unknown[], now: Date | null): Burndown {
  const sections: string[] = [];
  let total = 0;
  let surfaces = 0;
  let unreadable = 0;
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) {
      unreadable += 1;
      continue;
    }
    const name = doc.surface;
    if (typeof name !== 'string') {
      unreadable += 1;
      continue;
    }
    surfaces += 1;
    const findings = [...asArray(doc.blocking), ...asArray(doc.informational)];
    total += findings.length;
    sections.push('', `### \`${name}\` — ${findings.length} finding(s)`);
    for (const rawFinding of findings) {
      // `?? {}` so a garbage entry still gets a LINE (via `text`'s sentinel)
      // rather than vanishing: a finding hidden by a serialization bug is the
      // silencer shape this whole module exists to prevent (#335 C2).
      const finding = asRecord(rawFinding) ?? {};
      sections.push(
        `- \`${text(finding.id)}\` — severity ${text(finding.severity)}, ${text(finding.class)}`,
      );
    }
  }
  const clean = surfaces > 0 && unreadable === 0 && total === 0;
  const lines = [
    BURNDOWN_MARKER,
    '',
    `Last observed: ${now === null ? 'UNKNOWN — the job passed no usable date' : `${now.toISOString().slice(0, 10)} (UTC)`}, by the \`vuln-gate-absolute\` job.`,
    '',
    'This is the ABSOLUTE view of every vuln surface (issue #334, option 2): the',
    'total set of findings not covered by a `.vex/` record. It does NOT gate any',
    'pull request — the per-surface required checks score only what a change ADDS.',
    'This issue is the burndown queue for the rest.',
    '',
    `Surfaces reported: ${surfaces}. Findings: ${total}.`,
  ];
  if (surfaces === 0)
    lines.push(
      '',
      '**FAIL-CLOSED: no surface reported a finding set.** That is not evidence of a',
      'clean tree, it is an absence of evidence — check the `vuln-gate-absolute` job',
      'for a missing or misrouted artifact.',
    );
  if (unreadable > 0)
    lines.push(
      '',
      `**${unreadable} surface report(s) were unreadable** and are counted as UNKNOWN, not clean.`,
    );
  if (clean) lines.push('', 'No uncovered findings on any surface. 🎉');
  else lines.push(...sections);
  lines.push(
    '',
    '**How to clear an entry:** fix it (a bump the repo can reach), or record an',
    'honest `.vex/` acceptance with a `revisit_by` trigger. A `rebuild-blocked`',
    'entry cannot be fixed here — it needs an upstream image rebuild, so it wants a',
    '`wait-for-image-rebuild` record, not a code change.',
  );
  return { total, clean, body: `${lines.join('\n')}\n` };
}
