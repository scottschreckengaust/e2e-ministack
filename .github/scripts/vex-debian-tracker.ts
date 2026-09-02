// Join the `.vex/` ledger's `pkg:deb/debian/*` acceptances against Debian's OWN
// verdict, so a STANDING acceptance can cite evidence instead of asserting one
// (issue #352, the joiner half; the dialect half is `vex-revisit-gate.ts`).
//
// WHY THIS EXISTS. Most records in this ledger accept an unfixable CVE in the
// pinned MiniStack base image. Their `revisit_by` says `wait-for-image-rebuild`,
// i.e. "a rebuilt image will drop this" — but for a whole class of them that is
// simply false: Debian has looked at the CVE and decided it will never be fixed
// in this suite (`urgency: unimportant`, or a `<no-dsa>` deferral). No image
// rebuild can end such an acceptance, so the trigger is a fiction and the record
// can never expire. The honest form is a STANDING acceptance that carries the
// evidence for its own premise — and this module is where that evidence comes
// from, machine-readable and re-checkable.
//
// THE SOURCE. `https://security-tracker.debian.org/tracker/data/json` — the
// tracker's full JSON dump, keyed source package -> CVE -> `releases.<suite>`.
// Consumed as public DATA over ONE HTTPS GET with Node built-ins: nothing is
// adopted as a tool, nothing is redistributed, and no dependency is added, so
// the repo's tool-adoption line (AGENTS.md § Security checks) has nothing to
// clear here. The payload is ~86 MB and is NEVER committed — not whole, not
// sliced, not as a derived fixture. Every test below uses a hand-authored
// document that encodes a SHAPE.
//
// WHY IT IS NOT A GATE (the Gate Atomicity Law, #335 C1). A required check that
// GETs a third-party file makes CI's verdict depend on a service this repo
// cannot keep up. That is exactly the externally-mutable dependency C1 forbids
// in a blocking path, so this module is REPORT-ONLY and its workflow job runs on
// `schedule`/`workflow_dispatch` only. It also edits nothing: the classification
// is REPORTED, never applied (#322 — no record is added, deleted or re-dated).
//
// THE JOIN KEY IS THE VERSION, NOT THE NAME. Debian keys on SOURCE packages;
// a purl from an image scan carries the BINARY package. `libacl1` is built from
// source `acl`, `libattr1` from `attr`, `libc6`/`libc-bin` from `glibc` — so a
// name join fails by construction on essentially every library. The version
// string, however, is shared: the binary package's version IS its source
// version (modulo the two normalizations below), so matching the purl version
// against `releases.<suite>.repositories.<suite>` is the only key that works.
//
// LOGIC MODULE (jest-visible, gate-eligible): every decision lives here so it
// flows through the 100% coverage gate (#124) and Stryker (#122). TOTAL:
// malformed input yields an empty result, never a throw. The runnable CLI is the
// thin `vex-debian-tracker.mjs` shim (fetch/read/write only, #165).

// EXPLICIT `.ts` extensions: runtime VALUE cross-imports between
// `.github/scripts` siblings, resolvable by Node 24's type-stripping loader (the
// #251 convention — see the same note in npm-audit-gate.ts).
//
// REUSED, NOT RE-DERIVED: `statementName` / `statementPurls` are the ledger's
// own readers for "which CVE" and "which surface", so the joiner can never
// disagree with the suppression matcher about what a record covers — and
// `statementPurls` runs each product through `parsePurl`, which already
// percent-decodes components to spec (#337). That is why an encoded epoch
// (`1%3A2.5.2-3`) never reaches this module: half of the epoch problem was
// already solved, and only the MISSING-epoch half is normalized below.
import {
  asArray,
  asRecord,
  normId,
  statementName,
  statementPurls,
} from './vex-ledger.ts';
// `inForcePairs` / `revisitForm` are the revisit GATE's own readers for "which
// `revisit_by` form, and which `evidence`, is in force on this record". The
// class-C premise check below reuses them rather than re-deriving the resolution,
// so the gate and the check can never disagree about which records ARE standing
// acceptances (#353). `LedgerEntry` is the existing type for "one `.vex/` file as
// the shim hands it over".
import {
  type LedgerEntry,
  inForcePairs,
  revisitForm,
} from './vex-revisit-gate.ts';

/** The tracker's full JSON dump — the ONE URL the shim fetches. */
export const DEBIAN_TRACKER_URL =
  'https://security-tracker.debian.org/tracker/data/json';

/**
 * The Debian suite the pinned MiniStack image is built from. The join is only
 * meaningful per-suite: the same CVE is `unimportant` in one release and open in
 * the next, and `repositories.<suite>` is what carries the version to match.
 */
export const DEBIAN_SUITE = 'trixie';

/** The purl coordinates this module joins on (see the header). */
const DEB_PURL_TYPE = 'deb';
const DEB_PURL_NAMESPACE = 'debian';

/**
 * A Debian version split into the three parts a join has to reason about.
 * `epoch` is `null` when the version WROTE none — deliberately distinct from an
 * explicit `'0'`, because "no epoch written" can be a purl-rendering LOSS that
 * may be relaxed away, whereas `0:` is a claim.
 */
export interface DebianVersion {
  epoch: string | null;
  base: string;
  /** The binNMU marker (`+b1`), or `''` — a binary-only rebuild. */
  binNmu: string;
}

// Only `<digits>:` is an epoch (Debian Policy 5.6.12); `x:1.0-1` has none.
const EPOCH_RE = /^(\d+):(.*)$/;
// A binNMU suffix: `+b<digits>` at the very END. `+dfsg`, `+deb13u2` and
// `~deb13u2` are part of the version proper and must survive.
const BINNMU_RE = /\+b\d+$/;

/**
 * Split a Debian version. Total: any string parses (the whole input becomes
 * `base` when it carries neither marker).
 */
export function parseDebianVersion(value: string): DebianVersion {
  const epochMatch = EPOCH_RE.exec(value);
  const epoch = epochMatch === null ? null : epochMatch[1];
  const withoutEpoch = epochMatch === null ? value : epochMatch[2];
  const binNmuMatch = BINNMU_RE.exec(withoutEpoch);
  if (binNmuMatch === null) return { epoch, base: withoutEpoch, binNmu: '' };
  return {
    epoch,
    base: withoutEpoch.slice(0, -binNmuMatch[0].length),
    binNmu: binNmuMatch[0],
  };
}

/**
 * How much tolerance a successful join needed. Reported per row so the relaxation
 * is auditable: a join is only trustworthy if the reader can see what it ignored.
 */
export type VersionRelaxation =
  | 'exact'
  | 'binnmu'
  | 'epoch-stripped'
  | 'binnmu+epoch-stripped';

/**
 * Whether an image purl's version and a suite's version name the same source
 * version, and with how much relaxation — or null when they do not.
 *
 * TWO NORMALIZATIONS, both forced by real records:
 *
 *  1. binNMU. The image carries `2.3.2-2+b1` (a binary-only rebuild against a
 *     new library) while trixie's source version is `2.3.2-2`. The rebuild
 *     changes no source, so the tracker's verdict applies unchanged.
 *  2. A MISSING epoch. Trivy renders a Debian epoch into a purl QUALIFIER, and
 *     `.vex/README.md` mandates qualifier-less product purls — so the epoch is
 *     simply absent from one side. That is a rendering loss, not an epoch-0
 *     claim, which is why `.vex/README.md` already asks such records to list
 *     BOTH version forms. Relaxed in ONE direction only: when both sides WROTE
 *     an epoch and they differ, nothing was lost and the versions really are
 *     different (`1:1.0-1` != `2:1.0-1`).
 *
 * An EMPTY version on either side proves nothing (a purl may legally omit its
 * version, and a package may be absent from the suite repo) and never joins —
 * silently matching two blanks would fabricate evidence.
 */
export function matchDebianVersion(
  purlVersion: string,
  suiteVersion: string,
): VersionRelaxation | null {
  if (purlVersion === '' || suiteVersion === '') return null;
  const left = parseDebianVersion(purlVersion);
  const right = parseDebianVersion(suiteVersion);
  if (left.base !== right.base) return null;
  const epochsEqual = (left.epoch ?? '0') === (right.epoch ?? '0');
  if (!epochsEqual && left.epoch !== null && right.epoch !== null) return null;
  const rebuilt = left.binNmu !== right.binNmu;
  if (epochsEqual) return rebuilt ? 'binnmu' : 'exact';
  return rebuilt ? 'binnmu+epoch-stripped' : 'epoch-stripped';
}

/** One source package's tracker entry for one CVE in one suite. */
export interface TrackerEntry {
  /** The SOURCE package the tracker filed it under (never the binary one). */
  sourcePackage: string;
  /** `releases.<suite>.repositories.<suite>` — the version to join on. */
  suiteVersion: string;
  /** `open` | `resolved` | `undetermined`. */
  status: string;
  /** `unimportant` | `low` | `medium` | `high` | `not yet assigned` | `end-of-life`. */
  urgency: string;
  /** The version that fixes it in this suite, or `''` when none is named. */
  fixedVersion: string;
  /** Debian's `<no-dsa>` note — set when a fix is deliberately deferred. */
  nodsa: string;
  nodsaReason: string;
  /** CVE-level `scope`: `local` | `remote`. */
  scope: string;
}

/** A field as a string, or `''`. Absent/typed-wrong fields must not branch later. */
function stringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  return typeof value === 'string' ? value : '';
}

/**
 * The tracker payload indexed by CVE id — ONE pass over ~86 MB, so each triple's
 * lookup afterwards is O(candidates).
 *
 * A CVE can appear under SEVERAL source packages (the same flaw filed against
 * both a fork and its origin), so the value is a list; which of them applies to
 * a given purl is decided by the VERSION, later. An entry with no node for the
 * requested suite is dropped — it carries no verdict for the image we scan.
 * Malformed packages/CVEs/releases are skipped; never throws.
 */
export function indexTracker(
  tracker: unknown,
  suite: string,
): Map<string, TrackerEntry[]> {
  const index = new Map<string, TrackerEntry[]>();
  const root = asRecord(tracker);
  if (root === null) return index;
  for (const [sourcePackage, rawCves] of Object.entries(root)) {
    const cves = asRecord(rawCves);
    if (cves === null) continue;
    for (const [rawId, rawCve] of Object.entries(cves)) {
      const id = normId(rawId);
      if (id === null) continue;
      const cve = asRecord(rawCve);
      if (cve === null) continue;
      const releases = asRecord(cve.releases);
      if (releases === null) continue;
      const release = asRecord(releases[suite]);
      if (release === null) continue;
      const repositories = asRecord(release.repositories) ?? {};
      const entry: TrackerEntry = {
        sourcePackage,
        suiteVersion: stringField(repositories, suite),
        status: stringField(release, 'status'),
        urgency: stringField(release, 'urgency'),
        fixedVersion: stringField(release, 'fixed_version'),
        nodsa: stringField(release, 'nodsa'),
        nodsaReason: stringField(release, 'nodsa_reason'),
        scope: stringField(cve, 'scope'),
      };
      const existing = index.get(id);
      if (existing === undefined) index.set(id, [entry]);
      else existing.push(entry);
    }
  }
  return index;
}

/**
 * The classification of one acceptance. The first four are Debian's verdict for
 * a triple that JOINED; the last three are join outcomes that need a human.
 *
 * `FIXED-UPSTREAM` is the bucket #341's four-bucket table lacks, and it is the
 * loudest one: it says the suite HAS a fix, so an acceptance claiming there is
 * nothing to wait for has a false premise. Report order is the report's order.
 */
export const BUCKETS = [
  'UNIMPORTANT-NO-FIX',
  'NO-DSA',
  'OPEN-NO-FIX',
  'FIXED-UPSTREAM',
  'AMBIGUOUS',
  'NO-VERSION-MATCH',
  'NO-CVE-IN-TRACKER',
] as const;

export type Bucket = (typeof BUCKETS)[number];

/** The four buckets one JOINED entry can produce (never a join outcome). */
type EntryBucket = Extract<
  Bucket,
  'UNIMPORTANT-NO-FIX' | 'NO-DSA' | 'OPEN-NO-FIX' | 'FIXED-UPSTREAM'
>;

/**
 * Debian's verdict for ONE joined entry, most-actionable first:
 *
 *  - a named `fixed_version` OR `status: resolved` -> the suite is not (or no
 *    longer) vulnerable. The two signals are independent — a resolved entry does
 *    not always name a version — so either alone is enough.
 *  - `urgency: unimportant` -> Debian will not fix it here. No rebuild ends it.
 *  - a `<no-dsa>` note -> a fix is deliberately deferred (point release only).
 *  - otherwise -> genuinely open, which a rebuild genuinely might fix.
 */
export function entryVerdict(entry: TrackerEntry): EntryBucket {
  if (entry.fixedVersion !== '' || entry.status === 'resolved')
    return 'FIXED-UPSTREAM';
  if (entry.urgency === 'unimportant') return 'UNIMPORTANT-NO-FIX';
  if (entry.nodsa !== '') return 'NO-DSA';
  return 'OPEN-NO-FIX';
}

/** One (record, CVE, deb purl) triple — the unit the ledger is classified in. */
export interface DebTriple {
  /** The `.vex/` record path. */
  path: string;
  cve: string;
  /** The BINARY package name, kept for the report (never a join key). */
  name: string;
  version: string;
  /** The purl re-rendered decoded + qualifier-free, i.e. as the join saw it. */
  purl: string;
}

/**
 * Every `pkg:deb/debian/*` triple in the ledger. One row per (record, statement
 * CVE, product purl), which is the granularity an acceptance is actually
 * authored at — one record can accept a CVE on several binary packages, and each
 * needs its own verdict.
 *
 * Non-Debian purls (`pkg:deb/ubuntu/...`), other purl types and statements with
 * no usable vulnerability id contribute nothing. Malformed docs are skipped;
 * never throws.
 *
 * DE-DUPLICATED on (path, CVE, decoded purl). `statementPurls` deliberately
 * reads BOTH channels a product can carry its purl on — `@id` and
 * `identifiers.purl` — because a record may populate either, and a reader that
 * trusted only one would silently under-cover (the shared reader's job is to
 * find every purl, not to guess which field is authoritative). Every committed
 * record populates both with the same string, so the raw reader yields each
 * product purl TWICE; without this de-dup the report doubled every row and every
 * bucket count (measured: 134 triples for a ledger that holds 67). The key is the
 * DECODED purl, so the epoch-encoded `...@1%3A2.5.2-3` and a plain `...@1:2.5.2-3`
 * spelling of one product also collapse to a single row — while the genuinely
 * distinct epoch-stripped sibling `...@2.5.2-3`, which is a separate product
 * entry with its own join relaxation, correctly stays its own triple.
 */
export function debTriples(entries: readonly LedgerEntry[]): DebTriple[] {
  const triples: DebTriple[] = [];
  const seen = new Set<string>();
  for (const { path, doc } of entries) {
    const record = asRecord(doc);
    if (record === null) continue;
    for (const statement of asArray(record.statements)) {
      const cve = statementName(statement);
      if (cve === null) continue;
      for (const purl of statementPurls(statement)) {
        if (purl.type !== DEB_PURL_TYPE) continue;
        if (purl.namespace !== DEB_PURL_NAMESPACE) continue;
        const rendered = `pkg:${purl.type}/${purl.namespace}/${purl.name}@${purl.version}`;
        const key = `${path}|${cve}|${rendered}`;
        if (seen.has(key)) continue;
        seen.add(key);
        triples.push({
          path,
          cve,
          name: purl.name,
          version: purl.version,
          purl: rendered,
        });
      }
    }
  }
  return triples;
}

/** One tracker entry that joined a triple, with the tolerance it needed. */
export interface JoinedEntry {
  entry: TrackerEntry;
  relaxation: VersionRelaxation;
}

/** A triple with Debian's verdict and the evidence behind it. */
export interface ClassifiedTriple extends DebTriple {
  bucket: Bucket;
  /** How many source packages list this CVE for the suite at all. */
  candidates: number;
  joined: JoinedEntry[];
}

/**
 * The bucket for one triple. The three non-verdict outcomes are kept DISTINCT on
 * purpose: "the tracker never heard of this CVE" and "it did, but no version
 * joined" have completely different fixes, and collapsing either into a
 * verdict-shaped answer would make a join MISS indistinguishable from "Debian
 * has no opinion" — the worst failure mode an evidence source can have.
 *
 * Two joining source packages that disagree are reported AMBIGUOUS rather than
 * silently resolved; the report then lists both so a human decides.
 */
function bucketFor(candidates: number, joined: readonly JoinedEntry[]): Bucket {
  if (candidates === 0) return 'NO-CVE-IN-TRACKER';
  if (joined.length === 0) return 'NO-VERSION-MATCH';
  const verdicts = new Set(joined.map(({ entry }) => entryVerdict(entry)));
  if (verdicts.size > 1) return 'AMBIGUOUS';
  return entryVerdict(joined[0].entry);
}

/** Classify one triple against the indexed tracker. Never throws. */
export function classifyTriple(
  index: ReadonlyMap<string, TrackerEntry[]>,
  triple: DebTriple,
): ClassifiedTriple {
  const candidates = index.get(triple.cve) ?? [];
  const joined: JoinedEntry[] = [];
  for (const entry of candidates) {
    const relaxation = matchDebianVersion(triple.version, entry.suiteVersion);
    if (relaxation !== null) joined.push({ entry, relaxation });
  }
  return {
    ...triple,
    candidates: candidates.length,
    joined,
    bucket: bucketFor(candidates.length, joined),
  };
}

/** Classify every triple, preserving ledger order. */
export function classifyTriples(
  index: ReadonlyMap<string, TrackerEntry[]>,
  triples: readonly DebTriple[],
): ClassifiedTriple[] {
  return triples.map((triple) => classifyTriple(index, triple));
}

/**
 * Bucket totals in `BUCKETS` order, INCLUDING the zeros. A bucket that
 * disappears when empty is a bucket a reader cannot tell from one that was never
 * computed — and `NO-VERSION-MATCH: 0` is precisely the number this work exists
 * to prove.
 */
export function bucketCounts(
  rows: readonly ClassifiedTriple[],
): [Bucket, number][] {
  return BUCKETS.map((bucket) => [
    bucket,
    rows.filter((row) => row.bucket === bucket).length,
  ]);
}

/**
 * One scanner's fix-state claim for one CVE. Both gate scanners already publish
 * this and NOTHING in the repo reads it (verified: no `fix.state` / `Status`
 * reader existed before #352), so it is free corroboration — a second opinion on
 * "is there a fix?" that comes from a different vulnerability database than the
 * tracker.
 */
export interface FixStateClaim {
  id: string;
  scanner: string;
  state: string;
}

/**
 * Grype's `matches[].vulnerability.fix.state` (`fixed` | `not-fixed` |
 * `wont-fix` | `unknown`). Mirrors gate-findings.ts's traversal of the same
 * document. Entries with no id or no fix node contribute nothing; never throws.
 */
export function grypeFixStates(doc: unknown): FixStateClaim[] {
  const claims: FixStateClaim[] = [];
  for (const rawMatch of asArray(asRecord(doc)?.matches)) {
    const vulnerability = asRecord(asRecord(rawMatch)?.vulnerability);
    if (vulnerability === null) continue;
    const id = normId(vulnerability.id);
    if (id === null) continue;
    const state = stringField(asRecord(vulnerability.fix) ?? {}, 'state');
    if (state === '') continue;
    claims.push({ id, scanner: 'grype', state });
  }
  return claims;
}

/**
 * Trivy's `Results[].Vulnerabilities[].Status` (`fixed` | `affected` |
 * `will_not_fix` | `fix_deferred` | `end_of_life` | `unknown`) — the same
 * question in a different vocabulary, from a different vuln DB.
 */
export function trivyFixStates(doc: unknown): FixStateClaim[] {
  const claims: FixStateClaim[] = [];
  for (const rawResult of asArray(asRecord(doc)?.Results)) {
    for (const rawVuln of asArray(asRecord(rawResult)?.Vulnerabilities)) {
      const vulnerability = asRecord(rawVuln);
      if (vulnerability === null) continue;
      const id = normId(vulnerability.VulnerabilityID);
      if (id === null) continue;
      const state = stringField(vulnerability, 'Status');
      if (state === '') continue;
      claims.push({ id, scanner: 'trivy', state });
    }
  }
  return claims;
}

/** Claims grouped by CVE id, so a row's corroboration is one lookup. */
export function fixStateIndex(
  claims: readonly FixStateClaim[],
): Map<string, FixStateClaim[]> {
  const index = new Map<string, FixStateClaim[]>();
  for (const claim of claims) {
    const existing = index.get(claim.id);
    if (existing === undefined) index.set(claim.id, [claim]);
    else existing.push(claim);
  }
  return index;
}

/** Whether the tracker and the scanners agree that a fix exists. */
export type Corroboration = 'agree' | 'conflict' | 'no-scanner-data';

// The scanner vocabularies for "no fix exists", across both tools. A state in
// neither set (`unknown`) is UNINFORMATIVE — it must not be read as agreement.
const NO_FIX_STATES: ReadonlySet<string> = new Set([
  'not-fixed',
  'wont-fix',
  'affected',
  'will_not_fix',
  'fix_deferred',
  'end_of_life',
]);

/**
 * Cross-check Debian's verdict against the scanners' fix state. A `conflict` is
 * the interesting output: the tracker says a fix shipped while a scanner still
 * reports none (or the reverse), which means one of the two databases is stale —
 * and an acceptance resting on the stale one needs review.
 *
 * Report-only, and deliberately not folded into the bucket: a disagreement
 * between two external databases is evidence for a human, not a verdict.
 */
export function corroborate(
  bucket: Bucket,
  claims: readonly FixStateClaim[],
): Corroboration {
  const trackerHasFix = bucket === 'FIXED-UPSTREAM';
  let informative = 0;
  let conflict = false;
  for (const claim of claims) {
    if (claim.state === 'fixed') {
      informative += 1;
      if (!trackerHasFix) conflict = true;
      continue;
    }
    if (NO_FIX_STATES.has(claim.state)) {
      informative += 1;
      if (trackerHasFix) conflict = true;
    }
  }
  if (informative === 0) return 'no-scanner-data';
  return conflict ? 'conflict' : 'agree';
}

/**
 * Whether a class-C record's stated premise still holds against the tracker.
 *
 * `unverifiable` is kept DISTINCT from both other verdicts on purpose: a standing
 * acceptance whose products are not `pkg:deb/debian/*` has no row here at all, and
 * reporting that as `holds` would be this source claiming to have confirmed
 * something it never looked at — the same failure mode `NO-CVE-IN-TRACKER` exists
 * to avoid one layer down.
 */
export type PremiseVerdict = 'holds' | 'stale' | 'unverifiable';

/** One class-C record's premise, with the reason behind the verdict. */
export interface PremiseCheck {
  path: string;
  verdict: PremiseVerdict;
  /** Why — a report line, always populated, so no verdict is bare. */
  detail: string;
}

/**
 * The bucket a class-C acceptance's premise REQUIRES. `standing-acceptance` claims
 * "no fix will ever arrive because none is needed", which is exactly what Debian's
 * `urgency: unimportant` with no `fixed_version` says. Any OTHER bucket falsifies
 * it: a named fix (`FIXED-UPSTREAM`) means there IS something to wait for, a
 * `<no-dsa>` deferral means Debian intends a point release, `OPEN-NO-FIX` means the
 * CVE is still untriaged, and the three join outcomes mean the citation itself no
 * longer resolves.
 */
const STANDING_BUCKET: Bucket = 'UNIMPORTANT-NO-FIX';

/**
 * The premise check for ONE class-C record, given its rows and its cited evidence.
 *
 * Checks the two things the record ASSERTS, in the order a reader would:
 *  1. Debian's verdict is still `unimportant`-with-no-fix on every triple.
 *  2. The citation still resolves — the cited `source_package` is one the join
 *     actually landed on, and the cited `suite` is the one that was read.
 *
 * The second half matters as much as the first: a record citing `src=glibc` whose
 * purls now join through some other source package is no longer re-checkable by
 * following its own `url`, even if the verdict happens to still be `unimportant`.
 *
 * TOTAL: a non-object `evidence` (which the revisit gate already hard-fails on)
 * yields blank citations, which match nothing and so read as `stale` — never a
 * throw and never a silent pass.
 */
function premiseFor(
  suite: string,
  path: string,
  evidence: unknown,
  rows: readonly ClassifiedTriple[],
): PremiseCheck {
  if (rows.length === 0)
    return {
      path,
      verdict: 'unverifiable',
      detail:
        'no pkg:deb/debian triple — the Debian tracker cannot speak to it',
    };
  const wrong = rows.filter((row) => row.bucket !== STANDING_BUCKET);
  if (wrong.length > 0)
    return {
      path,
      verdict: 'stale',
      detail: `Debian no longer reads ${STANDING_BUCKET}: ${wrong
        .map((row) => `${row.cve} ${row.purl} -> ${row.bucket}`)
        .join(' ; ')}`,
    };
  const cited = asRecord(evidence) ?? {};
  const citedSuite = stringField(cited, 'suite');
  if (citedSuite !== suite)
    return {
      path,
      verdict: 'stale',
      detail: `cited evidence.suite=${citedSuite} is not the joined suite ${suite}`,
    };
  const joinedSources = new Set(
    rows.flatMap((row) => row.joined.map(({ entry }) => entry.sourcePackage)),
  );
  const citedPackage = stringField(cited, 'source_package');
  if (!joinedSources.has(citedPackage))
    return {
      path,
      verdict: 'stale',
      detail: `cited evidence.source_package=${citedPackage} is not among the joined src=${[
        ...joinedSources,
      ].join(',')}`,
    };
  return {
    path,
    verdict: 'holds',
    detail: `src=${citedPackage} suite=${suite} still ${STANDING_BUCKET} on ${rows.length} triple(s)`,
  };
}

/**
 * The premise of every class-C (`standing-acceptance`) record in the ledger, in
 * ledger order — the machine-checkable half of what replaces a countdown for a
 * class that by design never expires (#353; the human half is #354's quarterly
 * sweep).
 *
 * WHY THIS IS REPORT-ONLY, even though it asserts BOOKKEEPING accuracy (which the
 * repo can always fix in-repo) rather than vulnerability absence: the ASSERTION
 * would be safe to gate, but the MECHANISM is not. Deciding it requires the same
 * ~86 MB third-party GET as the join above, so a required check would put
 * `security-tracker.debian.org` on CI's critical path — the externally-mutable
 * dependency the Gate Atomicity Law forbids in a blocking path (#335 C1). So a
 * stale premise is loud in the report and never reds `main`.
 *
 * Records with no standing acceptance in force contribute nothing. Unreadable
 * records are skipped here on purpose — the hard-fail revisit gate already fails
 * CI on those, and re-reporting them would red twice for one cause.
 */
export function standingPremises(
  suite: string,
  entries: readonly LedgerEntry[],
  rows: readonly ClassifiedTriple[],
): PremiseCheck[] {
  const checks: PremiseCheck[] = [];
  for (const { path, doc } of entries) {
    const record = asRecord(doc);
    if (record === null) continue;
    const standing = inForcePairs(record).find(
      ({ value }) => revisitForm(value) === 'standing',
    );
    if (standing === undefined) continue;
    checks.push(
      premiseFor(
        suite,
        path,
        standing.evidence,
        rows.filter((row) => row.path === path),
      ),
    );
  }
  return checks;
}

// The evidence column for one joined candidate — EVERY tracker field the joiner
// resolved, plus the relaxation the join needed, so a reader can re-derive the
// bucket by hand from the row alone. `nodsa-reason` is not part of the verdict
// (`entryVerdict` only asks whether `nodsa` is non-empty) but is printed anyway:
// it is Debian's own short justification for deferring the DSA, which is exactly
// what a human re-reviewing a NO-DSA acceptance needs, and a resolved field that
// never reaches the artifact cannot inform that review.
function joinedEvidence({ entry, relaxation }: JoinedEntry): string {
  return [
    `src=${entry.sourcePackage}`,
    `suite-version=${entry.suiteVersion}`,
    `match=${relaxation}`,
    `status=${entry.status}`,
    `urgency=${entry.urgency}`,
    `fixed=${entry.fixedVersion}`,
    `nodsa=${entry.nodsa}`,
    `nodsa-reason=${entry.nodsaReason}`,
    `scope=${entry.scope}`,
  ].join(' ');
}

// A row's evidence: the joined candidates, or — when nothing joined — the
// candidate COUNT, which is what distinguishes "no such CVE" from "no version
// matched" at a glance.
function rowEvidence(row: ClassifiedTriple): string {
  if (row.joined.length === 0) return `candidates=${row.candidates}`;
  return row.joined.map(joinedEvidence).join(' ; ');
}

// The fix-state column: the verdict plus the raw claims behind it, so a conflict
// names which scanner disagreed rather than just asserting one did.
function fixStateColumn(
  row: ClassifiedTriple,
  fixStates: ReadonlyMap<string, FixStateClaim[]>,
): string {
  const claims = fixStates.get(row.cve) ?? [];
  const verdict = corroborate(row.bucket, claims);
  if (claims.length === 0) return `fix-state=${verdict}`;
  const detail = claims
    .map((claim) => `${claim.scanner}=${claim.state}`)
    .join(' ');
  return `fix-state=${verdict} (${detail})`;
}

// The in-repo remedy for a stale class-C premise. Printed with the finding, never
// only in docs: a gate — or, here, a report — that says "this is wrong" without
// saying what THIS REPO can do about it is how #321 happened. Every option below
// is an edit to a file in this repository; none of them is "wait for upstream",
// which is the whole reason a stale premise is actionable at all.
const PREMISE_REMEDY = [
  'REMEDY (always in-repo — reclassify the record, never wait on upstream):',
  '  Debian named a fixed_version   -> revisit <ISO-date> (class A) until the digest carries it',
  '  Debian deferred it (<no-dsa>)  -> wait-for-image-rebuild (class B)',
  '  the citation drifted           -> repoint evidence.source_package / suite and re-date checked_at',
];

/** The class-C premise section, rendered even when the ledger holds no class C. */
function premiseLines(checks: readonly PremiseCheck[]): string[] {
  const tally = (verdict: PremiseVerdict): number =>
    checks.filter((check) => check.verdict === verdict).length;
  const lines = [
    '',
    'class-C premise check (#353) — does each standing-acceptance still hold?',
    `  standing-acceptance records: ${checks.length} (holds ${tally('holds')} / stale ${tally('stale')} / unverifiable ${tally('unverifiable')})`,
  ];
  for (const check of checks)
    lines.push(
      `  ${check.path} | ${check.verdict.toUpperCase()} | ${check.detail}`,
    );
  // Only spell the remedy out when something actually needs remedying — an
  // unconditional four-line block would train the reader to skip the section
  // that matters.
  if (tally('stale') > 0) lines.push(...PREMISE_REMEDY);
  return lines;
}

/**
 * The uploaded artifact AND the job-summary surface, so it must be
 * self-explanatory: what was joined, what the totals are, and one line of
 * evidence per triple. Every count is printed even at zero, and the closing note
 * states the two constraints a reader must not have to infer — that nothing was
 * applied, and that this is not a gate.
 */
export function renderReport(
  suite: string,
  rows: readonly ClassifiedTriple[],
  fixStates: ReadonlyMap<string, FixStateClaim[]>,
  premises: readonly PremiseCheck[],
): string {
  const width = Math.max(...BUCKETS.map((bucket) => bucket.length));
  const lines = [
    '.vex/ ↔ Debian security tracker join (#352) — REPORT ONLY',
    `source: ${DEBIAN_TRACKER_URL}`,
    `suite: ${suite}`,
    `triples: ${rows.length} (record x CVE x deb purl)`,
    '',
    'buckets',
  ];
  for (const [bucket, count] of bucketCounts(rows))
    lines.push(`  ${bucket.padEnd(width)}  ${count}`);
  lines.push('', 'rows');
  for (const row of rows)
    lines.push(
      `  ${row.path} | ${row.cve} | ${row.purl} | ${row.bucket} | ${rowEvidence(row)} | ${fixStateColumn(row, fixStates)}`,
    );
  lines.push(...premiseLines(premises));
  lines.push(
    '',
    'NOTE — reported, not applied: this job edits no .vex/ record (#322). It is',
    'REPORT-ONLY and never a required gate: it fetches an ~86 MB third-party',
    'file, so gating on it would make CI depend on an external service (#335 C1).',
    '',
  );
  return lines.join('\n');
}
