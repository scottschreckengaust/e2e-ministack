// Pure logic for the upstream MiniStack tracker (#137, sub-issue C of epic
// #117).
//
// LOGIC MODULE (jest-visible, gate-eligible): every PURE function of the
// tracker lives here so it flows through the repo's 100% coverage gate (#124),
// Stryker mutation (#122), and the fuzz-regression tier. The runnable CLI is
// the `ministack-upstream.mjs` shim, which imports these + adds the thin,
// network-touching I/O (`gh search`, registry read/write) that CANNOT be
// gated in-process (same reason `services/**/checks.*.ts` are excluded — they
// only run against a live system). Node 24 imports the `.ts` natively (no
// build step), so `node scripts/ministack-upstream.mjs <cmd> <service>` is
// unchanged.
//
// CORE PRINCIPLE — query = automated, comment/watch = HUMAN-GATED. This module
// only ever DRAFTS text and formats commands; it never posts anything.

/** owner/repo the tracker watches. */
export const UPSTREAM_REPO = 'ministackorg/ministack';

// ── The single gate ────────────────────────────────────────────────────────
// #137: this is the ONE place a future maintainer would flip to enable
// auto-posting to the foreign repo. Flipping to true is a deliberate,
// documented policy change — do NOT flip it without maintainer sign-off.
// While false, `draft-comment` only PRINTS a command for a human to run.
export const AUTO_POST_UPSTREAM = false;

/** A single `gh search` result (the fields we consume). */
export interface SearchResult {
  number: number;
  title?: string;
  url?: string;
  state?: string;
}

/** A support-registry row (the fields we read for drafting). */
export interface RegistryRow {
  service: string;
  status: string;
  ministackRef: string | null;
}

/**
 * A service key must be a safe, stable token so it can never inject shell
 * metacharacters into a child_process call (defense-in-depth — we already use
 * argv arrays, not a shell). Matches the registry's `service` convention:
 * lowercase letters, digits and single dashes (e.g. `lambda`, `rds-postgres`).
 */
export function isValidServiceName(name: unknown): boolean {
  return typeof name === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name);
}

/**
 * Format a single `gh search` result as an `owner/repo#N` tracking ref, or
 * null when there is no match.
 */
export function formatRef(
  match: { number?: number } | null | undefined,
): string | null {
  if (!match || typeof match.number !== 'number') return null;
  return `${UPSTREAM_REPO}#${match.number}`;
}

/**
 * Choose the best upstream match for a service from `gh search` payloads.
 * Ranking (higher wins): a title hit outranks a non-title hit; among equal
 * title-hits an OPEN item outranks a CLOSED one; ties break to the LOWEST issue
 * number (the earliest/canonical tracking item). Returns null when nothing
 * mentions the service at all.
 *
 * The inputs are the parsed JSON of
 *   gh search issues --repo <repo> "<service>" --json number,title,url,state
 *   gh search prs    --repo <repo> "<service>" --json number,title,url,state
 * kept OUT of this function (thin I/O lives in the .mjs shim) so the ranking is
 * unit-tested offline against a fixture.
 */
export function selectBestMatch(
  issues: SearchResult[] | null | undefined,
  prs: SearchResult[] | null | undefined,
  service: string,
): SearchResult | null {
  const needle = String(service).toLowerCase();
  // Stryker disable next-line ArrayDeclaration: `?? []`→a bogus array only fires
  // when a list is nullish; the bogus string element has no numeric `number`,
  // so the very next `.filter` drops it → same as `[]` (equivalent, #165).
  const candidates = [...(issues ?? []), ...(prs ?? [])].filter(
    (r): r is SearchResult => Boolean(r) && typeof r.number === 'number',
  );
  // Stryker disable next-line ConditionalExpression: forcing this `false` skips
  // the early return, but an empty `candidates` then yields an empty `scored`,
  // which the `scored.length === 0` guard below returns null for anyway
  // (equivalent, #165).
  if (candidates.length === 0) return null;

  const scored = candidates
    .map((r) => {
      // Stryker disable next-line StringLiteral: `r.title ?? ''`→a bogus string
      // only matters for a title-less candidate; that bogus string doesn't
      // contain the service needle, so the candidate is filtered out either
      // way (equivalent, #165).
      const title = String(r.title ?? '').toLowerCase();
      // A candidate must actually mention the service to count as a match.
      const titleHit = title.includes(needle);
      return { r, titleHit, open: String(r.state).toLowerCase() === 'open' };
    })
    // gh already searched for the term, but be defensive: require a title hit.
    .filter((c) => c.titleHit);

  if (scored.length === 0) return null;

  scored.sort((a, b) => {
    if (a.open !== b.open) return a.open ? -1 : 1; // OPEN first
    return a.r.number - b.r.number; // then lowest (earliest) number
  });
  return scored[0].r;
}

/**
 * Draft the structured comment body for a service: what MiniStack digest it
 * was verified against, the current registry verdict, and the ask. This is the
 * text a maintainer would post — the caller only PRINTS it.
 */
export function draftCommentBody(row: RegistryRow, digest: string): string {
  const ref = row.ministackRef;
  const ask = ref
    ? `Is there an ETA or a way we can help move ${row.service} forward? We track it against your issue ${ref}.`
    : `Would you consider tracking ${row.service} emulation? We didn't find an existing issue/PR for it.`;
  return [
    `Hi from the [e2e-ministack](https://github.com/scottschreckengaust/e2e-ministack) compatibility harness 👋`,
    ``,
    `- **Service:** \`${row.service}\``,
    `- **Our verdict:** \`${row.status}\``,
    `- **Verified against MiniStack digest:** \`${digest}\``,
    ref ? `- **Upstream ref:** ${ref}` : `- **Upstream ref:** none found yet`,
    ``,
    `**Ask:** ${ask}`,
    ``,
    `_This message was drafted by an automated harness but posted manually by a maintainer — replies are read by a human._`,
  ].join('\n');
}

/**
 * The exact copy-pasteable command a maintainer runs to post the drafted
 * comment on an EXISTING upstream ref. The caller PRINTS this; it never runs
 * it (while AUTO_POST_UPSTREAM is false).
 */
export function formatPostCommand(ref: string, body: string): string {
  // Single-quote the body for a POSIX shell so the maintainer can paste it
  // verbatim; escape embedded single quotes the standard way (' → '\'').
  const escaped = String(body).replaceAll("'", String.raw`'\''`);
  return `gh issue comment ${ref} --repo ${UPSTREAM_REPO} --body '${escaped}'`;
}

/**
 * A one-click browser URL: the existing upstream issue (to comment on) when a
 * ref exists, otherwise the "new issue" page on the upstream repo.
 */
export function formatOneClickUrl(ref: string | null): string {
  if (ref) {
    const n = ref.split('#')[1];
    return `https://github.com/${UPSTREAM_REPO}/issues/${n}`;
  }
  return `https://github.com/${UPSTREAM_REPO}/issues/new`;
}
