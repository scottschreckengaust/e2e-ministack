// SPDX allow-list satisfiability verdict (#127 Leg B2).
//
// LOGIC MODULE (jest-visible, gate-eligible): `isAcceptable` flows through the
// repo's 100% coverage gate (#124), Stryker mutation (#122), and the
// fuzz-regression tier. The runnable CLI is the thin `license-verdict.mjs` shim,
// which imports `isAcceptable` from here (Node 24 strips the `.ts` on import —
// no build step). THIS ONE MAKES ACCEPT/REJECT DECISIONS — it is the
// highest-risk helper and therefore the most deserving of mutation/fuzz scrutiny.
//
// Decides whether a declared SPDX license expression is ACCEPTABLE given a
// comma-separated allow-list of SPDX ids, mirroring the dependency-review PR
// gate's semantics (OR = any branch satisfiable, AND = every conjunct).
//
// REUSE-OVER-BESPOKE (#222): the satisfiability check delegates to the vetted,
// community-standard `spdx-satisfies` (MIT) — built on `spdx-expression-parse`,
// the same parser npm/eslint/etc. use. We no longer hand-roll an SPDX tokenizer
// + recursive-descent evaluator: a bespoke parser for an adversarially-exposed,
// security-relevant decision is exactly the liability the repo's
// "prefer a vetted, time-tested fixer over bespoke code" rule targets
// (docs/SECURITY-TOOLING.md § Remediating). `spdx-satisfies` follows the SPDX
// spec strictly (canonical-case ids, real exception ids, `+`/GPL range
// semantics), so its verdicts are the standard ones — not our approximation.
//
// The CONSERVATIVE FALLBACK is preserved and is the design: anything the vetted
// parser rejects — junk, an unknown license/exception id, a malformed
// expression, NONE, NOASSERTION, or the empty expression — is UNACCEPTABLE, so
// the poller escalates a human instead of silently passing. `spdx-satisfies`
// signals all of these by throwing, which the `try/catch` maps to `false`.

import spdxSatisfies from 'spdx-satisfies';

/**
 * @param expression declared SPDX expression. A missing/nullish/empty value,
 *   the SPDX "no declared license" markers `NONE` / `NOASSERTION`, an unknown
 *   license/exception id, or any malformed expression is UNACCEPTABLE — the
 *   vetted parser throws on each and the fail-closed `catch` maps that to
 *   `false`, so no separate pre-check is needed (and adding one would be a
 *   redundant, unobservable branch: the verdict is identical either way).
 * @param allowList comma-separated SPDX ids (a missing/nullish/empty value
 *   yields an empty allow-list → usage error, matching the CLI's `argv ?? ''`)
 * @returns true = ACCEPTABLE (satisfiable from the allow-list)
 */
export function isAcceptable(
  expression: string | null | undefined,
  allowList: string | null | undefined,
): boolean {
  // spdx-satisfies wants an ARRAY of bare SPDX ids; the caller passes the
  // comma-separated `allow-licenses` string from security.yml. Split/trim/drop
  // blanks. An empty list is a USAGE ERROR (the CLI maps it to exit 2) — and
  // spdx-satisfies would silently return false for `[]` rather than signal it,
  // so we must reject it explicitly here (this is the only pre-check that is
  // NOT redundant with the parser's own throw).
  const allow = (allowList ?? '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);
  if (allow.length === 0) throw new Error('empty allow-list');

  try {
    // The vetted, community-standard satisfiability check. `expression` may be
    // null/undefined/junk/NONE/NOASSERTION — spdx-satisfies throws on all of
    // them, so the CONSERVATIVE FALLBACK below turns every such case into the
    // UNACCEPTABLE verdict the poller relies on.
    return spdxSatisfies(expression as string, allow);
  } catch {
    return false; // conservative: unparseable / unknown id / malformed / missing → UNACCEPTABLE
  }
}
