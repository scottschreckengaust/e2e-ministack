// SPDX allow-list satisfiability verdict (#127 Leg B2).
//
// LOGIC MODULE (jest-visible, gate-eligible): the tokenizer + recursive-descent
// evaluator live here so they flow through the repo's 100% coverage gate
// (#124), Stryker mutation (#122), and the fuzz-regression tier. The runnable
// CLI is the thin `license-verdict.mjs` shim, which imports `isAcceptable` from
// here (Node 24 strips the `.ts` on import — no build step), so the workflow
// call `node .github/scripts/license-verdict.mjs "<expr>" "<allow,list>"` is
// unchanged. THIS ONE MAKES ACCEPT/REJECT DECISIONS — it is the highest-risk
// helper and therefore the most deserving of mutation/fuzz scrutiny.
//
// Decides whether a declared SPDX license expression is ACCEPTABLE given a
// comma-separated allow-list of SPDX ids, mirroring the dependency-review
// PR gate's semantics:
//   - OR  : satisfiable if ANY branch is satisfiable
//   - AND : satisfiable only if EVERY conjunct is satisfiable
//   - id  : exact, case-insensitive match against an allow-list entry.
//           Suffixed ids (`Apache-2.0+`, `GPL-3.0-or-later`, `GPL-2.0-only`)
//           need an exact allow-list entry — `Apache-2.0` on the list does
//           NOT satisfy `Apache-2.0+` (conservative on purpose).
//   - WITH: a `<id> WITH <exception>` unit is one atom; it can never match a
//           plain-id allow-list entry, so it is unsatisfiable here (an OR
//           sibling can still satisfy the overall expression).
//
// This is NOT a full SPDX parser — just parentheses + AND/OR/WITH via a
// small tokenizer + recursive descent. The CONSERVATIVE FALLBACK is the
// design: anything unparseable, empty, NONE or NOASSERTION is UNACCEPTABLE
// (→ the poller escalates a human instead of silently passing).
//
// Node built-ins only — no npm deps (repo governance line, #73/#80).

const OPERATORS = new Set(['AND', 'OR', 'WITH']);

/**
 * Split an SPDX expression into id / parenthesis tokens.
 * @returns the tokens, or an EMPTY array if the expression contains any junk
 *   character (an empty result is treated as unparseable by the caller, exactly
 *   like a genuinely empty expression — the conservative fallback). Returning
 *   `[]` rather than `null` keeps the caller's guard a plain length check with
 *   no nullable deref.
 */
// The tokenizer scan: ONE global regex whose alternatives ARE the token
// classification, so there is no second re-validation pass (which is what used
// to generate equivalent anchor mutants — the scan already isolates each
// token). Alternatives, in order:
//   1. an SPDX id run (letters/digits/./-/+),
//   2. a single `(` or `)`,
//   3. a single "junk" char — ANY other non-whitespace (whitespace is skipped
//      by not being matched). A junk match makes the whole expression
//      unparseable. Every alternative here is observable: dropping the id run
//      breaks id tokenizing, dropping the parens breaks grouping, dropping the
//      junk catch-all lets an invalid char vanish instead of rejecting.
const TOKEN_RE = /([A-Za-z0-9.+-]+)|([()])|(\S)/g;

/**
 * Split an SPDX expression into id / parenthesis tokens (exported so the
 * junk-rejection is tested DIRECTLY, making the `[]` return observable rather
 * than an equivalent mutant hiding behind the downstream verdict).
 *
 * Single pass, single classification: each match is an id (capture group 1) or
 * a paren (group 2) — a real token — or a junk char (group 3) that makes the
 * whole expression unparseable → `[]`. Whitespace is skipped by not matching.
 */
export function tokenize(expression: string): string[] {
  const tokens: string[] = [];
  for (const m of expression.matchAll(TOKEN_RE)) {
    const junk = m[3]; // group 3 matched → a non-id, non-paren character
    if (junk !== undefined) {
      return []; // junk character → unparseable (conservative → UNACCEPTABLE)
    }
    tokens.push(m[0]); // an id run or a single paren
  }
  return tokens;
}

/**
 * Recursive-descent parse + evaluate in one pass.
 * Grammar (AND binds tighter than OR, per SPDX):
 *   or-expr   := and-expr ( OR and-expr )*
 *   and-expr  := with-expr ( AND with-expr )*
 *   with-expr := primary ( WITH id )?
 *   primary   := id | '(' or-expr ')'
 * Returns satisfiability (boolean) or throws on a parse error.
 */
function parse(tokens: string[], allow: Set<string>): boolean {
  let pos = 0;
  const peek = (): string | undefined => tokens[pos];
  const next = (): string | undefined => tokens[pos++];

  // THROW MESSAGES ARE UNOBSERVABLE: every `throw` here is caught by
  // `isAcceptable`'s `try/catch`, which maps ANY parse error to `false` (the
  // conservative fallback) and DISCARDS the error. So the throws carry no
  // message — an argument-less `new Error()` removes the dead message literal
  // (no StringLiteral mutant to disable) while keeping the load-bearing throw
  // (its removal is still killed by the `*.test.ts` cases).
  function primary(): boolean {
    // `next()` may return undefined at end-of-input; we do NOT guard it. A
    // missing token is not '(' and not ')'/operator, so it falls through to
    // `tok.toLowerCase()` where `undefined.toLowerCase()` throws — caught by
    // `isAcceptable` → false, the conservative verdict. No `=== undefined`
    // guard (that only generated an equivalent mutant); `tok!` documents that
    // the throw-on-undefined is intentional. Exercised by end-of-input tests.
    const tok = next()!;
    if (tok === '(') {
      const ok = orExpr();
      if (next() !== ')') throw new Error();
      return ok;
    }
    if (tok === ')' || OPERATORS.has(tok.toUpperCase())) {
      throw new Error();
    }
    return allow.has(tok.toLowerCase());
  }

  function withExpr(): boolean {
    let ok = primary();
    if (peek()?.toUpperCase() === 'WITH') {
      next();
      const exception = next();
      // No `exception === undefined` arm: a missing exception is not '(' / ')'
      // and reaches `exception.toUpperCase()` in the operator arm below, which
      // throws on undefined — caught → false, identical to an explicit reject.
      // The '(' / ')' / operator arms ARE observable and killed by tests.
      if (
        exception === '(' ||
        exception === ')' ||
        OPERATORS.has((exception as string).toUpperCase())
      ) {
        throw new Error();
      }
      // A WITH unit never matches a plain-id allow-list entry: conservative.
      ok = false;
    }
    return ok;
  }

  function andExpr(): boolean {
    let ok = withExpr();
    while (peek()?.toUpperCase() === 'AND') {
      next();
      ok = withExpr() && ok;
    }
    return ok;
  }

  function orExpr(): boolean {
    let ok = andExpr();
    while (peek()?.toUpperCase() === 'OR') {
      next();
      // Evaluate first (always consume tokens), then combine — a plain
      // `ok || andExpr()` would short-circuit and desync the parser.
      ok = andExpr() || ok;
    }
    return ok;
  }

  const ok = orExpr();
  if (pos !== tokens.length) {
    throw new Error(); // trailing tokens — caught → false (message unobservable)
  }
  return ok;
}

/**
 * @param expression declared SPDX expression (a missing/nullish value is
 *   treated as the empty expression → UNACCEPTABLE)
 * @param allowList comma-separated SPDX ids (a missing/nullish value yields an
 *   empty allow-list → usage error, matching the CLI's `argv ?? ''`)
 * @returns true = ACCEPTABLE (satisfiable from the allow-list)
 */
export function isAcceptable(
  expression: string | null | undefined,
  allowList: string | null | undefined,
): boolean {
  const allow = new Set(
    (allowList ?? '')
      .split(',')
      .map((id) => id.trim().toLowerCase())
      .filter(Boolean),
  );
  if (allow.size === 0) throw new Error('empty allow-list');

  // A nullish expression carries no declared license → UNACCEPTABLE. An explicit
  // early return (not an `?? ''` default) makes the nullish branch OBSERVABLE —
  // no default-string literal to leave an equivalent mutant. `.trim()` handles
  // padded markers and is exercised by tests.
  if (expression === null || expression === undefined) return false;
  const expr = expression.trim();
  const upper = expr.toUpperCase();
  // NONE / NOASSERTION are the SPDX "no declared license" markers, and the
  // empty expression carries no signal — all three are UNACCEPTABLE. (An empty
  // `expr` also tokenizes to `[]`, which `parse` rejects by throwing on the
  // first undefined token → caught → false, so no separate length check is
  // needed here — that check was redundant with the parser's own guard.)
  if (upper === 'NOASSERTION' || upper === 'NONE') return false;

  try {
    return parse(tokenize(expr), allow);
  } catch {
    return false; // conservative: unparseable / malformed → UNACCEPTABLE
  }
}
