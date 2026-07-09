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
function tokenize(expression: string): string[] {
  const tokens: string[] = [];
  // SPDX ids: letters, digits, dot, dash, plus. Everything else must be a
  // parenthesis or whitespace, otherwise the expression is unparseable.
  // Stryker disable next-line Regex: this scanning regex's alternatives are
  // re-validated per token by the `/^[A-Za-z0-9.+-]+$/` classifier below, so
  // its equivalent forms (paren-class flip, \s vs \s+, \S+) produce identical
  // token streams — verified equivalent against 3k+ adversarial inputs (#165).
  const re = /[A-Za-z0-9.+-]+|[()]|\s+|./g;
  for (const match of expression.matchAll(re)) {
    const tok = match[0];
    // Whitespace runs separate tokens but are not tokens themselves.
    if (tok.trim() === '') continue;
    // Stryker disable next-line Regex: the ^…$ anchors are redundant here — a
    // token is a single whole `matchAll` alternative, so anchored and
    // un-anchored forms accept exactly the same set (equivalent, #165).
    if (tok === '(' || tok === ')' || /^[A-Za-z0-9.+-]+$/.test(tok)) {
      tokens.push(tok);
    } else {
      // Stryker disable next-line ArrayDeclaration: `[]`→a non-empty bogus array
      // still fails to parse (its bogus element is not an allow-listed id →
      // false), so the verdict is unchanged (equivalent, #165).
      return []; // junk character → unparseable (conservative → UNACCEPTABLE)
    }
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

  // NOTE ON THROW MESSAGES: every `throw` in this parser is caught by the
  // `try/catch` in `isAcceptable`, which maps ANY parse error to `false` (the
  // conservative fallback). The message text is therefore developer-facing
  // only and never affects the boolean verdict — so a mutation of a throw's
  // message string is an EQUIVALENT mutant. `Stryker disable next-line
  // StringLiteral` documents that (the THROW itself — a ConditionalExpression /
  // logical mutant that removes it — is still killed by the `*.test.ts` cases,
  // which is what actually matters).
  function primary(): boolean {
    const tok = next();
    // Stryker disable next-line StringLiteral,ConditionalExpression: caught →
    // false; message unobservable. The `tok === undefined` guard is EQUIVALENT
    // to mutate — dropping it lets an undefined tok reach
    // `allow.has(tok.toLowerCase())`, which throws a TypeError that the same
    // catch maps to false: identical verdict (#165).
    if (tok === undefined) throw new Error('unexpected end of expression');
    if (tok === '(') {
      const ok = orExpr();
      // Stryker disable next-line StringLiteral: caught → false; message unobservable
      if (next() !== ')') throw new Error('unbalanced parenthesis');
      return ok;
    }
    if (tok === ')' || OPERATORS.has(tok.toUpperCase())) {
      // Stryker disable next-line StringLiteral: caught → false; message unobservable
      throw new Error(`unexpected token: ${tok}`);
    }
    return allow.has(tok.toLowerCase());
  }

  function withExpr(): boolean {
    let ok = primary();
    if (peek()?.toUpperCase() === 'WITH') {
      next();
      const exception = next();
      if (
        // Stryker disable next-line ConditionalExpression: mutating the
        // `exception === undefined` arm is EQUIVALENT — a missing exception then
        // reaches `exception.toUpperCase()` in the next arm, throwing a
        // TypeError the catch maps to false: identical verdict. The OTHER arms
        // ('(' / ')' / operator exceptions) ARE observable and killed by tests.
        exception === undefined ||
        exception === '(' ||
        exception === ')' ||
        OPERATORS.has(exception.toUpperCase())
      ) {
        // Stryker disable next-line StringLiteral: caught → false; message unobservable
        throw new Error('WITH must be followed by an exception id');
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
    // Stryker disable next-line StringLiteral: caught → false; message unobservable
    throw new Error(`trailing tokens after expression: ${tokens[pos]}`);
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

  // Stryker disable next-line StringLiteral: the `?? ''` default only applies to
  // a nullish expression; a bogus replacement string ("Stryker…!") contains a
  // junk char → tokenizes to `[]` → false, same as the empty default
  // (equivalent, #165). The `.trim()` here IS load-bearing (padded markers) and
  // is killed by a test, so only StringLiteral is disabled.
  const expr = (expression ?? '').trim();
  const upper = expr.toUpperCase();
  // NONE / NOASSERTION are the SPDX "no declared license" markers, and the
  // empty expression carries no signal — all three are UNACCEPTABLE. (An empty
  // `expr` also tokenizes to `[]` and is rejected below, but the explicit
  // marker check documents intent and short-circuits.)
  if (upper === 'NOASSERTION' || upper === 'NONE') return false;

  // An empty token list means the expression was empty or contained a junk
  // character — unparseable, so conservatively UNACCEPTABLE.
  const tokens = tokenize(expr);
  // Stryker disable next-line ConditionalExpression: forcing this `false` lets
  // an empty token list reach `parse([])`, whose first `next()` is undefined →
  // it throws → caught → false: identical verdict (equivalent, #165).
  if (tokens.length === 0) return false;
  try {
    return parse(tokens, allow);
  } catch {
    return false; // conservative: unparseable / malformed → UNACCEPTABLE
  }
}
