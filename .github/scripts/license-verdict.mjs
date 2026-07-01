#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — this
// file is the only standalone Node script it lints, so declare them inline
// rather than widening eslint.config.mjs.)
// SPDX allow-list satisfiability verdict (#127 Leg B2).
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
//
// CLI: node license-verdict.mjs "<spdx-expression>" "<allow,list,ids>"
//   exit 0 = ACCEPTABLE, exit 1 = UNACCEPTABLE, exit 2 = usage error.
// The allow-list is an argument, not a constant: the single source of truth
// is security.yml's `allow-licenses:` value, extracted at runtime by the
// caller (license-review-poller.yml).

const OPERATORS = new Set(['AND', 'OR', 'WITH']);

/** @returns {string[] | null} tokens, or null if the expression has junk */
function tokenize(expression) {
  const tokens = [];
  // SPDX ids: letters, digits, dot, dash, plus. Everything else must be a
  // parenthesis or whitespace, otherwise the expression is unparseable.
  const re = /[A-Za-z0-9.+-]+|[()]|\s+|./g;
  for (const match of expression.matchAll(re)) {
    const tok = match[0];
    if (/^\s+$/.test(tok)) continue;
    if (tok === '(' || tok === ')' || /^[A-Za-z0-9.+-]+$/.test(tok)) {
      tokens.push(tok);
    } else {
      return null; // junk character → unparseable
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
function parse(tokens, allow) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function primary() {
    const tok = next();
    if (tok === undefined) throw new Error('unexpected end of expression');
    if (tok === '(') {
      const ok = orExpr();
      if (next() !== ')') throw new Error('unbalanced parenthesis');
      return ok;
    }
    if (tok === ')' || OPERATORS.has(tok.toUpperCase())) {
      throw new Error(`unexpected token: ${tok}`);
    }
    return allow.has(tok.toLowerCase());
  }

  function withExpr() {
    let ok = primary();
    if (peek()?.toUpperCase() === 'WITH') {
      next();
      const exception = next();
      if (
        exception === undefined ||
        exception === '(' ||
        exception === ')' ||
        OPERATORS.has(exception.toUpperCase())
      ) {
        throw new Error('WITH must be followed by an exception id');
      }
      // A WITH unit never matches a plain-id allow-list entry: conservative.
      ok = false;
    }
    return ok;
  }

  function andExpr() {
    let ok = withExpr();
    while (peek()?.toUpperCase() === 'AND') {
      next();
      ok = withExpr() && ok;
    }
    return ok;
  }

  function orExpr() {
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
    throw new Error(`trailing tokens after expression: ${tokens[pos]}`);
  }
  return ok;
}

/**
 * @param {string} expression declared SPDX expression
 * @param {string} allowList comma-separated SPDX ids
 * @returns {boolean} true = ACCEPTABLE (satisfiable from the allow-list)
 */
export function isAcceptable(expression, allowList) {
  const allow = new Set(
    String(allowList ?? '')
      .split(',')
      .map((id) => id.trim().toLowerCase())
      .filter(Boolean),
  );
  if (allow.size === 0) throw new Error('empty allow-list');

  const expr = String(expression ?? '').trim();
  if (expr === '') return false;
  const upper = expr.toUpperCase();
  if (upper === 'NOASSERTION' || upper === 'NONE') return false;

  const tokens = tokenize(expr);
  if (tokens === null || tokens.length === 0) return false;
  try {
    return parse(tokens, allow);
  } catch {
    return false; // conservative: unparseable → UNACCEPTABLE
  }
}

// ── CLI entry (skipped when imported as a module) ──────────────────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const [expression, allowList] = process.argv.slice(2);
  let acceptable;
  try {
    acceptable = isAcceptable(expression ?? '', allowList ?? '');
  } catch (err) {
    console.error(`usage error: ${err instanceof Error ? err.message : err}`);
    console.error(
      'usage: license-verdict.mjs "<spdx-expression>" "<allow,list,ids>"',
    );
    process.exit(2);
  }
  console.log(
    `${acceptable ? 'ACCEPTABLE' : 'UNACCEPTABLE'}: ${JSON.stringify(
      expression ?? '',
    )}`,
  );
  process.exit(acceptable ? 0 : 1);
}
