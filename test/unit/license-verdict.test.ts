import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { isAcceptable } from '../../.github/scripts/license-verdict';

// Unit tests for .github/scripts/license-verdict.ts (#127 Leg B2, gated under
// #165): SPDX allow-list satisfiability, mirroring the dependency-review PR
// gate's semantics (OR = any branch satisfiable, AND = all conjuncts
// satisfiable), with a conservative fallback (unparseable / NOASSERTION /
// empty → reject).
//
// The satisfiability LOGIC is exercised by importing `isAcceptable` IN-PROCESS
// so it flows through the 100% coverage gate (#124) + Stryker mutation (#122).
// (The old suite spawned the .mjs CLI via execFileSync — a child process
// istanbul/Stryker cannot instrument, so the parser was silently ungated.) A
// small tail of CLI tests still spawns the thin `.mjs` shim to lock the
// argv/exit-code plumbing the license-review-poller workflow depends on.

// The repo's real allow-list — keep in sync with security.yml
// `allow-licenses:` (the workflow file is the single source of truth; the
// poller extracts it at runtime, this literal only pins the test fixtures).
const REPO_ALLOW_LIST =
  'MIT, Apache-2.0, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD, ' +
  'BlueOak-1.0.0, Python-2.0, CC0-1.0, CC-BY-4.0, Unlicense';

describe('license-verdict — SPDX allow-list satisfiability (in-process)', () => {
  it('accepts a bare allow-listed id', () => {
    expect(isAcceptable('MIT', REPO_ALLOW_LIST)).toBe(true);
  });

  it('rejects a bare id not on the allow-list', () => {
    expect(isAcceptable('GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
  });

  it('accepts an OR expression when any branch is allow-listed', () => {
    expect(isAcceptable('MIT OR GPL-3.0-or-later', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('GPL-3.0-or-later OR MIT', REPO_ALLOW_LIST)).toBe(true);
  });

  it('rejects an OR expression when NO branch is allow-listed', () => {
    expect(isAcceptable('GPL-2.0-only OR GPL-3.0-only', REPO_ALLOW_LIST)).toBe(
      false,
    );
  });

  it('accepts an AND expression when every conjunct is allow-listed', () => {
    expect(isAcceptable('MIT AND Apache-2.0', REPO_ALLOW_LIST)).toBe(true);
  });

  it('rejects an AND expression when any conjunct is not allow-listed', () => {
    expect(isAcceptable('MIT AND GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
    // …and when the first conjunct is the failing one (guards the &&-order
    // mutation: `withExpr() && ok` must fail if EITHER side is false).
    expect(isAcceptable('GPL-3.0-only AND MIT', REPO_ALLOW_LIST)).toBe(false);
  });

  it('handles nested parentheses with correct precedence', () => {
    expect(
      isAcceptable('(MIT OR GPL-3.0-or-later) AND Apache-2.0', REPO_ALLOW_LIST),
    ).toBe(true);
    // AND binds tighter than OR: MIT OR (GPL AND GPL) is satisfiable via MIT.
    expect(
      isAcceptable('MIT OR GPL-2.0-only AND GPL-3.0-only', REPO_ALLOW_LIST),
    ).toBe(true);
    // The parenthesised sub-expression must be able to FAIL too (guards the
    // `orExpr()` return inside `primary()`): a parenthesised unsatisfiable OR
    // is unsatisfiable even AND-ed with an allow-listed id.
    expect(
      isAcceptable('(GPL-2.0-only OR GPL-3.0-only) AND MIT', REPO_ALLOW_LIST),
    ).toBe(false);
    // A parenthesised satisfiable group ANDed with a failing id → false.
    expect(isAcceptable('(MIT) AND GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects NOASSERTION, NONE and the empty/blank expression', () => {
    expect(isAcceptable('NOASSERTION', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('noassertion', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('NONE', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('none', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('   ', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects unparseable garbage (conservative fallback)', () => {
    // Junk characters → tokenize() returns null → reject.
    expect(
      isAcceptable('??? not an spdx expression !!!', REPO_ALLOW_LIST),
    ).toBe(false);
    expect(isAcceptable('MIT@1.0', REPO_ALLOW_LIST)).toBe(false); // '@' is junk
    // Structurally-broken but tokenizable → parse throws → reject.
    expect(isAcceptable('MIT OR', REPO_ALLOW_LIST)).toBe(false); // dangling op
    expect(isAcceptable('(MIT OR Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // unbalanced (
    expect(isAcceptable('MIT Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // missing op
    expect(isAcceptable('MIT)', REPO_ALLOW_LIST)).toBe(false); // trailing )
    expect(isAcceptable(')', REPO_ALLOW_LIST)).toBe(false); // leading )
    expect(isAcceptable('AND MIT', REPO_ALLOW_LIST)).toBe(false); // leading op
    expect(isAcceptable('()', REPO_ALLOW_LIST)).toBe(false); // empty group
  });

  it('matches ids case-insensitively (both sides)', () => {
    expect(isAcceptable('mit', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT', 'mit, apache-2.0')).toBe(true);
    expect(isAcceptable('apache-2.0 AND mit', REPO_ALLOW_LIST)).toBe(true);
    // Lower-case operators must still be recognised as operators.
    expect(isAcceptable('mit or gpl-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('mit and gpl-3.0-only', REPO_ALLOW_LIST)).toBe(false);
  });

  it('treats suffixed ids as needing an exact allow-list entry', () => {
    // Conservative: Apache-2.0+ is NOT satisfied by Apache-2.0 on the list.
    expect(isAcceptable('Apache-2.0+', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('GPL-3.0-or-later', REPO_ALLOW_LIST)).toBe(false);
    // …but an exact suffixed entry on the allow-list does satisfy it.
    expect(isAcceptable('Apache-2.0+', 'Apache-2.0+')).toBe(true);
  });

  it('rejects WITH exception expressions unless a branch avoids them', () => {
    // A WITH unit can never match a comma-separated allow-list entry.
    expect(
      isAcceptable(
        'GPL-2.0-only WITH Classpath-exception-2.0',
        REPO_ALLOW_LIST,
      ),
    ).toBe(false);
    // …but an OR sibling can still satisfy the expression.
    expect(
      isAcceptable(
        'MIT OR (GPL-2.0-only WITH Classpath-exception-2.0)',
        REPO_ALLOW_LIST,
      ),
    ).toBe(true);
    // Even an allow-listed id, once ridered with WITH, becomes unsatisfiable
    // (guards the `ok = false` mutation inside withExpr()).
    expect(
      isAcceptable('MIT WITH Classpath-exception-2.0', REPO_ALLOW_LIST),
    ).toBe(false);
    // WITH not followed by a valid exception id → parse error → reject.
    expect(isAcceptable('MIT WITH', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT WITH OR', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT WITH )', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT WITH (', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects AND-rider expressions (Commons-Clause case from the docs)', () => {
    expect(
      isAcceptable('BSD-3-Clause AND Commons-Clause', REPO_ALLOW_LIST),
    ).toBe(false);
  });

  it('accepts the aiohttp case against the repo allow-list', () => {
    // aiohttp@3.14.1 wheel METADATA / eventual ClearlyDefined declared value.
    expect(isAcceptable('Apache-2.0 AND MIT', REPO_ALLOW_LIST)).toBe(true);
  });

  it('throws on a missing or empty allow-list (usage error)', () => {
    expect(() => isAcceptable('MIT', '')).toThrow(/empty allow-list/);
    expect(() => isAcceptable('MIT', ' , ,')).toThrow(/empty allow-list/);
    // A nullish allow-list collapses to the empty allow-list (usage error) —
    // matches the CLI's `argv ?? ''` plumbing.
    expect(() => isAcceptable('MIT', null)).toThrow(/empty allow-list/);
    expect(() => isAcceptable('MIT', undefined)).toThrow(/empty allow-list/);
  });

  it('treats a nullish expression as empty → UNACCEPTABLE', () => {
    expect(isAcceptable(null, REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable(undefined, REPO_ALLOW_LIST)).toBe(false);
  });

  // ── Mutation-hardening: pin every branch/operator so no mutant survives ──

  it('recognises AND/OR/WITH only as whole upper/lower-case operator tokens', () => {
    // A bare id that merely CONTAINS an operator substring is still just an id.
    // "MIT" allow-listed; "ANDES" is a plain id (not on the list) → false.
    expect(isAcceptable('ANDES', REPO_ALLOW_LIST)).toBe(false);
    // Mixed-case operators are honoured (guards the toUpperCase() calls on the
    // peeked operator tokens).
    expect(isAcceptable('MIT Or GPL-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT aNd GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('mit or apache-2.0', REPO_ALLOW_LIST)).toBe(true);
  });

  it('rejects an operator token used where a primary is expected', () => {
    // Guards `primary()`'s `tok === ')' || OPERATORS.has(tok.toUpperCase())`
    // rejection: each operator or a bare ) as the FIRST token is a parse error.
    expect(isAcceptable('AND', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('OR', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('WITH', REPO_ALLOW_LIST)).toBe(false);
    // …and used mid-stream where a primary is expected.
    expect(isAcceptable('MIT AND AND', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT AND )', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT OR (', REPO_ALLOW_LIST)).toBe(false);
  });

  it('AND is left-of and right-of a satisfiable id — both conjuncts checked', () => {
    // Kills the `withExpr() && ok` order/short-circuit mutants: BOTH a good&bad
    // and bad&good must be false, and good&good must be true.
    expect(isAcceptable('MIT AND Apache-2.0', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT AND ISC AND 0BSD', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT AND ISC AND GPL-3.0-only', REPO_ALLOW_LIST)).toBe(
      false,
    );
    expect(isAcceptable('GPL-3.0-only AND ISC AND MIT', REPO_ALLOW_LIST)).toBe(
      false,
    );
  });

  it('OR keeps a satisfiable branch even when a later branch fails, and vice-versa', () => {
    // Kills the `andExpr() || ok` order/short-circuit mutants: satisfiable in
    // EITHER position must win; both-fail must lose.
    expect(isAcceptable('MIT OR GPL-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('GPL-3.0-only OR MIT', REPO_ALLOW_LIST)).toBe(true);
    expect(
      isAcceptable('GPL-2.0-only OR GPL-3.0-only OR MIT', REPO_ALLOW_LIST),
    ).toBe(true);
    expect(
      isAcceptable(
        'GPL-2.0-only OR GPL-3.0-only OR LGPL-3.0-only',
        REPO_ALLOW_LIST,
      ),
    ).toBe(false);
  });

  it('a parenthesised group returns its own satisfiability (both truth values)', () => {
    // Kills the `orExpr()` return inside `primary()` being forced true/false.
    expect(isAcceptable('(MIT)', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('(GPL-3.0-only)', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('(MIT AND GPL-3.0-only)', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('((MIT))', REPO_ALLOW_LIST)).toBe(true);
  });

  it('a WITH rider makes an OTHERWISE-satisfiable id unsatisfiable (ok=false)', () => {
    // Kills the `ok = false` block mutants in withExpr: an allow-listed id, once
    // ridered, must flip to false; and the surrounding structure still parses.
    expect(isAcceptable('MIT', REPO_ALLOW_LIST)).toBe(true);
    expect(
      isAcceptable('MIT WITH Autoconf-exception-3.0', REPO_ALLOW_LIST),
    ).toBe(false);
    // In an AND, the WITH conjunct being false drags the whole thing false.
    expect(
      isAcceptable('MIT AND (Apache-2.0 WITH LLVM-exception)', REPO_ALLOW_LIST),
    ).toBe(false);
    // In an OR, a WITH branch cannot rescue an otherwise-failing expression.
    expect(
      isAcceptable(
        'GPL-3.0-only OR (MIT WITH Classpath-exception-2.0)',
        REPO_ALLOW_LIST,
      ),
    ).toBe(false);
  });

  it('accepts a whitespace-only-separated / multi-space expression (tokenizer \\s+)', () => {
    // Guards the `\s+` whitespace-run alternative and the `^\s+$` skip: runs of
    // spaces/tabs between tokens are collapsed, not treated as junk.
    expect(isAcceptable('MIT   OR\tGPL-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('  MIT  ', REPO_ALLOW_LIST)).toBe(true);
  });

  it('rejects a single junk character anywhere (tokenizer catch-all)', () => {
    // Guards the final `.` catch-all → return null path: any character outside
    // [A-Za-z0-9.+-()\s] makes the whole expression unparseable.
    expect(isAcceptable('MIT & Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // &
    expect(isAcceptable('MIT/Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // /
    expect(isAcceptable('MIT,Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // ,
    expect(isAcceptable('«MIT»', REPO_ALLOW_LIST)).toBe(false); // non-ASCII
  });

  it('accepts every allow-listed id shape, including dotted/plus/dash and 0-prefixed', () => {
    // Guards the id character class `[A-Za-z0-9.+-]+`: dots, digits, dashes and
    // a leading digit are all valid id characters.
    expect(isAcceptable('BSD-2-Clause', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('0BSD', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('CC-BY-4.0', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('BlueOak-1.0.0', REPO_ALLOW_LIST)).toBe(true);
  });

  it('distinguishes NOASSERTION/NONE from a genuine allow-listed id (exact compare)', () => {
    // Guards the `upper === 'NOASSERTION' || upper === 'NONE'` short-circuit
    // and its string operands: a near-miss id is NOT swallowed by that clause.
    expect(isAcceptable('NOASSERTIONX', REPO_ALLOW_LIST)).toBe(false); // not on list, but NOT via the NOASSERTION clause
    expect(isAcceptable('NON', REPO_ALLOW_LIST)).toBe(false);
    // A custom allow-list that literally contains "None" as an id still must be
    // rejected, because NONE is intercepted before tokenizing.
    expect(isAcceptable('NONE', 'MIT, None')).toBe(false);
    expect(isAcceptable('NOASSERTION', 'MIT, NOASSERTION')).toBe(false);
  });

  it('empty-after-trim expression short-circuits before tokenizing (expr === "")', () => {
    // Guards `if (expr === '') return false` and the trim() on the expression.
    expect(isAcceptable('\t\n  ', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects a leftover-tokens expression (trailing content after a valid parse)', () => {
    // Guards the `pos !== tokens.length` trailing-token throw.
    expect(isAcceptable('MIT Apache-2.0', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('(MIT) MIT', REPO_ALLOW_LIST)).toBe(false);
  });

  // ── Adversarial allow-lists: the ONLY way to observe several internal
  // guards from the boolean return. If a guard is mutated away, a junk /
  // operator / paren token would be looked up in the allow-list instead of
  // being rejected — so an allow-list that literally contains that token flips
  // the verdict, killing the mutant. (These allow-lists are synthetic probes,
  // not the repo's real list.)
  it('a junk char is rejected by the tokenizer even when the allow-list contains it', () => {
    // Kills the tokenizer catch-all guard (`return null` else-branch) and the
    // id-vs-junk classification: '&' must NEVER be a usable token, even if the
    // allow-list has it. The catch-all path returns null → false.
    expect(isAcceptable('&', '&,mit')).toBe(false);
    expect(isAcceptable('MIT & GPL', 'mit,&,gpl')).toBe(false);
    // A whitespace token is skipped (not junk): a space-separated pair is a
    // "missing operator" parse error, not a junk-null — still false, but via a
    // different path (guards the `^\s+$` skip vs the catch-all).
    expect(isAcceptable('MIT GPL', 'mit,gpl')).toBe(false);
  });

  it('an operator token is rejected as a primary even if the allow-list contains it', () => {
    // Kills the `tok === ')' || OPERATORS.has(tok.toUpperCase())` rejection in
    // primary(): with an allow-list literally containing "and"/"or"/"with"/")" ,
    // a mutant that drops the rejection would `allow.has(...)` → true. The real
    // parser must still THROW (→ false) on an operator/paren where a primary is
    // due.
    expect(isAcceptable('AND', 'and,mit')).toBe(false);
    expect(isAcceptable('OR', 'or,mit')).toBe(false);
    expect(isAcceptable('WITH', 'with,mit')).toBe(false);
    expect(isAcceptable(')', ')')).toBe(false);
    // Mixed-case operator, allow-list has the lower-case form (guards the
    // `.toUpperCase()` on the primary rejection AND the `.toLowerCase()` lookup).
    expect(isAcceptable('and', 'and,mit')).toBe(false);
  });

  it('a WITH exception token is rejected even if the allow-list contains it', () => {
    // Kills the WITH-exception validation guards (L86 disjunction / L89
    // OPERATORS.has(exception.toUpperCase())): an operator/paren as the
    // exception is a parse error → false, regardless of allow-list contents.
    expect(isAcceptable('MIT WITH AND', 'mit,and')).toBe(false);
    expect(isAcceptable('MIT WITH OR', 'mit,or')).toBe(false);
    expect(isAcceptable('MIT WITH WITH', 'mit,with')).toBe(false);
    expect(isAcceptable('MIT WITH )', 'mit')).toBe(false);
    expect(isAcceptable('MIT WITH (', 'mit')).toBe(false);
    // A VALID exception id parses (then the WITH unit is unsatisfiable) — proves
    // the guard lets a real exception through rather than always throwing.
    expect(isAcceptable('MIT WITH GCC-exception-3.1', 'mit')).toBe(false);
    // …and inside an OR the sibling still rescues it, proving the WITH parsed
    // (didn't abort the whole expression).
    expect(
      isAcceptable('MIT OR (Apache-2.0 WITH GCC-exception-3.1)', 'mit'),
    ).toBe(true);
  });

  it('consumes the WITH rider (peek guard) so trailing tokens do not leak', () => {
    // Kills the `peek()?.toUpperCase() === 'WITH'` guard being forced false: if
    // the WITH clause is skipped, its `<id> WITH <exc>` tokens are left
    // unconsumed → a trailing-token parse error. A WITH unit inside a
    // satisfiable OR must therefore be CONSUMED and the OR must succeed.
    expect(isAcceptable('Apache-2.0 WITH Foo OR MIT', REPO_ALLOW_LIST)).toBe(
      true,
    );
  });

  it('consumes chained AND / OR operators (loop guards) rather than leaking them', () => {
    // Kills the `while (peek() === 'AND')` / `while (peek() === 'OR')` guards
    // being forced false: an all-satisfiable AND/OR chain must succeed. If the
    // loop never runs, the second operand's tokens are left over → trailing
    // parse error → false, which these true-expectations detect.
    expect(isAcceptable('MIT AND Apache-2.0', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT AND Apache-2.0 AND ISC', REPO_ALLOW_LIST)).toBe(
      true,
    );
    expect(isAcceptable('GPL-3.0-only OR MIT', REPO_ALLOW_LIST)).toBe(true);
    expect(
      isAcceptable('GPL-3.0-only OR GPL-2.0-only OR MIT', REPO_ALLOW_LIST),
    ).toBe(true);
  });

  it('trims the expression BEFORE the NONE/NOASSERTION marker check', () => {
    // Kills the `.trim()` on the expression being removed: a padded marker like
    // "  NONE  " must still be recognised as NONE (→ false) rather than parsed
    // as an id. Probed with an allow-list that literally contains "none" so the
    // difference is observable: trimmed → marker → false; untrimmed → id lookup
    // → true.
    expect(isAcceptable('  NONE  ', 'none, mit')).toBe(false);
    expect(isAcceptable('\tNOASSERTION\t', 'noassertion, mit')).toBe(false);
  });

  it('a malformed WITH-exception ABORTS the whole expression, not just its unit', () => {
    // Kills the WITH-exception validation guards (L86 disjunction + L89
    // OPERATORS.has(exception.toUpperCase())): when the exception is itself an
    // operator/paren, the guard must THROW — aborting the ENTIRE parse → false —
    // rather than quietly setting ok=false and letting an OR sibling rescue it.
    // These inputs are the ONLY way to observe the throw-vs-quiet difference
    // from the boolean return (an OR sibling would flip false→true if the guard
    // were removed).
    expect(isAcceptable('MIT OR (Apache-2.0 WITH AND)', REPO_ALLOW_LIST)).toBe(
      false,
    );
    expect(isAcceptable('MIT OR (Apache-2.0 WITH OR)', REPO_ALLOW_LIST)).toBe(
      false,
    );
    expect(isAcceptable('MIT OR (Apache-2.0 WITH WITH)', REPO_ALLOW_LIST)).toBe(
      false,
    );
    expect(isAcceptable('(MIT WITH OR) OR Apache-2.0', REPO_ALLOW_LIST)).toBe(
      false,
    );
    // A missing exception (end of input) after WITH likewise aborts.
    expect(isAcceptable('Apache-2.0 OR (MIT WITH)', REPO_ALLOW_LIST)).toBe(
      false,
    );
    // The `exception === '('` and `exception === ')'` arms specifically.
    expect(isAcceptable('MIT OR (Apache-2.0 WITH ()', REPO_ALLOW_LIST)).toBe(
      false,
    );
    expect(isAcceptable('MIT OR (Apache-2.0 WITH ))', REPO_ALLOW_LIST)).toBe(
      false,
    );
  });

  it('the OPERATORS set members are each load-bearing (AND/OR/WITH)', () => {
    // Kills mutating the OPERATORS Set literal (L32): if any operator id is
    // dropped from the set, that operator stops being REJECTED as a primary, so
    // an allow-list containing it would flip a leading-operator expression to
    // true. Probe each member.
    expect(isAcceptable('AND MIT', 'and,mit')).toBe(false); // AND in set
    expect(isAcceptable('OR MIT', 'or,mit')).toBe(false); // OR in set
    expect(isAcceptable('MIT WITH', 'mit,with')).toBe(false); // WITH in set (dangling)
  });
});

// ── CLI contract: prove the thin .mjs shim still plumbs argv → exit codes ────
// This is the exact interface the license-review-poller workflow uses
// (exit 0 = ACCEPTABLE, 1 = UNACCEPTABLE, 2 = usage error), and it exercises
// the Node-24 `.ts` import at runtime — so the workflow entrypoint is proven,
// not just the pure module.
const SCRIPT = path.resolve(
  __dirname,
  '../../.github/scripts/license-verdict.mjs',
);

interface Verdict {
  code: number;
  stdout: string;
}

function cli(expression: string, allowList = REPO_ALLOW_LIST): Verdict {
  try {
    const stdout = execFileSync(
      process.execPath,
      [SCRIPT, expression, allowList],
      { encoding: 'utf8' },
    );
    return { code: 0, stdout };
  } catch (err) {
    const e = err as { status: number | null; stdout?: string };
    return { code: e.status ?? -1, stdout: String(e.stdout ?? '') };
  }
}

describe('license-verdict.mjs — CLI exit-code contract', () => {
  it('exits 0 and prints ACCEPTABLE for an allow-listed id', () => {
    const res = cli('MIT');
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('ACCEPTABLE');
  });

  it('exits 1 and prints UNACCEPTABLE for a rejected id', () => {
    const res = cli('GPL-3.0-only');
    expect(res.code).toBe(1);
    expect(res.stdout).toContain('UNACCEPTABLE');
  });

  it('exits 2 on a missing/empty allow-list (usage error)', () => {
    expect(cli('MIT', '').code).toBe(2);
    expect(cli('MIT', ' , ,').code).toBe(2);
  });
});
