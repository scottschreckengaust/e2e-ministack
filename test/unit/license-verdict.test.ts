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
    // Junk characters → parser throws → reject.
    expect(
      isAcceptable('??? not an spdx expression !!!', REPO_ALLOW_LIST),
    ).toBe(false);
    expect(isAcceptable('MIT@1.0', REPO_ALLOW_LIST)).toBe(false); // '@' is junk
    // Structurally-broken → parser throws → reject.
    expect(isAcceptable('MIT OR', REPO_ALLOW_LIST)).toBe(false); // dangling op
    expect(isAcceptable('(MIT OR Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // unbalanced (
    expect(isAcceptable('MIT Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // missing op
    expect(isAcceptable('MIT)', REPO_ALLOW_LIST)).toBe(false); // trailing )
    expect(isAcceptable(')', REPO_ALLOW_LIST)).toBe(false); // leading )
    expect(isAcceptable('AND MIT', REPO_ALLOW_LIST)).toBe(false); // leading op
    expect(isAcceptable('()', REPO_ALLOW_LIST)).toBe(false); // empty group
  });

  it('requires canonical-case SPDX license ids (case-sensitive per spec)', () => {
    // PARITY CHANGE (#222): the old bespoke parser lower-cased both sides and
    // matched case-insensitively — non-standard. SPDX license ids are
    // case-sensitive: `MIT` is a valid id, `mit` is not. `spdx-satisfies`
    // (via `spdx-expression-parse`) rejects a non-canonical id, and our
    // conservative fallback maps that to UNACCEPTABLE. This is the correct,
    // stricter behavior — the old case-insensitive verdicts were a bug.
    expect(isAcceptable('mit', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT', 'mit, apache-2.0')).toBe(false); // allow-list id also must be canonical
    expect(isAcceptable('apache-2.0 AND mit', REPO_ALLOW_LIST)).toBe(false);
    // Canonical-case ids on both sides are accepted.
    expect(isAcceptable('MIT', 'MIT, Apache-2.0')).toBe(true);
    expect(isAcceptable('Apache-2.0 AND MIT', REPO_ALLOW_LIST)).toBe(true);
  });

  it('honours the `+` "or later" range operator (SPDX semantics)', () => {
    // PARITY CHANGE (#222): the bespoke parser treated `Apache-2.0+` as a
    // distinct opaque id needing an exact `Apache-2.0+` allow entry. Per SPDX,
    // `Apache-2.0+` means "Apache-2.0 or later", which IS satisfied by
    // `Apache-2.0` on the allow-list — the standard `spdx-satisfies` verdict.
    expect(isAcceptable('Apache-2.0+', REPO_ALLOW_LIST)).toBe(true);
    // An exact suffixed allow entry naturally satisfies it too.
    expect(isAcceptable('Apache-2.0+', 'Apache-2.0+')).toBe(true);
    // A not-on-the-list copyleft id is still rejected.
    expect(isAcceptable('GPL-3.0-or-later', REPO_ALLOW_LIST)).toBe(false);
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

  // ── Behavior-parity cases (#222): these were authored against the old
  // bespoke parser and now pin the SAME verdicts against the vetted
  // `spdx-satisfies` delegate (comments describe the SPDX-spec behavior, not
  // the deleted tokenizer/recursive-descent internals). ──

  it('recognises AND/OR/WITH only as whole UPPER-CASE operator tokens (SPDX spec)', () => {
    // A bare id that merely CONTAINS an operator substring is still just an id.
    // "MIT" allow-listed; "ANDES" is not a valid SPDX id → false.
    expect(isAcceptable('ANDES', REPO_ALLOW_LIST)).toBe(false);
    // PARITY CHANGE (#222): SPDX operators are case-sensitive UPPER-CASE
    // keywords (`AND`/`OR`/`WITH`). The old bespoke parser accepted mixed/lower
    // case (`Or`, `aNd`, `or`) — non-standard. `spdx-satisfies` rejects them, so
    // our fallback returns UNACCEPTABLE. Canonical upper-case operators work.
    expect(isAcceptable('MIT Or GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('mit or apache-2.0', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT OR GPL-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT AND GPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects an operator/paren where a license id is expected', () => {
    // A bare operator or `)` where the grammar expects a license id is a
    // malformed expression → parser throws → UNACCEPTABLE.
    expect(isAcceptable('AND', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('OR', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('WITH', REPO_ALLOW_LIST)).toBe(false);
    // …and used mid-stream where a primary is expected.
    expect(isAcceptable('MIT AND AND', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT AND )', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('MIT OR (', REPO_ALLOW_LIST)).toBe(false);
  });

  it('AND is left-of and right-of a satisfiable id — both conjuncts checked', () => {
    // AND requires EVERY conjunct to be allow-listed: good&bad and bad&good
    // must both be false, good&good true (guards the SPDX AND semantics).
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
    // OR is satisfiable if ANY branch is allow-listed: a satisfiable branch in
    // EITHER position must win; all-branches-fail must lose.
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
    // A parenthesised sub-expression evaluates to its own satisfiability.
    expect(isAcceptable('(MIT)', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('(GPL-3.0-only)', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('(MIT AND GPL-3.0-only)', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('((MIT))', REPO_ALLOW_LIST)).toBe(true);
  });

  it('a WITH rider makes an OTHERWISE-satisfiable id unsatisfiable', () => {
    // A `<id> WITH <exception>` unit never matches a plain-id allow-list entry:
    // an allow-listed id, once ridered, is unsatisfiable; surrounding grammar
    // still parses.
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

  it('accepts multi-space-separated / space-padded expressions', () => {
    // Runs of ordinary spaces between tokens are valid SPDX whitespace, and
    // leading/trailing spaces are trimmed before evaluation.
    expect(isAcceptable('MIT   OR   GPL-3.0-only', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('  MIT  ', REPO_ALLOW_LIST)).toBe(true);
    // PARITY CHANGE (#222): the SPDX grammar's inter-token separator is the
    // SPACE character only. The old bespoke tokenizer treated any `\s` (tabs,
    // newlines) as a separator — non-standard; `spdx-satisfies` rejects a TAB
    // between tokens, so our fallback returns UNACCEPTABLE. Real declared
    // expressions from ClearlyDefined are space-separated, so this is inert in
    // practice while being spec-correct.
    expect(isAcceptable('MIT\tOR\tGPL-3.0-only', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects a single junk character anywhere', () => {
    // Any character outside the SPDX grammar makes the whole expression
    // unparseable → parser throws → UNACCEPTABLE.
    expect(isAcceptable('MIT & Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // &
    expect(isAcceptable('MIT/Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // /
    expect(isAcceptable('MIT,Apache-2.0', REPO_ALLOW_LIST)).toBe(false); // ,
    expect(isAcceptable('«MIT»', REPO_ALLOW_LIST)).toBe(false); // non-ASCII
  });

  it('accepts every allow-listed id shape, including dotted/plus/dash and 0-prefixed', () => {
    // Dotted, digit, dash and leading-digit SPDX ids are all valid.
    expect(isAcceptable('BSD-2-Clause', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('0BSD', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('CC-BY-4.0', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('BlueOak-1.0.0', REPO_ALLOW_LIST)).toBe(true);
  });

  it('distinguishes NOASSERTION/NONE from a genuine allow-listed id', () => {
    // A near-miss token is not a valid SPDX id → parser throws → UNACCEPTABLE.
    expect(isAcceptable('NOASSERTIONX', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('NON', REPO_ALLOW_LIST)).toBe(false);
    // The SPDX markers NONE / NOASSERTION are not license ids: they are rejected
    // even if an allow-list literally (and invalidly) lists them.
    expect(isAcceptable('NONE', 'MIT, None')).toBe(false);
    expect(isAcceptable('NOASSERTION', 'MIT, NOASSERTION')).toBe(false);
  });

  it('rejects an all-whitespace expression', () => {
    // A whitespace-only expression carries no license → parser throws → false.
    expect(isAcceptable('\t\n  ', REPO_ALLOW_LIST)).toBe(false);
  });

  it('rejects an expression with two ids and no operator', () => {
    // Two adjacent ids with no connecting operator is malformed SPDX → false.
    expect(isAcceptable('MIT Apache-2.0', REPO_ALLOW_LIST)).toBe(false);
    expect(isAcceptable('(MIT) MIT', REPO_ALLOW_LIST)).toBe(false);
  });

  // ── Adversarial allow-lists: a malformed token must NEVER become a usable
  // allow-list match. These use synthetic allow-lists that literally contain
  // the malformed token to prove the parser rejects the whole expression rather
  // than looking the token up — spdx-satisfies rejects an invalid allow-list id
  // too, so the verdict stays UNACCEPTABLE. (Not the repo's real allow-list.)
  it('a junk char is rejected even when the allow-list contains it', () => {
    // '&' is never a valid SPDX id, on either side → UNACCEPTABLE.
    expect(isAcceptable('&', '&,mit')).toBe(false);
    expect(isAcceptable('MIT & GPL', 'mit,&,gpl')).toBe(false);
    // A space-separated id pair with no operator is malformed → UNACCEPTABLE.
    expect(isAcceptable('MIT GPL', 'mit,gpl')).toBe(false);
  });

  it('an operator/paren where an id is due is rejected even if the allow-list lists it', () => {
    // A bare operator or `)` where the grammar expects an id is malformed →
    // parser throws → UNACCEPTABLE, regardless of allow-list contents.
    expect(isAcceptable('AND', 'and,mit')).toBe(false);
    expect(isAcceptable('OR', 'or,mit')).toBe(false);
    expect(isAcceptable('WITH', 'with,mit')).toBe(false);
    expect(isAcceptable(')', ')')).toBe(false);
    expect(isAcceptable('and', 'and,mit')).toBe(false);
  });

  it('a bogus WITH exception token is rejected even if the allow-list lists it', () => {
    // An operator/paren as the WITH exception is malformed → parser throws →
    // false, regardless of allow-list contents.
    expect(isAcceptable('MIT WITH AND', 'mit,and')).toBe(false);
    expect(isAcceptable('MIT WITH OR', 'mit,or')).toBe(false);
    expect(isAcceptable('MIT WITH WITH', 'mit,with')).toBe(false);
    expect(isAcceptable('MIT WITH )', 'mit')).toBe(false);
    expect(isAcceptable('MIT WITH (', 'mit')).toBe(false);
    // A VALID exception id parses; the WITH unit itself never matches a plain
    // allow-list id, so it is unsatisfiable on its own.
    expect(isAcceptable('MIT WITH GCC-exception-3.1', 'MIT')).toBe(false);
    // …and inside an OR the sibling still rescues it, proving the WITH parsed.
    expect(
      isAcceptable('MIT OR (Apache-2.0 WITH GCC-exception-3.1)', 'MIT'),
    ).toBe(true);
  });

  it('validates the WITH exception id against the SPDX exception list', () => {
    // PARITY CHANGE (#222): the old bespoke parser accepted ANY token after
    // WITH as an "exception" (it never checked the SPDX exception registry), so
    // `Apache-2.0 WITH Foo OR MIT` parsed and the OR-sibling MIT rescued it →
    // true. `spdx-satisfies` (via `spdx-expression-parse`) rejects `Foo` as an
    // unknown exception id and throws → our conservative fallback returns
    // UNACCEPTABLE. Correct: an expression referencing a bogus exception should
    // not silently pass on a sibling. A VALID exception id still parses (the OR
    // sibling then rescues) — proven in the WITH-exception test above.
    expect(isAcceptable('Apache-2.0 WITH Foo OR MIT', REPO_ALLOW_LIST)).toBe(
      false,
    );
    // With a real exception id the OR sibling rescues (rider unit is unsat).
    expect(
      isAcceptable('Apache-2.0 WITH LLVM-exception OR MIT', REPO_ALLOW_LIST),
    ).toBe(true);
  });

  it('evaluates chained AND / OR operators (three+ operands)', () => {
    // A multi-operand AND/OR chain evaluates fully: an all-satisfiable chain
    // succeeds regardless of length.
    expect(isAcceptable('MIT AND Apache-2.0', REPO_ALLOW_LIST)).toBe(true);
    expect(isAcceptable('MIT AND Apache-2.0 AND ISC', REPO_ALLOW_LIST)).toBe(
      true,
    );
    expect(isAcceptable('GPL-3.0-only OR MIT', REPO_ALLOW_LIST)).toBe(true);
    expect(
      isAcceptable('GPL-3.0-only OR GPL-2.0-only OR MIT', REPO_ALLOW_LIST),
    ).toBe(true);
  });

  it('rejects the padded SPDX NONE / NOASSERTION markers', () => {
    // A whitespace-padded NONE / NOASSERTION marker is not a license id — the
    // parser throws → UNACCEPTABLE, even against an allow-list that (invalidly)
    // lists a "none"/"noassertion" token.
    expect(isAcceptable('  NONE  ', 'none, mit')).toBe(false);
    expect(isAcceptable('\tNOASSERTION\t', 'noassertion, mit')).toBe(false);
  });

  it('a malformed WITH-exception ABORTS the whole expression, not just its unit', () => {
    // When the WITH exception is itself an operator/paren the expression is
    // malformed and the parser throws — aborting the ENTIRE parse → false —
    // rather than letting an OR sibling rescue it. (A sibling would flip
    // false→true if the whole expression were not rejected.)
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

  it('rejects a leading/dangling AND/OR/WITH operator', () => {
    // An operator at the start (AND/OR) or a dangling WITH is malformed SPDX →
    // parser throws → UNACCEPTABLE, even if the allow-list lists the keyword.
    expect(isAcceptable('AND MIT', 'and,mit')).toBe(false); // leading AND
    expect(isAcceptable('OR MIT', 'or,mit')).toBe(false); // leading OR
    expect(isAcceptable('MIT WITH', 'mit,with')).toBe(false); // dangling WITH
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
