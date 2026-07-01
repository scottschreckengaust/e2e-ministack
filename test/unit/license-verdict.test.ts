import { execFileSync } from 'node:child_process';
import * as path from 'node:path';

// TDD tests for .github/scripts/license-verdict.mjs (#127 Leg B2): SPDX
// allow-list satisfiability, mirroring the dependency-review PR gate's
// semantics (OR = any branch satisfiable, AND = all conjuncts satisfiable),
// with a conservative fallback (unparseable / NOASSERTION / empty → reject).
//
// The script is exercised through its CLI contract (exit 0 = ACCEPTABLE,
// exit 1 = UNACCEPTABLE, exit 2 = usage error) — the exact interface the
// license-review-poller workflow uses. A direct `import()` of the .mjs is
// not possible in this CJS ts-jest environment (jest's VM needs
// --experimental-vm-modules for ESM), and spawning the CLI also covers the
// argv plumbing the workflow depends on.
const SCRIPT = path.resolve(
  __dirname,
  '../../.github/scripts/license-verdict.mjs',
);

// The repo's real allow-list — keep in sync with security.yml
// `allow-licenses:` (the workflow file is the single source of truth; the
// poller extracts it at runtime, this literal only pins the test fixtures).
const REPO_ALLOW_LIST =
  'MIT, Apache-2.0, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD, ' +
  'BlueOak-1.0.0, Python-2.0, CC0-1.0, CC-BY-4.0, Unlicense';

interface Verdict {
  code: number;
  stdout: string;
}

function verdict(expression: string, allowList = REPO_ALLOW_LIST): Verdict {
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

describe('license-verdict.mjs — SPDX allow-list satisfiability (CLI)', () => {
  it('accepts a bare allow-listed id', () => {
    const res = verdict('MIT');
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('ACCEPTABLE');
  });

  it('rejects a bare id not on the allow-list', () => {
    const res = verdict('GPL-3.0-only');
    expect(res.code).toBe(1);
    expect(res.stdout).toContain('UNACCEPTABLE');
  });

  it('accepts an OR expression when any branch is allow-listed', () => {
    expect(verdict('MIT OR GPL-3.0-or-later').code).toBe(0);
    expect(verdict('GPL-3.0-or-later OR MIT').code).toBe(0);
  });

  it('rejects an AND expression when any conjunct is not allow-listed', () => {
    expect(verdict('MIT AND GPL-3.0-only').code).toBe(1);
  });

  it('handles nested parentheses with correct precedence', () => {
    expect(verdict('(MIT OR GPL-3.0-or-later) AND Apache-2.0').code).toBe(0);
    expect(verdict('(GPL-2.0-only OR GPL-3.0-only) AND MIT').code).toBe(1);
    // AND binds tighter than OR: MIT OR (GPL AND GPL) is satisfiable via MIT.
    expect(verdict('MIT OR GPL-2.0-only AND GPL-3.0-only').code).toBe(0);
  });

  it('rejects NOASSERTION, NONE and the empty expression', () => {
    expect(verdict('NOASSERTION').code).toBe(1);
    expect(verdict('NONE').code).toBe(1);
    expect(verdict('').code).toBe(1);
    expect(verdict('   ').code).toBe(1);
  });

  it('rejects unparseable garbage (conservative fallback)', () => {
    expect(verdict('??? not an spdx expression !!!').code).toBe(1);
    expect(verdict('MIT OR').code).toBe(1); // dangling operator
    expect(verdict('(MIT OR Apache-2.0').code).toBe(1); // unbalanced paren
    expect(verdict('MIT Apache-2.0').code).toBe(1); // missing operator
  });

  it('matches ids case-insensitively (both sides)', () => {
    expect(verdict('mit').code).toBe(0);
    expect(verdict('MIT', 'mit, apache-2.0').code).toBe(0);
    expect(verdict('apache-2.0 AND mit').code).toBe(0);
  });

  it('treats suffixed ids as needing an exact allow-list entry', () => {
    // Conservative: Apache-2.0+ is NOT satisfied by Apache-2.0 on the list.
    expect(verdict('Apache-2.0+').code).toBe(1);
    expect(verdict('GPL-3.0-or-later').code).toBe(1);
    // …but an exact suffixed entry on the allow-list does satisfy it.
    expect(verdict('Apache-2.0+', 'Apache-2.0+').code).toBe(0);
  });

  it('rejects WITH exception expressions unless a branch avoids them', () => {
    // A WITH unit can never match a comma-separated allow-list entry.
    expect(verdict('GPL-2.0-only WITH Classpath-exception-2.0').code).toBe(1);
    // …but an OR sibling can still satisfy the expression.
    expect(
      verdict('MIT OR (GPL-2.0-only WITH Classpath-exception-2.0)').code,
    ).toBe(0);
  });

  it('rejects AND-rider expressions (Commons-Clause case from the docs)', () => {
    expect(verdict('BSD-3-Clause AND Commons-Clause').code).toBe(1);
  });

  it('accepts the aiohttp case against the repo allow-list', () => {
    // aiohttp@3.14.1 wheel METADATA / eventual ClearlyDefined declared value.
    const res = verdict('Apache-2.0 AND MIT');
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('ACCEPTABLE');
  });

  it('exits 2 on a missing or empty allow-list (usage error)', () => {
    expect(verdict('MIT', '').code).toBe(2);
    expect(verdict('MIT', ' , ,').code).toBe(2);
  });
});
