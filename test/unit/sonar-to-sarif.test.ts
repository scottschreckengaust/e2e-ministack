import { toSarif } from '../../.github/scripts/sonar-to-sarif';

// Unit tests for .github/scripts/sonar-to-sarif.ts (#150; gated under #165):
// SonarQube api/issues/search response → SARIF 2.1.0. Imported IN-PROCESS so
// it flows through the 100% coverage gate (#124) + Stryker mutation (#122).
// (The old `sonar-to-sarif.test.mjs` used `node --test`, which nothing in CI
// ever ran.) An empty/wrong SARIF silently resolves the sonarqube alert stream.

const SAMPLE = {
  total: 2,
  issues: [
    {
      key: 'AY1',
      rule: 'javascript:S1234',
      severity: 'CRITICAL',
      component: 'e2e-ministack:lambda/index.js',
      line: 42,
      textRange: { startLine: 42, endLine: 42, startOffset: 2, endOffset: 10 },
      message: 'Refactor this function.',
      type: 'CODE_SMELL',
    },
    {
      key: 'AY2',
      rule: 'typescript:S5678',
      severity: 'MINOR',
      component: 'e2e-ministack:lib/env.ts',
      message: 'Remove this unused import.',
      type: 'CODE_SMELL',
    },
  ],
  components: [
    { key: 'e2e-ministack:lambda/index.js', path: 'lambda/index.js' },
    { key: 'e2e-ministack:lib/env.ts', path: 'lib/env.ts' },
    { key: 'e2e-ministack', path: '' },
  ],
};

describe('sonar-to-sarif — issues/search → SARIF', () => {
  it('maps each issue to a SARIF result with rule, level, location', () => {
    const sarif = toSarif(SAMPLE);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs[0].tool.driver.name).toBe('SonarQube');
    expect(sarif.runs[0].results).toHaveLength(2);

    const r0 = sarif.runs[0].results[0];
    expect(r0.ruleId).toBe('javascript:S1234');
    expect(r0.level).toBe('error'); // CRITICAL -> error
    expect(r0.message.text).toBe('Refactor this function.');
    expect(r0.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'lambda/index.js',
    );
    // textRange.startOffset is 0-based; SARIF startColumn is 1-based.
    const region = r0.locations[0].physicalLocation.region!;
    expect(region.startLine).toBe(42);
    expect(region.endLine).toBe(42);
    expect(region.startColumn).toBe(3);
    expect(region.endColumn).toBe(11);
  });

  it('MINOR maps to note; missing textRange falls back to line-only region', () => {
    const sarif = toSarif(SAMPLE);
    const r1 = sarif.runs[0].results[1];
    expect(r1.level).toBe('note'); // MINOR -> note
    expect(r1.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'lib/env.ts',
    );
    // no textRange and no line -> region omitted (only artifactLocation).
    expect(r1.locations[0].physicalLocation.region).toBeUndefined();
  });

  it('maps every legacy severity to the right SARIF level', () => {
    const levels = (
      ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'] as const
    ).map(
      (severity) =>
        toSarif({
          issues: [{ rule: 'r', severity, component: 'p:a.ts' }],
        }).runs[0].results[0].level,
    );
    expect(levels).toEqual(['error', 'error', 'warning', 'note', 'note']);
  });

  it('falls back to warning for an unknown legacy severity with no impacts', () => {
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'WEIRD', component: 'p:a.ts' }],
    });
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('resolves component path via components[]; falls back to stripping projectKey:', () => {
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'proj:src/a.ts' }],
      components: [], // no mapping -> strip "proj:" prefix
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('src/a.ts');
  });

  it('uses a components[] path override when present and non-empty', () => {
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'proj:key' }],
      components: [{ key: 'proj:key', path: 'resolved/path.ts' }],
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('resolved/path.ts');
  });

  it('ignores an EMPTY components[] path and strips the projectKey instead', () => {
    // An empty-string path in components[] must NOT be used (falsy) — the
    // strip-prefix fallback runs.
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'proj:x/y.ts' }],
      components: [{ key: 'proj:x/y.ts', path: '' }],
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('x/y.ts');
  });

  it('leaves a component with no colon untouched, and maps a missing component to "unknown"', () => {
    const noColon = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'nocolon' }],
    });
    expect(
      noColon.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('nocolon');
    const noComponent = toSarif({ issues: [{ rule: 'r', severity: 'MAJOR' }] });
    expect(
      noComponent.runs[0].results[0].locations[0].physicalLocation
        .artifactLocation.uri,
    ).toBe('unknown');
  });

  it('emits each rule once in tool.driver.rules (dedup)', () => {
    const sarif = toSarif({
      issues: [
        { rule: 'javascript:S1234', severity: 'MAJOR', component: 'p:a' },
        { rule: 'javascript:S1234', severity: 'MINOR', component: 'p:b' },
        { rule: 'typescript:S5678', severity: 'INFO', component: 'p:c' },
      ],
    });
    expect(sarif.runs[0].tool.driver.rules.map((r) => r.id).sort()).toEqual([
      'javascript:S1234',
      'typescript:S5678',
    ]);
  });

  it('a rule-less issue gets ruleId "unknown" and is not added to rules[]', () => {
    const sarif = toSarif({
      issues: [{ severity: 'MAJOR', component: 'p:a' }],
    });
    expect(sarif.runs[0].results[0].ruleId).toBe('unknown');
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
  });

  it('message falls back to the rule, then to a default, when absent', () => {
    const viaRule = toSarif({
      issues: [{ rule: 'js:S1', severity: 'MAJOR', component: 'p:a' }],
    });
    expect(viaRule.runs[0].results[0].message.text).toBe('js:S1');
    const viaDefault = toSarif({
      issues: [{ severity: 'MAJOR', component: 'p:a' }],
    });
    expect(viaDefault.runs[0].results[0].message.text).toBe('SonarQube issue');
  });

  it('empty issues yields a valid empty-results SARIF', () => {
    const sarif = toSarif({ total: 0, issues: [], components: [] });
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results).toEqual([]);
  });

  it('tolerates a null / undefined / non-array response defensively', () => {
    expect(toSarif(null).runs[0].results).toEqual([]);
    expect(toSarif(undefined).runs[0].results).toEqual([]);
    expect(
      toSarif({ issues: 'nope' as unknown as [] }).runs[0].results,
    ).toEqual([]);
  });

  it('derives level from impacts[] when legacy severity is absent (worst wins)', () => {
    const high = toSarif({
      issues: [
        {
          rule: 'r',
          component: 'p:a',
          impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }],
        },
      ],
    });
    expect(high.runs[0].results[0].level).toBe('error'); // HIGH impact -> error
    // Multiple impacts: the WORST (highest-ranked) level wins.
    const worst = toSarif({
      issues: [
        {
          rule: 'r',
          component: 'p:a',
          impacts: [
            { severity: 'LOW' },
            { severity: 'HIGH' },
            { severity: 'MEDIUM' },
          ],
        },
      ],
    });
    expect(worst.runs[0].results[0].level).toBe('error');
    const medium = toSarif({
      issues: [
        { rule: 'r', component: 'p:a', impacts: [{ severity: 'MEDIUM' }] },
      ],
    });
    expect(medium.runs[0].results[0].level).toBe('warning');
    const low = toSarif({
      issues: [{ rule: 'r', component: 'p:a', impacts: [{ severity: 'LOW' }] }],
    });
    expect(low.runs[0].results[0].level).toBe('note');
  });

  it('falls back to warning when impacts carry only unknown severities', () => {
    const sarif = toSarif({
      issues: [
        { rule: 'r', component: 'p:a', impacts: [{ severity: 'BOGUS' }] },
      ],
    });
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('ignores an impact with NO severity field, then honours a later valid one', () => {
    // Guards the `im.severity ? ... : undefined` false branch: an impact object
    // without `severity` contributes nothing, but a following HIGH still wins.
    const sarif = toSarif({
      issues: [
        {
          rule: 'r',
          component: 'p:a',
          impacts: [{ softwareQuality: 'SECURITY' }, { severity: 'HIGH' }],
        },
      ],
    });
    expect(sarif.runs[0].results[0].level).toBe('error');
    // …and an impacts list with ONLY a severity-less entry falls back to warning.
    const noneUsable = toSarif({
      issues: [
        { rule: 'r', component: 'p:a', impacts: [{ softwareQuality: 'X' }] },
      ],
    });
    expect(noneUsable.runs[0].results[0].level).toBe('warning');
  });

  it('tolerates a components[] entry with NO key (falls back to strip-prefix)', () => {
    // Guards the `c.key ?? ''` branch: a key-less component maps under '' and
    // must not hijack a real component lookup.
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'proj:z.ts' }],
      components: [{ path: 'orphan.ts' }, { key: 'other', path: 'o.ts' }],
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('z.ts');
  });

  it('emits startLine-only region when textRange has line but no offsets', () => {
    const sarif = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'MAJOR',
          component: 'p:a',
          textRange: { startLine: 7 },
        },
      ],
    });
    const region =
      sarif.runs[0].results[0].locations[0].physicalLocation.region!;
    expect(region).toEqual({ startLine: 7 });
  });

  it('uses issue.line for the region when textRange is absent', () => {
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'p:a', line: 99 }],
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.region,
    ).toEqual({ startLine: 99 });
  });

  // ── Mutation-hardening: pin every branch/level/region key precisely ──

  it('legacy severity WINS over impacts[] (precedence), proving each legacy map value', () => {
    // A MAJOR/MINOR/INFO issue that ALSO carries a HIGH impact must keep its
    // LEGACY level — this distinguishes the legacy map value from the impact
    // path (kills mutating LEGACY_LEVEL[MAJOR]='' → which would fall through to
    // the HIGH impact and wrongly return 'error').
    const major = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'MAJOR',
          component: 'p:a',
          impacts: [{ severity: 'HIGH' }],
        },
      ],
    });
    expect(major.runs[0].results[0].level).toBe('warning');
    const minor = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'MINOR',
          component: 'p:a',
          impacts: [{ severity: 'HIGH' }],
        },
      ],
    });
    expect(minor.runs[0].results[0].level).toBe('note');
    const info = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'INFO',
          component: 'p:a',
          impacts: [{ severity: 'HIGH' }],
        },
      ],
    });
    expect(info.runs[0].results[0].level).toBe('note');
  });

  it('MEDIUM impact ranks ABOVE LOW (proves IMPACT_LEVEL[MEDIUM] value)', () => {
    // Kills mutating IMPACT_LEVEL[MEDIUM]='' : with both MEDIUM and LOW impacts,
    // MEDIUM (warning) must win; drop MEDIUM's mapping and only LOW (note)
    // remains → a detectable 'note'.
    const sarif = toSarif({
      issues: [
        {
          rule: 'r',
          component: 'p:a',
          impacts: [{ severity: 'LOW' }, { severity: 'MEDIUM' }],
        },
      ],
    });
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('HIGH impact ranks ABOVE MEDIUM and LOW regardless of order (worst wins)', () => {
    // Kills the ranked[] first-element and the `<` comparison mutants: HIGH must
    // beat lower-ranked impacts no matter the array order.
    for (const order of [
      [{ severity: 'HIGH' }, { severity: 'LOW' }],
      [{ severity: 'LOW' }, { severity: 'HIGH' }],
      [{ severity: 'MEDIUM' }, { severity: 'HIGH' }, { severity: 'LOW' }],
    ]) {
      const sarif = toSarif({
        issues: [{ rule: 'r', component: 'p:a', impacts: order }],
      });
      expect(sarif.runs[0].results[0].level).toBe('error');
    }
  });

  it('strips a LEADING-colon component to its remainder (idx===0 branch)', () => {
    // Kills `idx >= 0` → `idx > 0`: a component that starts with ':' has idx 0;
    // it must still be stripped to '' … then '' is the uri. Use ':path' → 'path'
    // via a project key of zero length is unusual, so assert the strip happens.
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: ':leading.ts' }],
    });
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('leading.ts');
  });

  it('OMITS the region key entirely when there is no location info (not undefined)', () => {
    // Kills `if (region) physicalLocation.region = region` → `if (true)`: with no
    // textRange and no line, the physicalLocation must have NO `region` key at
    // all (a forced `region = undefined` would ADD the key). Assert on key
    // presence, since toEqual/toBeUndefined can't tell an absent key from
    // `undefined`.
    const sarif = toSarif({
      issues: [{ rule: 'r', severity: 'MAJOR', component: 'p:a' }],
    });
    const pl = sarif.runs[0].results[0].locations[0].physicalLocation as Record<
      string,
      unknown
    >;
    expect(Object.prototype.hasOwnProperty.call(pl, 'region')).toBe(false);
  });

  it('OMITS endLine/columns when the textRange lacks them (region key set)', () => {
    // Kills the `Number.isInteger(tr.endLine)` / startOffset / endOffset guards
    // being forced true (which would add endLine/columns = undefined). Assert
    // the region has EXACTLY startLine.
    const sarif = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'MAJOR',
          component: 'p:a',
          textRange: { startLine: 5 },
        },
      ],
    });
    const region = sarif.runs[0].results[0].locations[0].physicalLocation
      .region as unknown as Record<string, unknown>;
    expect(Object.keys(region).sort()).toEqual(['startLine']);
    expect(region.startLine).toBe(5);
  });

  it('sets endLine and 1-based columns only when the offsets are present', () => {
    // Positive side of the same guards: each optional region field appears with
    // the correct (offset+1) value when its source offset is an integer.
    const sarif = toSarif({
      issues: [
        {
          rule: 'r',
          severity: 'MAJOR',
          component: 'p:a',
          textRange: { startLine: 3, endLine: 4, startOffset: 0, endOffset: 7 },
        },
      ],
    });
    const region =
      sarif.runs[0].results[0].locations[0].physicalLocation.region!;
    expect(region).toEqual({
      startLine: 3,
      endLine: 4,
      startColumn: 1, // 0 + 1
      endColumn: 8, // 7 + 1
    });
  });
});
