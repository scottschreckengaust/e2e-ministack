import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toSarif } from './sonar-to-sarif.mjs';

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

test('maps each issue to a SARIF result with rule, level, location', () => {
  const sarif = toSarif(SAMPLE);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'SonarQube');
  assert.equal(sarif.runs[0].results.length, 2);

  const r0 = sarif.runs[0].results[0];
  assert.equal(r0.ruleId, 'javascript:S1234');
  assert.equal(r0.level, 'error'); // CRITICAL -> error
  assert.equal(r0.message.text, 'Refactor this function.');
  assert.equal(
    r0.locations[0].physicalLocation.artifactLocation.uri,
    'lambda/index.js',
  );
  // textRange.startOffset is 0-based; SARIF startColumn is 1-based
  assert.equal(r0.locations[0].physicalLocation.region.startLine, 42);
  assert.equal(r0.locations[0].physicalLocation.region.startColumn, 3);
  assert.equal(r0.locations[0].physicalLocation.region.endColumn, 11);
});

test('MINOR maps to note; missing textRange falls back to line-only region', () => {
  const sarif = toSarif(SAMPLE);
  const r1 = sarif.runs[0].results[1];
  assert.equal(r1.level, 'note'); // MINOR -> note
  assert.equal(
    r1.locations[0].physicalLocation.artifactLocation.uri,
    'lib/env.ts',
  );
  // no textRange and no line -> region omitted (only artifactLocation)
  assert.equal(r1.locations[0].physicalLocation.region, undefined);
});

test('resolves component path via components[]; falls back to stripping projectKey:', () => {
  const sarif = toSarif({
    issues: [
      { key: 'X', rule: 'r', severity: 'MAJOR', component: 'proj:src/a.ts' },
    ],
    components: [], // no mapping -> strip "proj:" prefix
  });
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'src/a.ts',
  );
});

test('emits each rule once in tool.driver.rules', () => {
  const sarif = toSarif(SAMPLE);
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id).sort();
  assert.deepEqual(ids, ['javascript:S1234', 'typescript:S5678']);
});

test('empty issues yields a valid empty-results SARIF', () => {
  const sarif = toSarif({ total: 0, issues: [], components: [] });
  assert.equal(sarif.version, '2.1.0');
  assert.deepEqual(sarif.runs[0].results, []);
});

test('derives level from impacts[] when legacy severity is absent', () => {
  const sarif = toSarif({
    issues: [
      {
        key: 'Z',
        rule: 'r',
        component: 'proj:a.ts',
        impacts: [{ softwareQuality: 'SECURITY', severity: 'HIGH' }],
      },
    ],
    components: [],
  });
  assert.equal(sarif.runs[0].results[0].level, 'error'); // HIGH impact -> error
});
