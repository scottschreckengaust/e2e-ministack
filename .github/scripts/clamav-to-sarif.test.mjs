import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toSarif } from './clamav-to-sarif.mjs';

const SAMPLE_FOUND = `/home/runner/work/repo/repo/evil.bin: Win.Test.EICAR_HDB-1 FOUND
./clean.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 1
`;

const SAMPLE_CLEAN = `./a.txt: OK
./b.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 0
`;

test('maps a FOUND line to one SARIF error result at severity 10.0', () => {
  const sarif = toSarif(SAMPLE_FOUND);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'ClamAV');
  assert.equal(sarif.runs[0].results.length, 1);
  const r = sarif.runs[0].results[0];
  assert.equal(r.ruleId, 'Win.Test.EICAR_HDB-1');
  assert.equal(r.level, 'error');
  assert.equal(r.properties['security-severity'], '10.0');
  assert.equal(
    r.locations[0].physicalLocation.artifactLocation.uri,
    '/home/runner/work/repo/repo/evil.bin',
  );
});

test('clean scan yields a valid empty-results SARIF', () => {
  const sarif = toSarif(SAMPLE_CLEAN);
  assert.equal(sarif.version, '2.1.0');
  assert.deepEqual(sarif.runs[0].results, []);
});

test('strips a leading ./ from the artifact URI', () => {
  const sarif = toSarif('./sub/dir/x.exe: Foo.Bar FOUND\n');
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'sub/dir/x.exe',
  );
});

test('does not treat the SCAN SUMMARY section as findings', () => {
  const sarif = toSarif(SAMPLE_FOUND);
  // exactly one result — the "Infected files: 1" line must not match
  assert.equal(sarif.runs[0].results.length, 1);
});
