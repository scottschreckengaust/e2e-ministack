import { toSarif } from '../../.github/scripts/clamav-to-sarif';

// Unit tests for .github/scripts/clamav-to-sarif.ts (#149; gated under #165):
// clamdscan --verbose log → SARIF 2.1.0. The parser is imported IN-PROCESS so
// it flows through the 100% coverage gate (#124) + Stryker mutation (#122).
// (The old `clamav-to-sarif.test.mjs` used `node --test`, which nothing in CI
// ever ran — a false green.) Its output is load-bearing for the Code Scanning
// alert stream: an empty/wrong SARIF silently resolves virus alerts.

// A real clamdscan --verbose log fragment. The REAL EICAR signature name is
// `Eicar-Test-Signature`, verified natively against `clamdscan` after #162 —
// use it, not a guessed one (issue #165 acceptance criterion). NB: this is the
// signature *name*, NOT the live EICAR byte-string; nothing scannable here.
const SAMPLE_FOUND = `/home/runner/work/repo/repo/evil.bin: Eicar-Test-Signature FOUND
./clean.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 1
`;

const SAMPLE_CLEAN = `./a.txt: OK
./b.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 0
`;

describe('clamav-to-sarif — clamdscan log → SARIF', () => {
  it('maps a FOUND line to one SARIF error result at severity 10.0', () => {
    const sarif = toSarif(SAMPLE_FOUND);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs[0].tool.driver.name).toBe('ClamAV');
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
    expect(sarif.runs[0].results).toHaveLength(1);
    const r = sarif.runs[0].results[0];
    expect(r.ruleId).toBe('Eicar-Test-Signature');
    expect(r.level).toBe('error');
    expect(r.properties['security-severity']).toBe('10.0');
    expect(r.message.text).toBe(
      'Eicar-Test-Signature detected in /home/runner/work/repo/repo/evil.bin',
    );
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      '/home/runner/work/repo/repo/evil.bin',
    );
  });

  it('clean scan yields a valid empty-results SARIF', () => {
    const sarif = toSarif(SAMPLE_CLEAN);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results).toEqual([]);
  });

  it('empty input yields a valid empty-results SARIF', () => {
    expect(toSarif('').runs[0].results).toEqual([]);
  });

  it('strips a leading ./ from the artifact URI but keeps the message path', () => {
    const sarif = toSarif('./sub/dir/x.exe: Foo.Bar FOUND\n');
    const r = sarif.runs[0].results[0];
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'sub/dir/x.exe',
    );
    // Only a LEADING ./ is stripped; the message keeps the original path.
    expect(r.message.text).toBe('Foo.Bar detected in ./sub/dir/x.exe');
  });

  it('does NOT strip a ./ that is not at the start of the path', () => {
    const sarif = toSarif('a/./b.exe: Foo FOUND\n');
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('a/./b.exe');
  });

  it('does not treat the SCAN SUMMARY section (or lines after it) as findings', () => {
    // Everything after the banner is stats — even a crafted "…: X FOUND" line.
    const sarif = toSarif(
      `./a: Sig FOUND\n----------- SCAN SUMMARY -----------\n./trap: Fake FOUND\nInfected files: 1\n`,
    );
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('Sig');
  });

  it('ignores blank lines and non-FOUND (OK) lines', () => {
    const sarif = toSarif('\n./ok.txt: OK\n\n./v: Bad FOUND\n\n');
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('Bad');
  });

  it('does not match a line that merely contains FOUND but not at the end', () => {
    // The regex anchors ` FOUND$` — a mention of FOUND mid-line is not a hit.
    expect(toSarif('note: nothing FOUND here\n').runs[0].results).toEqual([]);
  });

  it('handles a filename containing ": " and the literal FOUND (adversarial)', () => {
    // Greedy `path` group must swallow the internal ": " and "FOUND" so the
    // signature is only the final token before the trailing " FOUND".
    const sarif = toSarif('weird: FOUND/name.txt: Trojan.X FOUND\n');
    expect(sarif.runs[0].results).toHaveLength(1);
    const r = sarif.runs[0].results[0];
    expect(r.ruleId).toBe('Trojan.X');
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'weird: FOUND/name.txt',
    );
  });

  it('treats CRLF the same as LF', () => {
    const sarif = toSarif(
      './v.bin: Sig FOUND\r\n----------- SCAN SUMMARY -----------\r\n',
    );
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('Sig');
  });

  it('maps multiple detections to multiple results', () => {
    const sarif = toSarif('./a: S1 FOUND\n./b: S2 FOUND\n');
    expect(sarif.runs[0].results.map((r) => r.ruleId)).toEqual(['S1', 'S2']);
  });

  it('trims only the TRAILING whitespace of a line (guards trimEnd)', () => {
    // clamdscan can pad the line with trailing spaces; trimEnd() lets ` FOUND$`
    // still anchor. A leading-only trim (trimStart) would leave the spaces and
    // break the match — this pins trimEnd specifically.
    const sarif = toSarif('./v.bin: Sig FOUND   \n');
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('Sig');
    // Leading whitespace on the path is preserved by trimEnd (not stripped),
    // so a line that is ONLY leading-padded still matches at its content.
    const padded = toSarif('   ./p.bin: Sig2 FOUND\n');
    expect(padded.runs[0].results).toHaveLength(1);
    expect(
      padded.runs[0].results[0].locations[0].physicalLocation.artifactLocation
        .uri,
    ).toBe('   ./p.bin');
  });

  it('does NOT skip a real finding just because a summary appeared earlier is impossible (order matters)', () => {
    // Guards the `inSummary` short-circuit at the `if (inSummary || …)`: any
    // FOUND-shaped line AFTER the banner must be ignored (it is scan stats,
    // not a detection). Two post-banner FOUND lines must still yield zero.
    const sarif = toSarif(
      '----------- SCAN SUMMARY -----------\n./a: X FOUND\n./b: Y FOUND\n',
    );
    expect(sarif.runs[0].results).toEqual([]);
  });

  it('requires the ": " separator and trailing " FOUND" exactly (regex anchors)', () => {
    // No ": " separator → no match (guards the `: ` literal in the regex).
    expect(toSarif('evilFOUND\n').runs[0].results).toEqual([]);
    expect(toSarif('nocolon Sig FOUND\n').runs[0].results).toEqual([]);
    // Lower-case "found" must NOT match (the literal is upper-case FOUND).
    expect(toSarif('./x: Sig found\n').runs[0].results).toEqual([]);
    // A single space (not " FOUND") after the sig is not a hit.
    expect(toSarif('./x: SigFOUND\n').runs[0].results).toEqual([]);
    // The exact message text is pinned (guards the message template string).
    const ok = toSarif('./x: Sig FOUND\n');
    expect(ok.runs[0].results[0].message.text).toBe('Sig detected in ./x');
  });
});
