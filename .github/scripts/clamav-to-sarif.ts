// Convert `clamdscan --verbose` log text into a SARIF 2.1.0 document.
//
// LOGIC MODULE (jest-visible, gate-eligible): this holds the pure parser so it
// flows through the repo's 100% coverage gate (#124), Stryker mutation (#122),
// and the fuzz-regression tier. The runnable CLI is the thin
// `clamav-to-sarif.mjs` shim next to it, which imports `toSarif` from here —
// Node 24 strips the `.ts` on import, so the workflow's
// `node .github/scripts/clamav-to-sarif.mjs` keeps working with no build step.
//
// clamdscan has no machine-readable output, so we parse its text log: each
// detection is a `PATH: SIGNATURE FOUND` line. A virus-signature match is
// unambiguously critical, so every finding maps to level=error /
// security-severity=10.0 (surfaces at the top of the Security tab). A clean
// scan yields a valid empty-results SARIF (uploads fine, shows "no findings").

/** A single SARIF result (the subset this converter emits). */
export interface SarifResult {
  ruleId: string;
  level: 'error';
  message: { text: string };
  properties: { 'security-severity': string };
  locations: [{ physicalLocation: { artifactLocation: { uri: string } } }];
}

/** The SARIF 2.1.0 document shape this converter emits. */
export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: [
    {
      tool: { driver: { name: 'ClamAV'; rules: [] } };
      results: SarifResult[];
    },
  ];
}

// No leading `^` anchor: the pattern is `.exec`'d against one whole `line` and
// the greedy `(?<path>.+)` binds from position 0, so an anchored form would
// match identically — omitting it removes a redundant (equivalent-mutant) token
// rather than suppressing the mutator. The trailing `$` and the `.+` quantifiers
// ARE load-bearing (killed by the FOUND-at-end / path-message tests).
const FOUND_RE = /(?<path>.+): (?<sig>.+) FOUND$/;

export function toSarif(logText: string): SarifLog {
  const results: SarifResult[] = [];
  let inSummary = false;
  for (const raw of logText.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (line.includes('SCAN SUMMARY')) {
      inSummary = true; // everything after the banner is stats, not findings
      continue;
    }
    // Only the `inSummary` guard is load-bearing (everything after the SCAN
    // SUMMARY banner is stats, not findings — killed by the summary tests). The
    // former `line === ''` blank-line micro-opt was removed: a blank line can
    // never match FOUND_RE, so it changed nothing but generated an equivalent
    // mutant. Dropping it kills that mutant by construction.
    if (inSummary) continue;
    const m = FOUND_RE.exec(line);
    if (!m || !m.groups) continue;
    const uri = m.groups.path.replace(/^\.\//, '');
    results.push({
      ruleId: m.groups.sig,
      level: 'error',
      message: { text: `${m.groups.sig} detected in ${m.groups.path}` },
      properties: { 'security-severity': '10.0' },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    });
  }
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ClamAV', rules: [] } },
        results,
      },
    ],
  };
}
