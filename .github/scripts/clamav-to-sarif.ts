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

// Stryker disable next-line Regex: dropping the leading `^` anchor is
// EQUIVALENT — the pattern is `.exec`'d against one whole `line` and the
// greedy `(?<path>.+)` already binds from position 0, so anchored and
// un-anchored forms match identically. (This is a module-level/static regex;
// the `.+`→`.` and `$`-anchor mutants ARE observable and killed by tests.)
const FOUND_RE = /^(?<path>.+): (?<sig>.+) FOUND$/;

export function toSarif(logText: string): SarifLog {
  const results: SarifResult[] = [];
  let inSummary = false;
  for (const raw of logText.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (line.includes('SCAN SUMMARY')) {
      inSummary = true; // everything after the banner is stats, not findings
      continue;
    }
    // The `line === ''` guard is a micro-optimisation (skip blank lines before
    // the regex). Mutating it is EQUIVALENT: a blank line can never match
    // FOUND_RE (which requires `<path>: <sig> FOUND`), so skipping-or-not is
    // unobservable in the output. The `inSummary` guard, by contrast, IS
    // load-bearing and is killed by the SCAN-SUMMARY tests.
    // Stryker disable next-line ConditionalExpression,StringLiteral: blank-line skip is unobservable (see above) (#165)
    if (inSummary || line === '') continue;
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
