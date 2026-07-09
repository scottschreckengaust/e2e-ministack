#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// license-verdict.mjs and declare them inline rather than widening
// eslint.config.mjs.)
// Convert `clamdscan --verbose` log text into a SARIF 2.1.0 document.
// clamdscan has no machine-readable output, so we parse its text log: each
// detection is a `PATH: SIGNATURE FOUND` line. A virus-signature match is
// unambiguously critical, so every finding maps to level=error /
// security-severity=10.0 (surfaces at the top of the Security tab). A clean
// scan yields a valid empty-results SARIF (uploads fine, shows "no findings").
import { readFileSync, writeFileSync } from 'node:fs';

const FOUND_RE = /^(?<path>.+): (?<sig>.+) FOUND$/;

export function toSarif(logText) {
  const results = [];
  let inSummary = false;
  for (const raw of logText.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (line.includes('SCAN SUMMARY')) {
      inSummary = true; // everything after the banner is stats, not findings
      continue;
    }
    if (inSummary || line === '') continue;
    const m = FOUND_RE.exec(line);
    if (!m) continue;
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

// CLI: node clamav-to-sarif.mjs <infile> <outfile>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [, , infile, outfile] = process.argv;
  if (!infile || !outfile) {
    console.error('usage: clamav-to-sarif.mjs <infile> <outfile>');
    process.exit(2);
  }
  const text = readFileSync(infile, 'utf8');
  writeFileSync(outfile, JSON.stringify(toSarif(text), null, 2));
}
