#!/usr/bin/env node
/* global process, console */
// (The repo's flat eslint config declares no Node globals for .mjs — match
// license-verdict.mjs and declare them inline rather than widening
// eslint.config.mjs.)
// Convert a SonarQube `api/issues/search` response into a SARIF 2.1.0 document.
//
// We derive SARIF ourselves from the JSON the sonarqube job already fetches,
// rather than adopting okorach/sonar-tools: that exporter hard-requires
// `levenshtein` (GPL-2.0-or-later, strong copyleft), which is beyond the
// LGPL SonarQube exception the maintainer approved. This bespoke mapping adds
// zero dependencies and no copyleft. See docs/SECURITY-TOOLING.md.
//
// Mapping (issues/search response is long-stable):
//   issue.rule                        -> result.ruleId (+ unique tool.driver.rules[])
//   issue.severity / issue.impacts[]  -> result.level (error/warning/note)
//   issue.component (projectKey:path) -> artifactLocation.uri (resolved via
//                                        components[].path, else strip "key:")
//   issue.textRange / issue.line      -> region (SARIF 1-based columns)
//   issue.message                     -> result.message.text
import { readFileSync, writeFileSync } from 'node:fs';

// Legacy severities: BLOCKER/CRITICAL -> error, MAJOR -> warning,
// MINOR/INFO -> note. Newer analyses may omit severity and carry impacts[]
// with HIGH/MEDIUM/LOW instead.
const LEGACY_LEVEL = {
  BLOCKER: 'error',
  CRITICAL: 'error',
  MAJOR: 'warning',
  MINOR: 'note',
  INFO: 'note',
};
const IMPACT_LEVEL = { HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

function levelFor(issue) {
  if (issue.severity && LEGACY_LEVEL[issue.severity]) {
    return LEGACY_LEVEL[issue.severity];
  }
  const impacts = Array.isArray(issue.impacts) ? issue.impacts : [];
  const ranked = ['error', 'warning', 'note'];
  let best;
  for (const im of impacts) {
    const lvl = IMPACT_LEVEL[im.severity];
    if (
      lvl &&
      (best === undefined || ranked.indexOf(lvl) < ranked.indexOf(best))
    ) {
      best = lvl;
    }
  }
  return best ?? 'warning';
}

function uriFor(component, pathByKey) {
  if (!component) return 'unknown';
  if (pathByKey.has(component) && pathByKey.get(component)) {
    return pathByKey.get(component);
  }
  // Fallback: component is "projectKey:relative/path" — strip up to the first ':'.
  const idx = component.indexOf(':');
  return idx >= 0 ? component.slice(idx + 1) : component;
}

function regionFor(issue) {
  const tr = issue.textRange;
  if (tr && Number.isInteger(tr.startLine)) {
    const region = { startLine: tr.startLine };
    if (Number.isInteger(tr.endLine)) region.endLine = tr.endLine;
    // Sonar offsets are 0-based; SARIF columns are 1-based.
    if (Number.isInteger(tr.startOffset))
      region.startColumn = tr.startOffset + 1;
    if (Number.isInteger(tr.endOffset)) region.endColumn = tr.endOffset + 1;
    return region;
  }
  if (Number.isInteger(issue.line)) return { startLine: issue.line };
  return undefined;
}

export function toSarif(response) {
  const issues = Array.isArray(response?.issues) ? response.issues : [];
  const components = Array.isArray(response?.components)
    ? response.components
    : [];
  const pathByKey = new Map(components.map((c) => [c.key, c.path]));

  const ruleIds = new Set();
  const results = issues.map((issue) => {
    if (issue.rule) ruleIds.add(issue.rule);
    const region = regionFor(issue);
    const physicalLocation = {
      artifactLocation: { uri: uriFor(issue.component, pathByKey) },
    };
    if (region) physicalLocation.region = region;
    return {
      ruleId: issue.rule ?? 'unknown',
      level: levelFor(issue),
      message: { text: issue.message ?? issue.rule ?? 'SonarQube issue' },
      locations: [{ physicalLocation }],
    };
  });

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SonarQube',
            rules: [...ruleIds].map((id) => ({ id })),
          },
        },
        results,
      },
    ],
  };
}

// CLI: node sonar-to-sarif.mjs <issues.json> <out.sarif>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [, , infile, outfile] = process.argv;
  if (!infile || !outfile) {
    console.error('usage: sonar-to-sarif.mjs <issues.json> <out.sarif>');
    process.exit(2);
  }
  const response = JSON.parse(readFileSync(infile, 'utf8'));
  writeFileSync(outfile, JSON.stringify(toSarif(response), null, 2));
}
