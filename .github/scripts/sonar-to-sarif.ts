// Convert a SonarQube `api/issues/search` response into a SARIF 2.1.0 document.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure mapping lives here so it
// flows through the repo's 100% coverage gate (#124), Stryker mutation (#122),
// and the fuzz-regression tier. The runnable CLI is the thin
// `sonar-to-sarif.mjs` shim, which imports `toSarif` from here (Node 24 strips
// the `.ts` on import — no build step), so the workflow call
// `node .github/scripts/sonar-to-sarif.mjs <in> <out>` is unchanged.
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

/** SARIF severity level this converter emits. */
export type SarifLevel = 'error' | 'warning' | 'note';

/** A SonarQube issue impact (newer analyses). */
export interface SonarImpact {
  softwareQuality?: string;
  severity?: string;
}

/** A SonarQube `textRange` (0-based offsets). */
export interface SonarTextRange {
  startLine?: number;
  endLine?: number;
  startOffset?: number;
  endOffset?: number;
}

/** A single issue from `api/issues/search`. */
export interface SonarIssue {
  rule?: string;
  severity?: string;
  impacts?: SonarImpact[];
  component?: string;
  line?: number;
  textRange?: SonarTextRange;
  message?: string;
}

/** A `components[]` entry mapping a Sonar component key to a repo path. */
export interface SonarComponent {
  key?: string;
  path?: string;
}

/** The parsed `api/issues/search` response (only the fields we read). */
export interface SonarResponse {
  // The live response carries paging fields (total/p/ps/paging) we don't use;
  // keep `total` typed so fixtures can mirror the real payload shape.
  total?: number;
  issues?: SonarIssue[];
  components?: SonarComponent[];
}

/** A SARIF region (1-based lines and columns). */
export interface SarifRegion {
  startLine: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

/** A SARIF result (the subset this converter emits). */
export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: string };
        region?: SarifRegion;
      };
    },
  ];
}

/** The SARIF 2.1.0 document shape this converter emits. */
export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: [
    {
      tool: { driver: { name: 'SonarQube'; rules: { id: string }[] } };
      results: SarifResult[];
    },
  ];
}

// Legacy severities: BLOCKER/CRITICAL -> error, MAJOR -> warning,
// MINOR/INFO -> note. Newer analyses may omit severity and carry impacts[]
// with HIGH/MEDIUM/LOW instead.
const LEGACY_LEVEL: Record<string, SarifLevel> = {
  BLOCKER: 'error',
  CRITICAL: 'error',
  MAJOR: 'warning',
  MINOR: 'note',
  INFO: 'note',
};
const IMPACT_LEVEL: Record<string, SarifLevel> = {
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
};
// SARIF level priority, worst first — the fixed spec order the worst-wins pick
// in `levelFor` searches. Module-level (not a throwaway local), so a mutant that
// reorders/empties it changes a real, observable pick and dies.
const SARIF_PRIORITY: readonly SarifLevel[] = ['error', 'warning', 'note'];

function levelFor(issue: SonarIssue): SarifLevel {
  if (issue.severity && LEGACY_LEVEL[issue.severity]) {
    return LEGACY_LEVEL[issue.severity];
  }
  // Worst-wins over the newer `impacts[]`, expressed as a priority FIND rather
  // than a mutable running-best + index comparison. Collect the levels present,
  // then return the first (highest-priority) one that appears — `error` beats
  // `warning` beats `note`. This carries no `<`/`<=` comparison and no throwaway
  // `ranked` array to mutate: `SARIF_PRIORITY` is the module-level severity
  // order the SARIF spec fixes, so every mutant here is observable. `impacts` is
  // No impact matches → `warning` (Sonar's neutral default). The `Array.isArray`
  // GUARDS the loop rather than substituting a `: []` fallback literal — so
  // there is no array literal to spawn an equivalent `ArrayDeclaration` mutant,
  // yet the guard's false branch stays observable (a non-iterable `impacts`
  // must yield `warning`, not throw). Each element's level is added DIRECTLY —
  // an unknown/missing severity maps to `undefined`, which `find` below never
  // queries, so no `if (lvl)` guard is needed (adding it would be an equivalent
  // mutant; `present` is typed to admit the `undefined` sentinel deliberately).
  const present = new Set<SarifLevel | undefined>();
  if (Array.isArray(issue.impacts)) {
    for (const im of issue.impacts) {
      present.add(im && im.severity ? IMPACT_LEVEL[im.severity] : undefined);
    }
  }
  return SARIF_PRIORITY.find((l) => present.has(l)) ?? 'warning';
}

function uriFor(
  component: string | undefined,
  pathByKey: Map<string, string | undefined>,
): string {
  if (!component) return 'unknown';
  if (pathByKey.has(component) && pathByKey.get(component)) {
    return pathByKey.get(component) as string;
  }
  // Fallback: component is "projectKey:relative/path" — strip up to the first
  // ':'. `slice(idx + 1)` handles the no-colon case with no branch: when
  // `indexOf` returns -1, `slice(0)` yields the whole string — identical to a
  // `: component` else-branch. Removing the ternary removes the redundant
  // (equivalent-mutant) conditional entirely; a leading-colon input still
  // strips correctly (idx 0 → slice(1)), pinned by test.
  return component.slice(component.indexOf(':') + 1);
}

function regionFor(issue: SonarIssue): SarifRegion | undefined {
  const tr = issue.textRange;
  if (tr && Number.isInteger(tr.startLine)) {
    const region: SarifRegion = { startLine: tr.startLine as number };
    if (Number.isInteger(tr.endLine)) region.endLine = tr.endLine;
    // Sonar offsets are 0-based; SARIF columns are 1-based.
    if (Number.isInteger(tr.startOffset))
      region.startColumn = (tr.startOffset as number) + 1;
    if (Number.isInteger(tr.endOffset))
      region.endColumn = (tr.endOffset as number) + 1;
    return region;
  }
  if (Number.isInteger(issue.line)) return { startLine: issue.line as number };
  return undefined;
}

export function toSarif(response: SonarResponse | null | undefined): SarifLog {
  const issues = Array.isArray(response?.issues) ? response.issues : [];
  // Build the component key -> path lookup. `Array.isArray` GUARDS the loop
  // (no `: []` fallback literal to spawn an equivalent ArrayDeclaration mutant;
  // the false branch — a non-array `components` yields an empty map — stays
  // observable). Only components with a REAL key are inserted: a key-less
  // component can never be matched by an `issue.component`, so skipping it is
  // the same as the old `c.key ?? ''` sentinel but without the unobservable
  // blank-key mutant. `uriFor` falls back to path-stripping when a key misses.
  const pathByKey = new Map<string, string | undefined>();
  if (Array.isArray(response?.components)) {
    for (const c of response.components) {
      if (c && c.key) pathByKey.set(c.key, c.path);
    }
  }

  const ruleIds = new Set<string>();
  const results: SarifResult[] = issues.map((issue) => {
    if (issue.rule) ruleIds.add(issue.rule);
    const region = regionFor(issue);
    const physicalLocation: {
      artifactLocation: { uri: string };
      region?: SarifRegion;
    } = {
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
