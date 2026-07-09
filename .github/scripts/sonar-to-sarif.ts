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

function levelFor(issue: SonarIssue): SarifLevel {
  if (issue.severity && LEGACY_LEVEL[issue.severity]) {
    return LEGACY_LEVEL[issue.severity];
  }
  // Stryker disable next-line ArrayDeclaration: defensive fallback for a
  // non-array `impacts`; a bogus array element has no `.severity` so it is
  // skipped below → same result as `[]` (equivalent, #165).
  const impacts = Array.isArray(issue.impacts) ? issue.impacts : [];
  // Stryker disable next-line ArrayDeclaration,StringLiteral: mutating the
  // `ranked` array (empty it, or blank `'error'`) leaves worst-wins intact —
  // the first HIGH still becomes `best` and no lower impact displaces it via
  // the indexOf comparison (verified across all impact combos, equivalent #165).
  const ranked: SarifLevel[] = ['error', 'warning', 'note'];
  let best: SarifLevel | undefined;
  for (const im of impacts) {
    const lvl = im.severity ? IMPACT_LEVEL[im.severity] : undefined;
    // Stryker disable EqualityOperator: `<`→`<=` only re-assigns `best` to an
    // EQUAL-ranked level (the same value), so there is no observable change
    // (equivalent, verified across all impact combos, #165).
    if (
      lvl &&
      (best === undefined || ranked.indexOf(lvl) < ranked.indexOf(best))
    ) {
      best = lvl;
    }
    // Stryker restore EqualityOperator
  }
  return best ?? 'warning';
}

function uriFor(
  component: string | undefined,
  pathByKey: Map<string, string | undefined>,
): string {
  if (!component) return 'unknown';
  if (pathByKey.has(component) && pathByKey.get(component)) {
    return pathByKey.get(component) as string;
  }
  // Fallback: component is "projectKey:relative/path" — strip up to the first ':'.
  const idx = component.indexOf(':');
  // Stryker disable next-line ConditionalExpression: forcing this `true` calls
  // `slice(idx + 1)` when idx is -1 (no colon) → `slice(0)` === the whole
  // string === the `: component` else-branch, so it is EQUIVALENT. (The
  // `idx >= 0`→`idx > 0` mutant, which IS observable via a leading ':', is
  // killed by a test.) (#165)
  return idx >= 0 ? component.slice(idx + 1) : component;
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
  // Stryker disable ArrayDeclaration: the `: []` else-branch is a defensive
  // fallback for a non-array `components`; a bogus element resolves no lookup
  // key so it is inert → same result as `[]` (equivalent, #165). Block form
  // (not next-line) so prettier's multi-line reformat can't detach the comment.
  const components = Array.isArray(response?.components)
    ? response.components
    : [];
  // Stryker restore ArrayDeclaration
  const pathByKey = new Map<string, string | undefined>(
    // Stryker disable next-line StringLiteral: `c.key ?? ''`→a bogus string only
    // changes the map key for a KEY-LESS component; no real issue.component ever
    // equals that string, so the lookup never hits it (equivalent, #165).
    components.map((c) => [c.key ?? '', c.path]),
  );

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
