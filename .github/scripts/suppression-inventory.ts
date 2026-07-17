// Suppression-token inventory — classify in-code suppression tokens found in
// the tree into three buckets (#202, the in-code-comment arm of the
// suppression-governance program #167).
//
// LOGIC MODULE (jest-visible, gate-eligible): this holds the pure catalog +
// classifier + report/SARIF builders so they flow through the repo's 100%
// coverage gate (#124), Stryker mutation (#122), and the fuzz-regression tier.
// The runnable CLI is the thin `suppression-inventory.mjs` shim next to it,
// which shells out to ripgrep to find candidate lines and feeds each to
// `scanLine` here — Node 24 strips the `.ts` on import, so the workflow's
// `node .github/scripts/suppression-inventory.mjs` runs with no build step.
//
// Why three buckets, not pass/fail (per #202's classification note + binding
// policy comment):
//   - raw        — an UNregistered in-code suppression (a bare disable comment
//                  with no reason). This is the debt the sweep exists to kill.
//                  Per the maintainer's binding decision, `// Stryker disable`
//                  is categorically `raw` (an equivalent mutant is removable by
//                  construction), NOT a registered exception.
//   - registered — a reason-bearing, revisit-tracked exception (checkov CFN
//                  Metadata skip WITH a comment, cdk-nag `.acknowledge({reason})`,
//                  the gitleaks allowlist, dependency-review's license allow-list,
//                  and the `.vex/` OpenVEX records). These are honest, tracked
//                  risk acceptances — candidates to MIGRATE into the #167 registry,
//                  never to delete. Flagging them as violations would create
//                  pressure to delete legitimately-accepted-risk records.
//   - wiring      — the token appears in tooling config that POINTS AT the
//                  registered records (the VEX feed config), or in documentation
//                  that DEFINES/discusses the rule. Not a suppression → ignore.
//
// REPORT-ONLY: this inventory never hard-fails CI (it mirrors trivy-fs /
// sonarqube's report-first posture). The documented ratchet to hard-fail on the
// `raw` bucket lands once the reason-bearing suppressions are triaged into #167.

/** The three classification buckets. */
export type Bucket = 'raw' | 'registered' | 'wiring';

/**
 * One suppression token in the catalog. `pattern` is a regex string used
 * VERBATIM by both ripgrep (the fast pre-filter in the shim) and the JS
 * `RegExp` here (the authoritative matcher), so keep it compatible with both.
 */
export interface TokenDef {
  /** Stable catalog id (also the SARIF ruleId), e.g. `semgrep-nosemgrep`. */
  id: string;
  /** Human tool name for the report, e.g. `Semgrep`. */
  tool: string;
  /** Regex (string) matched against a single line. */
  pattern: string;
  /**
   * `comment` = a suppression that lives inside a source comment (the disable
   * IS the comment: `nosemgrep`, `eslint-disable`, `@ts-ignore`, `// Stryker
   * disable`, …). Being in a comment does NOT exempt it — that is the point.
   * `config` = a CLI flag / config key / env var (`--exclude-rule`,
   * `GRYPE_VEX_DOCUMENTS`, …) that is only an active suppression when NOT itself
   * commented out.
   */
  kind: 'comment' | 'config';
  /** Match case-insensitively (e.g. SonarQube `//NOSONAR`). */
  caseInsensitive?: boolean;
  /**
   * This config token IS a reason-bearing, revisit-tracked exception (checkov
   * Metadata skip, cdk-nag acknowledge, gitleaks allowlist, dep-review license
   * allow). Classifies as `registered` (→ #167), never `raw`.
   */
  registered?: boolean;
  /**
   * This config token is VEX/feed WIRING that points at the `.vex/` records
   * (trivy `vulnerability.vex`, `GRYPE_VEX_DOCUMENTS`). Classifies as `wiring`.
   */
  vexFeed?: boolean;
  /** Short note for the report (what the token is / where it's expected). */
  note: string;
}

// The catalog. Section A = tools WIRED into this repo (priority patterns);
// section B = common tools not currently in the tree, kept so the sweep is
// future-proof (they report 0 until a language/tool is added). Sourced from the
// research-verified master catalog in #202 — do not invent tokens.
export const TOKENS: readonly TokenDef[] = [
  // ── A. wired into this repo ──────────────────────────────────────────────
  {
    id: 'semgrep-nosemgrep',
    tool: 'Semgrep',
    pattern: 'nosemgrep',
    kind: 'comment',
    note: 'inline semgrep suppression',
  },
  {
    id: 'semgrep-exclude-rule',
    tool: 'Semgrep',
    pattern: '--exclude-rule',
    kind: 'config',
    note: 'CLI rule drop (#163/#79 burn-down target)',
  },
  {
    id: 'checkov-inline-skip',
    tool: 'Checkov',
    pattern: 'checkov:skip=',
    kind: 'comment',
    note: 'inline checkov skip',
  },
  {
    id: 'checkov-metadata-skip',
    tool: 'Checkov',
    pattern: 'addMetadata\\((?:\'|")checkov(?:\'|")',
    kind: 'config',
    registered: true,
    note: 'CFN Metadata checkov skip (carries a mandatory comment) → #167',
  },
  {
    id: 'cdknag-acknowledge',
    tool: 'cdk-nag',
    pattern: '\\.acknowledge\\(',
    kind: 'config',
    registered: true,
    note: 'cdk-nag suppression with reason → #167',
  },
  {
    id: 'eslint-disable',
    tool: 'ESLint',
    pattern: 'eslint-disable',
    kind: 'comment',
    note: 'eslint-disable / -line / -next-line / block',
  },
  {
    id: 'prettier-ignore',
    tool: 'Prettier',
    pattern: 'prettier-ignore',
    kind: 'comment',
    note: 'prettier formatting suppression',
  },
  {
    id: 'markdownlint-disable',
    tool: 'markdownlint',
    pattern: 'markdownlint-disable',
    kind: 'comment',
    note: 'markdownlint disable / -line / -next-line / -file',
  },
  {
    id: 'ts-ignore',
    tool: 'TypeScript',
    pattern: '@ts-ignore',
    kind: 'comment',
    note: 'TypeScript error suppression (next line)',
  },
  {
    id: 'ts-expect-error',
    tool: 'TypeScript',
    pattern: '@ts-expect-error',
    kind: 'comment',
    note: 'TypeScript expected-error suppression',
  },
  {
    id: 'ts-nocheck',
    tool: 'TypeScript',
    pattern: '@ts-nocheck',
    kind: 'comment',
    note: 'TypeScript whole-file check suppression',
  },
  {
    id: 'stryker-disable',
    tool: 'Stryker',
    pattern: 'Stryker\\s+(disable|restore)',
    kind: 'comment',
    note: 'mutation suppression — binding policy: always `raw` (#205/#217)',
  },
  {
    id: 'istanbul-ignore',
    tool: 'Istanbul/nyc',
    pattern: 'istanbul\\s+ignore',
    kind: 'comment',
    note: 'coverage suppression',
  },
  {
    id: 'c8-ignore',
    tool: 'c8',
    pattern: 'c8\\s+ignore',
    kind: 'comment',
    note: 'coverage suppression',
  },
  {
    id: 'gitleaks-allow-inline',
    tool: 'Gitleaks',
    pattern: 'gitleaks:allow',
    kind: 'comment',
    note: 'inline secret allow',
  },
  {
    id: 'gitleaks-allowlist',
    tool: 'Gitleaks',
    pattern: '\\[\\[allowlists\\]\\]',
    kind: 'config',
    registered: true,
    note: 'gitleaks allowlist (reason-bearing, regex-scoped) → #167',
  },
  {
    id: 'grype-vex-documents',
    tool: 'Grype',
    pattern: 'GRYPE_VEX_DOCUMENTS',
    kind: 'config',
    vexFeed: true,
    note: 'VEX feed env — points at .vex/ records',
  },
  {
    id: 'trivy-vex',
    tool: 'Trivy',
    pattern: '^\\s*vex:\\s*$',
    kind: 'config',
    vexFeed: true,
    note: 'trivy.yaml VEX feed key — points at .vex/ records',
  },
  {
    id: 'depreview-allow-licenses',
    tool: 'dependency-review',
    pattern: 'allow-dependencies-licenses',
    kind: 'config',
    registered: true,
    note: 'license allow-list (LGPL SonarSource exception, #161) → #167',
  },
  {
    id: 'shellcheck-disable',
    tool: 'shellcheck',
    pattern: 'shellcheck\\s+disable',
    kind: 'comment',
    note: 'shellcheck directive suppression',
  },
  {
    id: 'zizmor-ignore',
    tool: 'zizmor',
    pattern: 'zizmor:\\s*ignore',
    kind: 'comment',
    note: 'workflow-audit suppression',
  },
  {
    id: 'codeql-suppress',
    tool: 'CodeQL',
    pattern: '//\\s*codeql\\[',
    kind: 'comment',
    note: 'CodeQL alert-suppression comment',
  },
  // ── B. common tools not currently wired (future-proofing; report 0) ───────
  {
    id: 'nosec',
    tool: 'Bandit',
    pattern: '#\\s*nosec',
    kind: 'comment',
    note: 'python security suppression',
  },
  {
    id: 'noqa',
    tool: 'ruff/flake8',
    pattern: '#\\s*noqa',
    kind: 'comment',
    note: 'python lint suppression',
  },
  {
    id: 'type-ignore',
    tool: 'mypy',
    pattern: '#\\s*type:\\s*ignore',
    kind: 'comment',
    note: 'python type suppression',
  },
  {
    id: 'pylint-disable',
    tool: 'pylint',
    pattern: '#\\s*pylint:\\s*disable',
    kind: 'comment',
    note: 'python lint suppression',
  },
  {
    id: 'nolint',
    tool: 'golangci-lint',
    pattern: '//nolint',
    kind: 'comment',
    note: 'go lint suppression',
  },
  {
    id: 'nosonar',
    tool: 'SonarQube',
    pattern: 'NOSONAR',
    kind: 'comment',
    caseInsensitive: true,
    note: 'sonar inline suppression',
  },
  {
    id: 'hadolint-ignore',
    tool: 'Hadolint',
    pattern: 'hadolint\\s+ignore',
    kind: 'comment',
    note: 'dockerfile lint suppression',
  },
  {
    id: 'yamllint-disable',
    tool: 'yamllint',
    pattern: 'yamllint\\s+disable',
    kind: 'comment',
    note: 'yaml lint suppression',
  },
  {
    id: 'osv-ignored-vulns',
    tool: 'OSV-Scanner',
    pattern: '\\[\\[IgnoredVulns\\]\\]',
    kind: 'config',
    note: 'osv-scanner.toml per-ID ignore (unused; would be raw)',
  },
];

/** A single classified inventory hit. */
export interface Hit {
  path: string;
  line: number;
  text: string;
  tokenId: string;
  tool: string;
  bucket: Bucket;
  reason: string;
}

/** Input to the classifier: the location, the matched token, and its regex. */
export interface ClassifyInput {
  path: string;
  text: string;
  token: TokenDef;
  /** The token's regex, compiled ONCE from the hardcoded catalog by scanLine. */
  re: RegExp;
}

/** The classifier's verdict. */
export interface Classification {
  bucket: Bucket;
  reason: string;
}

// A documentation / definitional file: any Markdown file, or anything under
// `docs/`. These DEFINE or discuss the tokens (e.g. docs/SECURITY-TOOLING.md
// explains why we use `--exclude-rule` not `# nosemgrep`), so a token here is
// prose, never an active suppression.
export function isDocPath(path: string): boolean {
  return path.startsWith('docs/') || /\.md$/.test(path);
}

// The inventory tooling's own files (this module, its shim, and its test) name
// every token in the catalog as data — a self-reference, not a suppression.
export function isSelfPath(path: string): boolean {
  return path.includes('suppression-inventory');
}

// A `.vex/` OpenVEX record: a per-CVE, reason-bearing, revisit-tracked risk
// acceptance (the honest model #167 generalizes). Registered, never raw.
export function isVexRecord(path: string): boolean {
  return /^\.vex\/.*\.openvex\.json$/.test(path);
}

// Is the token wrapped in backticks (inline-code quoting)? A real directive is
// never backtick-quoted — `` `# nosemgrep` `` in a sentence is someone QUOTING
// the token as an example (e.g. security.yml's comment "we EXCLUDE the rule
// rather than `# nosemgrep`"), i.e. discussion, not an active suppression.
// Split on backticks: the odd-indexed segments are inside a backtick pair, so a
// token match there is a quoted mention. (An unbalanced/odd number of backticks
// leaves the trailing segment "open"; treat it as NOT quoted — fail toward
// flagging rather than silently exempting.) `re` is the token's regex compiled
// ONCE by the caller from the hardcoded catalog (not a per-call
// parameter-built RegExp — avoids the dynamic-pattern ReDoS shape).
export function isBacktickQuoted(text: string, re: RegExp): boolean {
  const segments = text.split('`');
  // segment[i] sits INSIDE a closed backtick pair when i is odd AND a closing
  // backtick follows it — i.e. i <= segments.length - 2. The final segment
  // (index segments.length - 1) is always "open" (after the last backtick), so
  // an odd number of backticks leaves its token UNquoted → still flagged.
  const lastClosed = segments.length - 2;
  for (let i = 1; i <= lastClosed; i += 2) {
    if (re.test(segments[i])) return true;
  }
  return false;
}

// Heuristic: does the matched token sit inside a source comment? Used only for
// `config`-kind tokens, where a commented mention is discussion (wiring) but an
// active line is a real suppression. Covers the comment leaders across the
// repo's languages: `#` (YAML/shell/TOML), `//` and `/* … *` (JS/TS), and
// `<!-- … -->` (Markdown/HTML).
export function isCommentLine(text: string): boolean {
  const trimmed = text.replace(/^\s+/, '');
  return (
    trimmed.startsWith('#') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('<!--')
  );
}

/**
 * Classify one token hit into raw / registered / wiring. Ordered rules, first
 * match wins — see the module header for the rationale of each bucket.
 */
export function classifyHit({
  path,
  text,
  token,
  re,
}: ClassifyInput): Classification {
  // 1. Documentation / definitional prose — always wiring.
  if (isDocPath(path)) {
    return {
      bucket: 'wiring',
      reason: 'documentation / tool-defining prose, not a suppression',
    };
  }
  // 2. The inventory tooling naming the catalog — self-reference.
  if (isSelfPath(path)) {
    return {
      bucket: 'wiring',
      reason: 'suppression-inventory tooling self-reference (token catalog)',
    };
  }
  // 3. A backtick-quoted mention is discussion (e.g. a workflow comment that
  //    QUOTES `# nosemgrep` to explain why it's NOT used), not an active
  //    directive.
  if (isBacktickQuoted(text, re)) {
    return {
      bucket: 'wiring',
      reason: 'backtick-quoted token mention (discussion), not active',
    };
  }
  // 4. `.vex/` OpenVEX records — registered, honest per-CVE risk acceptance.
  if (isVexRecord(path)) {
    return {
      bucket: 'registered',
      reason: 'OpenVEX per-CVE record (reason + revisit path) — migrate → #167',
    };
  }
  // 5. A `config` directive merely NAMED in a comment is discussion, not an
  //    active suppression — checked BEFORE registered/vexFeed so a comment that
  //    mentions e.g. `allow-dependencies-licenses` classifies as wiring, not as
  //    a live registered exception. (A `comment`-kind token IS the suppression,
  //    so this exemption deliberately does not apply to it — only to `config`.)
  if (token.kind === 'config' && isCommentLine(text)) {
    return {
      bucket: 'wiring',
      reason: 'directive named in a comment (discussion), not active',
    };
  }
  // 6. Reason-bearing, revisit-tracked config exceptions (the ACTIVE directive).
  if (token.registered) {
    return {
      bucket: 'registered',
      reason: `${token.note} (reason-bearing) — migrate → #167`,
    };
  }
  // 7. VEX/feed wiring that points at the registered records.
  if (token.vexFeed) {
    return {
      bucket: 'wiring',
      reason: 'VEX feed config — points at .vex/ records, not a suppression',
    };
  }
  // 8. Everything else — an unregistered in-code suppression: the #202 target.
  return {
    bucket: 'raw',
    reason: 'unregistered in-code suppression — the #202 target',
  };
}

/**
 * Scan one line for every catalog token, returning a classified `Hit` per
 * match. The shim calls this for each ripgrep candidate line; ripgrep is the
 * fast file walker + pre-filter, this is the authoritative matcher/classifier.
 */
export function scanLine(path: string, line: number, text: string): Hit[] {
  const hits: Hit[] = [];
  for (const token of TOKENS) {
    const re = new RegExp(token.pattern, token.caseInsensitive ? 'i' : '');
    if (!re.test(text)) continue;
    const { bucket, reason } = classifyHit({ path, text, token, re });
    hits.push({
      path,
      line,
      text: text.trim(),
      tokenId: token.id,
      tool: token.tool,
      bucket,
      reason,
    });
  }
  return hits;
}

/** Aggregated inventory report. */
export interface Report {
  total: number;
  counts: Record<Bucket, number>;
  raw: Hit[];
  registered: Hit[];
  wiring: Hit[];
  /** Count of `.vex/*.openvex.json` records (registered by construction). */
  vexRecords: number;
}

/**
 * Aggregate raw hits into a bucketed report. `vexRecords` is passed in from the
 * shim (a filesystem count of `.vex/*.openvex.json`) because those records hold
 * no catalog token in their JSON — they are registered exceptions by existence,
 * surfaced here so the report reflects the full registered posture.
 */
export function buildReport(hits: Hit[], vexRecords: number): Report {
  const raw = hits.filter((h) => h.bucket === 'raw');
  const registered = hits.filter((h) => h.bucket === 'registered');
  const wiring = hits.filter((h) => h.bucket === 'wiring');
  return {
    total: hits.length,
    counts: {
      raw: raw.length,
      registered: registered.length,
      wiring: wiring.length,
    },
    raw,
    registered,
    wiring,
    vexRecords,
  };
}

/** A single SARIF result (the subset this converter emits). */
export interface SarifResult {
  ruleId: string;
  level: 'warning';
  message: { text: string };
  properties: { 'security-severity': string };
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: string };
        region: { startLine: number };
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
      tool: { driver: { name: 'suppression-inventory'; rules: [] } };
      results: SarifResult[];
    },
  ];
}

/**
 * SARIF for the `raw` bucket only (the violations). Report-only, so every
 * result is `level: warning` / security-severity 4.0 — it surfaces on the
 * Security tab without gating. A clean tree yields a valid empty-results SARIF.
 */
export function toSarif(rawHits: Hit[]): SarifLog {
  const results: SarifResult[] = rawHits.map((h) => ({
    ruleId: h.tokenId,
    level: 'warning',
    message: {
      text: `Unregistered ${h.tool} suppression (${h.tokenId}): ${h.text}`,
    },
    properties: { 'security-severity': '4.0' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: h.path },
          region: { startLine: h.line },
        },
      },
    ],
  }));
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'suppression-inventory', rules: [] } },
        results,
      },
    ],
  };
}

/** Render a human-readable text report (the CI job-log / artifact form). */
export function formatText(report: Report): string {
  const lines: string[] = [];
  lines.push('Suppression-token inventory (#202) — REPORT-ONLY');
  lines.push('='.repeat(52));
  lines.push(`raw (unregistered — target): ${report.counts.raw}`);
  lines.push(`registered (reason-bearing → #167): ${report.counts.registered}`);
  lines.push(`wiring (feed config / docs — ignore): ${report.counts.wiring}`);
  lines.push(`.vex/ OpenVEX records (registered): ${report.vexRecords}`);
  lines.push('');
  const section = (title: string, hits: Hit[]): void => {
    lines.push(`── ${title} (${hits.length}) ──`);
    for (const h of hits) {
      lines.push(`  ${h.path}:${h.line} [${h.tokenId}] ${h.reason}`);
    }
    lines.push('');
  };
  section('RAW', report.raw);
  section('REGISTERED', report.registered);
  section('WIRING', report.wiring);
  return lines.join('\n');
}
