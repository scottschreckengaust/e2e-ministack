// Convert `npm audit --json` into a SARIF 2.1.0 document (issue #295), so npm
// audit becomes a FIRST-CLASS scanner: its findings reach the GitHub Security
// tab AND the Code Scanning Alerts API — the union ledger the VEX report (#189)
// reconciles against. Until now npm audit was the one vuln scanner that uploaded
// no SARIF (only a JSON artifact), so its findings were invisible to the
// Security tab and the VEX report. The npm-audit GATE decision still comes from
// `npm-audit-gate.ts`; this converter is purely the visibility/reporting surface.
//
// THE CRUX — ruleId carries the CVE when resolvable. npm audit keys advisories
// by package name and carries only a GHSA (in `via[].url`), no CVE. But every
// downstream consumer keys on CVE: `vex-to-sarif-suppressions.ts` does
// `extractCve(ruleId)` to dismiss covered alerts, and `alerts-findings.ts` /
// `vex-report.ts` reconcile by CVE. So the converter consults the `.vex/` ledger
// (which aliases GHSA↔CVE) and, when a record resolves the GHSA to a CVE, emits
// a ruleId `CVE-<id>-<pkg>` (the same CVE-token-plus-suffix shape grype uses,
// e.g. `CVE-2026-1-python`, which `idFromRule`/`extractCve` already parse). When
// nothing resolves it, the bare GHSA is the ruleId — still a valid alert, just
// not auto-reconciled to a `.vex/` record.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transform lives here so
// it flows through the 100% coverage gate (#124), Stryker mutation (#122), and
// the fuzz-regression tier. The runnable CLI is the thin `npm-audit-to-sarif.mjs`
// shim. TOTAL: malformed input yields a valid empty-results SARIF, never throws.

import { asArray, asRecord, normId, statementIds } from './vex-ledger.ts';

// Identifier PREFIXES. The `.vex/` ids are already normalized (upper-case,
// trimmed) by the ledger's `statementIds`/`normId`, so a prefix test is exact
// and — unlike a `\d+`-style regex whose quantifier has an equivalent `\d`
// mutant under `.test()` — carries no redundant, unkillable tokens. A GHSA/CVE
// id is `<PREFIX>-…`; a prefix check is all we need to CLASSIFY a normalized id.
const CVE_PREFIX = 'CVE-';
const GHSA_PREFIX = 'GHSA-';
// A GHSA token to LIFT out of a free-form advisory URL (not yet normalized).
// Permissive alphabet — see npm-audit-gate.ts for why an over-tight class is a
// fragility for a security gate. Case-insensitive.
const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

/** Whether a normalized id is a CVE / GHSA (the ledger normalizes before this). */
function isCve(id: string): boolean {
  return id.startsWith(CVE_PREFIX);
}
function isGhsa(id: string): boolean {
  return id.startsWith(GHSA_PREFIX);
}

/** A single SARIF result (the subset this converter emits). */
export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
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
      tool: { driver: { name: 'npm-audit'; rules: [] } };
      results: SarifResult[];
    },
  ];
}

/** The canonical (upper-case) GHSA token in a string, or null. */
function ghsaIn(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const m = GHSA_RE.exec(value);
  return m === null ? null : m[0].toUpperCase();
}

/**
 * Build a GHSA→CVE map from the `.vex/` docs: for every statement, if its id set
 * contains both a GHSA and a CVE, map each GHSA to that CVE. This is what lets a
 * GHSA-only npm advisory be labelled with the CVE its `.vex/` record names.
 * Malformed docs contribute nothing; never throws.
 */
export function ghsaCveMap(docs: readonly unknown[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const rawDoc of asArray(docs)) {
    const doc = asRecord(rawDoc);
    if (doc === null) continue;
    for (const rawStmt of asArray(doc.statements)) {
      const ids = statementIds(rawStmt);
      const cve = ids.find(isCve);
      if (cve === undefined) continue;
      for (const id of ids) {
        if (isGhsa(id)) map.set(id, cve);
      }
    }
  }
  return map;
}

/**
 * The CVE a GHSA maps to in the ledger, or null. `value` is normalized (so a
 * lowercase GHSA in a record/URL matches the upper-case map keys) and must look
 * like a GHSA — a non-GHSA normalized token can't be a valid key, so it returns
 * null without a lookup. Non-strings normalize to null → null (totality).
 */
export function ghsaToCve(
  value: unknown,
  map: ReadonlyMap<string, string>,
): string | null {
  const id = normId(value);
  if (id === null || !isGhsa(id)) return null;
  return map.get(id) ?? null;
}

/**
 * Every GHSA one npm-audit advisory is known by, from its `via[].url` entries.
 * String `via` entries (package cross-refs) contribute nothing. Never throws.
 */
function advisoryGhsas(advisory: unknown): string[] {
  const out: string[] = [];
  const adv = asRecord(advisory);
  if (adv === null) return out;
  for (const rawVia of asArray(adv.via)) {
    const via = asRecord(rawVia);
    if (via === null) continue;
    const ghsa = ghsaIn(via.url);
    if (ghsa !== null) out.push(ghsa);
  }
  return out;
}

/**
 * The SARIF ruleId for an advisory. When any of its GHSAs resolves to a ledger
 * CVE, emit `CVE-<id>-<pkg>` (so `extractCve`/`idFromRule` reconcile it to the
 * `.vex/` record and the report shows it Accepted/Tracked). Else the first GHSA
 * (a valid, if unreconciled, alert id). Else — no GHSA at all — the package name
 * (npm audit's natural key), so the alert is still addressable.
 */
export function advisoryRuleId(
  pkg: string,
  advisory: unknown,
  map: ReadonlyMap<string, string>,
): string {
  const ghsas = advisoryGhsas(advisory);
  for (const ghsa of ghsas) {
    const cve = map.get(ghsa);
    if (cve !== undefined) return `${cve}-${pkg}`;
  }
  if (ghsas.length > 0) return ghsas[0];
  return pkg;
}

// npm severity → a representative GitHub `security-severity` score (the same
// NVD-band midpoints GitHub uses for its badge). npm has no numeric CVSS in the
// summary, so a per-band constant is the honest mapping. Unknown/absent → 0.0.
const SEVERITY_SCORE: Record<string, string> = {
  critical: '9.8',
  high: '8.1',
  moderate: '5.5',
  low: '2.0',
};

/** The `security-severity` score for an npm severity keyword; 0.0 if unknown. */
export function severityScore(severity: unknown): string {
  if (typeof severity !== 'string') return '0.0';
  return SEVERITY_SCORE[severity.toLowerCase()] ?? '0.0';
}

// npm severity → SARIF result level. critical/high are `error`, moderate/low are
// `warning`, anything else `note` — so the Security tab ranks them sensibly.
const SEVERITY_LEVEL: Record<string, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  moderate: 'warning',
  low: 'warning',
};

function severityLevel(severity: unknown): 'error' | 'warning' | 'note' {
  if (typeof severity !== 'string') return 'note';
  return SEVERITY_LEVEL[severity.toLowerCase()] ?? 'note';
}

/**
 * Convert `npm audit --json` into a SARIF 2.1.0 document. One result per
 * vulnerable package (npm audit's natural granularity), ruleId per
 * `advisoryRuleId`, level/severity per the npm severity, located at
 * `package-lock.json` (the file the advisory pertains to). `vexDocs` supplies
 * the GHSA→CVE map so ruleIds carry the reconcilable CVE. A clean/empty/
 * malformed audit yields a valid empty-results SARIF (uploads fine). TOTAL.
 */
export function toSarif(
  auditJson: unknown,
  vexDocs: readonly unknown[],
): SarifLog {
  const map = ghsaCveMap(asArray(vexDocs));
  const results: SarifResult[] = [];
  const doc = asRecord(auditJson);
  const vulns = doc === null ? null : asRecord(doc.vulnerabilities);
  if (vulns !== null) {
    for (const [pkg, rawAdv] of Object.entries(vulns)) {
      const adv = asRecord(rawAdv);
      const severity = adv === null ? undefined : adv.severity;
      const ghsas = advisoryGhsas(rawAdv);
      const ghsaText = ghsas.length > 0 ? ` (${ghsas.join(', ')})` : '';
      results.push({
        ruleId: advisoryRuleId(pkg, rawAdv, map),
        level: severityLevel(severity),
        message: {
          text: `npm audit: ${String(severity)} severity advisory in ${pkg}${ghsaText}`,
        },
        properties: { 'security-severity': severityScore(severity) },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'package-lock.json' },
            },
          },
        ],
      });
    }
  }
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'npm-audit', rules: [] } },
        results,
      },
    ],
  };
}
