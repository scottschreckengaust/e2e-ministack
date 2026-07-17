// Pure logic for `mise run update:ministack` (#152, the ergonomics surface of
// the #78 pin-sync updater).
//
// LOGIC MODULE (jest-visible, gate-eligible): every PURE function of the digest
// fan-out lives here so it flows through the repo's 100% coverage gate (#124),
// Stryker mutation (#122), and the fuzz-regression tier. The runnable CLI is
// the `update-ministack.mjs` shim, which imports these + adds the thin,
// network/IO half that CANNOT be gated in-process:
//   - RESOLVE the current multi-arch OCI *index* digest of the MiniStack image
//     via `docker buildx imagetools inspect` (network + docker),
//   - READ/WRITE the pin-site files,
//   - run `.github/scripts/check-ministack-digest-drift.sh` to SELF-VERIFY.
// Node 24 imports the `.ts` natively (no build step), so
// `node scripts/update-ministack.mjs` is unchanged. Same split as
// `ministack-upstream.{ts,mjs}`.
//
// SINGLE SOURCE OF TRUTH: the canonical digest lives in
// `services/_registry/ministack-pin.json` (`.digest`). The fan-out rewrites the
// SAME set of pin sites the drift guard (#212) verifies — so after
// `update:ministack` runs, `check-ministack-digest-drift.sh` MUST pass.
// `provisioning.json`'s `lastVerifiedDigest` is deliberately EXCLUDED: it is a
// SEMANTIC record (a bump invalidates the compat catalog), so it is left to the
// compat re-verify flow rather than blindly rewritten (#152 proposal step 2).

/** The canonical MiniStack image reference the pin tracks. */
export const MINISTACK_IMAGE = 'ministackorg/ministack:full';

/**
 * The pin sites the fan-out rewrites — the SAME set the drift guard
 * (`.github/scripts/check-ministack-digest-drift.sh`) verifies:
 *   - the registry `.digest` field (canonical source),
 *   - the three workflows carrying `ministackorg/ministack:full@sha256:…`,
 *   - the two docs (AGENTS.md, README.md) that must stay in lockstep.
 * `services/_registry/provisioning.json` is intentionally NOT here (its
 * `lastVerifiedDigest` is semantic — see the module header). Paths are
 * repo-root-relative; the `.mjs` shim resolves them against the repo root.
 */
export const PIN_SITE_FILES: readonly string[] = [
  'services/_registry/ministack-pin.json',
  '.github/workflows/ci.yml',
  '.github/workflows/security.yml',
  '.github/workflows/ministack-compat.yml',
  'AGENTS.md',
  'README.md',
];

/**
 * A canonical OCI digest: `sha256:` + exactly 64 lowercase hex chars, anchored
 * so no surrounding decoration is accepted. This is the exact shape the drift
 * guard matches, so a digest that passes here is a legal pin the guard will
 * recognize. Used to fail closed if the resolver hands back garbage.
 */
export function isValidDigest(digest: unknown): boolean {
  return typeof digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(digest);
}

/** One pin-site file after substitution. */
export interface FanOutFile {
  path: string;
  content: string;
}

/** A single file's substituted contents plus the replacement count. */
export interface Substitution {
  content: string;
  replacements: number;
}

/** A substituted file plus how many pin occurrences were rewritten. */
export interface FanOutResult extends FanOutFile {
  replacements: number;
}

/**
 * Replace every LITERAL occurrence of the old digest with the new one in a
 * single file's contents, returning the new contents and the replacement
 * count. `split`/`join` on the literal string (not a RegExp) so a `.` in the
 * digest can never act as a metacharacter and a near-miss digest is never
 * rewritten. Only the full 64-hex pin matches — the truncated prose form
 * (`636c4ef5…`) is a different string and is left untouched.
 */
export function substituteDigest(
  content: string,
  oldDigest: string,
  newDigest: string,
): Substitution {
  const parts = content.split(oldDigest);
  const replacements = parts.length - 1;
  return { content: parts.join(newDigest), replacements };
}

/**
 * Fan the substitution across every pin-site file. Returns the rewritten files
 * (each with its own replacement count) and the grand total — the total is what
 * the caller checks to confirm the bump actually landed everywhere it should.
 */
export function fanOut(
  files: readonly FanOutFile[],
  oldDigest: string,
  newDigest: string,
): { results: FanOutResult[]; total: number } {
  const results = files.map((f) => {
    const { content, replacements } = substituteDigest(
      f.content,
      oldDigest,
      newDigest,
    );
    return { path: f.path, content, replacements };
  });
  const total = results.reduce((sum, r) => sum + r.replacements, 0);
  return { results, total };
}

/**
 * Human-readable summary of a fan-out: the old→new digests, a per-file
 * replacement count, and the totals. The caller PRINTS this. When old and new
 * are identical (a re-run against the CURRENT digest) it says so explicitly so
 * a no-op run reads as intentional rather than broken.
 */
export function formatReport(
  results: readonly FanOutResult[],
  oldDigest: string,
  newDigest: string,
): string {
  const total = results.reduce((sum, r) => sum + r.replacements, 0);
  const lines = [
    `MiniStack image: ${MINISTACK_IMAGE}`,
    `  old: ${oldDigest}`,
    `  new: ${newDigest}`,
  ];
  if (oldDigest === newDigest) {
    lines.push('  (no change — pin already current; fan-out is a no-op)');
  }
  lines.push('', `Pin sites (${results.length} files):`);
  for (const r of results) {
    lines.push(`  ${r.replacements}x  ${r.path}`);
  }
  lines.push('', `Total replacements: ${total} across ${results.length} files`);
  return lines.join('\n');
}
