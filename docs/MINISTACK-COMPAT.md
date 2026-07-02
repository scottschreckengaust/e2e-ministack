# MiniStack compatibility — operator guide

Operator docs for the MiniStack compatibility harness (`services/`, epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117)). The
harness records, per service, whether MiniStack emulates it (Axis 1) and
whether a given IaC tool can actually provision + exercise it (Axis 2) — see
[`services/README.md`](../services/README.md) for the model and layout.

This file documents the **upstream-tracking** flow: how a red/partial verdict
gets connected to upstream reality (an `ministackorg/ministack` issue/PR) so
it's actionable, and how a maintainer optionally comments upstream —
**query is automated, comment/watch is human-gated** (sub-issue C,
[#137](https://github.com/scottschreckengaust/e2e-ministack/issues/137)).

## The tool: `scripts/ministack-upstream.mjs`

A standalone Node script (Node built-ins + the authenticated `gh` CLI only —
no npm deps, matching `.github/scripts/license-verdict.mjs` and the repo's
governance line on standalone scripts, #73/#80). Run it with the repo's pinned
Node on `PATH`:

```bash
# Automated: search upstream for a service and record the tracking ref.
node scripts/ministack-upstream.mjs query <service>

# Human-gated: draft a comment + PRINT the exact post command. Never posts.
node scripts/ministack-upstream.mjs draft-comment <service>
```

`<service>` is a registry key (e.g. `agentcore`, `dsql`, `rds-postgres`) — the
same `service` value used in
[`services/_registry/ministack-support.json`](../services/_registry/ministack-support.json).
The script validates it (`^[a-z0-9]+(?:-[a-z0-9]+)*$`) so it can never carry
shell metacharacters into a child process.

### `query <service>` — automated (read upstream, write our registry)

1. Searches `ministackorg/ministack` **issues and PRs** for the service via
   `gh search issues` / `gh search prs` (argv arrays through `execFileSync` — no
   shell). Reusing `gh` means the existing GitHub auth path is reused and no
   secrets are committed.
2. Picks the **best match**: a title hit is required; an OPEN item outranks a
   CLOSED one; ties break to the lowest (earliest/canonical) number. No match →
   `null`.
3. Writes the matched ref (`owner/repo#N`, or `null`) into that service's
   `ministackRef` field in `ministack-support.json`. The write stays
   schema-valid (`test/unit/registry.test.ts` gates the registry), and verdict
   flips are reviewed as PR diffs — never auto-committed by CI.

Reading a foreign repo is cheap and safe, so `query` is fully automated.

Known cases (validated live against the pinned upstream):

- `query agentcore` → `ministackorg/ministack#1021` (an open "New service
  emulator — Amazon Bedrock AgentCore" issue).
- `query dsql` → none (`null`) — Aurora DSQL has no upstream issue/PR yet.

### `draft-comment <service>` — human-gated (never posts)

Prints a structured comment body — the service, our current verdict, the
MiniStack image digest it was verified against, and the ask — followed by the
**exact copy-pasteable `gh issue comment` command** (when the service has an
upstream ref) or a one-click "new issue" URL (when it doesn't). It **never
posts, subscribes, or watches** anything on the upstream repo. A maintainer
reads the draft, edits if needed, and runs the printed command manually.

## Why comment/watch is human-gated — and how to expand it later

Commenting on a foreign OSS repo we don't control is an **outward-facing,
hard-to-reverse** action. This repo's governance defaults to
confirm-before-outward-facing, and the maintainer has explicitly chosen to
**start gated and expand write-automation later, once comfortable**. So the
write path is built gated but structured so enabling auto-post later is a
single, well-marked change.

**The single flip point** is one constant at the top of
`scripts/ministack-upstream.mjs`:

```js
export const AUTO_POST_UPSTREAM = false;
```

While it is `false` (the default and current state), `draft-comment` only
**prints** a command for a human to run — no code path posts to the upstream
repo. Flipping it to `true` is the deliberate, documented policy change that
would enable auto-posting; **do not flip it without maintainer sign-off**. The
never-auto-post property is locked by a unit test
(`test/unit/ministack-upstream.test.ts`): the suite asserts the constant
defaults to `false` and that `draft-comment` only prints (never claims to have
posted/subscribed).

Expanding write-automation later means: flip the gate, add the guarded
`gh issue comment` execution behind it, and extend the test to cover the
enabled path (and, ideally, a dry-run/confirmation step). Until then the harness
reads upstream freely and writes only to our own registry.

## Related

- Epic [#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117)
  (compat harness), sub-issue A / #135 (harness core), sub-issue B / #136
  (Lambda vertical).
- Wiring `query`/`draft-comment` into a CI workflow is deferred to #138.
- Automated posting/watching on the upstream repo is a **non-goal** here
  (deferred by maintainer decision) — this script builds the gated path only.
