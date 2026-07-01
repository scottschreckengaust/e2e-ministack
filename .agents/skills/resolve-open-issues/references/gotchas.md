# Gotchas (learned — don't relearn)

Skim before the first dispatch, **because** several of these read as real failures and will
otherwise cost a debugging detour. Each is a quirk of this repo/harness, not a bug in the work — and
each is a **repo/harness-specific** fact, not part of the portable pipeline (the ones below marked
general are the exceptions). On another repo these may not apply — verify against that repo's
runtime manager (e.g. its `mise.toml`/version-pin setup) and configured hooks instead of assuming
them, and re-derive the equivalents (see SKILL.md intro).

**Worker-side quirks** (the worker hits these directly; the operative fixes live in
`prompts/subagent-issue.md` § Environment quirks — the orchestrator only needs to recognize them in a
worker's report and not misread them as failures):

- **mise PATH in git-hook subprocesses** — `git commit` can fail "Executable `npm` not found" even
  when `pre-commit run` passed (the hook subprocess doesn't inherit the mise PATH). Not a real break.
- **semgrep PostToolUse hook** — prints `No SEMGREP_APP_TOKEN` on every Write/Edit; it fires _after_
  the write so the file IS saved. Auth-missing noise, not a finding.
- **Worktrees branch from `origin/main`**, not the current canonical-root branch — verify the base
  HEAD if a worker reports a surprising base.

**Orchestrator-side facts:**

- **`needs:` doesn't imply a fork guard.** A downstream job inherits dependency ordering, not the
  upstream job's `if:`. Guard the socket-mounting job directly.

- **The "max open PRs per user" setting has NO API.** The GitHub UI's
  `settings/interaction_limits` can show a number, but `gh api repos/{o}/{r}/interaction-limits`
  returns `{}` and `.../rulesets` returns `[]` (verified) — native interaction-limits are only the
  `existing_users`/`contributors_only`/`collaborators_only` access gate, carrying no count, and
  admins/writers bypass them anyway. So the open-PR cap is **not machine-readable**: pass it as
  `--max-in-flight` and never fetch or HTML-scrape it (scraping needs a browser session cookie, not
  the `gh` token). _(This one is a general GitHub truth, not repo-specific.)_

- **Paraphrasing the worker prompt drops the newest step.** If the orchestrator reconstructs
  `prompts/subagent-issue.md` from memory instead of reading the file and filling its
  `{{PLACEHOLDERS}}`, the most recently merged instruction is exactly what the paraphrase loses — a
  batch once ran without self-assigning (the then-new step) for precisely this reason, and nothing
  failed loudly. The defense is three-layered: dispatch by literal template-fill (SKILL.md §7), the
  worker self-verifies its assignment and reports `ASSIGNED:` (worker prompt), and the merge-closer
  asserts + repairs the issue assignee (`concurrency-and-merge.md` § merge-closer). Always re-read
  the template each batch so merged changes propagate.
