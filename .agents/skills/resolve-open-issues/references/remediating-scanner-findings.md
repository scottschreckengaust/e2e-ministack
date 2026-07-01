# Reference — reuse-over-bespoke & remediating a scanner finding

Load this when a subagent's own code trips a SAST/code-scanning gate (Semgrep, CodeQL, …), or
whenever a fix touches adversarially-exposed code (parsing, path/URL handling, auth, crypto,
escaping, deserialization). It expands the two rules stated in `prompts/subagent-issue.md` and
points at the **externally-verifiable, time-tested** material the repo already ships — so a worker
copies a proven pattern instead of inventing one.

> **Single source of truth is the repo doc, not this file.** The ordered procedure and the license
> coupling live in [`docs/SECURITY-TOOLING.md` § "Remediating a scanner finding"](../../../../docs/SECURITY-TOOLING.md).
> This reference is the skill-side pointer + a walk of the repo's worked example. If the two ever
> disagree, the repo doc wins (it is what the drift audit #76 checks).

## The core rule: don't reinvent time-tested code

The finding is rarely "write a clever guard." It is almost always **"reach for the vetted thing."**
Bespoke security code lacks the years of adversarial exercise a standard primitive or a
widely-used library has, so it is a liability by default. Order of preference:

1. **Platform / standard-library primitive** — e.g. Node `path.win32.basename` / `path.posix.basename`,
   the WHATWG `URL` parser, `crypto.timingSafeEqual`, a framework's built-in output encoder. These
   are the most-exercised code on the planet for their job.
2. **A widely-used, actively-maintained, heavily-exercised library** (or an authoritative reference
   implementation — OWASP / the language community's canonical snippet). **This is a dependency and
   therefore a tool-adoption governance decision** (see `prompts/subagent-issue.md` § Scope
   discipline): it must be license-acceptable (permissive; no AGPL/copyleft per the repo policy) and
   version/SHA-pinned like any other dep. If the only vetted option has an unacceptable license,
   **escalate — don't silently vendor it.**
3. **Bespoke — only when nothing vetted fits the sink's exact semantics.** Judge by _behavior_, not
   familiarity. Even then, build **on** vetted primitives, keep it minimal, and prove it (below).
   Record _why_ bespoke was necessary in a comment.

**External canon** (time-tested, externally verifiable — cite these, don't paraphrase from memory):

- OWASP — <https://owasp.org/www-community/attacks/Path_Traversal> and the wider OWASP attack/cheat
  catalogue for the vuln class you're fixing.
- CWE — e.g. [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (path traversal),
  [CWE-23](https://cwe.mitre.org/data/definitions/23.html) (relative path traversal).
- The language's own docs for the primitive you're using (e.g. Node `path` module).

## Worked example (the repo's own, CI-verified)

`fuzz/handler.regression.test.js` (merged in #132, exercised by the unit gate every PR) is the
repo's reference for the **narrow case where bespoke was justified** — and it shows the discipline:

- **Why bespoke here:** the sink reads a corpus file by name. A drop-in like `sanitize-filename`
  **mutates** (strips bad chars and returns a _different_ name), which for a read would silently open
  the **wrong** file — worse than failing. No vetted library matched "**reject** anything that isn't
  a single safe segment," so a minimal guard built on stdlib primitives was the right call. That
  reasoning is recorded in the function's doc comment — do the same when you go bespoke.
- **Built on vetted primitives, not hand-rolled parsing:** it validates with `path.win32.basename`
  **and** `path.posix.basename` (so the guard is correct on any host — `\` separates on Windows but
  not POSIX), and explicitly rejects `.`/`..`, a NUL byte (`\0`, null-byte truncation), and `:`
  (Windows drive / NTFS alternate-data-stream). It **rejects, never mutates**.
- **Proven against an authoritative adversarial corpus:** the `describe('sanitizeCorpusName —
path-traversal containment')` block asserts the guard **rejects** OWASP-derived payloads
  (`../../etc/passwd`, `..\\..\\x`, `C:\\Windows\\…`, `name:stream`, `secret.doc\0.pdf`, `/etc/passwd`,
  …) and **accepts** legitimate single-segment names (`crash-abc123`, `number-double`, `a.b_c-1`).
  Prove-don't-assert earned its keep: a first-cut guard let `a\b` through on POSIX, and the
  OWASP-derived case **caught it before merge**.
- **Scoped honestly:** the comments state it guards a _filesystem name_, so URL-percent-encoded
  forms (`%2e%2e%2f`, overlong-UTF-8 `%c0%af`) are explicitly out of scope — nothing URL-decodes the
  value before the read, so claiming to catch them would misrepresent the guard. Don't fake coverage
  of a layer that isn't in the path.

## Checklist before you push a security fix

- [ ] Reached for a vetted primitive/library **first**; if bespoke, recorded _why_ no vetted option
      fit and built on vetted primitives anyway.
- [ ] If a library was adopted: license-acceptable + pinned, or escalated (§ Scope discipline).
- [ ] Read the flagging rule's own sanitizer set (Semgrep `pattern-sanitizers` / CodeQL
      sources-sinks-sanitizers) — didn't guess what clears it.
- [ ] Reproduced the scanner locally at the repo's **pinned** version → **0 findings**.
- [ ] Executable adversarial tests from an **authoritative source** (OWASP/CWE): guard **rejects**
      attacks, **accepts** legit input; existing behavior still passes.
- [ ] Scoped honestly in code + tests; documented out-of-scope forms.
- [ ] No `nosemgrep`/dismissal unless genuinely unfixable **and** maintainer-signed-off on the PR.
