# Threat Modeling

This project keeps a threat model as a version-controlled artifact,
[`threat-model.tc.json`](../threat-model.tc.json), authored with
[AWS **threat-composer**](https://github.com/awslabs/threat-composer).

The model is **design-time and human-maintained**. CI only checks that the file
parses and carries the expected sections (see the `threat-model` job in
[`.github/workflows/security.yml`](../.github/workflows/security.yml)); it does
**not** decide whether your threats are complete or correct — that's a human
judgment threat modeling can't automate.

## How to open and edit it

You don't need an AWS account, and your data stays local in every option below.

### Option 1 — Hosted web app (no install)

1. Open **<https://awslabs.github.io/threat-composer?mode=Full>** (a static SPA;
   data is stored in your browser only, nothing is uploaded).
2. Open the **workspace selector** (top-left) → **Import**.
3. Choose **Select file** and pick `threat-model.tc.json` from the repo root.
4. The left nav now shows **Application Info, Architecture, Dataflow,
   Assumptions, Threats, Mitigations**, and the assembled **Threat Model** report.

### Option 2 — VS Code (best for staying in the repo)

Install the **AWS Toolkit** extension
(`AmazonWebServices.aws-toolkit-vscode`). It registers a visual editor for
`.tc.json`, so opening `threat-model.tc.json` gives you the threat-composer UI
inline and saves straight to the file in git — no browser round-trip.

### Option 3 — Run the web app locally from source

Heavier; only if you want a fully offline instance. threat-composer is an AWS
PDK monorepo (there is **no** Docker image and no `npm start`):

```bash
git clone https://github.com/awslabs/threat-composer.git
cd threat-composer
npm install -g yarn @aws/pdk
pdk install --frozen-lockfile
pdk run dev          # serves at http://localhost:3000
```

## Authoring a threat (the threat grammar)

In **Threats → Add new threat**, threat-composer assembles a structured
sentence from these fields:

> A **[threat source]** **[prerequisites]** can **[threat action]**, which leads
> to **[threat impact]**, resulting in reduced **[impacted goal]** of
> **[impacted assets]**.

Forcing this structure is the point — it turns vague worries ("S3 could be
hacked") into testable statements you can link to a specific mitigation. An
unlinked threat is a visible gap.

After adding a threat, link it to a mitigation under **Mitigations** (or note
that none exists yet — that itself is a finding).

## Save your changes back to the repo

Browser/local edits are **not** in the repo until you export:

1. Workspace menu → **Export → Export current workspace**.
2. Save the file **over** `threat-model.tc.json` in the repo root.
3. Commit. CI re-validates it on push.

## What's intentionally NOT automated

threat-composer's only model *generator* is the experimental
`threat-composer-ai` CLI/MCP server, which requires a real **Amazon Bedrock**
account (LLM inference, billed per run; not emulated by MiniStack) and still
produces a *draft for human review*. So the loop here is deliberately
human-authored: **edit → export → commit → CI validates**.

For runtime posture checks that a template-time model can't provide (live IAM
trust, actual public buckets, account settings), see the
"Not used here" note in [`CLAUDE.md`](../CLAUDE.md) about ScoutSuite/Prowler —
relevant once a real AWS account exists.
