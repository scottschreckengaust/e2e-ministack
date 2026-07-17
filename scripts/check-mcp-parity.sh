#!/usr/bin/env bash
# Fail if a per-agent MCP config drifts from the canonical Claude .mcp.json on
# shared server shape: names, threat-composer pin, github url/type/headers.
# Interpolation syntax is allowed to differ (${VAR:-} vs ${env:VAR}), and the
# server-container key differs per agent (VS Code uses `servers`; everyone else
# `mcpServers`). Only agent files that EXIST are checked — missing optional
# targets are skipped, so this gate never obliges a config file to be created.
#
# Canonical source   : .mcp.json            (Claude Code, `.mcpServers`)
# Always checked      : .cursor/mcp.json     (Cursor,      `.mcpServers`)
# Checked if present  : .vscode/mcp.json     (VS Code,     `.servers`)
#                       .gemini/settings.json (Gemini CLI, `.mcpServers`)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE="${ROOT}/.mcp.json"
# jq path to the server map in the canonical file.
CLAUDE_ROOT=".mcpServers"

if ! command -v jq >/dev/null 2>&1; then
  echo "check-mcp-parity: jq is required" >&2
  exit 1
fi

if [[ ! -f "$CLAUDE" ]]; then
  echo "check-mcp-parity: missing canonical ${CLAUDE}" >&2
  exit 1
fi
jq empty "$CLAUDE"

# check_agent <file> <server-container-jq-path> <label>
# Compare one agent config against the canonical Claude .mcp.json. <path> is the
# jq path to the server map in the AGENT file (".servers" for VS Code, else
# ".mcpServers"); the canonical side always reads from CLAUDE_ROOT.
check_agent() {
  local agent="$1" root="$2" label="$3"
  local c r

  jq empty "$agent"

  # Same server names.
  local claude_names agent_names
  claude_names="$(jq -r "${CLAUDE_ROOT} | keys | sort | join(\",\")" "$CLAUDE")"
  agent_names="$(jq -r "${root} | keys | sort | join(\",\")" "$agent")"
  if [[ "$claude_names" != "$agent_names" ]]; then
    echo "check-mcp-parity: ${label}: server name mismatch" >&2
    echo "  Claude: ${claude_names}" >&2
    echo "  ${label}: ${agent_names}" >&2
    return 1
  fi

  # threat-composer-ai: same command + pinned args (env blocks may differ).
  local field
  for field in command args; do
    c="$(jq -c "${CLAUDE_ROOT}[\"threat-composer-ai\"].${field}" "$CLAUDE")"
    r="$(jq -c "${root}[\"threat-composer-ai\"].${field}" "$agent")"
    if [[ "$c" != "$r" ]]; then
      echo "check-mcp-parity: ${label}: threat-composer-ai.${field} mismatch" >&2
      echo "  Claude: ${c}" >&2
      echo "  ${label}: ${r}" >&2
      return 1
    fi
  done

  # github: same url.
  c="$(jq -r "${CLAUDE_ROOT}.github.url" "$CLAUDE")"
  r="$(jq -r "${root}.github.url" "$agent")"
  if [[ "$c" != "$r" ]]; then
    echo "check-mcp-parity: ${label}: github.url mismatch (${c} vs ${r})" >&2
    return 1
  fi

  # github: same type.
  c="$(jq -r "${CLAUDE_ROOT}.github.type // \"\"" "$CLAUDE")"
  r="$(jq -r "${root}.github.type // \"\"" "$agent")"
  if [[ "$c" != "$r" ]]; then
    echo "check-mcp-parity: ${label}: github.type mismatch (${c} vs ${r})" >&2
    return 1
  fi

  # github: same header keys.
  c="$(jq -r "${CLAUDE_ROOT}.github.headers | keys | sort | join(\",\")" "$CLAUDE")"
  r="$(jq -r "${root}.github.headers | keys | sort | join(\",\")" "$agent")"
  if [[ "$c" != "$r" ]]; then
    echo "check-mcp-parity: ${label}: github header keys mismatch" >&2
    echo "  Claude: ${c}" >&2
    echo "  ${label}: ${r}" >&2
    return 1
  fi

  # github: identical values for every header except Authorization.
  local key
  while IFS= read -r key; do
    [[ "$key" == "Authorization" ]] && continue
    c="$(jq -r --arg k "$key" "${CLAUDE_ROOT}.github.headers[\$k]" "$CLAUDE")"
    r="$(jq -r --arg k "$key" "${root}.github.headers[\$k]" "$agent")"
    if [[ "$c" != "$r" ]]; then
      echo "check-mcp-parity: ${label}: github header ${key} mismatch (${c} vs ${r})" >&2
      return 1
    fi
  done < <(jq -r "${CLAUDE_ROOT}.github.headers | keys[]" "$CLAUDE")

  # github Authorization must reference the token env var in both (syntax may differ).
  c="$(jq -r "${CLAUDE_ROOT}.github.headers.Authorization" "$CLAUDE")"
  r="$(jq -r "${root}.github.headers.Authorization" "$agent")"
  if [[ "$c" != *GITHUB_PERSONAL_ACCESS_TOKEN* ]] || [[ "$r" != *GITHUB_PERSONAL_ACCESS_TOKEN* ]]; then
    echo "check-mcp-parity: ${label}: github Authorization must reference GITHUB_PERSONAL_ACCESS_TOKEN" >&2
    return 1
  fi

  echo "check-mcp-parity: ${label} OK (${agent_names})"
}

# Cursor is a required target (same shape as Claude).
check_agent "${ROOT}/.cursor/mcp.json" ".mcpServers" "cursor"

# Optional targets — checked only when the file exists (this gate never creates
# a config). VS Code keys servers under `servers`; Gemini under `mcpServers`.
checked_optional=0
if [[ -f "${ROOT}/.vscode/mcp.json" ]]; then
  check_agent "${ROOT}/.vscode/mcp.json" ".servers" "vscode"
  checked_optional=1
fi
if [[ -f "${ROOT}/.gemini/settings.json" ]]; then
  check_agent "${ROOT}/.gemini/settings.json" ".mcpServers" "gemini"
  checked_optional=1
fi
if [[ "$checked_optional" -eq 0 ]]; then
  echo "check-mcp-parity: no optional agent configs present (.vscode/mcp.json, .gemini/settings.json) — skipped"
fi

echo "check-mcp-parity: OK"
