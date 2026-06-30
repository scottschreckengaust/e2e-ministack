#!/usr/bin/env bash
# Fail if .mcp.json (Claude) and .cursor/mcp.json (Cursor) drift on shared
# server shape: names, threat-composer pin, github url/headers. Interpolation
# syntax is allowed to differ (${VAR:-} vs ${env:VAR}).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE="${ROOT}/.mcp.json"
CURSOR="${ROOT}/.cursor/mcp.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "check-mcp-parity: jq is required" >&2
  exit 1
fi

for f in "$CLAUDE" "$CURSOR"; do
  if [[ ! -f "$f" ]]; then
    echo "check-mcp-parity: missing ${f}" >&2
    exit 1
  fi
  jq empty "$f"
done

claude_names="$(jq -r '.mcpServers | keys | sort | join(",")' "$CLAUDE")"
cursor_names="$(jq -r '.mcpServers | keys | sort | join(",")' "$CURSOR")"
if [[ "$claude_names" != "$cursor_names" ]]; then
  echo "check-mcp-parity: server name mismatch" >&2
  echo "  Claude: ${claude_names}" >&2
  echo "  Cursor: ${cursor_names}" >&2
  exit 1
fi

# threat-composer-ai: same command + pinned args (env blocks may differ)
for field in command args; do
  c="$(jq -c --arg f "$field" '.mcpServers["threat-composer-ai"][$f]' "$CLAUDE")"
  r="$(jq -c --arg f "$field" '.mcpServers["threat-composer-ai"][$f]' "$CURSOR")"
  if [[ "$c" != "$r" ]]; then
    echo "check-mcp-parity: threat-composer-ai.${field} mismatch" >&2
    echo "  Claude: ${c}" >&2
    echo "  Cursor: ${r}" >&2
    exit 1
  fi
done

# github: same url + non-Authorization headers
c_url="$(jq -r '.mcpServers.github.url' "$CLAUDE")"
r_url="$(jq -r '.mcpServers.github.url' "$CURSOR")"
if [[ "$c_url" != "$r_url" ]]; then
  echo "check-mcp-parity: github.url mismatch (${c_url} vs ${r_url})" >&2
  exit 1
fi

c_type="$(jq -r '.mcpServers.github.type // ""' "$CLAUDE")"
r_type="$(jq -r '.mcpServers.github.type // ""' "$CURSOR")"
if [[ "$c_type" != "$r_type" ]]; then
  echo "check-mcp-parity: github.type mismatch (${c_type} vs ${r_type})" >&2
  exit 1
fi

header_keys="$(jq -r '.mcpServers.github.headers | keys | sort | join(",")' "$CLAUDE")"
cursor_header_keys="$(jq -r '.mcpServers.github.headers | keys | sort | join(",")' "$CURSOR")"
if [[ "$header_keys" != "$cursor_header_keys" ]]; then
  echo "check-mcp-parity: github header keys mismatch" >&2
  exit 1
fi

while IFS= read -r key; do
  [[ "$key" == "Authorization" ]] && continue
  c="$(jq -r --arg k "$key" '.mcpServers.github.headers[$k]' "$CLAUDE")"
  r="$(jq -r --arg k "$key" '.mcpServers.github.headers[$k]' "$CURSOR")"
  if [[ "$c" != "$r" ]]; then
    echo "check-mcp-parity: github header ${key} mismatch (${c} vs ${r})" >&2
    exit 1
  fi
done < <(jq -r '.mcpServers.github.headers | keys[]' "$CLAUDE")

c_auth="$(jq -r '.mcpServers.github.headers.Authorization' "$CLAUDE")"
r_auth="$(jq -r '.mcpServers.github.headers.Authorization' "$CURSOR")"
if [[ "$c_auth" != *GITHUB_PERSONAL_ACCESS_TOKEN* ]] || [[ "$r_auth" != *GITHUB_PERSONAL_ACCESS_TOKEN* ]]; then
  echo "check-mcp-parity: github Authorization must reference GITHUB_PERSONAL_ACCESS_TOKEN" >&2
  exit 1
fi

echo "check-mcp-parity: OK (${claude_names})"
