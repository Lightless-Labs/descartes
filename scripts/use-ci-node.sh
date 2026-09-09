#!/usr/bin/env bash
# Source this helper before changing directories in a macOS CI guest.
# The shared image owns the cache; this helper never downloads or modifies it.
# It is intentionally source-only so the same body works in Bash and zsh.

_descartes_ci_node_fail() {
  printf 'CI Node helper: %s\n' "$1" >&2
  return 1
}

_descartes_ci_node_use() {
  local node_version="v22.21.1"
  local node_cache_name="node-v22.21.1-darwin-arm64"
  local cache_parent cache_dir node_bin_dir node_binary observed_version

  if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    _descartes_ci_node_fail "requires Darwin arm64"
    return 1
  fi
  if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ] || [ ! -d "$HOME" ]; then
    _descartes_ci_node_fail "HOME must be an existing non-root user directory"
    return 1
  fi

  cache_parent="$HOME/.local"
  cache_dir="$cache_parent/$node_cache_name"
  node_bin_dir="$cache_dir/bin"
  node_binary="$node_bin_dir/node"

  if [ -L "$cache_parent" ] || [ -L "$cache_dir" ] || [ -L "$node_bin_dir" ] || [ -L "$node_binary" ]; then
    _descartes_ci_node_fail "baked Node cache may not contain symlinks"
    return 1
  fi
  if [ ! -d "$cache_dir" ] || [ ! -x "$node_binary" ]; then
    _descartes_ci_node_fail "baked Node cache is missing or not executable"
    return 1
  fi

  observed_version="$("$node_binary" --version 2>/dev/null)" || {
    _descartes_ci_node_fail "baked Node version check failed"
    return 1
  }
  if [ "$observed_version" != "$node_version" ]; then
    _descartes_ci_node_fail "baked Node version mismatch"
    return 1
  fi

  PATH="$node_bin_dir${PATH:+:$PATH}"
  export PATH
}

_descartes_ci_node_use
