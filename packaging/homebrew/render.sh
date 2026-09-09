#!/usr/bin/env bash
# Renders the Homebrew formula for one release.
#
#   render.sh <version> <path to SHA256SUMS>
#
# Checksums come from the published SHA256SUMS asset and are never recomputed from a
# fresh download: that file is the manifest the release signed, and computing a second
# set is a second chance to describe something other than what was published.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: render.sh <version> <path to SHA256SUMS>\n' >&2
  exit 2
fi

version="$1"
sums="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$sums" ]; then
  printf 'render: %s does not exist\n' "$sums" >&2
  exit 1
fi

# The checksum for one asset, or empty when the manifest does not list it.
checksum_for() {
  awk -v want="warden-v${version}-$1.tar.gz" '$2 == want { print $1 }' "$sums"
}

require() {
  local target="$1"
  local value
  value="$(checksum_for "$target")"
  if [ -z "$value" ]; then
    printf 'render: %s lists no checksum for warden-v%s-%s.tar.gz\n' "$sums" "$version" "$target" >&2
    exit 1
  fi
  printf '%s' "$value"
}

darwin_arm64="$(require aarch64-apple-darwin)"
darwin_x64="$(require x86_64-apple-darwin)"
linux_arm64="$(require aarch64-unknown-linux-gnu)"
linux_x64="$(require x86_64-unknown-linux-gnu)"

sed \
  -e "s/{{VERSION}}/${version}/g" \
  -e "s/{{SHA_DARWIN_ARM64}}/${darwin_arm64}/g" \
  -e "s/{{SHA_DARWIN_X64}}/${darwin_x64}/g" \
  -e "s/{{SHA_LINUX_ARM64}}/${linux_arm64}/g" \
  -e "s/{{SHA_LINUX_X64}}/${linux_x64}/g" \
  "$here/warden.rb.template"
