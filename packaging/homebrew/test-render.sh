#!/usr/bin/env bash
# Asserts the rendered Homebrew formula against a real SHA256SUMS fixture.
#
# The formula is the one artifact nobody can test by running it here: `brew` is not a
# dependency of this repository and macOS runners are not in the gate. What can be
# tested is that the rendering names the right assets with the right checksums, which
# is where a formula actually goes wrong.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rendered="$("$here/render.sh" 0.1.0 "$here/testdata/SHA256SUMS")"

fail() {
  printf 'test-render: %s\n' "$1" >&2
  printf '--- rendered formula ---\n%s\n' "$rendered" >&2
  exit 1
}

contains() {
  case "$rendered" in
    *"$1"*) ;;
    *) fail "expected to find: $1" ;;
  esac
}

absent() {
  case "$rendered" in
    *"$1"*) fail "expected NOT to find: $1" ;;
    *) ;;
  esac
}

contains 'version "0.1.0"'
contains 'class Warden < Formula'
contains 'license "MIT"'

# Each of the four unix archives, at its own URL, with its own checksum.
contains "warden-v0.1.0-aarch64-apple-darwin.tar.gz"
contains "c4051f3c59004b950ac34c367600eb510878333f2860a7b1447bbf5111ba493a"
contains "warden-v0.1.0-x86_64-apple-darwin.tar.gz"
contains "efd1a916f6acda6cef826b40e6f3f161a31423250b4e4f2bbb63764d56da9b66"
contains "warden-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
contains "ec395e3cc88a3de385d000c0a42c8254539d864ee2b9b638d053e7f1d3241957"
contains "warden-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
contains "ea969847a71513dcbd27da85a7ed36b4712ed7f7bb2beb0e5674843ae18099fe"

# Homebrew installs no Windows binary, so that asset must not appear.
absent "x86_64-pc-windows-msvc"
absent "79ced8517d5bb0c010317acfe53522f03548af4b9d87f3c34a75bfbf98ce7ddd"

# No placeholder survived the rendering.
absent "{{"

# A missing checksum must fail loudly rather than render a formula with a blank
# `sha256`, which Homebrew would accept as "no checksum" on some code paths.
partial="$(mktemp)"
grep -v "aarch64-apple-darwin" "$here/testdata/SHA256SUMS" > "$partial"
if "$here/render.sh" 0.1.0 "$partial" > /dev/null 2>&1; then
  rm -f "$partial"
  fail "rendering succeeded with a checksum missing"
fi
rm -f "$partial"

printf 'test-render: ok\n'
