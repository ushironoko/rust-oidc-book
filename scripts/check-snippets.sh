#!/usr/bin/env bash
# src/snippets/**/*.rs を Playground と同じクレートバージョンで手元コンパイル・実行する。
# 並列実行してよい(実行ごとに別ディレクトリを作り、target のみ共有する)。
# 使い方: scripts/check-snippets.sh [chNN/name ...] (省略時は全件)
set -euo pipefail
cd "$(dirname "$0")/.."
base=snippet-check
run=$(mktemp -d "$PWD/$base/run.XXXXXX")
trap 'rm -rf "$run"' EXIT
cp "$base/Cargo.toml" "$run/"
[ -f "$base/Cargo.lock" ] && cp "$base/Cargo.lock" "$run/"
mkdir -p "$run/src/bin"
export CARGO_TARGET_DIR="$PWD/$base/target"
if [ $# -gt 0 ]; then files=(); for s in "$@"; do files+=("src/snippets/${s%.rs}.rs"); done
else files=(src/snippets/*/*.rs); fi
binname() { echo "${1#src/snippets/}" | sed 's#/#__#; s#\.rs$##; s#-#_#g'; }
for f in "${files[@]}"; do cp "$f" "$run/src/bin/$(binname "$f").rs"; done
fail=0
for f in "${files[@]}"; do
  echo "=== $f"
  if ! perl -e "alarm 120; exec @ARGV" cargo run -q --manifest-path "$run/Cargo.toml" --release --bin "$(binname "$f")" 2>&1 | sed 's/^/  /'; then
    echo "  !! FAILED: $f"; fail=1
  fi
done
exit $fail
