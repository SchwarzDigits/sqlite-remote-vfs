#!/usr/bin/env bash
# Runs the browser tests in headless Firefox. Arguments replace `--firefox` and are passed to `wasm-pack test`,
# e.g. `./test.sh --chrome`.
#
# SQLite's C code is compiled to WebAssembly and packed into a static archive. The macOS system `ar` cannot index
# WebAssembly objects ("not a mach-o file"), so the linker finds no symbols in the archive. `llvm-ar` is required.
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
  if command -v llvm-ar > /dev/null; then
    AR_wasm32_unknown_unknown=$(command -v llvm-ar)
  elif command -v brew > /dev/null && [ -x "$(brew --prefix llvm 2> /dev/null)/bin/llvm-ar" ]; then
    AR_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/llvm-ar"
  else
    echo "llvm-ar not found: install LLVM or set AR_wasm32_unknown_unknown to an archiver that supports WebAssembly" >&2
    exit 1
  fi
  export AR_wasm32_unknown_unknown
fi

# The measurement tests run longer than the test runner's default timeout of 20 s, in Firefox much longer, because
# its IndexedDB is slower. Default to 180 s instead of reducing the number of samples.
export WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT:-180}

browser=(--firefox)
if [ "$#" -gt 0 ]; then
  browser=("$@")
fi

echo "llvm-ar: $AR_wasm32_unknown_unknown"

# wasm-pack downloads its own chromedriver and ignores CHROMEDRIVER. If that chromedriver does not match the installed
# Chrome, set CHROMEDRIVER to a matching one. The script then calls the test runner that wasm-pack installed directly.
if [ -n "${CHROMEDRIVER:-}" ] && [ "${browser[0]}" = "--chrome" ]; then
  runner=$(ls -t "$HOME"/Library/Caches/.wasm-pack/wasm-bindgen-cargo-install-*/wasm-bindgen-test-runner 2> /dev/null | head -1 || true)
  runner=${runner:-$(ls -t "$HOME"/Library/Caches/.wasm-pack/wasm-bindgen-cargo-install-*/bin/wasm-bindgen-test-runner 2> /dev/null | head -1 || true)}
  if [ -z "$runner" ]; then
    echo "wasm-bindgen-test-runner not found: run ./test.sh once with Firefox, which makes wasm-pack install it" >&2
    exit 1
  fi
  echo "chromedriver: $CHROMEDRIVER"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$runner" WASM_BINDGEN_TEST_ONLY_WEB=1
  exec cargo test --target wasm32-unknown-unknown
fi

exec wasm-pack test --headless "${browser[@]}"
