#!/usr/bin/env bash
# Runs the browser tests in headless Firefox. Arguments replace `--firefox` and are passed to `wasm-pack test`,
# e.g. `./test.sh --chrome`.
#
# With GECKODRIVER (for --firefox) or CHROMEDRIVER (for --chrome) set, the script does not use wasm-pack. It runs the
# tests with wasm-bindgen-test-runner and that driver. wasm-pack downloads its own drivers and ignores these
# variables, and its chromedriver can be a version ahead of the installed Chrome.
#
# SQLite's C code is compiled to WebAssembly and packed into a static archive. The macOS system `ar` cannot index
# WebAssembly objects ("not a mach-o file"), so the linker finds no symbols in the archive. `llvm-ar` is required.
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
  # Linux distributions often install llvm-ar only under a versioned name such as llvm-ar-18.
  versioned=$(compgen -c llvm-ar- | grep -E '^llvm-ar-[0-9]+$' | sort -t- -k3 -n | tail -1 || true)
  if command -v llvm-ar > /dev/null; then
    AR_wasm32_unknown_unknown=$(command -v llvm-ar)
  elif [ -n "$versioned" ]; then
    AR_wasm32_unknown_unknown=$(command -v "$versioned")
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

# Prints the path of wasm-bindgen-test-runner: from PATH, or from the cache where wasm-pack installs it on its first
# run (macOS and Linux locations). Its version must match the wasm-bindgen version in Cargo.lock.
find_runner() {
  if command -v wasm-bindgen-test-runner > /dev/null; then
    command -v wasm-bindgen-test-runner
    return
  fi
  local cache
  for cache in "$HOME/Library/Caches/.wasm-pack" "${XDG_CACHE_HOME:-$HOME/.cache}/.wasm-pack"; do
    ls -t "$cache"/wasm-bindgen-cargo-install-*/wasm-bindgen-test-runner \
      "$cache"/wasm-bindgen-cargo-install-*/bin/wasm-bindgen-test-runner 2> /dev/null || true
  done | head -1
}

driver=""
case "${browser[0]}" in
  --firefox) [ -n "${GECKODRIVER:-}" ] && driver=GECKODRIVER ;;
  --chrome) [ -n "${CHROMEDRIVER:-}" ] && driver=CHROMEDRIVER ;;
esac

if [ -n "$driver" ]; then
  runner=$(find_runner)
  if [ -z "$runner" ]; then
    echo "wasm-bindgen-test-runner not found: install wasm-bindgen-cli in the version from Cargo.lock, or run" \
      "./test.sh once without a driver variable, which makes wasm-pack install it" >&2
    exit 1
  fi
  echo "$driver: ${!driver}"
  echo "runner: $runner"
  # The runner chooses the browser by the first driver variable that is set, so only the chosen one may be set.
  if [ "$driver" = GECKODRIVER ]; then unset CHROMEDRIVER; else unset GECKODRIVER; fi
  unset SAFARIDRIVER MSEDGEDRIVER
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="$runner" WASM_BINDGEN_TEST_ONLY_WEB=1
  # As with `wasm-pack test`, arguments after `--` go to `cargo test`.
  extra=("${browser[@]:1}")
  if [ "${#extra[@]}" -gt 0 ] && [ "${extra[0]}" = "--" ]; then
    extra=("${extra[@]:1}")
  fi
  exec cargo test --target wasm32-unknown-unknown ${extra[@]+"${extra[@]}"}
fi

exec wasm-pack test --headless "${browser[@]}"
