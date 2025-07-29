#!/bin/sh
if [ $# -lt 1 ]; then
    echo "Error: Name of fuzz target is required."
    echo "Usage: $0 fuzz_target [sources...]"
    exit 1
fi
FUZZ_TARGET="$1"
RUSTFLAGS="-C instrument-coverage" 
cargo fuzz coverage $FUZZ_TARGET
shift
SRC_FILTER="$@"
TARGET=$(rustc -vV | sed -n 's|host: ||p')

llvm-cov show \
--use-color --ignore-filename-regex='/.cargo/registry' \
--instr-profile="fuzz/coverage/$FUZZ_TARGET/coverage.profdata" \
-show-line-counts-or-regions \
-show-instantiations \
-format=html -output-dir=fuzz/html/ \
--object "fuzz/target/$TARGET/release/$FUZZ_TARGET"
