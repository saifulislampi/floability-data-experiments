#!/usr/bin/env bash
set -euo pipefail

SPEC="synthetic-bench-data.yml"
BENCH_SCRIPT="data-cache-benchmark.py"
CACHE_DIR="floability-data-cache"
RESULT_ROOT="results"
N_RUNS=10

# Default benchmark group is single.
GROUP="${1:-single}"

usage() {
    cat <<EOF
Usage:
  $0 [single|dirs|all]

Examples:
  $0
  $0 single
  $0 dirs
  $0 all
EOF
}

run_profile() {
    local profile="$1"
    local result_dir="$RESULT_ROOT/$profile"

    mkdir -p "$result_dir"

    for i in $(seq 1 "$N_RUNS"); do
        echo "=== Profile: $profile | Run $i / $N_RUNS ==="

        # Start clean so every run measures cold miss + download/build.
        rm -rf "$CACHE_DIR"
        mkdir -p "$CACHE_DIR"

        python "$BENCH_SCRIPT" "$SPEC" \
            --profile "$profile" \
            --cache-dir "$CACHE_DIR" \
            --download-on-miss \
	    --verbose \
	    --output "$result_dir/run_${i}.json"
        echo "Saved: $result_dir/run_${i}.json"

        # Remove downloaded cache data to avoid storage overflow.
        rm -rf "$CACHE_DIR"

        echo "Cleaned cache after run $i"
        echo
    done
}

run_dirs() {
    for profile in \
        dir_1000_mixed \
        dir_5000_mixed \
        dir_10000_mixed
    do
        run_profile "$profile"
    done
}

case "$GROUP" in
    single)
        run_profile "synthetic_single"
        ;;

    dirs)
        run_dirs
        ;;

    all)
        run_profile "synthetic_single"
        run_dirs
        ;;

    -h|--help|help)
        usage
        ;;

    *)
        echo "Unknown group: $GROUP"
        usage
        exit 1
        ;;
esac

echo "Done. Results are in: $RESULT_ROOT"
