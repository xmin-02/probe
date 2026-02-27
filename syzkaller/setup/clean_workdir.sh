#!/bin/bash
# Clean workdirs while preserving AI cost data
# Usage: sudo ./setup/clean_workdir.sh
#
# Cleans workdir-fast, workdir-kasan, workdir-hub (actual fuzzer workdirs).
# The legacy 'workdir' directory is NOT touched.

SETUP_DIR="$(dirname "$0")"
SYZKALLER_DIR="$(cd "$SETUP_DIR/.." && pwd)"

# Actual fuzzer workdirs used by probe.sh
WORKDIRS=(
    "$SYZKALLER_DIR/workdir-fast"
    "$SYZKALLER_DIR/workdir-kasan"
    "$SYZKALLER_DIR/workdir-hub"
)

# AI cost files to preserve (NEVER delete these)
COST_FILES=(
    "ai-cost.json"
    "ai-emb-cost.json"
    "ai-log.json"
    "ai-clusters.json"
    "ai-strategy.json"
    "ai-syzgpt-results.json"
    "specgen_cost.json"
)

TMPDIR=$(mktemp -d)

for WORKDIR in "${WORKDIRS[@]}"; do
    if [ ! -d "$WORKDIR" ]; then
        echo "Skipping (not found): $WORKDIR"
        continue
    fi

    DIRNAME="$(basename "$WORKDIR")"
    mkdir -p "$TMPDIR/$DIRNAME"

    # Backup cost files from this workdir
    PRESERVED=0
    for f in "${COST_FILES[@]}"; do
        if [ -f "$WORKDIR/$f" ]; then
            cp "$WORKDIR/$f" "$TMPDIR/$DIRNAME/$f"
            echo "  Preserved: $DIRNAME/$f"
            PRESERVED=$((PRESERVED + 1))
        fi
    done

    # Clean everything
    rm -rf "$WORKDIR"/*
    echo "  Cleaned:  $WORKDIR"

    # Restore cost files
    for f in "${COST_FILES[@]}"; do
        if [ -f "$TMPDIR/$DIRNAME/$f" ]; then
            cp "$TMPDIR/$DIRNAME/$f" "$WORKDIR/$f"
        fi
    done
done

rm -rf "$TMPDIR"

# Clean MOCK BiGRU model state (forces retrain from new corpus)
MOCK_DIR="$SYZKALLER_DIR/tools/mock_model"
for f in model.pt vocab.pt training_data.jsonl; do
    if [ -f "$MOCK_DIR/$f" ]; then
        rm -f "$MOCK_DIR/$f"
        echo "Removed: mock_model/$f"
    fi
done

echo ""
echo "Done. workdir-fast, workdir-kasan, workdir-hub cleaned. AI cost data preserved. MOCK model reset."
