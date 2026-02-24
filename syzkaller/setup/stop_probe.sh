#!/bin/bash

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run with sudo privileges"
    echo "  Please run: sudo $0"
    exit 1
fi

# Kill everything silently first, then restore terminal, then print.
{
    sudo pkill -9 -f "syz-manager"
    pkill -f "syz-hub"
    pkill -f "python.*server.py"
} >/dev/null 2>&1
sleep 1

# Restore terminal AFTER all kills (QEMU -serial stdio corrupts tty on death).
stty sane 2>/dev/null

echo "Stopping PROBE Phase 17 (2-Tier Mixed-Mode Fuzzing)..."
echo "syz-manager, syz-hub, MOCK BiGRU server stopped."
echo "Done."
