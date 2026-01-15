#!/bin/bash
# Benchmark script for git-pkgs CLI

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Default test repo
TEST_REPO="${1:-$HOME/code/octobox}"

if [ ! -d "$TEST_REPO" ]; then
    echo -e "${RED}Error: Test repository not found at $TEST_REPO${NC}"
    echo "Usage: $0 [path-to-repo]"
    exit 1
fi

echo "========================================"
echo "git-pkgs CLI Benchmark"
echo "========================================"
echo "Repository: $TEST_REPO"
echo ""

# Build fresh binary
echo -e "${YELLOW}Building git-pkgs...${NC}"
go build -o /tmp/git-pkgs-bench .
echo -e "${GREEN}Build complete${NC}"
echo ""

cd "$TEST_REPO"

# Clean up any existing database
rm -rf .git/pkgs

# Benchmark: Fresh init
echo "----------------------------------------"
echo "Benchmark: Fresh init"
echo "----------------------------------------"
time /tmp/git-pkgs-bench init -q

# Get database size
DB_SIZE=$(du -sh .git/pkgs/pkgs.sqlite3 2>/dev/null | cut -f1)
echo "Database size: $DB_SIZE"
echo ""

# Benchmark: list command
echo "----------------------------------------"
echo "Benchmark: list"
echo "----------------------------------------"
time /tmp/git-pkgs-bench list > /dev/null
echo ""

# Benchmark: log command
echo "----------------------------------------"
echo "Benchmark: log (last 50 commits)"
echo "----------------------------------------"
time /tmp/git-pkgs-bench log -n 50 > /dev/null
echo ""

# Benchmark: diff command
echo "----------------------------------------"
echo "Benchmark: diff HEAD~10..HEAD"
echo "----------------------------------------"
time /tmp/git-pkgs-bench diff HEAD~10 HEAD > /dev/null
echo ""

# Benchmark: blame command
echo "----------------------------------------"
echo "Benchmark: blame"
echo "----------------------------------------"
time /tmp/git-pkgs-bench blame > /dev/null
echo ""

# Benchmark: stale command
echo "----------------------------------------"
echo "Benchmark: stale"
echo "----------------------------------------"
time /tmp/git-pkgs-bench stale > /dev/null
echo ""

# Benchmark: stats command
echo "----------------------------------------"
echo "Benchmark: stats"
echo "----------------------------------------"
time /tmp/git-pkgs-bench stats > /dev/null
echo ""

# Benchmark: tree command
echo "----------------------------------------"
echo "Benchmark: tree"
echo "----------------------------------------"
time /tmp/git-pkgs-bench tree > /dev/null
echo ""

# Benchmark: Incremental update (should be fast)
echo "----------------------------------------"
echo "Benchmark: Incremental update (no changes)"
echo "----------------------------------------"
time /tmp/git-pkgs-bench init -q
echo ""

# Summary
echo "========================================"
echo "Benchmark complete"
echo "========================================"

# Show commit count
COMMIT_COUNT=$(git rev-list --count HEAD)
echo "Total commits analyzed: $COMMIT_COUNT"

# Show dependency count
DEP_COUNT=$(/tmp/git-pkgs-bench list -f json 2>/dev/null | grep -c '"name"' || echo "0")
echo "Total dependencies: $DEP_COUNT"

# Cleanup
rm -f /tmp/git-pkgs-bench
