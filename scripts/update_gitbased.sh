#!/bin/bash
set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly PROJECT_ROOT

# Repos to update
REPOS=(
    "exploitdb"
    "0day.today.archive"
)

# Logging
log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Error trap
trap 'err "Failed at line $LINENO. Aborting."' ERR

# Update each repo
for repo in "${REPOS[@]}"; do
    repo_path="${PROJECT_ROOT}/${repo}"
    if [[ ! -d "$repo_path/.git" ]]; then
        warn "Not a git repo, skipping: $repo_path"
        continue
    fi
    log "Updating $repo..."
    git -C "$repo_path" pull --ff-only
done

log "All repos updated."