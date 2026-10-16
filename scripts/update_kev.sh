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

VENV_PATH="${PROJECT_ROOT}/.venv"
readonly VENV_PATH

SRC_UTILS="${PROJECT_ROOT}/src/utils"
readonly SRC_UTILS

# Logging
log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Error trap
trap 'err "Failed at line $LINENO. Aborting."' ERR

# Sanity checks
[[ -d "$VENV_PATH" ]] || { err "Venv not found at $VENV_PATH"; exit 1; }
[[ -d "$SRC_UTILS" ]] || { err "Directory $SRC_UTILS does not exist"; exit 1; }

# Activate venv
log "Activating virtual environment..."
# shellcheck disable=SC1091
source "${VENV_PATH}/bin/activate"

cd "$SRC_UTILS" || exit 1

log "Running kevcat_fetch.py..."
python3 kevcat_fetch.py

log "Running kevcat_process.py..."
python3 kevcat_process.py

log "Done."