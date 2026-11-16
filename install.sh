#!/usr/bin/env bash
#
# OpenCode Privacy Masking Plugin - One-Key Installer
# Usage:
#   ./install.sh [OPTIONS]
#
# Options:
#   -g, --global       Install globally to ~/.config/opencode/plugins/ (default)
#   -l, --local [DIR]  Install locally to [DIR]/.opencode/plugins/ (defaults to .)
#   --link             Create symbolic links to source repository (default)
#   --copy             Copy files instead of symlinking
#   --skip-deps        Skip dependency installation (bun/npm install)
#   -h, --help         Show this help message
#

set -euo pipefail

# ANSI Colors
if [[ -t 1 ]]; then
  BOLD="$(printf '\033[1m')"
  GREEN="$(printf '\033[32m')"
  BLUE="$(printf '\033[34m')"
  YELLOW="$(printf '\033[33m')"
  RED="$(printf '\033[31m')"
  RESET="$(printf '\033[0m')"
else
  BOLD=""
  GREEN=""
  BLUE=""
  YELLOW=""
  RED=""
  RESET=""
fi

log_info() {
  printf "${BLUE}${BOLD}[INFO]${RESET} %s\n" "$1"
}

log_success() {
  printf "${GREEN}${BOLD}[SUCCESS]${RESET} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}${BOLD}[WARN]${RESET} %s\n" "$1"
}

log_error() {
  printf "${RED}${BOLD}[ERROR]${RESET} %s\n" "$1" >&2
}

# Resolve source repository directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"

# Defaults
MODE="global"
TARGET_DIR=""
METHOD="link"
SKIP_DEPS=false

show_help() {
  cat <<EOF
${BOLD}OpenCode Privacy Masking Plugin - Installer${RESET}

${BOLD}USAGE:${RESET}
  ./install.sh [OPTIONS]

${BOLD}OPTIONS:${RESET}
  -g, --global          Install plugin globally to ~/.config/opencode/plugins/ (default)
  -l, --local [DIR]     Install plugin locally to [DIR]/.opencode/plugins/ (defaults to current dir)
  --link                Install via symlinks to this source repository (recommended for dev)
  --copy                Install by copying files directly (standalone distribution)
  --skip-deps           Skip running bun/npm install
  -h, --help            Show this help message

${BOLD}EXAMPLES:${RESET}
  # Global installation (available in all OpenCode workspaces)
  ./install.sh --global

  # Local installation for current workspace
  ./install.sh --local

  # Local installation for a specific project
  ./install.sh --local /path/to/my-project

  # Standalone copy without symlinks
  ./install.sh --global --copy
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--global)
      MODE="global"
      shift
      ;;
    -l|--local)
      MODE="local"
      if [[ $# -gt 1 && ! "$2" =~ ^- ]]; then
        TARGET_DIR="$2"
        shift 2
      else
        TARGET_DIR="."
        shift
      fi
      ;;
    --link)
      METHOD="link"
      shift
      ;;
    --copy)
      METHOD="copy"
      shift
      ;;
    --skip-deps)
      SKIP_DEPS=true
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Detect package manager
detect_package_manager() {
  if command -v bun >/dev/null 2>&1; then
    echo "bun"
  elif command -v pnpm >/dev/null 2>&1; then
    echo "pnpm"
  elif command -v npm >/dev/null 2>&1; then
    echo "npm"
  else
    echo "none"
  fi
}

PM="$(detect_package_manager)"

# Step 1: Install dependencies
if [[ "$SKIP_DEPS" == false ]]; then
  if [[ "$PM" != "none" ]]; then
    log_info "Installing dependencies with $PM in $SOURCE_DIR..."
    (cd "$SOURCE_DIR" && "$PM" install)
    log_success "Dependencies installed."
  else
    log_warn "Neither bun, pnpm, nor npm was found. Skipping dependency installation."
  fi
fi

# Step 2: Determine target plugin directory
if [[ "$MODE" == "global" ]]; then
  DEST_BASE="${HOME}/.config/opencode"
  DEST_PLUGINS="${DEST_BASE}/plugins"
  DEST_CONF_FILE="${DEST_BASE}/privacy-masking.json"
else
  TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
  DEST_BASE="${TARGET_DIR}/.opencode"
  DEST_PLUGINS="${DEST_BASE}/plugins"
  DEST_CONF_FILE="${TARGET_DIR}/privacy-masking.json"
fi

DEST_SUBDIR="${DEST_PLUGINS}/privacy-masking"

log_info "Installing plugin to: $DEST_PLUGINS (mode: $MODE, method: $METHOD)"

# Step 3: Create target plugins directory
mkdir -p "$DEST_PLUGINS"

# Step 4: Install entrypoint and module directory
resolve_relpath() {
  local src="$1"
  local dst_dir="$2"
  python3 -c "import os.path; print(os.path.relpath('$src', '$dst_dir'))" 2>/dev/null || echo "$src"
}

if [[ "$METHOD" == "link" ]]; then
  log_info "Creating symlink for entrypoint: privacy-masking.ts"
  REL_ENTRY="$(resolve_relpath "${SOURCE_DIR}/privacy-masking.ts" "$DEST_PLUGINS")"
  rm -f "${DEST_PLUGINS}/privacy-masking.ts"
  ln -sf "$REL_ENTRY" "${DEST_PLUGINS}/privacy-masking.ts"

  log_info "Creating symlink for module directory: privacy-masking/"
  REL_SUBDIR="$(resolve_relpath "${SOURCE_DIR}/privacy-masking" "$DEST_PLUGINS")"
  rm -rf "${DEST_PLUGINS}/privacy-masking"
  ln -sfn "$REL_SUBDIR" "${DEST_PLUGINS}/privacy-masking"
else
  log_info "Copying entrypoint: privacy-masking.ts"
  cp -p "${SOURCE_DIR}/privacy-masking.ts" "${DEST_PLUGINS}/privacy-masking.ts"

  log_info "Copying module files into ${DEST_PLUGINS}/privacy-masking/"
  mkdir -p "${DEST_PLUGINS}/privacy-masking"
  MODULES=(
    "config.ts"
    "crypto.ts"
    "rules.ts"
    "store.ts"
    "local-model.ts"
    "local_model.ts"
    "tabular.ts"
  )
  for mod in "${MODULES[@]}"; do
    cp -p "${SOURCE_DIR}/${mod}" "${DEST_PLUGINS}/privacy-masking/${mod}"
  done
fi

# Step 5: Initialize default configuration if missing
if [[ ! -f "$DEST_CONF_FILE" && ! -f "${DEST_BASE}/privacy-masking.json" ]]; then
  log_info "Creating default configuration at $DEST_CONF_FILE"
  cp -p "${SOURCE_DIR}/privacy-masking.json" "$DEST_CONF_FILE"
fi

# Step 6: Verify with OpenCode CLI if available
if command -v opencode >/dev/null 2>&1; then
  log_info "Verifying plugin discovery with OpenCode..."
  if opencode debug config >/dev/null 2>&1; then
    log_success "OpenCode successfully discovered and loaded privacy-masking plugin!"
  else
    log_warn "OpenCode debug config encountered a warning or error. Check 'opencode debug config'."
  fi
fi

echo ""
log_success "OpenCode Privacy Masking Plugin installed successfully!"
echo ""
printf "${BOLD}Installation Summary:${RESET}\n"
printf "  Entrypoint: %s\n" "${DEST_PLUGINS}/privacy-masking.ts"
printf "  Modules:    %s\n" "${DEST_SUBDIR}/"
printf "  Config:     %s\n" "$DEST_CONF_FILE"
printf "  Method:     %s\n" "$METHOD"
printf "  Mode:       %s\n" "$MODE"
echo ""
printf "Run tests anytime with:\n"
printf "  ${BOLD}npm test${RESET} (or ${BOLD}bun test${RESET})\n"
echo ""
