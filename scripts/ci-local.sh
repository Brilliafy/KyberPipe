#!/usr/bin/env bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}       KyberPipe Local CI/CD Pre-Commit Verification ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Rust Formatting Check
echo -e "\n${BLUE}[1/5] Checking Rust Code Formatting (cargo fmt)...${NC}"
cargo fmt --check
echo -e "${GREEN}✓ Rust formatting clean.${NC}"

# 2. Rust Clippy Lints (Strict zero-warning policy)
echo -e "\n${BLUE}[2/5] Running Rust Static Analysis (cargo clippy)...${NC}"
cargo clippy --workspace --all-targets -- -D warnings
echo -e "${GREEN}✓ Rust clippy static analysis passed with zero warnings.${NC}"

# 3. Rust Core & Workspace Unit/Property Tests
# AUDIT hang-watch: the desktop-app e2e drives a real QUIC server and can, on a
# bad day, leave a non-daemon thread (keyring/zbus, clipboard, tokio worker)
# holding the test binary open after the assertions pass. A hard timeout turns
# that into a visible CI failure instead of a silent pipeline hang; the e2e
# itself is now fully hermetic (no OS clipboard, no keyring RPC under the
# FORCE_EMPTY_CLIPBOARD flag) so a normal run exits well inside the bound.
echo -e "\n${BLUE}[3/5] Running Rust Core Unit & Property Tests (cargo test, 240s hang-watch)...${NC}"
timeout 240s cargo test --workspace
if [ $? -eq 124 ]; then
  echo -e "${RED}✗ cargo test hit the 240s hang-watch timeout — a test thread did not exit.${NC}" >&2
  exit 124
fi
echo -e "${GREEN}✓ All Rust unit & proptests passed.${NC}"

# 4. Vue 3 / Tauri Desktop App Typecheck & Build
echo -e "\n${BLUE}[4/5] Building Desktop Frontend (Vue 3 / Vite / TypeScript)...${NC}"
(
  cd desktop-app
  if command -v pnpm &> /dev/null; then
    pnpm run build
  else
    npm run build
  fi
)
echo -e "${GREEN}✓ Desktop app built successfully.${NC}"

# 5. Android Companion App Lint & Unit Tests
echo -e "\n${BLUE}[5/5] Running Android Companion Lint & Unit Tests...${NC}"

# AUDIT F9: the UniFFI Kotlin binding must exist in exactly ONE place
# (core-crypto/generated_kotlin, consumed via Gradle srcDir). A second copy
# under the Android tree is the ABI-drift landmine — fail the build loudly.
if [ -e "android-app/app/src/main/java/uniffi/core_crypto/core_crypto.kt" ]; then
  echo -e "${RED}✗ Duplicate UniFFI Kotlin binding at android-app/app/src/main/java/uniffi/core_crypto/core_crypto.kt — single source of truth is core-crypto/generated_kotlin (AUDIT F9).${NC}" >&2
  exit 1
fi

(
  cd android-app
  chmod +x gradlew
  ./gradlew lintDebug testDebugUnitTest --build-cache --configuration-cache --parallel
)
echo -e "${GREEN}✓ Android lint and unit tests passed.${NC}"

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN} 🎉 ALL CI/CD CHECKS PASSED LOCALLY! READY TO COMMIT. ${NC}"
echo -e "${GREEN}====================================================${NC}"
