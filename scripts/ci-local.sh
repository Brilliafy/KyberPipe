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
echo -e "\n${BLUE}[3/5] Running Rust Core Unit & Property Tests (cargo test)...${NC}"
cargo test --workspace
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
(
  cd android-app
  chmod +x gradlew
  ./gradlew lintDebug testDebugUnitTest --build-cache --configuration-cache --parallel
)
echo -e "${GREEN}✓ Android lint and unit tests passed.${NC}"

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN} 🎉 ALL CI/CD CHECKS PASSED LOCALLY! READY TO COMMIT. ${NC}"
echo -e "${GREEN}====================================================${NC}"
