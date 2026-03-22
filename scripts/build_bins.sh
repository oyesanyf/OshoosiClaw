#!/bin/bash
# Build OpenỌ̀ṣọ́ọ̀sì to bins/ folder with all dependencies for standalone run.
# Run from project root: ./scripts/build_bins.sh
# Then: cd bins && ./osoosi-cli start

set -e
cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"
BINS_DIR="$PROJECT_ROOT/bins"
TARGET_DIR="$PROJECT_ROOT/target/release"

echo "Building release (multithreaded)..."
cargo build --release -p osoosi-cli

rm -rf "$BINS_DIR"
mkdir -p "$BINS_DIR"

# Copy main executable
EXE_NAME="osoosi-cli"
[ -f "$TARGET_DIR/$EXE_NAME" ] && cp "$TARGET_DIR/$EXE_NAME" "$BINS_DIR/" && echo "Copied $EXE_NAME"

# Copy config and assets
[ -d config ] && cp -r config "$BINS_DIR/" && echo "Copied config"
[ -d sigma ] && cp -r sigma "$BINS_DIR/" && echo "Copied sigma"
[ -d dashboard/dist ] && mkdir -p "$BINS_DIR/dashboard" && cp -r dashboard/dist "$BINS_DIR/dashboard/" && echo "Copied dashboard/dist"
[ -f osoosi.toml ] && cp osoosi.toml "$BINS_DIR/" && echo "Copied osoosi.toml"
[ -d yara ] && cp -r yara "$BINS_DIR/" && echo "Copied yara"

# Create default config if missing
mkdir -p "$BINS_DIR/config"
[ ! -f "$BINS_DIR/config/firewall_allowlist.txt" ] && echo -e "# Firewall allowlist\ngit.exe\ncom.docker.cli.exe" > "$BINS_DIR/config/firewall_allowlist.txt"
[ ! -f "$BINS_DIR/config/software_replacement.txt" ] && echo -e "# Software replacement: basename|source\n# git.exe|github:git-for-windows/git:64-bit" > "$BINS_DIR/config/software_replacement.txt"

# Create logs, quarantine, models
mkdir -p "$BINS_DIR/logs" "$BINS_DIR/quarantine" "$BINS_DIR/models"

# Create run script
cat > "$BINS_DIR/run.sh" << 'RUN'
#!/bin/bash
cd "$(dirname "$0")"
./osoosi-cli start
RUN
chmod +x "$BINS_DIR/run.sh"

echo ""
echo "Build complete. Standalone package in: $BINS_DIR"
echo "Run: cd bins && ./osoosi-cli start"
