#!/data/data/com.termux/files/usr/bin/env bash
# install.sh - sec-osint installer
set -euo pipefail

TARGET_DIR="$HOME/sec-osint"
BIN_DIR="$HOME/bin"
BIN_FILE="$BIN_DIR/sec-osint"

# Create main dir
mkdir -p "$TARGET_DIR" "$BIN_DIR"

# Copy package
cp -r /data/data/com.termux/files/home/sec-osint/* "$TARGET_DIR/"

# Create install shim
cat > "$BIN_FILE" << 'EOF'
#!/data/data/com.termux/files/usr/bin/env python3
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "home" / "sec-osint"))
from sec_osint import main
main()
EOF
chmod +x "$BIN_FILE"

# Create install script
cat > "$TARGET_DIR/install.sh" << 'EOF'
#!/data/data/com.termux/files/usr/bin/env bash
set -euo pipefail

echo "Installing sec-osint CLI..."
cp -f /data/data/com.termux/files/home/sec-osint/bin/sec-osint "$HOME/bin/sec-osint" 2>/dev/null || echo "⚠️  Installing to ~/bin/sec-osint"
echo "✅ sec-osint installed. Try: sec-osint --help"
EOF
chmod +x "$TARGET_DIR/install.sh"

echo "✅ Installation complete. Run: ~/sec-osint/install.sh"