#!/bin/sh
set -eu

PYTHON="${PYTHON:-$(command -v python3 || true)}"
[ -n "$PYTHON" ] || { echo "effectlock: python3 is required" >&2; exit 1; }
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' || {
  echo "effectlock: Python 3.10+ is required" >&2
  exit 1
}

VERSION="$($PYTHON -c 'import pathlib,re; s=pathlib.Path("effectlock/__init__.py").read_text(); print(re.search(r"__version__ = \"([^\"]+)\"",s).group(1))')"
ROOT="${EFFECTLOCK_HOME:-$HOME/.local/share/effectlock}"
BIN="${EFFECTLOCK_BIN:-$HOME/.local/bin}"
DEST="$ROOT/$VERSION"

case "$ROOT" in ""|/|.) echo "effectlock: unsafe EFFECTLOCK_HOME" >&2; exit 1;; esac
case "$BIN" in ""|/|.) echo "effectlock: unsafe EFFECTLOCK_BIN" >&2; exit 1;; esac
[ ! -L "$ROOT" ] || { echo "effectlock: install root must not be a symlink" >&2; exit 1; }
[ ! -L "$BIN" ] || { echo "effectlock: bin directory must not be a symlink" >&2; exit 1; }
[ ! -L "$DEST" ] || { echo "effectlock: version directory must not be a symlink" >&2; exit 1; }

mkdir -p "$DEST/effectlock" "$BIN"
chmod 700 "$ROOT" "$DEST" 2>/dev/null || true
cp effectlock/__init__.py effectlock/core.py effectlock/graph.py effectlock/policy.py effectlock/report.py effectlock/cli.py "$DEST/effectlock/"
chmod 600 "$DEST/effectlock/"*.py

LAUNCHER="$BIN/effectlock"
if [ -L "$LAUNCHER" ]; then
  echo "effectlock: refusing to replace symlink $LAUNCHER" >&2
  exit 1
fi
TMP="$BIN/.effectlock.tmp.$$"
trap 'rm -f "$TMP"' EXIT HUP INT TERM
cat > "$TMP" <<EOF
#!/bin/sh
PYTHONPATH='$DEST' exec '$PYTHON' -m effectlock.cli "\$@"
EOF
chmod 700 "$TMP"
mv -f "$TMP" "$LAUNCHER"
trap - EXIT HUP INT TERM

echo "installed: $LAUNCHER"
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) echo "add to PATH: export PATH=\"$BIN:\$PATH\"" ;;
esac
