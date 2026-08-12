#!/usr/bin/env bash
#
# vibe-guardrails installer
#
#   bash install.sh                 install for the current user (~/.claude)
#   bash install.sh --project       install into ./.claude for this repo only
#   bash install.sh --mode strict   install with a stricter policy
#   bash install.sh --uninstall     remove it again
#
# It copies one Python file and adds one hook entry to settings.json. Your
# existing settings.json is backed up before anything is touched, and the
# script refuses to guess if it cannot parse it.

set -euo pipefail

MODE="balanced"
SCOPE="user"
ACTION="install"

while [ $# -gt 0 ]; do
  case "$1" in
    --project)   SCOPE="project"; shift ;;
    --user)      SCOPE="user"; shift ;;
    --mode)      MODE="${2:-balanced}"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift ;;
    -h|--help)   sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

case "$MODE" in
  strict|balanced|relaxed) ;;
  *) echo "mode must be one of: strict, balanced, relaxed" >&2; exit 1 ;;
esac

if [ "$SCOPE" = "project" ]; then
  BASE="$(pwd)/.claude"
else
  BASE="$HOME/.claude"
fi

TARGET_DIR="$BASE/vibe-guardrails"
SETTINGS="$BASE/settings.json"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  echo "Python 3 is required but was not found on PATH." >&2
  echo "找不到 Python 3，请先安装：https://www.python.org/downloads/" >&2
  exit 1
fi

# ---------------------------------------------------------------------------

patch_settings() {
  local action="$1"
  "$PY" - "$SETTINGS" "$TARGET_DIR/guard.py" "$MODE" "$action" <<'PYEOF'
import json, os, shutil, sys

settings_path, guard_path, mode, action = sys.argv[1:5]
command = "%s %s" % (sys.executable, guard_path)

data = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as fh:
            text = fh.read().strip()
        data = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        sys.stderr.write(
            "Refusing to touch %s: it is not valid JSON (%s).\n"
            "拒绝修改该文件，因为它不是合法的 JSON。请先手动修复。\n"
            % (settings_path, exc))
        sys.exit(1)
    shutil.copyfile(settings_path, settings_path + ".vibe-guardrails.bak")

hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

# Drop any entry we previously installed, identified by the guard.py path.
def ours(entry):
    return any("vibe-guardrails" in h.get("command", "")
               for h in entry.get("hooks", []) if isinstance(h, dict))

pre[:] = [e for e in pre if not ours(e)]

if action == "install":
    pre.append({
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [{"type": "command", "command": command, "timeout": 10}],
    })
    env = data.setdefault("env", {})
    env["VIBE_GUARDRAILS_MODE"] = mode

if not pre:
    hooks.pop("PreToolUse", None)
if not hooks:
    data.pop("hooks", None)
if action != "install":
    data.get("env", {}).pop("VIBE_GUARDRAILS_MODE", None)
    if data.get("env") == {}:
        data.pop("env", None)

os.makedirs(os.path.dirname(settings_path), exist_ok=True)
with open(settings_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PYEOF
}

# ---------------------------------------------------------------------------

if [ "$ACTION" = "uninstall" ]; then
  patch_settings uninstall
  rm -rf "$TARGET_DIR"
  echo "vibe-guardrails removed. 已卸载。"
  echo "Backup of your previous settings: $SETTINGS.vibe-guardrails.bak"
  exit 0
fi

mkdir -p "$TARGET_DIR"
cp "$SRC_DIR/hooks/guard.py" "$TARGET_DIR/guard.py"
chmod 755 "$TARGET_DIR/guard.py"

if [ ! -f "$TARGET_DIR/rules.json" ]; then
  cp "$SRC_DIR/examples/rules.json" "$TARGET_DIR/rules.json"
fi

patch_settings install

echo
echo "  vibe-guardrails installed"
echo "  ------------------------------------------------------------"
echo "  scope     : $SCOPE  ($BASE)"
echo "  mode      : $MODE"
echo "  guard     : $TARGET_DIR/guard.py"
echo "  settings  : $SETTINGS"
echo "  your rules: $TARGET_DIR/rules.json   (edit to add exceptions)"
echo
echo "  Restart your agent, then try:  rm -rf /"
echo "  重启 agent 后，可以让它执行 rm -rf / 试试，应该会被拦下来。"
echo
echo "  Change mode later : bash install.sh --mode strict"
echo "  Turn off for one run : VIBE_GUARDRAILS_OFF=1 claude"
echo "  Uninstall : bash install.sh --uninstall"
echo
