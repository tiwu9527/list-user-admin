#!/bin/sh
# Safe updater for a deployment checkout. No automatic invocation.
set -eu

APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BRANCH=${UPDATE_BRANCH:-main}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:19100/health}
BACKUP_ROOT=${BACKUP_ROOT:-"$APP_DIR/backups"}
STAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="$BACKUP_ROOT/$STAMP"

command -v git >/dev/null 2>&1 || { echo 'git is required' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required' >&2; exit 1; }
mkdir -p "$BACKUP"

# Refuse to overwrite locally changed tracked files.
if ! git -C "$APP_DIR" diff --quiet || ! git -C "$APP_DIR" diff --cached --quiet; then
  echo 'Tracked files have local changes; commit or save them before updating.' >&2
  exit 1
fi

OLD_COMMIT=$(git -C "$APP_DIR" rev-parse HEAD)
OLD_VERSION=$(cat "$APP_DIR/VERSION" 2>/dev/null || echo unknown)
cp "$APP_DIR/app.py" "$BACKUP/app.py"
[ ! -f "$APP_DIR/VERSION" ] || cp "$APP_DIR/VERSION" "$BACKUP/VERSION"

# Consistent SQLite backup (handles WAL mode); use active Python stdlib sqlite3.
python3 - "$APP_DIR/data.db" "$BACKUP/data.db" <<'PY'
import os, sqlite3, sys
src, dst = sys.argv[1:]
if os.path.exists(src):
    a = sqlite3.connect(src, timeout=15)
    b = sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        b.close(); a.close()
PY

rollback() {
  echo 'Update failed; restoring previous code.' >&2
  git -C "$APP_DIR" reset --hard "$OLD_COMMIT" >&2 || cp "$BACKUP/app.py" "$APP_DIR/app.py"
  printf '%s\n' "$OLD_VERSION" > "$APP_DIR/VERSION"
  "$APP_DIR/ensure-running.sh" || true
  exit 1
}

# Only fetch the selected branch; deploy its tip after backup.
git -C "$APP_DIR" fetch --prune origin "$BRANCH"
git -C "$APP_DIR" checkout -q "$BRANCH"
git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
python3 -m py_compile "$APP_DIR/app.py" || rollback

# Restart current instance if identifiable; ensure-running starts it if absent.
PIDFILE="$APP_DIR/app.pid"
if [ -r "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fq "$APP_DIR/app.py"; then
    kill "$pid"
    n=0
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 10 ]; do sleep 1; n=$((n+1)); done
  fi
fi
"$APP_DIR/ensure-running.sh"

# Allow a short startup window, then verify health; roll code back on failure.
ok=0
n=0
while [ "$n" -lt 15 ]; do
  if python3 - "$HEALTH_URL" <<'PY'
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=2) as r:
        raise SystemExit(0 if r.status == 200 and r.read(128).strip() == b'ok' else 1)
except Exception:
    raise SystemExit(1)
PY
  then ok=1; break; fi
  sleep 1; n=$((n+1))
done
[ "$ok" -eq 1 ] || rollback

echo "Updated successfully: $OLD_VERSION -> $(cat "$APP_DIR/VERSION" 2>/dev/null || echo unknown)"
echo "Backup: $BACKUP"
