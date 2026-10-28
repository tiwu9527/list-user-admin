#!/bin/sh
set -eu
BASE=/vol1/@apphome/trim.openclaw/data/workspace/openlist-user-admin
PIDFILE="$BASE/app.pid"
LOG="$BASE/app.log"
# Only accept the PID if it is still this project's app.py process.
if [ -r "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fq "$BASE/app.py"; then
    exit 0
  fi
fi
cd "$BASE"
nohup python3 -u "$BASE/app.py" >>"$LOG" 2>&1 &
echo $! >"$PIDFILE"
