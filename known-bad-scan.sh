#!/bin/bash
# known-bad-scan.sh — run PenScan against the known-bad 2026-pattern target.
# Starts the deliberately vulnerable sample app on your own machine, scans it,
# prints the verdict, and shuts it down.
# Expected verdict: DO NOT SHIP (checks 1, 2 and 4 fail; 3 and 5 pass).
set -u
cd "$(dirname "$0")"

python3 examples/known_bad_app.py &
APP_PID=$!
sleep 1

python3 penscan.py \
  --site http://127.0.0.1:8766 \
  --supabase-url http://127.0.0.1:8766 \
  --anon-key demo
CODE=$?

kill $APP_PID 2>/dev/null
wait $APP_PID 2>/dev/null
exit $CODE
