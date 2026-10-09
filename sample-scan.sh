#!/bin/bash
# sample-scan.sh — the 60-second PenScan demo.
# Starts a deliberately vulnerable demo app on your own machine, scans it,
# prints the verdict, and shuts the demo down. Expected verdict: DO NOT SHIP.
set -u
cd "$(dirname "$0")"

python3 examples/mock_target.py &
MOCK_PID=$!
sleep 1

python3 penscan.py \
  --site http://127.0.0.1:8765 \
  --supabase-url http://127.0.0.1:8765 \
  --anon-key demo
CODE=$?

kill $MOCK_PID 2>/dev/null
wait $MOCK_PID 2>/dev/null
exit $CODE
