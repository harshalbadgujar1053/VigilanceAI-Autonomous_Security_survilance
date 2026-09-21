#!/bin/bash
# Stepped load test: 10 -> 50 -> 100 -> 500 -> 1000 concurrent users
# Each step runs for 3 min, results saved separately for comparison.
set -e
HOST="http://192.168.80.129:8001"
mkdir -p results

for USERS in 10 50 100 500 1000; do
  SPAWN_RATE=$((USERS / 10 > 0 ? USERS / 10 : 1))
  echo "=== Step: $USERS concurrent users (spawn rate $SPAWN_RATE/s) ==="
  locust -f locustfile.py --host "$HOST" \
    --headless -u "$USERS" -r "$SPAWN_RATE" \
    --run-time 3m \
    --csv "results/step_${USERS}users" \
    --html "results/step_${USERS}users.html"
  echo "Cooling down 30s before next step..."
  sleep 30
done

echo "Done. Compare results/step_*_stats.csv for latency/failure trends across load levels."
