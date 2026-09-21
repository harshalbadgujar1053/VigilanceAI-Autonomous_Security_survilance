#!/bin/bash
# Static check for lingering unpaginated .map() renders in the frontend.
# Run from the frontend/ directory root.
#
# This is a heuristic, not proof - flags every .map( over something that looks
# like a full alert/data array, so you can manually confirm each one is either
# paginated (slice()'d / receives already-paginated props) or genuinely fine
# (e.g. mapping over a fixed-size filter-pill array).

echo "=== .map() calls in components (manually verify each is paginated) ==="
grep -rn "\.map(" src --include="*.tsx" --include="*.ts" | grep -iv "test" | grep -Ei "alert|dashboard|history|classification|row"

echo ""
echo "=== Confirm these ARE paginated (look for slice/pageSize/limit nearby) ==="
grep -rln "\.map(" src --include="*.tsx" | xargs grep -L "slice\|pageSize\|limit\|useMemo.*page" 2>/dev/null

echo ""
echo "Manually open each file above and confirm the array passed to .map() is"
echo "already sliced/paginated (e.g. by the API cursor, or client-side slice()),"
echo "not the full fetched dataset. Also profile with React DevTools Profiler"
echo "against the 50k-row seeded test DB (point frontend API base at :8001)."
