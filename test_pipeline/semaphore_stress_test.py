"""
Tests wazuh_forwarder.py's own concurrency behavior, since its
`_classify_semaphore` caps classification to 1 in-flight request regardless
of how much load Locust throws at the backend directly. This answers: under
burst load, does the semaphore become the actual bottleneck (alerts queue up
waiting their turn) before Gemini/DB/ChromaDB limits are ever reached?

Two ways to run this, pick based on how forward_async() is structured:

OPTION A (forwarder exposes forward_async() importable as a function):
    Feed N alerts through it concurrently and measure end-to-end completion
    time vs N, to see if it scales linearly (semaphore-bound, expected) or
    plateaus/errors (other bottleneck reached first).

OPTION B (forwarder is a standalone watcher, not importable):
    Temporarily point it at a directory/log of N pre-generated alert files
    and time how long it takes to drain the queue, then compare against
    manually raising _classify_semaphore's value (e.g. 1 -> 4 -> 8) and
    re-running, to see if throughput scales or Gemini 429s start dominating.

This script implements OPTION A. Adjust the import path to match your
actual module structure.
"""
import argparse
import asyncio
import glob
import json
import time

# TODO: adjust import to match your actual module layout, e.g.:
# from wazuh_forwarder import forward_async
try:
    from wazuh_forwarder import forward_async
except ImportError:
    forward_async = None


async def run_batch(alerts, concurrency_label=""):
    t0 = time.perf_counter()
    results = await asyncio.gather(*(forward_async(a) for a in alerts), return_exceptions=True)
    elapsed = time.perf_counter() - t0
    errors = [r for r in results if isinstance(r, Exception)]
    print(f"[{concurrency_label}] {len(alerts)} alerts in {elapsed:.1f}s "
          f"({len(alerts)/elapsed:.2f} alerts/sec), {len(errors)} errors")
    if errors:
        print("  sample error:", errors[0])
    return elapsed, len(errors)


def load_alerts(samples_dir, n):
    paths = glob.glob(samples_dir)
    if not paths:
        raise RuntimeError(f"No samples found at {samples_dir}")
    alerts = []
    for i in range(n):
        with open(paths[i % len(paths)]) as f:
            a = json.load(f)
        a = dict(a)
        a["id"] = f"semtest-{i}-{time.time_ns()}"
        alerts.append(a)
    return alerts


async def main_async(args):
    if forward_async is None:
        raise SystemExit(
            "Could not import forward_async from wazuh_forwarder.py — adjust the "
            "import at the top of this script to match your module layout, or "
            "use OPTION B described in the module docstring instead."
        )
    alerts = load_alerts(args.samples_dir, args.n)

    print(f"Current semaphore limit as configured in wazuh_forwarder.py (check _classify_semaphore value).")
    await run_batch(alerts, concurrency_label=f"n={args.n}, current semaphore setting")

    print(
        "\nTo test whether raising the semaphore helps or just shifts the bottleneck:\n"
        "  1. Edit wazuh_forwarder.py: _classify_semaphore = asyncio.Semaphore(4)\n"
        "  2. Restart the forwarder process\n"
        "  3. Re-run this script with the same -n\n"
        "  4. Compare alerts/sec and error count (watch for Gemini 429s in logs —\n"
        "     if errors spike, Gemini's own rate limit is the real ceiling, not\n"
        "     the semaphore, and raising it further won't help)."
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-dir", default="./alert_samples/*.json")
    ap.add_argument("-n", type=int, default=50, help="number of alerts to fire concurrently")
    args = ap.parse_args()
    asyncio.run(main_async(args))
