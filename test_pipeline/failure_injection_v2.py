#!/usr/bin/env python3
"""Phase 6 - failure/resilience tests against the DB-backed classification queue.
Run as root:  python3 failure_injection_v2.py [gemini|gemini-drop|pg-kill|pg-stop|all]
"""
import subprocess, sys, time, socket, json, urllib.request

import os
DB, API, N = "vigilancedb_test", "http://192.168.80.129:8001", int(os.getenv("N", "30"))
PENDING, DONE = "pending", "done"      # adjust if your worker uses other names
GEMINI_HOST, STUCK_AFTER_S = "generativelanguage.googleapis.com", 120
results = []

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def sql(q):
    r = subprocess.run(["sudo","-u","postgres","psql","-d",DB,"-At","-c",q], capture_output=True, text=True)
    if r.returncode != 0: raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()

def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}")

def api_ok(timeout=5):
    try:
        with urllib.request.urlopen(f"{API}/alerts?limit=1", timeout=timeout) as r:
            return r.status == 200 and json.load(r).get("success")
    except Exception:
        return False

def seed(n=N):
    out = sql(f"""INSERT INTO classification_queue(alert_id,status,attempts,enqueued_at,updated_at)
      SELECT a.id,'{PENDING}',0,now(),now() FROM alerts a
      LEFT JOIN classifications c ON c.alert_id=a.id
      WHERE c.id IS NULL AND NOT EXISTS (SELECT 1 FROM classification_queue q WHERE q.alert_id=a.id)
      ORDER BY a.created_at DESC LIMIT {n} RETURNING alert_id;""")
    ids = [l for l in out.splitlines() if l and not l.startswith("INSERT")]
    print(f"  seeded {len(ids)} queue rows")
    return ids

def in_list(ids): return ",".join("'" + i + "'" for i in ids)

def counts(ids):
    rows = sql(f"SELECT status,count(*),coalesce(sum(attempts),0) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) GROUP BY 1;")
    return rows.replace("\n", " | ")

def gemini_ips():
    return sorted({l.split()[0] for l in sh(f"getent ahostsv4 {GEMINI_HOST}").splitlines()})

def block(mode):
    ips = gemini_ips()
    for ip in ips: sh(f"iptables -I OUTPUT -d {ip} -j {mode}")
    return ips

def unblock(ips, mode):
    for ip in ips: sh(f"iptables -D OUTPUT -d {ip} -j {mode}")

def wait_drain(ids, timeout=420):
    t = time.time()
    while time.time() - t < timeout:
        left = int(sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) AND status<>'{DONE}';") or 0)
        print(f"    {int(time.time()-t):>3}s not-done={left}")
        if left == 0: return True
        time.sleep(15)
    return False

def final_checks(ids, label):
    total = int(sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)});"))
    check(f"{label}: no queue rows lost", total == len(ids), f"({total}/{len(ids)})")
    cls = int(sql(f"SELECT count(DISTINCT alert_id) FROM classifications WHERE alert_id IN ({in_list(ids)});"))
    check(f"{label}: every alert classified", cls == len(ids), f"({cls}/{len(ids)})")
    dup = sql(f"SELECT count(*) FROM (SELECT alert_id FROM classifications WHERE alert_id IN ({in_list(ids)}) GROUP BY 1 HAVING count(*)>1) t;")
    check(f"{label}: no double-classification", dup == "0", f"(dupes={dup})")
    stuck = sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) AND status NOT IN ('{DONE}','{PENDING}') AND updated_at < now() - interval '{STUCK_AFTER_S} seconds';")
    check(f"{label}: no stuck non-pending/non-done rows", stuck == "0", f"(stuck={stuck})")

def test_gemini(mode="REJECT", secs=int(os.getenv("SECS","90"))):
    print(f"\n== Gemini outage ({mode}, {secs}s) ==")
    ids = seed(); 
    if not ids: return check("seed", False, "no unclassified alerts left")
    time.sleep(3)
    done_before = int(sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) AND status='{DONE}';"))
    ips = block(mode)
    try:
        for i in range(secs // 15):
            time.sleep(15); print(f"    [blocked {(i+1)*15}s] {counts(ids)} | api_ok={bool(api_ok())}")
        done_during = int(sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) AND status='{DONE}';"))
        check("no false 'done' during outage", done_during - done_before <= 1, f"(+{done_during-done_before})")
        check("API stays up during outage", bool(api_ok()))
        att = int(sql(f"SELECT coalesce(sum(attempts),0) FROM classification_queue WHERE alert_id IN ({in_list(ids)});"))
        check("worker alive (attempts incremented)", att > 0, f"(attempts={att})")
    finally:
        unblock(ips, mode)
    print("  unblocked, waiting for drain")
    check("backlog drains after restore", wait_drain(ids))
    final_checks(ids, "gemini")

def test_pg(kind):
    print(f"\n== Postgres {kind} ==")
    ids = seed()
    if not ids: return check("seed", False, "no unclassified alerts left")
    time.sleep(20)   # let worker start processing
    if kind == "kill":
        sh(f"sudo -u postgres psql -At -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{DB}' AND pid<>pg_backend_pid();\"")
    else:
        sh("systemctl stop postgresql"); print("    postgres stopped 30s"); time.sleep(30)
        print("    API during outage ->", "up" if api_ok() else "down/err (expected)")
        sh("systemctl start postgresql"); time.sleep(5)
    t = time.time(); rec = False
    while time.time() - t < 60:
        if api_ok(): rec = True; break
        time.sleep(3)
    check("API recovers without uvicorn restart", rec, f"({int(time.time()-t)}s)")
    check("backlog drains after recovery", wait_drain(ids))
    final_checks(ids, f"pg-{kind}")


def wait_drain(ids, timeout=420):
    t = time.time()
    while time.time() - t < timeout:
        try:
            left = int(sql(f"SELECT count(*) FROM classification_queue WHERE alert_id IN ({in_list(ids)}) AND status<>'{DONE}';"))
        except Exception as e:
            print("    db unavailable:", str(e)[:60]); time.sleep(5); continue
        print(f"    {int(time.time()-t):>3}s not-done={left}")
        if left == 0: return True
        time.sleep(15)
    return False

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("gemini", "all"):      test_gemini("REJECT")
    if which in ("gemini-drop", "all"): test_gemini("DROP")
    if which in ("pg-kill", "all"):     test_pg("kill")
    if which in ("pg-stop", "all"):     test_pg("stop")
    print("\n== SUMMARY =="); [print(("PASS" if ok else "FAIL"), n, d) for n, ok, d in results]
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)
