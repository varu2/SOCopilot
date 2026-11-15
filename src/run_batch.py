import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

from enrichment import load_alerts, load_lookups, enrich_alert
import triage

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "results.db"
DELAY_SECONDS = 2  # pause between alerts to stay inside free-tier rate limits


def init_db(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS triage_results (
            run_id TEXT,
            alert_id TEXT,
            verdict TEXT,
            confidence INTEGER,
            severity TEXT,
            mitre_technique TEXT,
            reasoning TEXT,
            recommended_action TEXT,
            model TEXT,
            seconds REAL,
            error TEXT,
            created_at TEXT,
            PRIMARY KEY (run_id, alert_id)
        )"""
    )
    conn.commit()


def already_done(conn, run_id):
    rows = conn.execute(
        "SELECT alert_id FROM triage_results WHERE run_id = ? AND error IS NULL",
        (run_id,),
    ).fetchall()
    return {r[0] for r in rows}


def save(conn, run_id, alert_id, result, seconds, error=None):
    result = result or {}
    conn.execute(
        """INSERT OR REPLACE INTO triage_results
           (run_id, alert_id, verdict, confidence, severity, mitre_technique,
            reasoning, recommended_action, model, seconds, error, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id, alert_id,
            result.get("verdict"), result.get("confidence"), result.get("severity"),
            result.get("mitre_technique"), result.get("reasoning"),
            result.get("recommended_action"),
            triage.MODEL, round(seconds, 2), error,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()


def main():
    # Pass an existing run id to resume a run; otherwise a new one is created
    run_id = sys.argv[1] if len(sys.argv) > 1 else datetime.now().strftime(f"{triage.PROMPT_VERSION}_%Y%m%d_%H%M%S")
    alerts = load_alerts()
    lookups = load_lookups()

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    done = already_done(conn, run_id)

    print(f"Run: {run_id} | model: {triage.MODEL} | alerts: {len(alerts)} | already done: {len(done)}\n")

    ok, failed = 0, 0
    batch_start = time.time()
    for alert in alerts:
        aid = alert["alert_id"]
        if aid in done:
            continue
        start = time.time()
        try:
            result = triage.triage_alert(enrich_alert(alert, lookups))
            secs = time.time() - start
            save(conn, run_id, aid, result, secs)
            ok += 1
            print(f"{aid}  {result['verdict']:<15} {result['severity']:<9} {result['mitre_technique']:<10} ({secs:.1f}s)")
        except Exception as e:  # keep going: one failure must not stop the batch
            secs = time.time() - start
            save(conn, run_id, aid, None, secs, error=str(e)[:300])
            failed += 1
            print(f"{aid}  FAILED: {str(e)[:80]}")
        time.sleep(DELAY_SECONDS)

    print(f"\nDone in {time.time() - batch_start:.0f}s | saved: {ok} | failed: {failed}")
    if failed:
        print(f"Re-run only the failed ones with:  py src/run_batch.py {run_id}")
    conn.close()


if __name__ == "__main__":
    main()