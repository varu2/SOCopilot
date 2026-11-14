import csv
import json
import sqlite3
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "results.db"
POSITIVE = "true_positive"  # "positive" means a real threat


def load_labels():
    with open(DATA_DIR / "labels.json", encoding="utf-8") as f:
        return json.load(f)


def load_results(conn, run_id):
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM triage_results WHERE run_id = ? AND error IS NULL ORDER BY alert_id",
        (run_id,),
    ).fetchall()
    return {r["alert_id"]: dict(r) for r in rows}


def latest_run(conn):
    row = conn.execute(
        "SELECT run_id FROM triage_results ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def ratio(a, b):
    return a / b if b else 0.0


def main():
    conn = sqlite3.connect(DB_PATH)
    run_id = sys.argv[1] if len(sys.argv) > 1 else latest_run(conn)
    if not run_id:
        print("No results found. Run run_batch.py first.")
        return
    labels = load_labels()
    results = load_results(conn, run_id)

    tp = fp = fn = tn = 0
    sev_match = sev_total = 0
    mitre_exact = mitre_family = mitre_total = 0
    mismatches = []
    rows_out = []

    for aid, truth in labels.items():
        res = results.get(aid)
        if not res:
            continue
        actual = truth["label"] == POSITIVE
        predicted = res["verdict"] == POSITIVE
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
        if actual != predicted:
            mismatches.append((aid, truth, res))

        sev_total += 1
        sev_match += res["severity"] == truth["expected_severity"]

        # MITRE is scored only where the alert really is a threat
        if actual:
            mitre_total += 1
            exp, got = truth["expected_mitre"], res["mitre_technique"]
            mitre_exact += exp == got
            mitre_family += exp.split(".")[0] == (got or "").split(".")[0]

        rows_out.append({
            "alert_id": aid, "true_label": truth["label"], "ai_verdict": res["verdict"],
            "verdict_correct": actual == predicted,
            "expected_severity": truth["expected_severity"], "ai_severity": res["severity"],
            "expected_mitre": truth["expected_mitre"], "ai_mitre": res["mitre_technique"],
            "confidence": res["confidence"], "scenario": truth["scenario"],
        })

    n = tp + fp + fn + tn
    accuracy = ratio(tp + tn, n)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)

    print(f"Run: {run_id} | alerts scored: {n}\n")
    print("Confusion matrix (positive = real threat)")
    print("                      AI: threat   AI: benign")
    print(f"  Actual threat       {tp:>10}   {fn:>10}")
    print(f"  Actual benign       {fp:>10}   {tn:>10}\n")
    print(f"Accuracy : {accuracy:.1%}   ({tp + tn} of {n} verdicts correct)")
    print(f"Precision: {precision:.1%}   (of alerts called threats, how many were real)")
    print(f"Recall   : {recall:.1%}   (of real threats, how many were caught)")
    print(f"F1-score : {f1:.1%}\n")
    print(f"Severity exact match : {sev_match}/{sev_total}")
    print(f"MITRE exact match    : {mitre_exact}/{mitre_total}  (real threats only)")
    print(f"MITRE same family    : {mitre_family}/{mitre_total}  (e.g. T1110.001 vs T1110.003)\n")

    if mismatches:
        print("Wrong verdicts:")
        for aid, truth, res in mismatches:
            print(f"  {aid}: truth={truth['label']}, AI={res['verdict']}")
            print(f"     scenario: {truth['scenario']}")
            print(f"     AI reasoning: {res['reasoning']}")
    else:
        print("No wrong verdicts.")

    out = DATA_DIR / f"eval_{run_id}.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        w.writeheader()
        w.writerows(rows_out)
    print(f"\nPer-alert table saved to {out.name}")
    conn.close()


if __name__ == "__main__":
    main()