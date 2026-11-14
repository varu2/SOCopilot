from evaluate import load_labels, load_results, ratio, DB_PATH, POSITIVE
import sqlite3


def score(labels, results):
    tp = fp = fn = tn = sev = mex = mtot = n = 0
    for aid, t in labels.items():
        r = results.get(aid)
        if not r:
            continue
        n += 1
        actual = t["label"] == POSITIVE
        pred = r["verdict"] == POSITIVE
        tp += actual and pred
        fn += actual and not pred
        fp += (not actual) and pred
        tn += (not actual) and (not pred)
        sev += r["severity"] == t["expected_severity"]
        if actual:
            mtot += 1
            mex += r["mitre_technique"] == t["expected_mitre"]
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    return n, ratio(tp + tn, n), precision, recall, f1, sev, mex, mtot


def main():
    conn = sqlite3.connect(DB_PATH)
    run_ids = [r[0] for r in conn.execute(
        "SELECT run_id FROM triage_results WHERE error IS NULL "
        "GROUP BY run_id ORDER BY MIN(created_at)")]
    labels = load_labels()

    print(f"{'run':<22}{'n':>3} {'acc':>7} {'prec':>7} {'recall':>7} {'F1':>7}  {'sev':>6} {'mitre':>7}")
    all_results = {}
    for rid in run_ids:
        res = load_results(conn, rid)
        all_results[rid] = res
        n, acc, p, rc, f1, sev, mex, mtot = score(labels, res)
        print(f"{rid:<22}{n:>3} {acc:>7.1%} {p:>7.1%} {rc:>7.1%} {f1:>7.1%}  {sev:>3}/{n:<2} {mex:>4}/{mtot}")

    print("\nAlerts where runs disagree (verdict / severity / MITRE):")
    any_diff = False
    for aid in labels:
        vals = [(r[aid]["verdict"], r[aid]["severity"], r[aid]["mitre_technique"])
                for r in all_results.values() if aid in r]
        if len(set(vals)) > 1:
            any_diff = True
            print(f"  {aid}:")
            for rid, v in zip(all_results, vals):
                print(f"     {rid}: {v[0]}, {v[1]}, {v[2]}")
    if not any_diff:
        print("  none")
    conn.close()


if __name__ == "__main__":
    main()
    