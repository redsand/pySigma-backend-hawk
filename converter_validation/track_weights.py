"""Keep a local ledger of production score weights that must survive a Sigma sync.

The ledger (score_weights.json, tracked in git) maps hawk_id -> the weight production must keep,
with why and when. sync_scores.py sends the ledger weight for any id in it, so a refresh can
never undo a hand-tuned weight.

    python track_weights.py            # record portal edits since the last run (dry run)
    python track_weights.py --write    # ...and save them to score_weights.json
    python track_weights.py --set <hawk_id>=<weight> --reason "noisy on DCs" --write

A portal edit is a live weight that differs from the weight this tooling last pushed (batch
manifests) -- or, for a score never pushed, from the 2026-09-25 snapshot -- and from the ledger.
Weights the converter itself put there are not recorded (they carry no human decision).
"""
import argparse
import datetime
import json
from pathlib import Path

import requests
import urllib3

HERE = Path(__file__).resolve().parent
LEDGER = HERE / "score_weights.json"
BASE = "https://portal.hawk.io:8080/API/1.1/"
urllib3.disable_warnings()


def api_key() -> str:
    for line in (HERE / "hawk.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("HAWK_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("HAWK_API_KEY missing from converter_validation/hawk.env")


def load_ledger() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else {}


def save_ledger(ledger: dict) -> None:
    LEDGER.write_text(json.dumps(dict(sorted(ledger.items())), indent=1) + "\n", encoding="utf-8")


def load_converted(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            out[str(rec["hawk_id"]).lower()] = rec
    return out


def last_pushed() -> dict:
    """hawk_id -> weight from the most recent executed push that sent it."""
    out = {}
    for m in sorted((HERE / "reports" / "batches").glob("batch_*Z.json")):
        for item in json.loads(m.read_text(encoding="utf-8"))["items"]:
            if (item.get("result") or {}).get("status") in (None, "success", "ok", True) and item.get("score") is not None:
                out[item["hawk_id"].lower()] = float(item["score"])
    return out


def baseline() -> dict:
    p = HERE / "live" / "scores_2026-09-25.json"
    if not p.exists():
        return {}
    d = json.loads(p.read_text(encoding="utf-8"))
    d = d.get("results", d) if isinstance(d, dict) else d
    return {str(r.get("hawk_id")).lower(): float(r.get("correlation_action") or 0) for r in d if r.get("hawk_id")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--set", action="append", default=[], help="hawk_id=weight (repeatable)")
    ap.add_argument("--reason", default="")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    today = datetime.date.today().isoformat()
    ledger = load_ledger()
    conv = load_converted(Path(args.converted))
    live = requests.get(BASE + "scores?recursive=true&format=json", headers={"Authorization": "Bearer " + api_key()},
                        timeout=600, verify=False).json()["results"]
    live = {str(r.get("hawk_id")).lower(): r for r in live if r.get("hawk_id")}

    pushed, base = last_pushed(), baseline()
    changes = []
    for spec in args.set:
        hid, w = spec.split("=", 1)
        hid = hid.strip().lower()
        row = live.get(hid, {})
        changes.append((hid, {"weight": float(w), "reason": args.reason or "set locally", "source": "local",
                              "recorded": today, "score_id": row.get("score_id"), "title": row.get("filter_name")}))
    if not args.set:
        for hid, row in live.items():
            if hid not in conv:
                continue
            lw = float(row.get("correlation_action") or 0)
            cw = float(conv[hid].get("correlation_action") or 0)
            have = ledger.get(hid)
            if have is not None and abs(have["weight"] - lw) < 1e-6:
                continue
            expected = pushed.get(hid, base.get(hid))
            if have is None and (expected is None or abs(expected - lw) < 1e-6):
                continue
            changes.append((hid, {"weight": lw, "reason": args.reason or "portal edit",
                                  "source": "portal", "recorded": today, "portal_last_updated": row.get("last_updated"),
                                  "converter_weight": cw, "expected_weight": expected, "previous_ledger_weight": have and have["weight"],
                                  "score_id": row.get("score_id"), "title": row.get("filter_name")}))

    for hid, entry in changes:
        print(f"{entry['score_id']!s:>7} {entry['weight']:>5} (converter {entry.get('converter_weight')}, ledger {entry.get('previous_ledger_weight')}) "
              f"{str(entry['title'])[:60]}")
        ledger[hid] = entry
    print(f"{len(changes)} change(s); ledger holds {len(ledger)}" + ("" if args.write else " [dry run, use --write]"))
    if args.write and changes:
        save_ledger(ledger)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
