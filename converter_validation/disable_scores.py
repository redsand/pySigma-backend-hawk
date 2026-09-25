"""Disable (or enable) production scores by numeric score_id.

The hawk_id upsert cannot change `enabled`; only POST /scores/<numeric id> can. This tool reads
the live score list, finds the rows for the requested hawk_ids or score_ids, and posts the full
row back with enabled flipped. Dry run by default.

Usage:
    python disable_scores.py --hawk-ids-file reports/batch_000_deprecated.txt            # dry run
    python disable_scores.py --hawk-ids-file reports/batch_000_deprecated.txt --execute
    python disable_scores.py --score-ids 123,456 --enable --execute
"""
import argparse
import datetime
import json
import time
from pathlib import Path

import requests
import urllib3

HERE = Path(__file__).resolve().parent
BASE = "https://portal.hawk.io:8080/API/1.1/"
urllib3.disable_warnings()


def api_key() -> str:
    for line in (HERE / "hawk.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("HAWK_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("HAWK_API_KEY missing")


def row_to_form(row: dict, enabled: bool) -> dict:
    form = {
        "hawk_id": row.get("hawk_id") or "",
        "group_name": row.get("group_name") or ".",
        "filter_name": str(row.get("filter_name") or "").replace('"', "'"),
        "filter_details": row.get("filter_details") or "",
        "actions_category_name": row.get("actions_category_name") or "Add (+)",
        "correlation_action": str(row.get("correlation_action") or 0),
        "enabled": "true" if enabled else "false",
        "public": "true" if row.get("public") else "false",
        "references": row.get("references") or "",
        "comments": row.get("comments") or "",
        "technique": (row.get("technique") or "")[:16],
        "tags": json.dumps(row.get("tags") or []) if not isinstance(row.get("tags"), str) else row["tags"],
        "rules": json.dumps(row.get("rules")) if not isinstance(row.get("rules"), str) else row["rules"],
    }
    tactics = row.get("tactics") or []
    if isinstance(tactics, str):
        try:
            tactics = json.loads(tactics)
        except Exception:  # noqa: BLE001
            tactics = []
    for i, t in enumerate(tactics):
        if isinstance(t, dict):
            for k, v in t.items():
                form[f"tactics[{i}][{k}]"] = str(v)
    return form


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hawk-ids-file")
    ap.add_argument("--score-ids")
    ap.add_argument("--enable", action="store_true", help="enable instead of disable")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--manifest-dir", default=str(HERE / "reports" / "batches"))
    args = ap.parse_args()

    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    live = s.get(BASE + "scores?recursive=true&format=json", timeout=600, verify=False).json()["results"]
    by_hawk = {str(r.get("hawk_id")).lower(): r for r in live if r.get("hawk_id")}
    by_id = {str(r.get("score_id")): r for r in live}

    targets = []
    if args.hawk_ids_file:
        for line in Path(args.hawk_ids_file).read_text(encoding="utf-8").splitlines():
            line = line.strip().split("#")[0].strip()
            if line.lower().startswith("score_id:") and line.split(":", 1)[1].strip() in by_id:
                targets.append(by_id[line.split(":", 1)[1].strip()])
            elif line and line.lower() in by_hawk:
                targets.append(by_hawk[line.lower()])
    if args.score_ids:
        for sid in args.score_ids.split(","):
            if sid.strip() in by_id:
                targets.append(by_id[sid.strip()])
    want = bool(args.enable)
    targets = [t for t in targets if bool(t.get("enabled")) != want]
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest = {"batch": stamp, "action": "enable" if want else "disable", "execute": args.execute, "items": []}
    for row in targets:
        item = {"score_id": row.get("score_id"), "hawk_id": row.get("hawk_id"), "title": row.get("filter_name"), "enabled_before": bool(row.get("enabled"))}
        if args.execute:
            r = s.post(BASE + f"scores/{row['score_id']}", data=row_to_form(row, want), timeout=120, verify=False)
            try:
                j = r.json()
            except Exception:  # noqa: BLE001
                j = {"raw": r.text[:200]}
            item["result"] = {"http": r.status_code, "status": j.get("status"), "details": str(j.get("details"))[:160]}
            time.sleep(0.2)
        manifest["items"].append(item)
        print(f"{'POST' if args.execute else 'DRY '} score_id={row.get('score_id')} {str(row.get('filter_name'))[:70]!r}" + (f" -> {item['result']['status']}" if args.execute else ""))
    Path(args.manifest_dir).mkdir(parents=True, exist_ok=True)
    out = Path(args.manifest_dir) / f"{manifest['action']}_{stamp}{'' if args.execute else '_dryrun'}.json"
    out.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"{len(targets)} scores to {manifest['action']}; manifest: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
