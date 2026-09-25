"""Push converted Sigma scores to the HAWK portal in reviewable batches.

Default is a dry run that only writes the batch manifest. `--execute` performs the upserts.

Behaviour (verified against hawk-data app.php / query_wrapper.php, 2026-09-25):
  * POST /API/1.1/scores/<hawk_id> with a letter-bearing id is insert-or-update.
  * On update it refreshes filter_name, filter_details, action fields, tactics, technique, tags
    and rules, and leaves enabled/public/group_name alone. So re-pushing a rule that is already
    live keeps its enabled state; a brand-new rule is inserted with enabled=false.
  * tactics must be form-encoded (tactics[0][tactic_id]=...), tags/rules are JSON strings,
    technique is VARCHAR(16), filter_name must not contain double quotes.

Usage:
    python sync_scores.py --select reports/batch_001.txt            # dry run (manifest only)
    python sync_scores.py --select reports/batch_001.txt --execute  # push
    python sync_scores.py --select ... --verify                     # re-read /scores and confirm

`--select` is a text file with one hawk_id (Sigma rule UUID) per line, or `--ids a,b,c`.
"""
import argparse
import datetime
import json
import re
import sys
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
    raise SystemExit("HAWK_API_KEY missing from converter_validation/hawk.env")


def load_converted(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            out[str(rec["hawk_id"]).lower()] = rec
    return out


def to_form(rec: dict, group: str, date_added: str = "") -> dict:
    hid = str(rec["hawk_id"])
    if not re.search(r"[A-Za-z]", hid):
        hid = "SIGMA-" + hid  # the API requires a letter in a hawk_id
    form = {
        "hawk_id": hid,
        "group_name": group,
        "filter_name": str(rec["filter_name"]).replace('"', "'")[:255],
        "filter_details": rec.get("filter_details") or "",
        "actions_category_name": rec.get("actions_category_name") or "Add (+)",
        "correlation_action": str(float(rec.get("correlation_action") or 0.0)),
        "enabled": "false",
        "public": "true" if rec.get("public", True) else "false",
        "references": rec.get("references") or "",
        "comments": rec.get("comments") or "",
        "technique": (rec.get("technique") or "")[:16],
        "tags": json.dumps(rec.get("tags") or []),
        "rules": json.dumps(rec.get("rules") or []),
        # the hawk_id insert/upsert stores date_added from the request (epoch 0 when absent);
        # keep an existing row's date, stamp new rows with now (UTC)
        "date_added": date_added or datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S"),
    }
    for i, t in enumerate(rec.get("tactics") or []):
        for k, v in t.items():
            form[f"tactics[{i}][{k}]"] = str(v)
    return form


def push(session: requests.Session, form: dict) -> dict:
    r = session.post(BASE + "scores/" + form["hawk_id"], data=form, timeout=120, verify=False)
    try:
        j = r.json()
    except Exception:  # noqa: BLE001
        j = {"raw": r.text[:300]}
    return {"http": r.status_code, "status": j.get("status"), "code": j.get("code"), "details": str(j.get("details"))[:200]}


def fetch_live(session: requests.Session) -> dict:
    r = session.get(BASE + "scores?recursive=true&format=json", timeout=600, verify=False)
    rows = r.json().get("results", [])
    return {str(x.get("hawk_id")).lower(): x for x in rows if x.get("hawk_id")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--converted", default=str(HERE / "reports" / "converted.jsonl"))
    ap.add_argument("--select", help="file with one hawk_id per line")
    ap.add_argument("--ids", help="comma-separated hawk_ids")
    ap.add_argument("--group", default=".")
    ap.add_argument("--batch-size", type=int, default=100)
    ap.add_argument("--manifest-dir", default=str(HERE / "reports" / "batches"))
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--verify", action="store_true", help="after pushing, re-read /scores and confirm each id")
    args = ap.parse_args()

    conv = load_converted(Path(args.converted))
    ids: list[str] = []
    if args.select:
        ids += [l.split("#", 1)[0].strip().lower() for l in Path(args.select).read_text(encoding="utf-8").splitlines() if l.split("#", 1)[0].strip()]
    if args.ids:
        ids += [x.strip().lower() for x in args.ids.split(",") if x.strip()]
    ids = list(dict.fromkeys(ids))
    missing = [i for i in ids if i not in conv]
    if missing:
        print(f"WARNING {len(missing)} ids not in converted set, e.g. {missing[:3]}", file=sys.stderr)
    ids = [i for i in ids if i in conv]
    if len(ids) > args.batch_size:
        raise SystemExit(f"{len(ids)} ids exceed batch size {args.batch_size}; split the selection")

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    Path(args.manifest_dir).mkdir(parents=True, exist_ok=True)
    manifest = {"batch": stamp, "group": args.group, "execute": args.execute, "items": []}

    session = requests.Session()
    session.headers["Authorization"] = "Bearer " + api_key()
    live_before = fetch_live(session) if (args.execute or args.verify) else {}

    for hid in ids:
        rec = conv[hid]
        prev = live_before.get(hid, {})
        prev_date = str(prev.get("date_added") or "")
        form = to_form(rec, args.group, prev_date if prev_date and not prev_date.startswith("1970") else "")
        item = {
            "hawk_id": form["hawk_id"],
            "title": rec.get("filter_name"),
            "source": rec.get("_source"),
            "level": rec.get("_level"),
            "score": form["correlation_action"],
            "existed_before": hid in live_before,
            "enabled_before": bool(live_before.get(hid, {}).get("enabled")) if hid in live_before else None,
        }
        if args.execute:
            item["result"] = push(session, form)
            time.sleep(0.2)
        manifest["items"].append(item)
        print(f"{'PUSH' if args.execute else 'DRY '} {form['hawk_id']} {str(rec.get('filter_name'))[:60]!r} score={form['correlation_action']} existed={item['existed_before']}"
              + (f" -> {item['result']['status']} {item['result']['details'][:60]}" if args.execute else ""))

    if args.verify and (args.execute or ids):
        live_after = fetch_live(session)
        ok = 0
        for item in manifest["items"]:
            hid = item["hawk_id"].lower()
            row = live_after.get(hid)
            item["verified"] = row is not None
            item["enabled_after"] = bool(row.get("enabled")) if row else None
            ok += row is not None
        print(f"verified {ok}/{len(manifest['items'])} present in live /scores")

    out = Path(args.manifest_dir) / f"batch_{stamp}{'' if args.execute else '_dryrun'}.json"
    out.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("manifest:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
