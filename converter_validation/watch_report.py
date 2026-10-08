"""Daily watch report for devices a customer asked us to keep an eye on.

One watchlist per customer in watchlists/<group_guid>.yml (format: watchlists/example.yml.sample).
Each watchlist reads only that customer's explore index (hawkio-<group_guid>) and only agents in
that customer's group subtree, so customers stay isolated. Read-only: no scores are changed.

Per device:
  coverage    is it on the agents page (in this customer's groups), agent version, last
              check-in, duplicate registrations; when its own agent last sent events
  activity    events in the window where the device is the source/actor/target, by role
  detections  scores that fired on those events (baseline tags removed), with the event's
              final weight band - final weight is what opens cases (see case_weight.py)

    python watch_report.py                          # every watchlist, last 24h
    python watch_report.py --customer <guid> --hours 72
Writes reports/watch/<group_guid>/<date>.md (gitignored) and prints it.
"""
import argparse
import datetime
import re
from pathlib import Path

import requests
import urllib3
import yaml

from backtest_explore import BASE, api_key
from score_filters import fetch_group_tree, subtree_names

HERE = Path(__file__).resolve().parent
urllib3.disable_warnings()

# Where a device name shows up. resource_name is the reporting asset (the device's own agent);
# the rest are the device seen in other systems' logs. dns_query is left out: other hosts look
# the name up all day, which says nothing about the device itself.
ROLES = [
    ("own agent", "resource_name"),
    ("source", "hostname"),
    ("source", "ip_src_host"),
    ("source", "hostname_src"),
    ("source", "workstation_name"),
    ("machine account", "target_username"),
    ("destination", "hostname_dst"),
    ("destination", "ip_dst_host"),
]
# result_name entries every event carries - not detections
BASELINE = re.compile(r"^(Bayesian Signature \(.*\)|Asset Risk - .*|Priority \d+( - (Low|High) Threshold)?|"
                      r"Detected (Internal to Internal|Internal to External|External to Internal) Event)$")
BANDS = [("<15", None, 15), ("15-19", 15, 20), ("20-29", 20, 30), ("30-49", 30, 50), (">=50", 50, None)]
MIN_AGENT = (3, 0, 8)   # first build with the YARA allocator fix
STALE_HOURS = 24


def ci(text):
    return "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else re.escape(c) for c in text)


def device_query(name, col):
    # Lucene regexp is anchored: the bare name, its FQDN, or the machine account (NAME$)
    return f"{col}:/{ci(name)}(\\..*|\\$)?/"


class Explore:
    def __init__(self, session, guid, hours):
        self.s, self.idx, self.frm = session, f"hawkio-{guid}", f"now-{int(hours * 60)}m"

    def agg(self, q, group_by, size=200, frm=None):
        j = self.s.post(BASE + "explore/aggregate", data={"idx": self.idx, "q": q, "from": frm or self.frm, "to": "now",
                        "group_by": group_by, "metric": "count", "size": str(size)}, timeout=600, verify=False).json()
        if j.get("status") != "success":
            raise SystemExit(f"explore/aggregate failed for {q!r}: {str(j.get('details'))[:200]}")
        return [(r.get(group_by), int(r.get("count") or 0)) for r in (j.get("results") or {}).get("rows") or []]

    def last_seen(self, q, days=7):
        # explore/search returns newest first
        j = self.s.post(BASE + "explore/search", data={"idx": self.idx, "q": q, "from": f"now-{days}d", "to": "now", "size": "1"},
                        timeout=600, verify=False).json()
        rows = (j.get("results") or {}).get("rows") or []
        return str(rows[0].get("@timestamp")) if rows else None


def band(w):
    for b, lo, hi in BANDS:
        if (lo is None or w >= lo) and (hi is None or w < hi):
            return b
    return BANDS[-1][0]


def version_tuple(v):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(v))
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def report(session, wl, tree, agents, hours, today):
    guid = wl["group_guid"]
    top = next((g for g in tree.get("children") or [] if str(g.get("guid")) == guid), None)
    if top is None or str(top.get("name")).lower() != str(wl["customer"]).lower():
        raise SystemExit(f"watchlist {guid}: customer {wl['customer']!r} does not match the group tree "
                         f"({top.get('name') if top else 'no such group'})")
    groups = {g.lower() for g in subtree_names(tree, top["name"])}
    ex = Explore(session, guid, hours)
    out = [f"# Watch report: {wl['customer']} - {today.isoformat()} (last {hours:g}h)", ""]
    for d in wl.get("devices") or []:
        name = str(d["name"])
        exp = d.get("expires")
        if exp and datetime.date.fromisoformat(str(exp)) < today:
            out += [f"## {name} - EXPIRED {exp} (requested by {d.get('requested_by')}); renew or remove it", ""]
            continue
        out += [f"## {name}", f"Requested by {d.get('requested_by')} on {d.get('added')}, until {exp}: {d.get('reason')}", ""]
        flags = []

        # coverage: agents page, scoped to this customer's groups
        mine = [a for a in agents if str(a.get("hostname")).lower() == name.lower() and str(a.get("group_name")).lower() in groups]
        if not mine:
            flags.append("NOT ON THE AGENTS PAGE - no HAWK agent; only other systems' logs show this device")
        for a in sorted(mine, key=lambda a: str(a.get("date_updated")), reverse=True):
            upd = str(a.get("date_updated"))
            out.append(f"- agent {a.get('agent_id')}: {a.get('agent_version')}, last check-in {upd}, group {a.get('group_name')}, {a.get('os')}")
            if version_tuple(a.get("agent_version")) < MIN_AGENT:
                flags.append(f"agent {a.get('agent_id')} runs {a.get('agent_version')} (older than {'.'.join(map(str, MIN_AGENT))})")
        if len(mine) > 1:
            flags.append(f"{len(mine)} agent registrations for one device (duplicates)")
        if mine:
            newest = max(str(a.get("date_updated")) for a in mine)
            try:
                age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                       - datetime.datetime.fromisoformat(newest)).total_seconds() / 3600
                if age > STALE_HOURS:
                    flags.append(f"agent has not checked in for {age:.0f}h")
            except ValueError:
                pass
        own = ex.last_seen(device_query(name, "resource_name"))
        out.append(f"- own agent telemetry last seen (7 days): {own or 'never'}")
        if mine and not own:
            flags.append("agent is registered but none of its events reached HAWK in 7 days")
        elif own and own[:10] < (today - datetime.timedelta(days=1)).isoformat():
            flags.append(f"own agent telemetry stopped on {own[:10]}")

        # activity and detections in the window
        detections, bands, total = {}, {b: 0 for b, _, _ in BANDS}, 0
        out.append("- activity in the window:")
        for role, col in ROLES:
            q = device_query(name, col)
            rn = ex.agg(q, "result_name", size=500)
            n = sum(c for _, c in rn)
            if not n:
                continue
            total += n
            out.append(f"  - {role} ({col}): {n} events")
            for res, c in rn:
                for t in (x.strip() for x in str(res).split(",")):
                    if t and not BASELINE.match(t):
                        detections.setdefault(t, {})[role] = detections.get(t, {}).get(role, 0) + c
            for w, c in ex.agg(q, "weight", size=200):
                try:
                    bands[band(float(w))] += c
                except (TypeError, ValueError):
                    pass
        if not total:
            out.append("  - none")
            flags.append("no events mention this device in the window")
        out.append(f"- final event weight: {', '.join(f'{b}: {n}' for b, n in bands.items() if n) or 'n/a'}"
                   f"  (cases start around 20)")
        if detections:
            out.append("- detections (score: events by role):")
            for t, roles in sorted(detections.items(), key=lambda kv: -sum(kv[1].values())):
                out.append(f"  - {t}: " + ", ".join(f"{r} {c}" for r, c in roles.items()))
        else:
            out.append("- detections: none")
        if bands[">=50"] or bands["30-49"] or bands["20-29"]:
            flags.append(f"{bands['20-29'] + bands['30-49'] + bands['>=50']} events at case-level weight (>=20)")
        out += ["", "**Attention:** " + ("; ".join(flags) if flags else "nothing - coverage OK, no case-level events"), ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--customer", help="group_guid of one watchlist (default: all)")
    ap.add_argument("--hours", type=float, default=24)
    args = ap.parse_args()
    files = sorted((HERE / "watchlists").glob("*.yml"))
    if args.customer:
        files = [f for f in files if f.stem == args.customer]
    if not files:
        raise SystemExit("no watchlists found")
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + api_key()
    tree = fetch_group_tree(s, BASE)
    agents = s.post(BASE + "search/agents", data={"column[]": ["agent_id", "hostname", "group_name", "agent_version", "os", "date_updated"],
                    "limit": "50000", "exact_columns": "1"}, timeout=300, verify=False).json()["results"]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    for f in files:
        wl = yaml.safe_load(f.read_text(encoding="utf-8"))
        if wl.get("group_guid") != f.stem:
            raise SystemExit(f"{f.name}: group_guid {wl.get('group_guid')} does not match the file name")
        text = report(s, wl, tree, agents, args.hours, today)
        dest = HERE / "reports" / "watch" / f.stem / f"{today.isoformat()}.md"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text + "\n", encoding="utf-8")
        print(text)
        print(f"\n(written to {dest})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
