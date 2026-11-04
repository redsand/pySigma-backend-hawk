"""hunt_explore: what counts as NEW. Run: python test_hunt_explore.py

A hunt is only useful if yesterday's benign value is not reported again under a new spelling. If
per-user folders or per-run installer names leak into the value, every laptop and every install is
"new" and the daily report drowns real findings; if masking is too broad, a renamed attacker binary
collapses into a known benign value and is never reported.
"""
from pathlib import Path

import yaml

from hunt_explore import build_query, normalize

HERE = Path(__file__).resolve().parent


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL " + msg)


# the same software for two users is one value
check(normalize(r"C:\Users\alice\AppData\Roaming\Zoom\bin\Zoom.exe") == normalize(r"C:\Users\Bob.Smith\AppData\Roaming\Zoom\bin\Zoom.exe"),
      "per-user folder must be masked")
# InstallShield runs from a fresh GUID folder with a random _isXXXX.exe each time
check(normalize(r"C:\Windows\Temp\{96B2BD93-6F4B-4CDC-86E3-C063A0C4D944}\{94724ADC}\_isC285.exe")
      == normalize(r"C:\Windows\Temp\{1773DBF7-EE78-46DF-9CED-9B8C03B23335}\{95F4EB9A}\_is180F.exe"), "installer run names must be masked")
# but a binary NAME is the finding: it must survive masking, hex-looking or not
check(normalize(r"C:\Users\alice\Downloads\cafe.exe") != normalize(r"C:\Users\alice\Downloads\beef.exe"), "file names must not be masked")
check(normalize(r"C:\Windows\Temp\_isnotinstaller.exe").endswith("_isnotinstaller.exe"), "only _is + 3-5 hex is an installer stub")

# every hunt builds, and the positive control is first so a broken search fails before any hunt is trusted
hunts = yaml.safe_load((HERE / "hunts.yml").read_text(encoding="utf-8"))["hunts"]
check(hunts and hunts[0].get("expect_hits"), "hunts.yml must start with a positive control")
for h in hunts:
    check(build_query(h), f"{h['name']}: empty query")
print("PASS hunt_explore")
