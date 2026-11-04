"""Run one scheduled detection job and email its outcome, so a failed or stalled job is never silent.

    python run_job.py <name> <script.py> [args...]

Writes reports/<name>_last.log (as the old .cmd wrappers did) and mails the job's summary.md when the
script prints a `report: <path>` line, else the log tail. A non-zero exit, a timeout or a crash is
mailed with FAILED in the subject and the runner exits non-zero, so the scheduled task shows it too.

Mail settings (env): DETECTION_SMTP (host:port, default the octorepl relay), DETECTION_MAIL_TO,
DETECTION_MAIL_FROM. DETECTION_SMTP=off disables mail (tests, dev boxes).
"""
import os
import re
import smtplib
import subprocess
import sys
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).resolve().parent
SMTP = os.environ.get("DETECTION_SMTP", "10.11.0.200:1025")
MAIL_TO = os.environ.get("DETECTION_MAIL_TO", "tshelton@hawkdefense.com")
MAIL_FROM = os.environ.get("DETECTION_MAIL_FROM", "hawk-detection-jobs@hawk.io")
TIMEOUT = int(os.environ.get("DETECTION_JOB_TIMEOUT", str(6 * 3600)))


def mail(subject: str, body: str) -> None:
    if SMTP == "off":
        return
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, MAIL_FROM, MAIL_TO
    msg.set_content(body)
    host, _, port = SMTP.partition(":")
    with smtplib.SMTP(host, int(port or 25), timeout=60) as s:
        s.send_message(msg)


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    name, cmd = sys.argv[1], [sys.executable, *sys.argv[2:]]
    log = HERE / "reports" / f"{name}_last.log"
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=TIMEOUT)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out = -1, f"{e.stdout or ''}{e.stderr or ''}\nTIMEOUT after {TIMEOUT}s"
    log.write_text(out, encoding="utf-8", errors="replace")
    m = re.findall(r"(?m)^report: (.+)$", out)
    report = Path(m[-1].strip()) if m else None
    if rc == 0 and report and report.exists():
        body = report.read_text(encoding="utf-8")
    else:
        body = f"exit code {rc}\nlog: {log}\n\n" + out[-6000:]
    subject = f"[HAWK detection] {name}: {'ok' if rc == 0 else 'FAILED'}"
    try:
        mail(subject, body)
    except OSError as e:
        print(f"mail failed: {e}", file=sys.stderr)
        rc = rc or 3  # the job ran, but nobody will hear about it: still a failure of the job's purpose
    print(out[-3000:])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
