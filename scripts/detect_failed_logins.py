#!/usr/bin/env python3

import argparse
import re
from collections import Counter
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Analyze failed authentication events."
)
parser.add_argument(
    "log_file",
    nargs="?",
    default="logs/auth-events.txt",
    help="Input authentication log file",
)
parser.add_argument(
    "--report",
    default="reports/failed-login-report.txt",
    help="Output report path",
)
parser.add_argument(
    "--threshold",
    type=int,
    default=3,
    help="Alert when an account reaches this event count",
)
args = parser.parse_args()

if args.threshold < 1:
    parser.error("--threshold must be at least 1")

log_file = Path(args.log_file)
report_file = Path(args.report)

if not log_file.is_file():
    parser.error(f"Log file not found: {log_file}")

lines = [
    line.strip()
    for line in log_file.read_text(errors="replace").splitlines()
    if line.strip()
]

user_counts = Counter()
service_counts = Counter()
events = []

for line in lines:
    match = re.search(r"\buser=([^\s;]+)", line)
    if not match:
        match = re.search(
            r"Failed password for (?:invalid user )?(\S+)", line
        )

    username = match.group(1) if match else "unknown"

    if "gdm-password" in line:
        service = "gdm-password"
    elif "sshd" in line:
        service = "sshd"
    else:
        service = "other/unknown"

    timestamp = line[:15] if len(line) >= 15 else "unknown time"

    user_counts[username] += 1
    service_counts[service] += 1
    events.append((timestamp, username, service))

report = [
    "FAILED LOGIN DETECTION REPORT",
    "=" * 32,
    f"Input file: {log_file}",
    f"Matching events analyzed: {len(events)}",
    "",
    "Events by account:",
]

for username, count in user_counts.most_common():
    report.append(f"  {username}: {count}")

report.extend(["", "Events by service:"])

for service, count in service_counts.most_common():
    report.append(f"  {service}: {count}")

report.extend(["", "Event timeline:"])

for timestamp, username, service in events:
    report.append(
        f"  {timestamp} | account={username} | service={service}"
    )

report.extend(["", f"THRESHOLD ALERTS ({args.threshold}+ events)"])

alerts = [
    (username, count)
    for username, count in user_counts.items()
    if count >= args.threshold
]

if alerts:
    report.extend(
        f"  ALERT: {username} has {count} failed events"
        for username, count in alerts
    )
else:
    report.append("  No accounts reached the threshold.")

report.extend([
    "",
    "ASSESSMENT",
    "Failed authentication does not by itself confirm malicious activity.",
    "Source IPs and attack attribution are not inferred from these records.",
    "Further investigation is needed to establish cause and intent.",
])

report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text("\n".join(report) + "\n")

print("\n".join(report))
print(f"\nReport saved to: {report_file}")
