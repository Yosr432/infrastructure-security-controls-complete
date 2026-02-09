#!/usr/bin/env python3
"""
IAM Access Review Helper (CSV)

Flags accounts that likely need review:
- Admin/privileged users
- Inactive users based on last_login
- Service accounts without owners
- Shared accounts

CSV columns (recommended):
username,role,is_admin(true/false),last_login(YYYY-MM-DD),account_type(user/service),owner,status(active/disabled)
"""

import csv
import sys
from datetime import datetime, date
from pathlib import Path


def parse_date(s: str):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def as_bool(s: str) -> bool:
    return (s or "").strip().lower() in {"true", "1", "yes", "y"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/iam_review.py data/iam_export.csv [--inactive-days 90]")
        sys.exit(2)

    csv_path = Path(sys.argv[1])
    inactive_days = 90
    if "--inactive-days" in sys.argv:
        i = sys.argv.index("--inactive-days")
        try:
            inactive_days = int(sys.argv[i + 1])
        except Exception:
            print("Invalid --inactive-days value")
            sys.exit(2)

    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        sys.exit(1)

    today = date.today()

    flagged = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"username", "role", "is_admin", "last_login", "account_type", "owner", "status"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            print(f"Missing required columns: {', '.join(sorted(missing))}")
            sys.exit(2)

        for row in reader:
            username = (row.get("username") or "").strip()
            role = (row.get("role") or "").strip()
            is_admin = as_bool(row.get("is_admin"))
            last_login = parse_date(row.get("last_login"))
            acct_type = (row.get("account_type") or "").strip().lower()
            owner = (row.get("owner") or "").strip()
            status = (row.get("status") or "").strip().lower()

            reasons = []

            if status != "active":
                continue  # ignore disabled accounts in this simple version

            if is_admin or "admin" in role.lower():
                reasons.append("Privileged/admin access")

            if last_login:
                age = (today - last_login).days
                if age >= inactive_days:
                    reasons.append(f"Inactive account (last login {age} days ago)")
            else:
                reasons.append("Missing/invalid last_login")

            if acct_type == "service" and not owner:
                reasons.append("Service account missing owner")

            if "shared" in username.lower():
                reasons.append("Potential shared account (username contains 'shared')")

            if reasons:
                flagged.append((username, reasons, row))

    if not flagged:
        print("✅ No accounts flagged.")
        return

    print(f"⚠️ Flagged {len(flagged)} accounts for review (inactive_days={inactive_days}):\n")
    for username, reasons, row in flagged:
        print(f"- {username} ({row.get('role')}, type={row.get('account_type')}):")
        for r in reasons:
            print(f"   • {r}")
        print()

    sys.exit(1)


if __name__ == "__main__":
    main()
