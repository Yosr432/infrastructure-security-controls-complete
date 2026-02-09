#!/usr/bin/env python3
"""
Firewall Rules Linter (CSV)

Flags risky or poorly-governed rules:
- ANY source/destination (0.0.0.0/0, any)
- Wide port ranges
- Missing owner/comment
- Old rules (if date_added provided)

CSV columns (recommended):
rule_id,src,dst,port,protocol,action,owner,comment,date_added(YYYY-MM-DD)
"""

import csv
import sys
from datetime import datetime, date
from pathlib import Path

ANY_VALUES = {"any", "0.0.0.0/0", "::/0", "*"}


def parse_date(s: str):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def port_is_wide(port: str) -> bool:
    """Return True if port is wide / risky."""
    p = (port or "").strip().lower()
    if not p or p in {"any", "*"}:
        return True
    # Examples: "22", "80,443", "1000-2000"
    if "-" in p:
        try:
            a, b = p.split("-", 1)
            a_i, b_i = int(a.strip()), int(b.strip())
            return (b_i - a_i) >= 1000 or (a_i == 0 and b_i == 65535)
        except ValueError:
            return True
    # Multiple ports
    if "," in p:
        parts = [x.strip() for x in p.split(",") if x.strip()]
        # If someone listed a huge list, still not ideal
        return len(parts) >= 20
    # Single port
    try:
        int(p)
        return False
    except ValueError:
        return True


def is_any(s: str) -> bool:
    return (s or "").strip().lower() in ANY_VALUES


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/firewall_linter.py data/firewall_rules.csv [--max-age-days 180]")
        sys.exit(2)

    csv_path = Path(sys.argv[1])
    max_age_days = 180
    if "--max-age-days" in sys.argv:
        i = sys.argv.index("--max-age-days")
        try:
            max_age_days = int(sys.argv[i + 1])
        except Exception:
            print("Invalid --max-age-days value")
            sys.exit(2)

    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        sys.exit(1)

    findings = []
    today = date.today()

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"rule_id", "src", "dst", "port", "protocol", "action"}
        missing_cols = required - set(reader.fieldnames or [])
        if missing_cols:
            print(f"Missing required columns: {', '.join(sorted(missing_cols))}")
            sys.exit(2)

        for row in reader:
            rid = (row.get("rule_id") or "").strip() or "<no-id>"
            src = row.get("src", "")
            dst = row.get("dst", "")
            port = row.get("port", "")
            owner = (row.get("owner") or "").strip()
            comment = (row.get("comment") or "").strip()
            date_added = parse_date(row.get("date_added", ""))

            issues = []

            if is_any(src):
                issues.append("Source is ANY (0.0.0.0/0)")
            if is_any(dst):
                issues.append("Destination is ANY (::/0 or any)")
            if port_is_wide(port):
                issues.append(f"Port definition is wide/invalid: '{port}'")
            if not owner:
                issues.append("Missing owner")
            if not comment:
                issues.append("Missing comment/justification")

            if date_added:
                age = (today - date_added).days
                if age > max_age_days:
                    issues.append(f"Rule is old ({age} days > {max_age_days})")
            elif "date_added" in (reader.fieldnames or []):
                issues.append("Missing/invalid date_added")

            if issues:
                findings.append((rid, issues, row))

    if not findings:
        print("✅ No issues found.")
        return

    print(f"⚠️ Found {len(findings)} rules with issues:\n")
    for rid, issues, row in findings:
        print(f"- Rule {rid}:")
        for issue in issues:
            print(f"   • {issue}")
        print(f"   Context: src={row.get('src')} dst={row.get('dst')} port={row.get('port')} action={row.get('action')}")
        print()

    sys.exit(1)


if __name__ == "__main__":
    main()
