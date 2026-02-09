#!/usr/bin/env python3
"""
Vulnerability Report -> Risk Summary (Markdown)

Input: JSON findings list with fields:
- id, title, severity, asset, evidence, recommendation(optional), root_cause(optional)

Output: Markdown report with:
- Summary by severity
- Top findings
- Common root causes
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def sev_key(sev: str) -> int:
    return SEV_ORDER.get((sev or "").strip().lower(), -1)


def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/vuln_to_risk_report.py data/vuln_report.json reports/risk_report.md")
        sys.exit(2)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    data = json.loads(in_path.read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        print("Invalid JSON: expected {\"findings\": [...]} ")
        sys.exit(2)

    severities = Counter((f.get("severity", "unknown") or "unknown").lower() for f in findings)
    root_causes = Counter((f.get("root_cause", "unspecified") or "unspecified").lower() for f in findings)

    # Top findings: sort by severity then title
    top = sorted(findings, key=lambda f: (-sev_key(f.get("severity")), (f.get("title") or "")))[:10]

    # Group by asset
    by_asset = defaultdict(list)
    for f in findings:
        by_asset[f.get("asset", "unknown")].append(f)

    md = []
    md.append("# Risk Summary Report\n")
    md.append(f"Total findings: **{len(findings)}**\n")

    md.append("## Severity Breakdown\n")
    for sev, count in sorted(severities.items(), key=lambda x: -sev_key(x[0])):
        md.append(f"- **{sev.title()}**: {count}")
    md.append("")

    md.append("## Top Findings (by severity)\n")
    for f in top:
        md.append(f"### {f.get('id','N/A')} — {f.get('title','(no title)')}")
        md.append(f"- Severity: **{(f.get('severity') or 'unknown').title()}**")
        md.append(f"- Asset: `{f.get('asset','unknown')}`")
        if f.get("root_cause"):
            md.append(f"- Root cause: {f.get('root_cause')}")
        if f.get("evidence"):
            md.append(f"- Evidence: {f.get('evidence')}")
        if f.get("recommendation"):
            md.append(f"- Recommendation: {f.get('recommendation')}")
        md.append("")

    md.append("## Common Root Causes\n")
    for cause, count in root_causes.most_common(10):
        md.append(f"- {cause}: {count}")
    md.append("")

    md.append("## Findings by Asset (count)\n")
    for asset, flist in sorted(by_asset.items(), key=lambda x: len(x[1]), reverse=True):
        md.append(f"- `{asset}`: {len(flist)}")
    md.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(md), encoding="utf-8")
    print(f"✅ Wrote report to: {out_path}")


if __name__ == "__main__":
    main()
