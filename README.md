# Security Review & Assurance Helpers

## Purpose
The scripts in this directory are lightweight security helpers designed
to support **infrastructure security reviews**, **control assurance**,
and **risk-based decision making**.

They are intentionally simple and transparent, focusing on:
- Control effectiveness
- Governance signals
- Risk visibility

Rather than performing exploitation or intrusive testing, these tools
help identify **systemic weaknesses**, **poor security hygiene**, and
**control gaps** commonly observed in real-world infrastructure.

## Tools Overview

### firewall_linter.py
Reviews firewall rules exported in CSV format and flags:
- Overly permissive rules (ANY / 0.0.0.0/0)
- Wide or undefined port ranges
- Missing ownership or justification
- Stale rules lacking periodic review

**Typical use cases:**
- Network security governance reviews  
- Firewall rulebase clean-up exercises  
- Audit and assurance activities  

---

### iam_review.py
Assists with periodic identity and access management (IAM) reviews by
highlighting:
- Privileged or admin accounts
- Inactive users
- Service accounts without owners
- Potential shared accounts

**Typical use cases:**
- Access recertification support  
- Privileged access governance  
- IAM control effectiveness reviews  

---

### vuln_to_risk_report.py
Transforms vulnerability or penetration test outputs into a structured,
management-ready **risk summary**.

The script:
- Aggregates findings by severity
- Identifies common root causes
- Highlights assets with concentrated risk

**Typical use cases:**
- Translating technical findings into risk language  
- Supporting remediation prioritisation  
- Audit reporting and assurance  

## Design Principles
- No external dependencies
- Readable, auditable code
- Clear input/output formats
- Security controls and risk context over tooling complexity

## Disclaimer
These tools are provided for educational and demonstration purposes and
do not replace production-grade security tooling.
