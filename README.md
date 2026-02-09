Architecture, Workflow & Security Model
Project Overview

This repository demonstrates a controls-first approach to infrastructure and cloud security.
It bridges formal security frameworks with practical infrastructure reviews, realistic risk scenarios, and lightweight automation to support governance, assurance, and engineering-aligned security decisions.

Repository Structure

The repository is organised to reflect how infrastructure security is typically assessed in real environments.

```mermaid
flowchart TB
  A[Infrastructure Security Controls Repo] --> B[controls/]
  A --> C[frameworks/]
  A --> D[risk-scenarios/]
  A --> E[examples/]
  A --> F[tools/]
  A --> G[data/]
  A --> H[reports/]

  B --> B1[IAM Controls]
  B --> B2[Network Security Controls]
  B --> B3[Logging & Monitoring Controls]
  B --> B4[Cloud Configuration Controls]

  C --> C1[ISO 27001 Mapping]
  C --> C2[NIST CSF Mapping]
  C --> C3[CIS Benchmarks Mapping]

  D --> D1[Excessive Privileges]
  D --> D2[Exposed Services]
  D --> D3[Insufficient Logging]

  E --> E1[Firewall Rule Review Example]
  E --> E2[Access Review Example]

  F --> F1[firewall_linter.py]
  F --> F2[iam_review.py]
  F --> F3[vuln_to_risk_report.py]
```

How the Repository Is Used

The workflow mirrors a real infrastructure security or assurance engagement: controls → evidence → findings → reporting.
```mermaid
sequenceDiagram
  participant Reviewer as Security Reviewer
  participant Controls as controls/*.md
  participant Evidence as Evidence (exports/logs/reports)
  participant Tools as tools/*.py
  participant Findings as Risk Findings
  participant Report as reports/*.md

  Reviewer->>Controls: Select applicable controls
  Reviewer->>Evidence: Collect technical evidence
  Reviewer->>Tools: Run lightweight review helpers
  Tools-->>Reviewer: Governance gaps & signals
  Reviewer->>Findings: Document risk-based findings
  Reviewer->>Report: Produce management-ready summary
```
Control & Framework Mapping Logic

Security frameworks provide structure, while controls define expectations and risk scenarios explain failure modes.
```mermaid
flowchart LR
  ISO[ISO/IEC 27001] --> MAP[frameworks/*-mapping.md]
  NIST[NIST CSF] --> MAP
  CIS[CIS Benchmarks] --> MAP

  MAP --> CTRL[controls/*.md]
  CTRL --> RS[risk-scenarios/*.md]
  RS --> EX[examples/*.md]
```
