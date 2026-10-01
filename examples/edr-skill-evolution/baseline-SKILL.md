---
name: edr-triage
description: Initial baseline triage procedure for OpenỌ̀ṣọ́ọ̀sì security alerts and suspicious telemetry events.
---

# EDR Triage Procedure (Baseline)

Follow these initial steps when an alert or event is flagged:

## 1. Event Identification
- Extract the alert timestamp, host, and reported event type.
- Identify the target process name and reported Process ID (PID).

## 2. Basic Filename Check
- Check if the target process filename matches standard Windows system executables (e.g. `svchost.exe`, `lsass.exe`, `explorer.exe`).
- If the filename is recognized as a system binary, treat it with low suspicion unless an alert severity is explicitly set to Critical.

## 3. Produce Triage Report
- Generate a summary JSON report with:
  - `alert_id`: ID of the alert
  - `verdict`: "BENIGN", "SUSPICIOUS", or "MALICIOUS"
  - `summary`: One sentence overview of findings.
