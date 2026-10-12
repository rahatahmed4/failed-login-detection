# Failed Login Detection & Log Investigation

A beginner SOC Analyst portfolio project built with Python and Ubuntu Linux.

## Objectives

- Analyze authentication logs for failed login events.
- Extract usernames, timestamps, and authentication services.
- Count events by account and service.
- Generate configurable threshold alerts.
- Produce an investigation report.

## Tools

- Ubuntu Linux
- Python 3
- Linux authentication logs
- Git and GitHub

## Project Structure

```text
project-03/
├── logs/
│   └── sample-auth-events.txt
├── reports/
│   └── sample-detection-report.txt
├── scripts/
│   └── detect_failed_logins.py
├── .gitignore
└── README.md
```

## Run the Detector

```bash
python3 scripts/detect_failed_logins.py logs/sample-auth-events.txt --report reports/sample-detection-report.txt
```

Set a different alert threshold:

```bash
python3 scripts/detect_failed_logins.py logs/sample-auth-events.txt --threshold 5 --report reports/sample-detection-report.txt
```

## Sample Findings

The sanitized demonstration dataset contains three failed authentication events for a fictional account named `analyst`. With the default threshold of three, the script raises an alert.

These are demonstration records, not original forensic evidence.

## Investigation Assessment

Failed authentication does not automatically indicate a cyberattack. Analysts should review event frequency, timing, source information, affected accounts, and surrounding activity before reaching a conclusion.

## Current Limitations

- The threshold counts events across the entire file, not within a time window.
- Source IP extraction and correlation are not implemented.
- The parser supports only a limited set of log formats.
- Alerts require analyst review and do not confirm malicious activity.

## Future Improvements

- Add time-window-based detection.
- Extract source IPs when available.
- Create automated unit tests.
- Support additional authentication log formats.
- Correlate events to identify suspicious patterns.

## Disclaimer

For educational and defensive security analysis. Only analyze logs you are authorized to access. Never publish raw authentication logs containing sensitive information.
