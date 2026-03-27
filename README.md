# Detection Rules

Sigma detection rules with automated conversion and deployment to Splunk.

## Repository Structure
detection-rules/
├── rules/                    # Sigma rules organized by platform/category
│   ├── windows/
│   │   ├── process_creation/ # Sysmon EventCode 1
│   │   ├── registry/         # Sysmon EventCode 12, 13, 14
│   │   ├── network/          # Sysmon EventCode 3, 22
│   │   ├── credential_access/# LSASS, mimikatz, etc.
│   │   ├── defense_evasion/  # Log clearing, timestomping
│   │   ├── persistence/      # Run keys, scheduled tasks
│   │   ├── lateral_movement/ # PsExec, WMI, RDP
│   │   ├── discovery/        # System info, network enum
│   │   └── exfiltration/     # DNS tunneling, large transfers
│   ├── cloud/aws/            # AWS CloudTrail detections
│   └── linux/                # Linux syslog detections
├── scripts/                  # Conversion and testing scripts
├── tests/                    # Atomic Red Team test mappings
├── splunk/                   # Auto-generated Splunk savedsearches
│   └── savedsearches/        # SPL files deployed to Splunk
├── .github/workflows/        # CI/CD pipeline
└── docs/                     # Documentation

## Pipeline

1. Write Sigma rule in `rules/`
2. Test locally using `scripts/sigma2splunk.py`
3. Push to GitHub
4. GitHub Actions auto-converts and deploys to Splunk

## Tools Used

- [Sigma](https://github.com/SigmaHQ/sigma) - Detection rule format
- [pySigma](https://github.com/SigmaHQ/pySigma) - Rule conversion
- [Splunk Free](https://www.splunk.com) - SIEM
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Testing

## Author

Anwesh - Security Engineer