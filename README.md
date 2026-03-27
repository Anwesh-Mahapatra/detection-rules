# Detection Rules

Sigma detection rules with automated conversion and deployment to Splunk.

Built as part of a home SOC lab running on a Dell PowerEdge R720 with Proxmox VE.

## Repository Structure

```
detection-rules/
│
├── rules/                          # Sigma rules organized by platform and tactic
│   ├── windows/
│   │   ├── process_creation/       # Sysmon EventCode 1
│   │   ├── registry/               # Sysmon EventCode 12, 13, 14
│   │   ├── network/                # Sysmon EventCode 3, 22
│   │   ├── credential_access/      # LSASS access, Mimikatz, etc.
│   │   ├── defense_evasion/        # Log clearing, timestomping
│   │   ├── persistence/            # Run keys, scheduled tasks
│   │   ├── lateral_movement/       # PsExec, WMI, RDP
│   │   ├── discovery/              # System info, network enumeration
│   │   └── exfiltration/           # DNS tunneling, large transfers
│   ├── cloud/
│   │   └── aws/                    # AWS CloudTrail detections
│   └── linux/                      # Linux syslog detections
│
├── scripts/
│   ├── sigma2splunk.py             # Converts Sigma to SPL, tests against live Splunk
│   └── deploy_to_splunk.py         # Deploys rules as Splunk saved searches via REST API
│
├── splunk/
│   └── savedsearches/              # Auto-generated SPL files (created by CI/CD)
│
├── tests/                          # Atomic Red Team test procedure mappings
│
├── .github/
│   └── workflows/
│       └── deploy-detections.yml   # CI/CD: auto-converts and deploys on push
│
└── docs/                           # Additional documentation
```

## Pipeline

```
Write Sigma Rule ──> Test Locally ──> Push to GitHub ──> Auto-Deploy to Splunk
     (YAML)        (sigma2splunk.py)    (git push)     (GitHub Actions + REST API)
                         │                                       │
                         ▼                                       ▼
                   Splunk validates                     Saved Search created
                   Shows hits or                       (runs every 5 minutes)
                   suggests field fixes                        │
                                                               ▼
                                                    Alert fires ──> n8n webhook
                                                                       │
                                                                       ▼
                                                              TheHive case created
```

## Tools Used

| Tool | Purpose |
|------|---------|
| [Sigma](https://github.com/SigmaHQ/sigma) | Detection rule standard format |
| [pySigma](https://github.com/SigmaHQ/pySigma) | Rule conversion engine |
| [Splunk Free](https://www.splunk.com) | SIEM - log analysis and detection |
| [Grafana + Loki](https://grafana.com) | Dashboards and log visualization |
| [TheHive](https://thehive-project.org) | Case management |
| [Cortex](https://thehive-project.org) | IOC enrichment (VirusTotal, AbuseIPDB) |
| [n8n](https://n8n.io) | SOAR automation |
| [CALDERA](https://caldera.mitre.org) | Adversary emulation (MITRE) |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Technique-level testing |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | Cloud (AWS) attack simulation |

## Quick Start

### Prerequisites

- Python 3.10+
- pySigma and Splunk backend installed:

```bash
pip install pySigma pySigma-backend-splunk pySigma-pipeline-sysmon pySigma-pipeline-splunk PyYAML requests
```

### Convert and test a single rule

```bash
python scripts/sigma2splunk.py rules/windows/process_creation/powershell_suspicious.yml
```

### Convert and test all rules

```bash
python scripts/sigma2splunk.py --test-all
```

### Convert only (skip Splunk testing)

```bash
python scripts/sigma2splunk.py rules/windows/ --no-test
```

### Search a wider time range

```bash
python scripts/sigma2splunk.py rules/windows/credential_access/lsass_access.yml --earliest=-7d
```

## Detection Coverage

| MITRE Tactic | Technique ID | Rule | Tested |
|---|---|---|---|
| Execution | T1059.001 | PowerShell Suspicious Execution | ☐ |
| Persistence | T1053.005 | Scheduled Task Creation | ☐ |
| Credential Access | T1003.001 | LSASS Memory Access | ☐ |
| Defense Evasion | T1070.001 | Event Log Clearing | ☐ |
| Defense Evasion | T1562.001 | Sysmon Service Tampering | ☐ |

## Lab Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Proxmox VE — Dell PowerEdge R720                        │
│  32 threads | 32GB RAM | ZFS RAIDZ1                      │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  VM 107 — soc-stack (Ubuntu 24.04)                       │
│  ├── Splunk Free              :8000                      │
│  ├── Grafana + Loki           :3000 / :3100              │
│  ├── TheHive + Cortex         :9000 / :9001              │
│  ├── n8n                      :5678                      │
│  └── CALDERA                  :8888                      │
│                                                           │
│  VM 106 — Win11-Baseline (Victim)                        │
│  ├── Sysmon (SwiftOnSecurity config)                     │
│  ├── Splunk Universal Forwarder → soc-stack:9997         │
│  ├── Atomic Red Team                                     │
│  └── CALDERA Sandcat Agent                               │
│                                                           │
│  VM 100 — FlareVM (Analyst Workstation)                  │
│  ├── Git + SSH → GitHub                                  │
│  ├── Python + pySigma                                    │
│  └── sigma2splunk.py (writes + tests rules)              │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

## Author

**Anwesh** — Security Engineer

Building detection engineering portfolio. Focused on SIEM, detection-as-code, and security automation.
