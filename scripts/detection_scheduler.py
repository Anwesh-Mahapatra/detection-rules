#!/usr/bin/env python3
"""
detection_scheduler.py — External Detection Scheduler for Splunk Free

WHY THIS EXISTS:
================
Splunk Free does NOT support scheduled saved searches or alerting.
Once the 60-day Enterprise trial expires, all your deployed saved
searches stop firing. This script replaces Splunk's internal scheduler.

HOW IT WORKS:
=============
1. Reads all deployed detection rules from .deploy_state.json
2. For each rule, runs the SPL query against Splunk via REST API
   (REST API searches work on Splunk Free — only the internal
   scheduler is disabled)
3. If results > 0: fires the n8n webhook with the alert data
4. Tracks what it already fired to avoid duplicate alerts
5. Runs via cron every 5 minutes (or however often you want)

SETUP:
======
    # Make it executable
    chmod +x scripts/detection_scheduler.py

    # Test run (shows what would happen)
    python3 scripts/detection_scheduler.py --dry-run

    # Single manual run
    python3 scripts/detection_scheduler.py

    # Add to cron (every 5 minutes)
    crontab -e
    # Add this line:
    # */5 * * * * /usr/bin/python3 /home/anwesh/actions-runner/_work/detection-rules/detection-rules/scripts/detection_scheduler.py >> /var/log/detection_scheduler.log 2>&1

    # Or install as systemd timer (more reliable than cron):
    sudo cp scripts/detection_scheduler.service /etc/systemd/system/
    sudo cp scripts/detection_scheduler.timer /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now detection_scheduler.timer

USAGE:
======
    python3 detection_scheduler.py              # Normal run
    python3 detection_scheduler.py --dry-run    # Show what would fire, don't actually fire
    python3 detection_scheduler.py --verbose    # Show detailed output for every rule
    python3 detection_scheduler.py --once RULE  # Run a single rule by name/path
    python3 detection_scheduler.py --status     # Show scheduler state
"""

import os
import sys
import json
import yaml # type: ignore
import time
import hashlib
import argparse
import requests # type: ignore
import urllib3 # type: ignore
from datetime import datetime, timezone, timedelta
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURATION
# ============================================================

# Splunk connection
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', '192.168.1.162')
SPLUNK_PORT = os.environ.get('SPLUNK_PORT', '8089')
SPLUNK_WEB_PORT = os.environ.get('SPLUNK_WEB_PORT', '8000')
SPLUNK_USER = os.environ.get('SPLUNK_USER', 'admin')
SPLUNK_PASS = os.environ.get('SPLUNK_PASS', 'ChangeMeNow1!')
SPLUNK_API = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# n8n webhook for alert forwarding
N8N_WEBHOOK_URL = os.environ.get(
    'N8N_WEBHOOK_URL',
    'http://192.168.1.162:5678/webhook-test/splunk-alert'
)

# Paths
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY_STATE = os.path.join(REPO_ROOT, '.deploy_state.json')
SCHEDULER_STATE = os.path.join(REPO_ROOT, '.scheduler_state.json')
SPL_DIR = os.path.join(REPO_ROOT, 'splunk', 'savedsearches')

# How far back each run searches (should match cron interval)
# If you run every 5 minutes, search the last 6 minutes (1 min overlap for safety)
DEFAULT_SEARCH_WINDOW = '-6m'

# Deduplication window: don't re-alert on the same event within this period
# This prevents the same event from triggering multiple alerts across runs
DEDUP_WINDOW_MINUTES = 30

# Maximum concurrent searches (don't overload Splunk Free)
MAX_CONCURRENT_SEARCHES = 3

# Timeout for each search (seconds)
SEARCH_TIMEOUT = 120


# ============================================================
# TERMINAL OUTPUT
# ============================================================

class C:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

# Disable colors if not a terminal (e.g., running from cron)
if not sys.stdout.isatty():
    for attr in dir(C):
        if not attr.startswith('_'):
            setattr(C, attr, '')


def log(msg, level='INFO'):
    """Print a timestamped log message."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{ts}] [{level}] {msg}")


# ============================================================
# SCHEDULER STATE
#
# Separate from deploy state. Tracks:
# - Last run time for each rule
# - Last alert hashes (for deduplication)
# - Alert counts per rule (for metrics)
#
# Structure:
# {
#   "last_run": "2026-03-28T10:00:00Z",
#   "rules": {
#     "Detection: Suspicious PowerShell Execution": {
#       "last_searched": "2026-03-28T10:00:00Z",
#       "last_alert_time": "2026-03-28T09:55:00Z",
#       "total_alerts": 5,
#       "recent_event_hashes": ["abc123", "def456"],
#       "consecutive_failures": 0
#     }
#   }
# }
# ============================================================

def load_scheduler_state():
    """Load scheduler state from disk."""
    if os.path.exists(SCHEDULER_STATE):
        try:
            with open(SCHEDULER_STATE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, KeyError):
            pass
    return {'last_run': None, 'rules': {}}


def save_scheduler_state(state):
    """Save scheduler state to disk."""
    state['last_run'] = datetime.now(timezone.utc).isoformat()
    with open(SCHEDULER_STATE, 'w') as f:
        json.dump(state, f, indent=2)


def event_hash(event):
    """Create a hash of an event for deduplication.

    We hash a combination of fields that uniquely identify an event.
    If Splunk returns the same event in the next run, the hash will
    match and we skip it.
    """
    # Use _time + _raw as the unique identifier
    # Falls back to the entire event dict if those aren't present
    key_parts = [
        event.get('_time', ''),
        event.get('_raw', ''),
        event.get('_cd', ''),  # Splunk's internal event ID
    ]
    key = '|'.join(str(p) for p in key_parts)
    return hashlib.md5(key.encode()).hexdigest()


# ============================================================
# LOAD DETECTION RULES
# ============================================================

def load_detection_rules():
    """Load all deployed detection rules from SPL files.

    Reads the YAML files in splunk/savedsearches/ that were
    generated by sigma2splunk.py and deployed by deploy_to_splunk.py.

    Returns:
        list of dicts, each containing the rule metadata and SPL query
    """
    rules = []

    if not os.path.exists(SPL_DIR):
        log(f"SPL directory not found: {SPL_DIR}", 'WARN')
        return rules

    for filename in sorted(os.listdir(SPL_DIR)):
        if not filename.endswith('.yml'):
            continue

        filepath = os.path.join(SPL_DIR, filename)
        try:
            with open(filepath, 'r') as f:
                rule_data = yaml.safe_load(f)

            ss = rule_data.get('splunk_saved_search', {})
            spl_query = ss.get('search', '')
            name = ss.get('name', '')

            if not spl_query or not name:
                continue

            # Determine search window based on severity
            level = rule_data.get('rule_level', 'medium')
            window_map = {
                'critical': '-2m',   # Check more frequently
                'high': '-3m',
                'medium': '-6m',
                'low': '-16m',
                'informational': '-31m'
            }
            search_window = window_map.get(level, DEFAULT_SEARCH_WINDOW)

            rules.append({
                'name': name,
                'spl_query': spl_query,
                'level': level,
                'title': rule_data.get('rule_title', name),
                'description': rule_data.get('description', ''),
                'mitre': rule_data.get('mitre_attack', []),
                'source_file': rule_data.get('source_sigma_file', ''),
                'search_window': search_window,
                'filename': filename
            })

        except Exception as e:
            log(f"Error loading {filename}: {e}", 'ERROR')

    return rules


# ============================================================
# SPLUNK SEARCH EXECUTION
# ============================================================

def run_search(spl_query, earliest='-6m', latest='now'):
    """Run an SPL search against Splunk and return results.

    Uses Splunk's REST API which works even on Splunk Free.
    The only thing Free disables is the INTERNAL scheduler —
    API-initiated searches work fine.

    Args:
        spl_query: The SPL search string
        earliest: Search time range start
        latest: Search time range end

    Returns:
        list of result dicts, or None on error
    """
    try:
        # Create search job
        resp = requests.post(
            f"{SPLUNK_API}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data={
                'search': f"search {spl_query} | head 100",
                'earliest_time': earliest,
                'latest_time': latest,
                'output_mode': 'json'
            }
        )

        if resp.status_code != 201:
            return None

        sid = resp.json()['sid']

        # Poll until done
        for _ in range(SEARCH_TIMEOUT):
            status_resp = requests.get(
                f"{SPLUNK_API}/services/search/jobs/{sid}",
                auth=(SPLUNK_USER, SPLUNK_PASS),
                verify=False,
                params={'output_mode': 'json'}
            )

            job = status_resp.json()['entry'][0]['content']
            if job['isDone']:
                break
            time.sleep(1)
        else:
            log(f"Search timed out after {SEARCH_TIMEOUT}s", 'WARN')
            return None

        event_count = int(job.get('eventCount', 0))
        if event_count == 0:
            return []

        # Get results
        results_resp = requests.get(
            f"{SPLUNK_API}/services/search/jobs/{sid}/results",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={'output_mode': 'json', 'count': 100}
        )

        return results_resp.json().get('results', [])

    except requests.exceptions.ConnectionError:
        log(f"Cannot connect to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}", 'ERROR')
        return None
    except Exception as e:
        log(f"Search error: {e}", 'ERROR')
        return None


# ============================================================
# ALERT FIRING (n8n WEBHOOK)
# ============================================================

def fire_alert(rule, results, dry_run=False):
    """Send alert data to n8n via webhook.

    Formats the data to match what Splunk's native webhook action
    would send, so your n8n workflow doesn't need to change.

    Args:
        rule: dict with rule metadata
        results: list of matching Splunk events
        dry_run: if True, just print what would happen

    Returns:
        True if webhook sent successfully
    """
    # Build payload that mimics Splunk's webhook format
    # This way n8n workflows work the same whether alerts come
    # from Splunk's scheduler or this external scheduler
    for i, result in enumerate(results):
        payload = {
            'search_name': rule['name'],
            'results_link': (
                f"http://{SPLUNK_HOST}:{SPLUNK_WEB_PORT}/en-US/app/search/search"
                f"?q=search%20{requests.utils.quote(rule['spl_query'])}"
                f"&earliest={rule['search_window']}&latest=now"
            ),
            'result': result,
            'result_count': len(results),
            'alert_metadata': {
                'rule_title': rule['title'],
                'rule_level': rule['level'],
                'mitre_attack': rule['mitre'],
                'description': rule['description'],
                'source_sigma_file': rule['source_file'],
                'fired_by': 'detection_scheduler',
                'fired_at': datetime.now(timezone.utc).isoformat()
            }
        }

        if dry_run:
            log(f"  [DRY RUN] Would fire webhook for event {i+1}/{len(results)}")
            continue

        try:
            resp = requests.post(
                N8N_WEBHOOK_URL,
                json=payload,
                timeout=10
            )

            if resp.status_code in [200, 201]:
                # Only send first event to avoid flooding n8n
                # n8n can query Splunk for the full result set if needed
                return True
            else:
                log(f"  Webhook returned {resp.status_code}", 'WARN')
                return False

        except requests.exceptions.ConnectionError:
            log(f"  Cannot reach n8n at {N8N_WEBHOOK_URL}", 'WARN')
            return False
        except Exception as e:
            log(f"  Webhook error: {e}", 'ERROR')
            return False

        # Only send the first event per rule per run
        break

    return True


# ============================================================
# MAIN SCHEDULER LOOP
# ============================================================

def run_scheduler(args):
    """Main scheduler function.

    Loads all detection rules, runs each one against Splunk,
    deduplicates results, and fires webhooks for new detections.
    """
    start_time = datetime.now()
    log("=" * 60)
    log("Detection Scheduler starting")
    log("=" * 60)

    # Load rules
    rules = load_detection_rules()
    if not rules:
        log("No detection rules found — nothing to do", 'WARN')
        return

    log(f"Loaded {len(rules)} detection rules")

    # Filter to single rule if --once specified
    if args.once:
        rules = [r for r in rules if args.once.lower() in r['name'].lower()
                 or args.once.lower() in r['source_file'].lower()
                 or args.once.lower() in r['filename'].lower()]
        if not rules:
            log(f"No rule matching '{args.once}' found", 'ERROR')
            return
        log(f"Running single rule: {rules[0]['name']}")

    # Load scheduler state (for dedup)
    sched_state = load_scheduler_state()

    # Check Splunk connectivity
    try:
        resp = requests.get(
            f"{SPLUNK_API}/services/server/info",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={'output_mode': 'json'},
            timeout=5
        )
        if resp.status_code != 200:
            log(f"Splunk returned {resp.status_code} — aborting", 'ERROR')
            return
    except Exception:
        log(f"Cannot connect to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT} — aborting", 'ERROR')
        return

    log(f"Splunk connected at {SPLUNK_HOST}:{SPLUNK_PORT}")

    # Lab mode banners
    if hasattr(args, 'alltime') and args.alltime:
        log(f"{C.CYAN}▶ ALL-TIME MODE — searching entire index, no time windows{C.END}")
    if hasattr(args, 'interactive') and args.interactive:
        log(f"{C.CYAN}▶ INTERACTIVE MODE — will ask before firing each alert{C.END}")

    # Process each rule
    stats = {
        'total': len(rules),
        'searched': 0,
        'with_results': 0,
        'alerts_fired': 0,
        'deduplicated': 0,
        'errors': 0,
        'skipped': 0
    }

    for rule in rules:
        rule_name = rule['name']
        rule_state = sched_state['rules'].get(rule_name, {
            'last_searched': None,
            'last_alert_time': None,
            'total_alerts': 0,
            'recent_event_hashes': [],
            'consecutive_failures': 0
        })

        if args.verbose:
            log(f"\n{'─' * 50}")
            log(f"Rule: {rule['title']}")
            log(f"Level: {rule['level']}")

        # Override search window in alltime/interactive mode
        search_window = rule['search_window']
        if hasattr(args, 'alltime') and args.alltime:
            search_window = '0'  # Splunk '0' = all time

        if args.verbose:
            log(f"Window: {search_window}")
            log(f"SPL: {rule['spl_query'][:80]}...")

        # Run the search
        results = run_search(
            rule['spl_query'],
            earliest=search_window,
            latest='now'
        )

        rule_state['last_searched'] = datetime.now(timezone.utc).isoformat()
        stats['searched'] += 1

        if results is None:
            # Search error
            log(f"  {C.RED}✗{C.END} {rule['title']} — search error", 'ERROR')
            rule_state['consecutive_failures'] = rule_state.get('consecutive_failures', 0) + 1
            stats['errors'] += 1
            sched_state['rules'][rule_name] = rule_state
            continue

        rule_state['consecutive_failures'] = 0

        if len(results) == 0:
            if args.verbose:
                log(f"  {C.DIM}○{C.END} {rule['title']} — no results")
            sched_state['rules'][rule_name] = rule_state
            continue

        # We have results — check for duplicates
        stats['with_results'] += 1

        # Skip dedup in alltime mode — treat all results as new
        if hasattr(args, 'alltime') and args.alltime:
            new_results = results
            deduped_count = 0
        else:
            old_hashes = set(rule_state.get('recent_event_hashes', []))
            new_results = []

            for event in results:
                h = event_hash(event)
                if h not in old_hashes:
                    new_results.append(event)

            deduped_count = len(results) - len(new_results)
            if deduped_count > 0:
                stats['deduplicated'] += deduped_count
                if args.verbose:
                    log(f"  Deduplicated {deduped_count} already-seen events")

        if len(new_results) == 0:
            if args.verbose:
                log(f"  {C.DIM}○{C.END} {rule['title']} — {len(results)} results (all previously seen)")
            sched_state['rules'][rule_name] = rule_state
            continue

        # New events found — fire alert
        level_color = {
            'critical': C.RED, 'high': C.RED,
            'medium': C.YELLOW, 'low': C.BLUE
        }.get(rule['level'], C.END)

        log(f"  {level_color}▶{C.END} {rule['title']} — "
            f"{C.BOLD}{len(new_results)} new events{C.END} "
            f"({len(results)} total, {deduped_count} deduped)")

        # Show first event summary
        first = new_results[0]
        summary_fields = ['_time', 'Image', 'CommandLine', 'User', 'Computer',
                          'DestinationIp', 'QueryName', 'TargetObject']
        for field in summary_fields:
            if field in first and first[field]:
                val = str(first[field])[:80]
                log(f"    {field}: {val}")

        # Interactive mode: ask before firing
        should_fire = True
        if hasattr(args, 'interactive') and args.interactive:
            try:
                answer = input(f"\n  {C.CYAN}Fire alert for {rule['title']}? [Y/n/q]: {C.END}").strip().lower()
                if answer == 'q':
                    log("Aborted by user")
                    break
                elif answer == 'n':
                    should_fire = False
                    log(f"  {C.DIM}Skipped{C.END}")
                    stats['skipped'] += 1
            except (EOFError, KeyboardInterrupt):
                log("\nAborted")
                break

        # Fire webhook
        if should_fire:
            if fire_alert(rule, new_results, dry_run=args.dry_run):
                stats['alerts_fired'] += 1
                rule_state['last_alert_time'] = datetime.now(timezone.utc).isoformat()
                rule_state['total_alerts'] = rule_state.get('total_alerts', 0) + 1

        # Update dedup hashes (skip in alltime mode — state isn't saved anyway)
        if not (hasattr(args, 'alltime') and args.alltime):
            new_hashes = [event_hash(e) for e in results]
            all_hashes = list(old_hashes) + new_hashes
            rule_state['recent_event_hashes'] = all_hashes[-500:]

        sched_state['rules'][rule_name] = rule_state

    # Save state (skip in alltime mode to keep dedup clean for production runs)
    if not args.dry_run and not (hasattr(args, 'alltime') and args.alltime):
        save_scheduler_state(sched_state)

    # Summary
    elapsed = (datetime.now() - start_time).total_seconds()
    log("")
    log("=" * 60)
    log("SCHEDULER RUN COMPLETE")
    log("=" * 60)
    log(f"  Rules searched:    {stats['searched']}/{stats['total']}")
    log(f"  With results:      {stats['with_results']}")
    log(f"  Alerts fired:      {stats['alerts_fired']}")
    log(f"  Skipped:           {stats['skipped']}")
    log(f"  Events deduped:    {stats['deduplicated']}")
    log(f"  Errors:            {stats['errors']}")
    log(f"  Runtime:           {elapsed:.1f}s")
    if args.dry_run:
        log(f"  {C.YELLOW}*** DRY RUN — no webhooks were actually sent ***{C.END}")
    if hasattr(args, 'alltime') and args.alltime:
        log(f"  {C.CYAN}*** ALL-TIME MODE — dedup state NOT updated ***{C.END}")
    log("")


def show_status():
    """Show current scheduler state."""
    state = load_scheduler_state()
    rules = load_detection_rules()

    print(f"\n{'═' * 60}")
    print(f"{C.BOLD}SCHEDULER STATUS{C.END}")
    print(f"{'═' * 60}")
    print(f"  Last run:    {state.get('last_run', 'Never')}")
    print(f"  Rules loaded: {len(rules)}")
    print(f"  State file:  {SCHEDULER_STATE}")

    if state.get('rules'):
        print(f"\n  {'Rule':<40} {'Alerts':<8} {'Last Alert':<22} {'Fails'}")
        print(f"  {'─' * 40} {'─' * 8} {'─' * 22} {'─' * 5}")

        for name, info in sorted(state['rules'].items()):
            total = info.get('total_alerts', 0)
            last = info.get('last_alert_time', 'Never')
            if last != 'Never':
                last = last[:19]
            fails = info.get('consecutive_failures', 0)

            # Truncate name
            display_name = name[:38] + '..' if len(name) > 40 else name

            fail_color = C.RED if fails > 0 else C.DIM
            print(f"  {display_name:<40} {total:<8} {last:<22} {fail_color}{fails}{C.END}")

    print()


# ============================================================
# SYSTEMD SERVICE AND TIMER FILES
# ============================================================

def install_systemd():
    """Create systemd service and timer files for the scheduler.

    This is more reliable than cron because:
    - systemd tracks if the previous run is still going
    - journalctl gives you proper logs
    - systemctl status shows you the last run result
    """
    script_path = os.path.abspath(__file__)
    working_dir = REPO_ROOT

    service_content = f"""[Unit]
Description=SOC Detection Scheduler
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path}
WorkingDirectory={working_dir}
User=anwesh
Environment=SPLUNK_HOST=localhost
Environment=SPLUNK_PORT=8089
Environment=SPLUNK_USER=admin
Environment=SPLUNK_PASS=ChangeMeNow1!
Environment=N8N_WEBHOOK_URL=http://localhost:5678/webhook/splunk-alert

[Install]
WantedBy=multi-user.target
"""

    timer_content = """[Unit]
Description=Run SOC Detection Scheduler every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
"""

    service_path = '/etc/systemd/system/detection_scheduler.service'
    timer_path = '/etc/systemd/system/detection_scheduler.timer'

    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
        with open(timer_path, 'w') as f:
            f.write(timer_content)

        os.system('systemctl daemon-reload')
        os.system('systemctl enable detection_scheduler.timer')
        os.system('systemctl start detection_scheduler.timer')

        log(f"Installed systemd timer")
        log(f"  Service: {service_path}")
        log(f"  Timer:   {timer_path}")
        log(f"")
        log(f"  Check status:  systemctl status detection_scheduler.timer")
        log(f"  Check logs:    journalctl -u detection_scheduler -f")
        log(f"  Run manually:  systemctl start detection_scheduler.service")
        log(f"  Stop timer:    systemctl stop detection_scheduler.timer")

    except PermissionError:
        log("Run with sudo to install systemd files", 'ERROR')
        log(f"  sudo python3 {script_path} --install-systemd")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='External detection scheduler for Splunk Free',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script replaces Splunk's internal scheduler (which is disabled
in Splunk Free). It runs your detection rules via the REST API and
fires webhooks to n8n when detections match.

Examples:
  python3 detection_scheduler.py                    # Normal run
  python3 detection_scheduler.py --dry-run          # Preview without firing
  python3 detection_scheduler.py --verbose           # Detailed output
  python3 detection_scheduler.py --once "PowerShell" # Run one rule
  python3 detection_scheduler.py --status            # Show state
  python3 detection_scheduler.py --alltime -v        # Search all time (lab mode)
  python3 detection_scheduler.py -i                  # Interactive: ask before each alert
  python3 detection_scheduler.py --reset-dedup       # Clear dedup so alerts re-fire
  sudo python3 detection_scheduler.py --install-systemd  # Install as timer
        """
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would fire without actually sending webhooks')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output for every rule')
    parser.add_argument('--once', type=str, default=None,
                        help='Run a single rule (match by name, file, or keyword)')
    parser.add_argument('--status', action='store_true',
                        help='Show scheduler state and exit')
    parser.add_argument('--install-systemd', action='store_true',
                        help='Install as a systemd timer (requires sudo)')
    parser.add_argument('--alltime', action='store_true',
                        help='Search all time instead of narrow windows (lab mode)')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Ask before firing each alert (implies --alltime --verbose)')
    parser.add_argument('--reset-dedup', action='store_true',
                        help='Clear dedup state so alerts can re-fire on existing events')

    args = parser.parse_args()

    # --interactive implies --alltime and --verbose
    if args.interactive:
        args.alltime = True
        args.verbose = True

    if args.status:
        show_status()
    elif args.install_systemd:
        install_systemd()
    elif args.reset_dedup:
        if os.path.exists(SCHEDULER_STATE):
            os.remove(SCHEDULER_STATE)
            log(f"Cleared dedup state: {SCHEDULER_STATE}")
        else:
            log("No dedup state file found — nothing to clear")
    else:
        run_scheduler(args)


if __name__ == '__main__':
    main()