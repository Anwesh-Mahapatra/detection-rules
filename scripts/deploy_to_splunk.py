#!/usr/bin/env python3
"""
deploy_to_splunk.py — Deploys converted SPL rules as Splunk saved searches.

This script is called by GitHub Actions after sigma2splunk.py converts
all the rules. It reads the SPL files from splunk/savedsearches/ and
creates or updates Splunk saved searches via the REST API.

This runs on the self-hosted runner (soc-stack), so it can access
Splunk at localhost.
"""

import os
import sys
import yaml # type: ignore
import requests # type: ignore
import urllib3 # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = os.environ.get('SPLUNK_PORT', '8089')
SPLUNK_USER = os.environ.get('SPLUNK_USER', 'admin')
SPLUNK_PASS = os.environ.get('SPLUNK_PASS', 'ChangeMeNow1!')

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
SPL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'splunk', 'savedsearches')


def get_existing_searches():
    """Get list of existing saved searches in Splunk"""
    try:
        resp = requests.get(
            f"{BASE_URL}/servicesNS/admin/search/saved/searches",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={'output_mode': 'json', 'count': 0}
        )
        if resp.status_code == 200:
            entries = resp.json().get('entry', [])
            return {e['name'] for e in entries}
    except Exception as e:
        print(f"Warning: Could not fetch existing searches: {e}")
    return set()


def deploy_saved_search(rule_data):
    """Create or update a saved search in Splunk"""
    ss = rule_data.get('splunk_saved_search', {})
    name = ss.get('name', '')
    search = ss.get('search', '')

    if not name or not search:
        return False

    # Map severity to Splunk alert severity
    level_map = {'critical': 6, 'high': 5, 'medium': 4, 'low': 3, 'informational': 2}
    severity = level_map.get(rule_data.get('rule_level', 'medium'), 4)

    payload = {
        'name': name,
        'search': search,
        'is_scheduled': 1,
        'cron_schedule': ss.get('cron_schedule', '*/5 * * * *'),
        'dispatch.earliest_time': ss.get('dispatch_earliest_time', '-5m'),
        'dispatch.latest_time': ss.get('dispatch_latest_time', 'now'),
        'alert_type': 'number of events',
        'alert_comparator': 'greater than',
        'alert_threshold': '0',
        'alert.severity': severity,
        'description': rule_data.get('description', ''),
        'disabled': 0,
        'actions': 'webhook',
        'action.webhook.param.url': 'http://localhost:5678/webhook/splunk-alert'
    }

    # Check if it already exists
    existing = get_existing_searches()
    if name in existing:
        # Update existing
        safe_name = requests.utils.quote(name, safe='')
        resp = requests.post(
            f"{BASE_URL}/servicesNS/admin/search/saved/searches/{safe_name}",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data=payload
        )
        action = "Updated"
    else:
        # Create new
        resp = requests.post(
            f"{BASE_URL}/servicesNS/admin/search/saved/searches",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data=payload
        )
        action = "Created"

    if resp.status_code in [200, 201]:
        print(f"  [+] {action}: {name}")
        return True
    else:
        print(f"  [!] Failed to deploy '{name}': {resp.status_code}")
        try:
            error_msg = resp.json().get('messages', [{}])[0].get('text', '')
            if error_msg:
                print(f"      Error: {error_msg}")
        except:
            pass
        return False


def main():
    print("=" * 60)
    print("Deploying detection rules to Splunk")
    print("=" * 60)

    if not os.path.exists(SPL_DIR):
        print(f"No SPL directory found at {SPL_DIR}")
        sys.exit(0)

    spl_files = [f for f in os.listdir(SPL_DIR) if f.endswith('.yml')]
    print(f"Found {len(spl_files)} rules to deploy\n")

    success = 0
    failed = 0

    for spl_file in sorted(spl_files):
        filepath = os.path.join(SPL_DIR, spl_file)
        try:
            with open(filepath, 'r') as f:
                rule_data = yaml.safe_load(f)
            if deploy_saved_search(rule_data):
                success += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  [!] Error processing {spl_file}: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Deployment complete: {success} succeeded, {failed} failed")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()