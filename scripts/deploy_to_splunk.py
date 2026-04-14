#!/usr/bin/env python3
"""
deploy_to_splunk.py — Intelligent Splunk Saved Search Deployer with Git Diff Sync

This script is the deployment engine for the detection-as-code pipeline.
Instead of blindly redeploying every rule on every push, it uses git diff
to figure out exactly what changed, and only touches what needs touching.

HOW IT WORKS:
=============

1. Reads a state file (deploy_state.json) that maps rule files to Splunk
   saved search names and their last-deployed content hashes.

2. Uses `git diff` to find which files in rules/ and splunk/savedsearches/
   were Added, Modified, or Deleted since the last deploy.

3. For ADDED files:    → Converts Sigma to SPL → Creates new Splunk saved search
4. For MODIFIED files: → Converts Sigma to SPL → Updates existing saved search
5. For DELETED files:  → Removes the saved search from Splunk

6. Updates the state file with the new hashes so next run knows what changed.

USAGE:
======
    # Normal run (auto-detects changes via git diff)
    python scripts/deploy_to_splunk.py

    # Force redeploy ALL rules (ignores git diff)
    python scripts/deploy_to_splunk.py --force-all

    # Dry run (shows what WOULD happen without actually deploying)
    python scripts/deploy_to_splunk.py --dry-run

    # Show current deploy state
    python scripts/deploy_to_splunk.py --status

ENVIRONMENT VARIABLES:
======================
    SPLUNK_HOST  — Splunk server hostname/IP (default: localhost)
    SPLUNK_PORT  — Splunk management port (default: 8089)
    SPLUNK_USER  — Splunk admin username (default: admin)
    SPLUNK_PASS  — Splunk admin password (default: ChangeMeNow1!)
"""

import os
import sys
import json
import yaml # type: ignore
import hashlib
import subprocess
import argparse
import requests # type: ignore
import urllib3 # type: ignore
from pathlib import Path
from datetime import datetime, timezone

# Suppress SSL warnings for self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURATION
# ============================================================
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', '192.168.1.162')
SPLUNK_PORT = os.environ.get('SPLUNK_PORT', '8089')
SPLUNK_USER = os.environ.get('SPLUNK_USER', 'admin')
SPLUNK_PASS = os.environ.get('SPLUNK_PASS', 'ChangeMeNow1!')

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# Paths (relative to repo root)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPL_DIR = os.path.join(REPO_ROOT, 'splunk', 'savedsearches')
RULES_DIR = os.path.join(REPO_ROOT, 'rules')
STATE_FILE = os.path.join(REPO_ROOT, '.deploy_state.json')

# n8n webhook URL for alert forwarding (set to empty string to disable)
N8N_WEBHOOK_URL = os.environ.get('N8N_WEBHOOK_URL', 'http://localhost:5678/webhook/splunk-alert')


# ============================================================
# TERMINAL COLORS
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

if sys.platform == 'win32':
    os.system('color')


# ============================================================
# STATE MANAGEMENT
#
# The state file (.deploy_state.json) lives in the repo root.
# It tracks:
#   - Which rule files have been deployed
#   - The content hash of each deployed rule (to detect modifications)
#   - The Splunk saved search name for each rule (to handle renames/deletes)
#   - Timestamp of last deployment
#
# Structure:
# {
#   "last_deploy": "2026-03-28T10:00:00Z",
#   "deployed_rules": {
#     "rules/windows/process_creation/powershell_suspicious.yml": {
#       "content_hash": "abc123...",
#       "spl_file": "splunk/savedsearches/Suspicious_PowerShell_Execution.yml",
#       "splunk_search_name": "Detection: Suspicious PowerShell Execution",
#       "deployed_at": "2026-03-28T10:00:00Z"
#     },
#     ...
#   }
# }
# ============================================================

def load_state():
    """Load the deployment state from disk.
    
    Returns an empty state dict if the file doesn't exist yet
    (first run) or if it's corrupted.
    """
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
                # Validate structure
                if 'deployed_rules' not in state:
                    state['deployed_rules'] = {}
                return state
        except (json.JSONDecodeError, KeyError):
            print(f"  {C.YELLOW}[!] State file corrupted, starting fresh{C.END}")
    
    return {
        'last_deploy': None,
        'deployed_rules': {}
    }


def save_state(state):
    """Save the deployment state to disk.
    
    This gets committed to the repo by GitHub Actions so the
    next run knows what was already deployed.
    """
    state['last_deploy'] = datetime.now(timezone.utc).isoformat()
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2, sort_keys=False)
    print(f"\n  {C.DIM}State saved to {STATE_FILE}{C.END}")


def file_hash(filepath):
    """Compute SHA256 hash of a file's contents.
    
    This is how we detect if a rule file was actually modified
    (vs just touched/reformatted). Two files with identical content
    produce the same hash regardless of modification timestamp.
    """
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None


# ============================================================
# GIT DIFF DETECTION
#
# This is the core of the sync mechanism. Instead of scanning
# every file, we ask git what actually changed since the last
# commit (or between two commits).
#
# git diff --name-status gives output like:
#   A  rules/windows/process_creation/new_rule.yml      (Added)
#   M  rules/windows/persistence/scheduled_task.yml     (Modified)
#   D  rules/windows/defense_evasion/old_rule.yml       (Deleted)
#   R  rules/old_path.yml -> rules/new_path.yml         (Renamed)
#
# We parse this to build three lists: added, modified, deleted.
# ============================================================

def get_git_changes():
    """Detect which rule files changed using git diff.
    
    Strategy:
    1. First try: git diff HEAD~1 (compare with previous commit)
       This works for normal pushes where there's a parent commit.
    
    2. Fallback: If HEAD~1 doesn't exist (first commit), compare
       against an empty tree to treat everything as "added".
    
    3. We only care about files under rules/ and splunk/savedsearches/
    
    Returns:
        dict with keys 'added', 'modified', 'deleted', 'renamed'
        Each value is a list of file paths (relative to repo root)
    """
    changes = {
        'added': [],
        'modified': [],
        'deleted': [],
        'renamed': []   # Tuples of (old_path, new_path)
    }

    try:
        # Try comparing with the previous commit
        result = subprocess.run(
            ['git', 'diff', '--name-status', 'HEAD~1', 'HEAD'],
            capture_output=True, text=True, cwd=REPO_ROOT
        )

        if result.returncode != 0:
            # HEAD~1 doesn't exist (first commit) — compare with empty tree
            # The empty tree hash is a well-known git constant
            empty_tree = '4b825dc642cb6eb9a060e54bf899d15363da7b23'
            result = subprocess.run(
                ['git', 'diff', '--name-status', empty_tree, 'HEAD'],
                capture_output=True, text=True, cwd=REPO_ROOT
            )

        if result.returncode != 0:
            print(f"  {C.RED}[!] git diff failed: {result.stderr.strip()}{C.END}")
            return None

        # Parse the output
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue

            parts = line.split('\t')
            status = parts[0].strip()

            if status == 'A':
                # Added
                filepath = parts[1].strip()
                if is_rule_file(filepath) or is_spl_file(filepath):
                    changes['added'].append(filepath)

            elif status == 'M':
                # Modified
                filepath = parts[1].strip()
                if is_rule_file(filepath) or is_spl_file(filepath):
                    changes['modified'].append(filepath)

            elif status == 'D':
                # Deleted
                filepath = parts[1].strip()
                if is_rule_file(filepath) or is_spl_file(filepath):
                    changes['deleted'].append(filepath)

            elif status.startswith('R'):
                # Renamed (R100 = 100% rename, R080 = 80% similar)
                old_path = parts[1].strip()
                new_path = parts[2].strip()
                if is_rule_file(old_path) or is_rule_file(new_path):
                    changes['renamed'].append((old_path, new_path))

        return changes

    except FileNotFoundError:
        print(f"  {C.RED}[!] git not found — is git installed?{C.END}")
        return None
    except Exception as e:
        print(f"  {C.RED}[!] Error running git diff: {e}{C.END}")
        return None


def is_rule_file(filepath):
    """Check if a filepath is a Sigma rule file."""
    return (filepath.startswith('rules/') and 
            (filepath.endswith('.yml') or filepath.endswith('.yaml')))


def is_spl_file(filepath):
    """Check if a filepath is a converted SPL file."""
    return filepath.startswith('splunk/savedsearches/') and filepath.endswith('.yml')


def get_all_rule_files():
    """Scan the rules/ directory for all Sigma rule files.
    
    Used when --force-all is specified, or when we need to do
    a full reconciliation.
    """
    rule_files = []
    for root, dirs, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith('.yml') or f.endswith('.yaml'):
                # Get path relative to repo root
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, REPO_ROOT)
                # Normalize path separators for cross-platform
                rel_path = rel_path.replace('\\', '/')
                rule_files.append(rel_path)
    return sorted(rule_files)


# ============================================================
# SIGMA CONVERSION
#
# We import the conversion logic here rather than calling
# sigma2splunk.py as a subprocess. This is faster and gives
# us direct access to the conversion results.
# ============================================================

def convert_sigma_file(sigma_path):
    """Convert a single Sigma YAML file to SPL.
    
    Args:
        sigma_path: Path to the .yml file (relative to repo root)
    
    Returns:
        dict with spl_query, rule_title, rule_id, etc.
        None if conversion fails.
    """
    import re
    from sigma.collection import SigmaCollection # type: ignore
    from sigma.backends.splunk import SplunkBackend # type: ignore
    from sigma.pipelines.sysmon import sysmon_pipeline # type: ignore
    from sigma.pipelines.splunk import splunk_windows_pipeline # type: ignore

    full_path = os.path.join(REPO_ROOT, sigma_path)
    
    if not os.path.exists(full_path):
        print(f"    {C.RED}File not found: {sigma_path}{C.END}")
        return None

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            raw_yaml = f.read()

        rule_data = yaml.safe_load(raw_yaml)

        # Build conversion pipeline
        pipeline = sysmon_pipeline() + splunk_windows_pipeline()
        backend = SplunkBackend(pipeline)
        sigma_collection = SigmaCollection.from_yaml(raw_yaml)
        spl_queries = backend.convert(sigma_collection)

        if not spl_queries:
            print(f"    {C.RED}Conversion produced no output{C.END}")
            return None

        spl_query = spl_queries[0]

        # ── Post-process pySigma output ──
        # Fix 1: field IN ("*wildcard*") → (field="*w1*" OR field="*w2*")
        def fix_in_with_wildcards(match):
            field = match.group(1)
            values_str = match.group(2)
            values = re.findall(r'"([^"]*)"', values_str)
            if not values:
                values = re.findall(r"'([^']*)'", values_str)
            if not values:
                values = [v.strip() for v in values_str.split(',')]
            has_wildcard = any('*' in v for v in values)
            if not has_wildcard and len(values) > 1:
                return match.group(0)
            if len(values) == 1:
                return f'{field}="{values[0]}"'
            return '(' + ' OR '.join(f'{field}="{v}"' for v in values) + ')'

        spl_query = re.sub(r'(\w+)\s+IN\s*\(([^)]+)\)', fix_in_with_wildcards, spl_query)

        # Fix 2: Duplicate EventCode=X EventCode=X
        spl_query = re.sub(r'(EventCode[=]\s*\d+)\s+\1', r'\1', spl_query)

        # Fix 3: Collapse redundant whitespace
        spl_query = re.sub(r'  +', ' ', spl_query).strip()

        # Fix 4: Quadruple backslash → double
        spl_query = spl_query.replace('\\\\\\\\', '\\\\')

        # ── Apply environment-specific source/index fixes ──
        spl_query = spl_query.replace(
            'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
            'index="sysmon" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:Security"',
            'index="windows" source="WinEventLog:Security"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:System"',
            'index="windows" source="WinEventLog:System"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:Application"',
            'index="windows" source="WinEventLog:Application"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:Microsoft-Windows-PowerShell/Operational"',
            'index="windows" source="WinEventLog:Microsoft-Windows-PowerShell/Operational"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"',
            'index="windows" source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"'
        )
        if 'index=' not in spl_query and 'source="' in spl_query:
            if 'Sysmon' in spl_query:
                spl_query = 'index="sysmon" ' + spl_query
            else:
                spl_query = 'index="windows" ' + spl_query

        # Extract metadata
        tags = rule_data.get('tags', [])
        mitre_tags = [t for t in tags if t.startswith('attack.')]

        return {
            'spl_query': spl_query,
            'rule_title': rule_data.get('title', 'Unknown'),
            'rule_id': rule_data.get('id', 'no-id'),
            'rule_level': rule_data.get('level', 'medium'),
            'mitre_attack': mitre_tags,
            'description': rule_data.get('description', ''),
            'status': rule_data.get('status', 'unknown'),
            'source_file': sigma_path
        }

    except Exception as e:
        print(f"    {C.RED}Conversion error: {e}{C.END}")
        return None


def save_spl_file(conversion_result):
    """Save the converted SPL to the savedsearches directory.
    
    Returns the relative path to the saved file.
    """
    os.makedirs(SPL_DIR, exist_ok=True)

    # Sanitize filename from rule title
    safe_name = "".join(
        c if c.isalnum() or c in '-_' else '_' 
        for c in conversion_result['rule_title']
    )
    safe_name = safe_name[:80]

    spl_filename = f"{safe_name}.yml"
    spl_full_path = os.path.join(SPL_DIR, spl_filename)
    spl_rel_path = os.path.relpath(spl_full_path, REPO_ROOT).replace('\\', '/')

    # Map severity to cron schedule
    # Higher severity = more frequent checks
    level = conversion_result.get('rule_level', 'medium')
    cron_map = {
        'critical': '* * * * *',       # Every minute
        'high':     '*/2 * * * *',     # Every 2 minutes
        'medium':   '*/5 * * * *',     # Every 5 minutes
        'low':      '*/15 * * * *',    # Every 15 minutes
        'informational': '*/30 * * * *' # Every 30 minutes
    }
    cron = cron_map.get(level, '*/5 * * * *')

    # Map severity to dispatch time window
    dispatch_map = {
        'critical': '-1m',
        'high':     '-2m',
        'medium':   '-5m',
        'low':      '-15m',
        'informational': '-30m'
    }
    dispatch = dispatch_map.get(level, '-5m')

    output = {
        'rule_title': conversion_result['rule_title'],
        'rule_id': conversion_result['rule_id'],
        'rule_level': level,
        'mitre_attack': conversion_result['mitre_attack'],
        'description': conversion_result['description'],
        'spl_query': conversion_result['spl_query'],
        'source_sigma_file': conversion_result['source_file'],
        'converted_at': datetime.now(timezone.utc).isoformat(),
        'splunk_saved_search': {
            'name': f"Detection: {conversion_result['rule_title']}",
            'search': conversion_result['spl_query'],
            'cron_schedule': cron,
            'is_scheduled': True,
            'alert_type': 'number of events',
            'alert_threshold': 0,
            'alert_comparator': 'greater than',
            'dispatch_earliest_time': dispatch,
            'dispatch_latest_time': 'now'
        }
    }

    with open(spl_full_path, 'w', encoding='utf-8') as f:
        yaml.dump(output, f, default_flow_style=False, sort_keys=False)

    return spl_rel_path


# ============================================================
# SPLUNK API OPERATIONS
#
# All Splunk interactions go through the REST API on port 8089.
# Three operations: CREATE, UPDATE, DELETE saved searches.
# ============================================================

def splunk_api(method, endpoint, data=None):
    """Make a request to the Splunk REST API.
    
    Args:
        method: 'GET', 'POST', 'DELETE'
        endpoint: API path (e.g., '/servicesNS/admin/search/saved/searches')
        data: dict of form data for POST requests
    
    Returns:
        requests.Response object, or None on connection error
    """
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method == 'GET':
            resp = requests.get(
                url, auth=(SPLUNK_USER, SPLUNK_PASS),
                verify=False, params={'output_mode': 'json'}
            )
        elif method == 'POST':
            resp = requests.post(
                url, auth=(SPLUNK_USER, SPLUNK_PASS),
                verify=False, data=data
            )
        elif method == 'DELETE':
            resp = requests.delete(
                url, auth=(SPLUNK_USER, SPLUNK_PASS),
                verify=False
            )
        else:
            return None

        return resp

    except requests.exceptions.ConnectionError:
        print(f"    {C.RED}Cannot connect to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}{C.END}")
        return None


def get_existing_searches():
    """Get all existing saved searches from Splunk.
    
    Returns a set of saved search names.
    """
    resp = splunk_api('GET', '/servicesNS/admin/search/saved/searches')
    if resp and resp.status_code == 200:
        entries = resp.json().get('entry', [])
        return {e['name'] for e in entries}
    return set()


def create_saved_search(rule_data):
    """Create a new saved search in Splunk.
    
    Args:
        rule_data: dict loaded from the SPL YAML file
    
    Returns:
        True on success, False on failure
    """
    ss = rule_data.get('splunk_saved_search', {})
    name = ss.get('name', '')
    search = ss.get('search', '')

    if not name or not search:
        return False

    level_map = {
        'critical': 6, 'high': 5, 'medium': 4,
        'low': 3, 'informational': 2
    }
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
        'description': rule_data.get('description', '')[:250],
        'disabled': 1,  # detection_scheduler.py handles alerting, not Splunk
    }

    resp = splunk_api('POST', '/servicesNS/admin/search/saved/searches', data=payload)

    if resp and resp.status_code in [200, 201]:
        return True
    else:
        if resp:
            try:
                msg = resp.json().get('messages', [{}])[0].get('text', '')
                print(f"    {C.RED}Splunk error: {msg}{C.END}")
            except:
                print(f"    {C.RED}HTTP {resp.status_code}{C.END}")
        return False


def update_saved_search(rule_data):
    """Update an existing saved search in Splunk.
    
    Args:
        rule_data: dict loaded from the SPL YAML file
    
    Returns:
        True on success, False on failure
    """
    ss = rule_data.get('splunk_saved_search', {})
    name = ss.get('name', '')
    search = ss.get('search', '')

    if not name or not search:
        return False

    level_map = {
        'critical': 6, 'high': 5, 'medium': 4,
        'low': 3, 'informational': 2
    }
    severity = level_map.get(rule_data.get('rule_level', 'medium'), 4)

    # URL-encode the search name for the API path
    safe_name = requests.utils.quote(name, safe='')

    payload = {
        'search': search,
        'is_scheduled': 1,
        'cron_schedule': ss.get('cron_schedule', '*/5 * * * *'),
        'dispatch.earliest_time': ss.get('dispatch_earliest_time', '-5m'),
        'dispatch.latest_time': ss.get('dispatch_latest_time', 'now'),
        'alert_type': 'number of events',
        'alert_comparator': 'greater than',
        'alert_threshold': '0',
        'alert.severity': severity,
        'description': rule_data.get('description', '')[:250],
        'disabled': 1,  # detection_scheduler.py handles alerting, not Splunk
    }

    resp = splunk_api(
        'POST',
        f'/servicesNS/admin/search/saved/searches/{safe_name}',
        data=payload
    )

    if resp and resp.status_code in [200, 201]:
        return True
    elif resp and resp.status_code == 404:
        # Search doesn't exist in Splunk (was deleted) — fall back to create
        print(f"    {C.YELLOW}Search not found in Splunk — creating instead{C.END}")
        return create_saved_search(rule_data)
    else:
        if resp:
            try:
                msg = resp.json().get('messages', [{}])[0].get('text', '')
                print(f"    {C.RED}Splunk error: {msg}{C.END}")
            except:
                print(f"    {C.RED}HTTP {resp.status_code}{C.END}")
        return False


def delete_saved_search(search_name):
    """Delete a saved search from Splunk.
    
    Args:
        search_name: The name of the saved search to delete
    
    Returns:
        True on success, False on failure
    """
    safe_name = requests.utils.quote(search_name, safe='')
    resp = splunk_api(
        'DELETE',
        f'/servicesNS/admin/search/saved/searches/{safe_name}'
    )

    if resp and resp.status_code in [200, 204]:
        return True
    else:
        if resp and resp.status_code == 404:
            # Already doesn't exist — that's fine
            return True
        return False


# ============================================================
# DEPLOY LOGIC
#
# This is where git diff, state tracking, and Splunk API
# come together. The main deploy function orchestrates
# the entire sync process.
# ============================================================

def deploy_added(sigma_path, state, existing_searches, dry_run=False):
    """Handle a newly added Sigma rule.
    
    1. Convert Sigma to SPL
    2. Save SPL file
    3. Create saved search in Splunk
    4. Update state
    """
    print(f"\n  {C.GREEN}[ADD]{C.END} {sigma_path}")

    # Convert
    result = convert_sigma_file(sigma_path)
    if not result:
        return False

    search_name = f"Detection: {result['rule_title']}"
    print(f"    SPL: {result['spl_query'][:80]}...")

    if dry_run:
        print(f"    {C.YELLOW}[DRY RUN] Would create: {search_name}{C.END}")
        return True

    # Save SPL file
    spl_path = save_spl_file(result)

    # Deploy to Splunk
    if search_name in existing_searches:
        # Already exists (maybe from a previous partial deploy)
        success = update_saved_search(
            yaml.safe_load(open(os.path.join(REPO_ROOT, spl_path), 'r'))
        )
        action = "Updated (already existed)"
    else:
        spl_data = yaml.safe_load(open(os.path.join(REPO_ROOT, spl_path), 'r'))
        success = create_saved_search(spl_data)
        action = "Created"

    if success:
        print(f"    {C.GREEN}✓ {action}: {search_name}{C.END}")
        # Update state
        state['deployed_rules'][sigma_path] = {
            'content_hash': file_hash(os.path.join(REPO_ROOT, sigma_path)),
            'spl_file': spl_path,
            'splunk_search_name': search_name,
            'rule_title': result['rule_title'],
            'rule_level': result['rule_level'],
            'deployed_at': datetime.now(timezone.utc).isoformat()
        }
        return True
    else:
        print(f"    {C.RED}✗ Failed to deploy{C.END}")
        return False


def deploy_modified(sigma_path, state, dry_run=False, force=False):
    """Handle a modified Sigma rule.
    
    1. Check if content actually changed (hash comparison)
    2. If yes: re-convert and update saved search
    3. If no: skip (content might be same despite git reporting a change)
    """
    print(f"\n  {C.BLUE}[MOD]{C.END} {sigma_path}")

    # Check if content actually changed
    old_hash = state['deployed_rules'].get(sigma_path, {}).get('content_hash', '')
    new_hash = file_hash(os.path.join(REPO_ROOT, sigma_path))

    if old_hash == new_hash and not force:
        print(f"    {C.DIM}Content unchanged (hash match) — skipping{C.END}")
        return True

    # Content changed — reconvert
    result = convert_sigma_file(sigma_path)
    if not result:
        return False

    search_name = f"Detection: {result['rule_title']}"
    old_search_name = state['deployed_rules'].get(sigma_path, {}).get('splunk_search_name', '')

    print(f"    SPL: {result['spl_query'][:80]}...")

    if dry_run:
        print(f"    {C.YELLOW}[DRY RUN] Would update: {search_name}{C.END}")
        return True

    # Save updated SPL file
    spl_path = save_spl_file(result)

    # If the rule was renamed (different title), delete old and create new
    if old_search_name and old_search_name != search_name:
        print(f"    {C.YELLOW}Rule title changed: '{old_search_name}' → '{search_name}'{C.END}")
        delete_saved_search(old_search_name)
        spl_data = yaml.safe_load(open(os.path.join(REPO_ROOT, spl_path), 'r'))
        success = create_saved_search(spl_data)
        action = "Recreated (title changed)"
    else:
        spl_data = yaml.safe_load(open(os.path.join(REPO_ROOT, spl_path), 'r'))
        success = update_saved_search(spl_data)
        action = "Updated"

    if success:
        print(f"    {C.GREEN}✓ {action}: {search_name}{C.END}")
        state['deployed_rules'][sigma_path] = {
            'content_hash': new_hash,
            'spl_file': spl_path,
            'splunk_search_name': search_name,
            'rule_title': result['rule_title'],
            'rule_level': result['rule_level'],
            'deployed_at': datetime.now(timezone.utc).isoformat()
        }
        return True
    else:
        print(f"    {C.RED}✗ Failed to update{C.END}")
        return False


def deploy_deleted(sigma_path, state, dry_run=False):
    """Handle a deleted Sigma rule.
    
    1. Look up the Splunk saved search name from state
    2. Delete the saved search from Splunk
    3. Remove from state
    4. Delete the SPL file if it exists
    """
    print(f"\n  {C.RED}[DEL]{C.END} {sigma_path}")

    rule_state = state['deployed_rules'].get(sigma_path, {})
    search_name = rule_state.get('splunk_search_name', '')
    spl_file = rule_state.get('spl_file', '')

    if not search_name:
        print(f"    {C.DIM}Not in deploy state — nothing to delete from Splunk{C.END}")
        # Still remove from state if present
        state['deployed_rules'].pop(sigma_path, None)
        return True

    if dry_run:
        print(f"    {C.YELLOW}[DRY RUN] Would delete: {search_name}{C.END}")
        return True

    # Delete from Splunk
    success = delete_saved_search(search_name)

    if success:
        print(f"    {C.GREEN}✓ Deleted from Splunk: {search_name}{C.END}")
    else:
        print(f"    {C.YELLOW}⚠ Could not delete from Splunk (may not exist){C.END}")

    # Delete SPL file from repo
    if spl_file:
        spl_full_path = os.path.join(REPO_ROOT, spl_file)
        if os.path.exists(spl_full_path):
            os.remove(spl_full_path)
            print(f"    {C.DIM}Removed SPL file: {spl_file}{C.END}")

    # Remove from state
    state['deployed_rules'].pop(sigma_path, None)
    return True


def deploy_renamed(old_path, new_path, state, existing_searches, dry_run=False):
    """Handle a renamed Sigma rule.
    
    This is essentially a delete of the old + add of the new,
    but we try to be smart about it by updating the state mapping.
    """
    print(f"\n  {C.CYAN}[REN]{C.END} {old_path} → {new_path}")

    if dry_run:
        old_name = state['deployed_rules'].get(old_path, {}).get('splunk_search_name', '?')
        print(f"    {C.YELLOW}[DRY RUN] Would rename in Splunk: {old_name}{C.END}")
        return True

    # Delete old
    deploy_deleted(old_path, state, dry_run=False)

    # Add new
    return deploy_added(new_path, state, existing_searches, dry_run=False)


# ============================================================
# RECONCILIATION
#
# After processing git diff changes, we do a reconciliation
# pass to catch any drift between state and reality:
# - Rules in state but not on disk (orphaned state entries)
# - Rules on disk but not in state (missed additions)
# - Rules in Splunk but not in state (manually created)
# ============================================================

def reconcile(state, existing_searches, dry_run=False):
    """Reconcile state with filesystem and Splunk.
    
    This catches edge cases that git diff might miss:
    - Someone manually deleted a file without committing
    - State file got out of sync
    - Rules were added outside the pipeline
    """
    issues = []

    # Check 1: Rules in state but file doesn't exist on disk
    for sigma_path in list(state['deployed_rules'].keys()):
        full_path = os.path.join(REPO_ROOT, sigma_path)
        if not os.path.exists(full_path):
            issues.append(('orphaned_state', sigma_path))

    # Check 2: Rules on disk but not in state
    all_rules = get_all_rule_files()
    for rule_path in all_rules:
        if rule_path not in state['deployed_rules']:
            issues.append(('missing_state', rule_path))

    if issues:
        print(f"\n  {C.YELLOW}[RECONCILE] Found {len(issues)} inconsistencies:{C.END}")
        for issue_type, path in issues:
            if issue_type == 'orphaned_state':
                print(f"    {C.YELLOW}State references deleted file: {path}{C.END}")
                if not dry_run:
                    deploy_deleted(path, state, dry_run=False)
            elif issue_type == 'missing_state':
                print(f"    {C.YELLOW}File on disk but not tracked: {path}{C.END}")
                if not dry_run:
                    deploy_added(path, state, existing_searches, dry_run=False)
    else:
        print(f"\n  {C.GREEN}[RECONCILE] State is consistent — no issues found{C.END}")


# ============================================================
# STATUS DISPLAY
# ============================================================

def show_status(state):
    """Display the current deployment state."""
    print(f"\n{'═' * 60}")
    print(f"{C.BOLD}DEPLOYMENT STATUS{C.END}")
    print(f"{'═' * 60}")
    print(f"  Last deploy: {state.get('last_deploy', 'Never')}")
    print(f"  State file:  {STATE_FILE}")

    rules = state.get('deployed_rules', {})
    print(f"  Tracked rules: {len(rules)}")

    if rules:
        print(f"\n  {'Rule File':<55} {'Level':<10} {'Deployed'}")
        print(f"  {'─' * 55} {'─' * 10} {'─' * 20}")

        for path, info in sorted(rules.items()):
            level = info.get('rule_level', '?')
            deployed = info.get('deployed_at', '?')[:19]
            title = info.get('rule_title', '?')

            # Color by level
            level_color = {
                'critical': C.RED, 'high': C.RED,
                'medium': C.YELLOW, 'low': C.BLUE,
                'informational': C.DIM
            }.get(level, C.END)

            print(f"  {path:<55} {level_color}{level:<10}{C.END} {deployed}")

    # Show rules on disk but not tracked
    all_rules = get_all_rule_files()
    untracked = [r for r in all_rules if r not in rules]
    if untracked:
        print(f"\n  {C.YELLOW}Untracked rules on disk ({len(untracked)}):{C.END}")
        for r in untracked:
            print(f"    • {r}")

    print()


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Deploy Sigma detection rules to Splunk with git diff sync',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deploy_to_splunk.py                 # Deploy only changed rules (git diff)
  python deploy_to_splunk.py --force-all     # Redeploy ALL rules
  python deploy_to_splunk.py --dry-run       # Show what would happen
  python deploy_to_splunk.py --status        # Show current deployment state
  python deploy_to_splunk.py --reconcile     # Fix any state/Splunk drift
        """
    )
    parser.add_argument('--force-all', action='store_true',
                        help='Force redeploy of ALL rules (ignores git diff)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would happen without actually deploying')
    parser.add_argument('--status', action='store_true',
                        help='Show current deployment state and exit')
    parser.add_argument('--reconcile', action='store_true',
                        help='Run reconciliation to fix state/Splunk drift')
    parser.add_argument('--no-reconcile', action='store_true',
                        help='Skip the reconciliation step after deployment')

    args = parser.parse_args()

    print(f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
║   SPLUNK DETECTION DEPLOYER — Git Diff Sync v2.0     ║
╚═══════════════════════════════════════════════════════╝{C.END}""")

    # Load state
    state = load_state()

    # Status command
    if args.status:
        show_status(state)
        return

    # Check Splunk connectivity
    print(f"\n{C.BLUE}[*] Connecting to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}...{C.END}")
    existing_searches = get_existing_searches()
    if existing_searches is not None:
        print(f"  {C.GREEN}✓ Connected — {len(existing_searches)} existing saved searches{C.END}")
    else:
        print(f"  {C.RED}✗ Cannot connect to Splunk — aborting{C.END}")
        sys.exit(1)

    # Counters
    stats = {'created': 0, 'updated': 0, 'deleted': 0, 'skipped': 0, 'failed': 0}

    if args.force_all:
        # ── FORCE ALL MODE ──
        print(f"\n{C.YELLOW}[*] FORCE ALL MODE — redeploying every rule{C.END}")
        all_rules = get_all_rule_files()
        print(f"  Found {len(all_rules)} rules on disk")

        for rule_path in all_rules:
            old_hash = state['deployed_rules'].get(rule_path, {}).get('content_hash', '')
            new_hash = file_hash(os.path.join(REPO_ROOT, rule_path))

            if old_hash == new_hash and not args.force_all:
                stats['skipped'] += 1
                continue

            if rule_path in state['deployed_rules']:
                if deploy_modified(rule_path, state, args.dry_run, force=True):
                    stats['updated'] += 1
                else:
                    stats['failed'] += 1
            else:
                if deploy_added(rule_path, state, existing_searches, args.dry_run):
                    stats['created'] += 1
                else:
                    stats['failed'] += 1

        # Check for rules in state that no longer exist on disk
        for sigma_path in list(state['deployed_rules'].keys()):
            if sigma_path not in all_rules:
                if deploy_deleted(sigma_path, state, args.dry_run):
                    stats['deleted'] += 1
                else:
                    stats['failed'] += 1

    elif args.reconcile:
        # ── RECONCILE ONLY MODE ──
        print(f"\n{C.BLUE}[*] Running reconciliation...{C.END}")
        reconcile(state, existing_searches, args.dry_run)

    else:
        # ── NORMAL MODE — use git diff ──
        print(f"\n{C.BLUE}[*] Detecting changes via git diff...{C.END}")
        changes = get_git_changes()

        if changes is None:
            print(f"  {C.YELLOW}Git diff failed — falling back to full reconciliation{C.END}")
            reconcile(state, existing_searches, args.dry_run)
        else:
            total_changes = (
                len(changes['added']) + len(changes['modified']) +
                len(changes['deleted']) + len(changes['renamed'])
            )

            if total_changes == 0:
                print(f"  {C.GREEN}No rule changes detected — nothing to deploy{C.END}")
            else:
                print(f"  Changes detected:")
                if changes['added']:
                    print(f"    {C.GREEN}Added:    {len(changes['added'])}{C.END}")
                if changes['modified']:
                    print(f"    {C.BLUE}Modified: {len(changes['modified'])}{C.END}")
                if changes['deleted']:
                    print(f"    {C.RED}Deleted:  {len(changes['deleted'])}{C.END}")
                if changes['renamed']:
                    print(f"    {C.CYAN}Renamed:  {len(changes['renamed'])}{C.END}")

                # Process each change type
                for path in changes['added']:
                    if is_rule_file(path):
                        if deploy_added(path, state, existing_searches, args.dry_run):
                            stats['created'] += 1
                        else:
                            stats['failed'] += 1

                for path in changes['modified']:
                    if is_rule_file(path):
                        if deploy_modified(path, state, args.dry_run):
                            stats['updated'] += 1
                        else:
                            stats['failed'] += 1

                for path in changes['deleted']:
                    if is_rule_file(path):
                        if deploy_deleted(path, state, args.dry_run):
                            stats['deleted'] += 1
                        else:
                            stats['failed'] += 1

                for old_path, new_path in changes['renamed']:
                    if deploy_renamed(old_path, new_path, state, existing_searches, args.dry_run):
                        stats['updated'] += 1
                    else:
                        stats['failed'] += 1

            # Run reconciliation unless disabled
            if not args.no_reconcile:
                reconcile(state, existing_searches, args.dry_run)

    # Save state (unless dry run)
    if not args.dry_run:
        save_state(state)

    # Print summary
    print(f"\n{'═' * 60}")
    print(f"{C.BOLD}DEPLOYMENT SUMMARY{C.END}")
    print(f"{'═' * 60}")
    if args.dry_run:
        print(f"  {C.YELLOW}*** DRY RUN — no changes were made ***{C.END}")
    print(f"  {C.GREEN}Created:  {stats['created']}{C.END}")
    print(f"  {C.BLUE}Updated:  {stats['updated']}{C.END}")
    print(f"  {C.RED}Deleted:  {stats['deleted']}{C.END}")
    print(f"  {C.DIM}Skipped:  {stats['skipped']}{C.END}")
    print(f"  {C.RED}Failed:   {stats['failed']}{C.END}")
    print(f"  Total rules tracked: {len(state.get('deployed_rules', {}))}")
    print()

    # Exit with error code if any failures
    if stats['failed'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()