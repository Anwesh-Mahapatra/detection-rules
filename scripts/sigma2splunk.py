#!/usr/bin/env python3
"""
sigma2splunk.py — Smart Sigma Rule Converter and Tester

Usage:
    python scripts/sigma2splunk.py rules/windows/process_creation/my_rule.yml
    python scripts/sigma2splunk.py rules/windows/process_creation/  (converts all rules in directory)
    python scripts/sigma2splunk.py --test-all  (converts and tests every rule in the repo)

What it does:
    1. Reads your Sigma YAML file
    2. Converts it to Splunk SPL using pySigma
    3. Runs the query against your live Splunk instance
    4. Shows results or suggests field corrections
    5. Saves the SPL file for deployment

Requirements:
    pip install pySigma pySigma-backend-splunk pySigma-pipeline-sysmon pySigma-pipeline-splunk PyYAML requests
"""

import sys
import os
import yaml # type: ignore
import json
import time
import argparse
import urllib3 # type: ignore
from pathlib import Path
from datetime import datetime

# Suppress SSL warnings for self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# pySigma imports
from sigma.collection import SigmaCollection # type: ignore
from sigma.backends.splunk import SplunkBackend # type: ignore
from sigma.pipelines.sysmon import sysmon_pipeline # type: ignore
from sigma.pipelines.splunk import splunk_windows_pipeline # type: ignore

# ============================================================
# CONFIGURATION — EDIT THESE TO MATCH YOUR LAB
# ============================================================
SPLUNK_HOST = "192.168.0.8"          # Your soc-stack IP (change this!)
SPLUNK_PORT = 8089                    # Splunk management port (NOT 8000)
SPLUNK_USER = "admin"
SPLUNK_PASS = "ChangeMeNow1!"
SPLUNK_WEB_PORT = 8000                # For generating clickable links
SEARCH_EARLIEST = "-24h"             # How far back to search
SEARCH_LATEST = "now"

# Where to save converted SPL files
SPL_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "splunk", "savedsearches")

# ============================================================
# COLORS FOR TERMINAL OUTPUT
# ============================================================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

# On Windows, enable ANSI colors
if sys.platform == 'win32':
    os.system('color')

def print_banner():
    print(f"""{Colors.CYAN}
    ╔═══════════════════════════════════════════════════════╗
    ║        SIGMA → SPLUNK CONVERTER & TESTER              ║
    ║        Detection-as-Code Pipeline v1.0                ║
    ╚═══════════════════════════════════════════════════════╝{Colors.END}
    """)

# ============================================================
# SIGMA CONVERSION
# ============================================================
def convert_sigma_to_spl(sigma_file_path):
    """
    Converts a Sigma YAML rule to Splunk SPL query.

    Args:
        sigma_file_path: Path to the .yml Sigma rule file

    Returns:
        dict with keys: spl_query, rule_title, rule_id, rule_level,
                        mitre_attack, description, status
    """
    print(f"\n{Colors.BLUE}[*] Reading Sigma rule: {sigma_file_path}{Colors.END}")

    # Read and parse the YAML
    with open(sigma_file_path, 'r', encoding='utf-8') as f:
        raw_yaml = f.read()

    rule_data = yaml.safe_load(raw_yaml)

    # Check if the file is empty or invalid
    if rule_data is None:
        print(f"  {Colors.RED}[!] Sigma file is empty or invalid: {sigma_file_path}{Colors.END}")
        return None

    # Display rule metadata
    rule_title = rule_data.get('title', 'Unknown')
    rule_id = rule_data.get('id', 'no-id')
    rule_level = rule_data.get('level', 'unknown')
    rule_status = rule_data.get('status', 'unknown')
    rule_description = rule_data.get('description', 'No description')
    rule_author = rule_data.get('author', 'Unknown')

    # Extract MITRE ATT&CK tags
    tags = rule_data.get('tags', [])
    mitre_tags = [t for t in tags if t.startswith('attack.')]

    print(f"  {Colors.BOLD}Title:{Colors.END}       {rule_title}")
    print(f"  {Colors.BOLD}ID:{Colors.END}          {rule_id}")
    print(f"  {Colors.BOLD}Level:{Colors.END}       {rule_level}")
    print(f"  {Colors.BOLD}Status:{Colors.END}      {rule_status}")
    print(f"  {Colors.BOLD}Author:{Colors.END}      {rule_author}")
    print(f"  {Colors.BOLD}MITRE:{Colors.END}       {', '.join(mitre_tags) if mitre_tags else 'None'}")
    print(f"  {Colors.BOLD}Description:{Colors.END} {rule_description[:100]}...")

    # Create the conversion pipeline
    # sysmon_pipeline() handles Sysmon-specific field mappings
    # splunk_windows_pipeline() handles Splunk-specific transformations
    pipeline = sysmon_pipeline() + splunk_windows_pipeline()

    # Create the backend and convert
    backend = SplunkBackend(pipeline)

    try:
        sigma_collection = SigmaCollection.from_yaml(raw_yaml)
        spl_queries = backend.convert(sigma_collection)

        if not spl_queries:
            print(f"  {Colors.RED}[!] Conversion produced no output{Colors.END}")
            return None

        spl_query = spl_queries[0]  # First query (usually there's only one)

        # Fix source name and add index for our Splunk environment
        spl_query = spl_query.replace(
            'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
            'index="sysmon" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
        )
        # Also handle Windows Security/System/Application logs
        spl_query = spl_query.replace(
            'source="WinEventLog:Security"',
            'index="windows" source="WinEventLog:Security"'
        )
        spl_query = spl_query.replace(
            'source="WinEventLog:System"',
            'index="windows" source="WinEventLog:System"'
        )

        print(f"\n  {Colors.GREEN}[+] Converted SPL query:{Colors.END}")
        print(f"  {Colors.CYAN}────────────────────────────────────────{Colors.END}")
        # Print query with line wrapping for readability
        for i in range(0, len(spl_query), 100):
            print(f"  {spl_query[i:i+100]}")
        print(f"  {Colors.CYAN}────────────────────────────────────────{Colors.END}")

        return {
            'spl_query': spl_query,
            'rule_title': rule_title,
            'rule_id': rule_id,
            'rule_level': rule_level,
            'mitre_attack': mitre_tags,
            'description': rule_description,
            'status': rule_status,
            'source_file': str(sigma_file_path)
        }

    except Exception as e:
        print(f"  {Colors.RED}[!] Conversion error: {e}{Colors.END}")
        return None


# ============================================================
# SPLUNK QUERY EXECUTION
# ============================================================
def run_splunk_search(spl_query, earliest=SEARCH_EARLIEST, latest=SEARCH_LATEST):
    """
    Runs an SPL query against Splunk and returns results.

    Uses Splunk's REST API:
    1. POST to /services/search/jobs to create a search job
    2. Poll the job until it's done
    3. GET the results

    Args:
        spl_query: The SPL search string
        earliest: Search time range start (e.g., "-24h", "-7d")
        latest: Search time range end (e.g., "now")

    Returns:
        dict with keys: results (list of events), result_count (int), search_id (str)
    """
    import requests # type: ignore

    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

    print(f"\n{Colors.BLUE}[*] Running query against Splunk ({SPLUNK_HOST})...{Colors.END}")
    print(f"  Time range: {earliest} to {latest}")

    # Step 1: Create a search job
    # We wrap the query with | head 50 to avoid pulling too much data
    # and add | table to get structured results
    search_query = f"search {spl_query} | head 50"

    try:
        # Create search job
        response = requests.post(
            f"{base_url}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,  # Self-signed cert
            data={
                'search': search_query,
                'earliest_time': earliest,
                'latest_time': latest,
                'output_mode': 'json'
            }
        )

        if response.status_code != 201:
            print(f"  {Colors.RED}[!] Failed to create search job: {response.status_code}{Colors.END}")
            print(f"  {Colors.RED}    {response.text[:200]}{Colors.END}")
            return None

        search_id = response.json()['sid']
        print(f"  Search ID: {search_id}")

        # Step 2: Wait for the search to complete
        for attempt in range(60):  # Max 60 seconds
            status_response = requests.get(
                f"{base_url}/services/search/jobs/{search_id}",
                auth=(SPLUNK_USER, SPLUNK_PASS),
                verify=False,
                params={'output_mode': 'json'}
            )
            job_status = status_response.json()['entry'][0]['content']

            if job_status['isDone']:
                break

            # Show progress
            scan_count = job_status.get('scanCount', 0)
            event_count = job_status.get('eventCount', 0)
            print(f"  Searching... scanned {scan_count} events, {event_count} matches", end='\r')
            time.sleep(1)
        else:
            print(f"\n  {Colors.YELLOW}[!] Search timed out after 60 seconds{Colors.END}")
            return None

        # Step 3: Get results
        result_count = int(job_status.get('resultCount', 0))
        event_count = int(job_status.get('eventCount', 0))

        results_response = requests.get(
            f"{base_url}/services/search/jobs/{search_id}/results",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={
                'output_mode': 'json',
                'count': 50
            }
        )

        results = results_response.json().get('results', [])

        return {
            'results': results,
            'result_count': event_count,  # Total matching events
            'search_id': search_id
        }

    except requests.exceptions.ConnectionError:
        print(f"  {Colors.RED}[!] Cannot connect to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}{Colors.END}")
        print(f"  {Colors.RED}    Make sure Splunk is running and port {SPLUNK_PORT} is accessible{Colors.END}")
        return None
    except Exception as e:
        print(f"  {Colors.RED}[!] Error running search: {e}{Colors.END}")
        return None


def get_available_fields(index="sysmon", sourcetype=None):
    """
    Queries Splunk to find what fields are actually available in the data.
    This is used when a Sigma rule returns no results — to help you figure out
    which fields exist and what values they have.

    Args:
        index: The Splunk index to check (default: sysmon)
        sourcetype: Optional sourcetype filter

    Returns:
        dict mapping field names to sample values
    """
    import requests # type: ignore

    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

    # Build a query that shows top fields and their values
    if sourcetype:
        base_search = f"search index={index} sourcetype=\"{sourcetype}\" earliest=-24h"
    else:
        base_search = f"search index={index} earliest=-24h"

    # Get field summary
    field_query = f"{base_search} | head 1000 | fieldsummary | where count > 10 | table field, distinct_count, values | sort -distinct_count"

    print(f"\n{Colors.BLUE}[*] Fetching available fields from index={index}...{Colors.END}")

    try:
        response = requests.post(
            f"{base_url}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data={
                'search': field_query,
                'earliest_time': '-24h',
                'latest_time': 'now',
                'output_mode': 'json',
                'exec_mode': 'blocking'  # Wait for results
            }
        )

        if response.status_code != 201:
            return {}

        search_id = response.json()['sid']

        results_response = requests.get(
            f"{base_url}/services/search/jobs/{search_id}/results",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={'output_mode': 'json', 'count': 100}
        )

        results = results_response.json().get('results', [])

        fields = {}
        for r in results:
            field_name = r.get('field', '')
            distinct = r.get('distinct_count', '')
            values = r.get('values', '')
            fields[field_name] = {
                'distinct_count': distinct,
                'sample_values': values[:200]  # Truncate long value lists
            }

        return fields

    except Exception as e:
        print(f"  {Colors.RED}[!] Error fetching fields: {e}{Colors.END}")
        return {}


def get_eventcode_fields(index="sysmon", event_code=None):
    """
    For Sysmon data, get the fields available for a specific EventCode.
    This is incredibly useful when your Sigma rule targets a specific event type.

    Args:
        index: The Splunk index
        event_code: Sysmon EventCode (1, 3, 10, 13, etc.)

    Returns:
        list of field names
    """
    import requests # type: ignore

    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

    if event_code:
        search = f"search index={index} EventCode={event_code} earliest=-24h | head 1 | fields *"
    else:
        search = f"search index={index} earliest=-24h | head 1 | fields *"

    try:
        response = requests.post(
            f"{base_url}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            data={
                'search': search,
                'earliest_time': '-24h',
                'latest_time': 'now',
                'output_mode': 'json',
                'exec_mode': 'blocking'
            }
        )

        search_id = response.json()['sid']

        results_response = requests.get(
            f"{base_url}/services/search/jobs/{search_id}/results",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=False,
            params={'output_mode': 'json', 'count': 1}
        )

        results = results_response.json().get('results', [])
        if results:
            return list(results[0].keys())
        return []

    except Exception as e:
        return []


def suggest_field_corrections(spl_query, available_fields):
    """
    Compares fields used in the SPL query against fields actually available
    in Splunk, and suggests corrections.

    This is the "smart" part — when your Sigma rule uses a field name that
    doesn't exist in Splunk, this function finds the closest matching field.

    Args:
        spl_query: The SPL query string
        available_fields: dict of available field names

    Returns:
        list of suggestions
    """
    suggestions = []
    available_names = set(available_fields.keys())

    # Common field name mappings between Sigma and Splunk/Sysmon
    # Sigma uses generic names, Splunk/Sysmon uses specific names
    KNOWN_MAPPINGS = {
        'Image': ['Image', 'process', 'Process', 'NewProcessName'],
        'ParentImage': ['ParentImage', 'ParentProcess', 'ParentProcessName'],
        'CommandLine': ['CommandLine', 'command_line', 'cmd', 'Process_Command_Line'],
        'ParentCommandLine': ['ParentCommandLine', 'parent_command_line'],
        'User': ['User', 'user', 'SourceUser', 'SubjectUserName', 'TargetUserName'],
        'TargetFilename': ['TargetFilename', 'TargetFileName', 'file_name', 'FilePath'],
        'SourceIp': ['SourceIp', 'SourceIP', 'src_ip', 'src'],
        'DestinationIp': ['DestinationIp', 'DestinationIP', 'dest_ip', 'dest'],
        'DestinationPort': ['DestinationPort', 'dest_port', 'DestPort'],
        'TargetObject': ['TargetObject', 'ObjectName', 'RegistryKey'],
        'Details': ['Details', 'RegistryValue', 'ObjectValue'],
        'EventType': ['EventType', 'EventCode', 'event_id'],
        'QueryName': ['QueryName', 'query', 'dns_query'],
        'Hashes': ['Hashes', 'hash', 'SHA256', 'MD5', 'file_hash'],
    }

    # Extract field names from the SPL query
    # Look for patterns like: field_name="value" or field_name=value
    import re
    field_pattern = re.compile(r'(\w+)\s*[=!<>]+\s*["\']?')
    used_fields = set(field_pattern.findall(spl_query))

    # Remove SPL keywords from the "used fields" list
    spl_keywords = {'search', 'index', 'sourcetype', 'source', 'host', 'earliest',
                    'latest', 'NOT', 'AND', 'OR', 'head', 'table', 'stats',
                    'count', 'where', 'eval', 'rename', 'sort', 'dedup',
                    'EventCode', 'Type'}
    used_fields -= spl_keywords

    for field in used_fields:
        if field not in available_names:
            # Field doesn't exist — try to find a close match
            suggestion = None

            # Check known mappings first
            for sigma_name, splunk_alternatives in KNOWN_MAPPINGS.items():
                if field == sigma_name or field.lower() == sigma_name.lower():
                    for alt in splunk_alternatives:
                        if alt in available_names:
                            suggestion = alt
                            break

            # If no known mapping, try fuzzy matching
            if not suggestion:
                # Simple: check for case-insensitive match
                for available in available_names:
                    if field.lower() == available.lower():
                        suggestion = available
                        break

                # Check for partial match (field name contained in available field)
                if not suggestion:
                    close_matches = [a for a in available_names
                                     if field.lower() in a.lower() or a.lower() in field.lower()]
                    if close_matches:
                        suggestion = close_matches[0]

            if suggestion:
                suggestions.append({
                    'used_field': field,
                    'suggested_field': suggestion,
                    'confidence': 'HIGH' if field.lower() == suggestion.lower() else 'MEDIUM'
                })
            else:
                suggestions.append({
                    'used_field': field,
                    'suggested_field': None,
                    'confidence': 'NONE'
                })

    return suggestions


# ============================================================
# SPL FILE SAVING (for deployment)
# ============================================================
def save_spl_file(conversion_result):
    """
    Saves the converted SPL query to a file for Splunk deployment.

    The file is saved in the splunk/savedsearches/ directory with metadata
    that GitHub Actions will use to deploy it.

    Args:
        conversion_result: dict from convert_sigma_to_spl()

    Returns:
        Path to the saved SPL file
    """
    os.makedirs(SPL_OUTPUT_DIR, exist_ok=True)

    # Create filename from rule title (sanitized)
    safe_name = "".join(c if c.isalnum() or c in '-_' else '_' for c in conversion_result['rule_title'])
    safe_name = safe_name[:80]  # Truncate long names

    spl_file_path = os.path.join(SPL_OUTPUT_DIR, f"{safe_name}.yml")

    # Save as a YAML file containing both the SPL and metadata
    # GitHub Actions will read this to create Splunk saved searches
    output = {
        'rule_title': conversion_result['rule_title'],
        'rule_id': conversion_result['rule_id'],
        'rule_level': conversion_result['rule_level'],
        'mitre_attack': conversion_result['mitre_attack'],
        'description': conversion_result['description'],
        'spl_query': conversion_result['spl_query'],
        'source_sigma_file': conversion_result['source_file'],
        'converted_at': datetime.utcnow().isoformat(),
        'splunk_saved_search': {
            'name': f"Detection: {conversion_result['rule_title']}",
            'search': conversion_result['spl_query'],
            'cron_schedule': '*/5 * * * *',  # Every 5 minutes
            'is_scheduled': True,
            'alert_type': 'number of events',
            'alert_threshold': 0,
            'alert_comparator': 'greater than',
            'dispatch_earliest_time': '-5m',
            'dispatch_latest_time': 'now'
        }
    }

    with open(spl_file_path, 'w', encoding='utf-8') as f:
        yaml.dump(output, f, default_flow_style=False, sort_keys=False)

    print(f"\n  {Colors.GREEN}[+] Saved SPL to: {spl_file_path}{Colors.END}")
    return spl_file_path


# ============================================================
# MAIN EXECUTION
# ============================================================
def process_single_rule(sigma_file_path, skip_test=False):
    """
    Full pipeline for a single Sigma rule:
    1. Convert to SPL
    2. Test against Splunk
    3. Show results or suggest fixes
    4. Save the SPL file
    """
    # Step 1: Convert
    result = convert_sigma_to_spl(sigma_file_path)
    if not result:
        return False

    # Step 2: Save the SPL file regardless of test results
    spl_path = save_spl_file(result)

    if skip_test:
        print(f"\n{Colors.YELLOW}[*] Skipping Splunk test (--no-test flag){Colors.END}")
        return True

    # Step 3: Test against Splunk
    search_result = run_splunk_search(result['spl_query'], earliest=SEARCH_EARLIEST, latest=SEARCH_LATEST)

    if search_result is None:
        print(f"\n{Colors.YELLOW}[!] Could not connect to Splunk — skipping live test{Colors.END}")
        print(f"  SPL file saved at: {spl_path}")
        return True

    # Step 4: Display results
    result_count = search_result['result_count']

    if result_count > 0:
        # SUCCESS — we have hits!
        print(f"\n  {Colors.GREEN}{'═' * 50}{Colors.END}")
        print(f"  {Colors.GREEN}[+] RESULTS FOUND: {result_count} events matched!{Colors.END}")
        print(f"  {Colors.GREEN}{'═' * 50}{Colors.END}")

        # Show first few results
        print(f"\n  {Colors.BOLD}Sample results (first 5):{Colors.END}")
        for i, event in enumerate(search_result['results'][:5]):
            print(f"\n  {Colors.CYAN}--- Event {i+1} ---{Colors.END}")
            # Show key fields
            for key in ['_time', 'EventCode', 'Image', 'CommandLine', 'User',
                        'ParentImage', 'TargetObject', 'DestinationIp', 'QueryName',
                        'SourceIp', 'DestinationPort', 'Hashes']:
                if key in event and event[key]:
                    val = str(event[key])[:120]  # Truncate long values
                    print(f"    {key}: {val}")

        # Generate Splunk web link
        encoded_query = result['spl_query'].replace(' ', '%20').replace('"', '%22')
        splunk_url = f"http://{SPLUNK_HOST}:{SPLUNK_WEB_PORT}/en-US/app/search/search?q=search%20{encoded_query}&earliest={SEARCH_EARLIEST}&latest={SEARCH_LATEST}"
        print(f"\n  {Colors.BLUE}[→] View in Splunk:{Colors.END}")
        print(f"  {splunk_url}")

    else:
        # NO RESULTS — help the user fix the rule
        print(f"\n  {Colors.YELLOW}{'═' * 50}{Colors.END}")
        print(f"  {Colors.YELLOW}[!] NO RESULTS — 0 events matched{Colors.END}")
        print(f"  {Colors.YELLOW}{'═' * 50}{Colors.END}")

        print(f"\n  {Colors.BOLD}Possible reasons:{Colors.END}")
        print(f"  1. The attack hasn't been executed yet (run Atomic Red Team first)")
        print(f"  2. The Sigma rule uses field names that don't match your Splunk data")
        print(f"  3. The time range is too narrow (currently searching {SEARCH_EARLIEST} to {SEARCH_LATEST})")
        print(f"  4. The sourcetype or index might be wrong")

        # Get available fields and suggest corrections
        print(f"\n  {Colors.BOLD}Analyzing field availability...{Colors.END}")

        # Try to figure out which EventCode this rule targets
        import re
        ec_match = re.search(r'EventCode[=:]\s*["\']?(\d+)', result['spl_query'])
        event_code = ec_match.group(1) if ec_match else None

        available_fields = get_available_fields(index="sysmon")
        if event_code:
            ec_fields = get_eventcode_fields(index="sysmon", event_code=event_code)
            print(f"\n  {Colors.BOLD}Fields available for EventCode={event_code}:{Colors.END}")
            # Show fields in a readable format
            for f in sorted(ec_fields)[:30]:
                if not f.startswith('_'):
                    print(f"    • {f}")

        # Suggest corrections
        suggestions = suggest_field_corrections(result['spl_query'], available_fields)
        if suggestions:
            has_issues = [s for s in suggestions if s['suggested_field'] is not None]
            no_match = [s for s in suggestions if s['suggested_field'] is None]

            if has_issues:
                print(f"\n  {Colors.YELLOW}[!] Field name mismatches detected:{Colors.END}")
                for s in has_issues:
                    print(f"    {Colors.RED}✗ Your rule uses: {s['used_field']}{Colors.END}")
                    print(f"    {Colors.GREEN}✓ Splunk has:      {s['suggested_field']} ({s['confidence']} confidence){Colors.END}")
                    print()

            if no_match:
                print(f"\n  {Colors.RED}[!] Fields not found in Splunk at all:{Colors.END}")
                for s in no_match:
                    print(f"    ✗ {s['used_field']}")
                print(f"\n  These fields might not be extracted by Sysmon or your sourcetype.")
                print(f"  Check if the Sysmon config captures these events.")

        # Show a sample raw event so the user can see what fields exist
        print(f"\n  {Colors.BOLD}Quick check — run this in Splunk to see available data:{Colors.END}")
        if event_code:
            print(f"  {Colors.CYAN}index=sysmon EventCode={event_code} | head 5{Colors.END}")
        else:
            print(f"  {Colors.CYAN}index=sysmon | head 5{Colors.END}")

        # Generate Splunk web link for exploration
        explore_query = f"index%3Dsysmon%20EventCode%3D{event_code}" if event_code else "index%3Dsysmon"
        splunk_url = f"http://{SPLUNK_HOST}:{SPLUNK_WEB_PORT}/en-US/app/search/search?q=search%20{explore_query}%20%7C%20head%2020&earliest=-24h&latest=now"
        print(f"\n  {Colors.BLUE}[→] Explore data in Splunk:{Colors.END}")
        print(f"  {splunk_url}")

    return result_count > 0


def main():
    parser = argparse.ArgumentParser(
        description='Sigma to Splunk converter and tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sigma2splunk.py rules/windows/process_creation/my_rule.yml
  python sigma2splunk.py rules/windows/process_creation/     (all rules in dir)
  python sigma2splunk.py --test-all                           (all rules in repo)
  python sigma2splunk.py rules/my_rule.yml --no-test          (convert only, skip testing)
  python sigma2splunk.py rules/my_rule.yml --earliest=-7d     (search last 7 days)
        """
    )
    parser.add_argument('path', nargs='?', help='Path to Sigma rule (.yml) or directory')
    # Update search time range if specified
    global SEARCH_EARLIEST, SEARCH_LATEST

    parser.add_argument('--test-all', action='store_true', help='Test all rules in the rules/ directory')
    parser.add_argument('--no-test', action='store_true', help='Convert only, skip Splunk testing')
    parser.add_argument('--earliest', default=SEARCH_EARLIEST, help='Search time range start (default: -24h)')
    parser.add_argument('--latest', default=SEARCH_LATEST, help='Search time range end (default: now)')

    args = parser.parse_args()
    SEARCH_EARLIEST = args.earliest
    SEARCH_LATEST = args.latest

    print_banner()

    if not args.path and not args.test_all:
        parser.print_help()
        sys.exit(1)

    # Collect all sigma files to process
    sigma_files = []

    if args.test_all:
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rules')
        for root, dirs, files in os.walk(rules_dir):
            for f in files:
                if f.endswith('.yml') or f.endswith('.yaml'):
                    sigma_files.append(os.path.join(root, f))
        print(f"Found {len(sigma_files)} Sigma rules to process\n")

    elif os.path.isdir(args.path):
        for f in os.listdir(args.path):
            if f.endswith('.yml') or f.endswith('.yaml'):
                sigma_files.append(os.path.join(args.path, f))
        print(f"Found {len(sigma_files)} Sigma rules in {args.path}\n")

    elif os.path.isfile(args.path):
        sigma_files.append(args.path)

    else:
        print(f"{Colors.RED}[!] Path not found: {args.path}{Colors.END}")
        sys.exit(1)

    # Process each rule
    results_summary = {'passed': 0, 'no_results': 0, 'errors': 0}

    for sigma_file in sorted(sigma_files):
        try:
            success = process_single_rule(sigma_file, skip_test=args.no_test)
            if success:
                results_summary['passed'] += 1
            else:
                results_summary['no_results'] += 1
        except Exception as e:
            print(f"{Colors.RED}[!] Error processing {sigma_file}: {e}{Colors.END}")
            results_summary['errors'] += 1

    # Print summary
    total = len(sigma_files)
    print(f"\n{'═' * 50}")
    print(f"{Colors.BOLD}SUMMARY{Colors.END}")
    print(f"{'═' * 50}")
    print(f"  Total rules processed: {total}")
    print(f"  {Colors.GREEN}✓ With results:  {results_summary['passed']}{Colors.END}")
    print(f"  {Colors.YELLOW}○ No results:    {results_summary['no_results']}{Colors.END}")
    print(f"  {Colors.RED}✗ Errors:        {results_summary['errors']}{Colors.END}")
    print()


if __name__ == '__main__':
    main()