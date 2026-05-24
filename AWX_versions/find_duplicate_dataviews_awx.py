#!/usr/bin/env python3
"""
Find Duplicate Data Views — AWX Edition

Refactored for execution as an Ansible AWX Job Template.

WHAT CHANGED FROM THE ORIGINAL
------------------------------
1. There is NO clusters.json. Each Kibana deployment already has its own secret
   in AWS Secrets Manager, where the SECRET NAME equals the DEPLOYMENT NAME. The
   secret's JSON contents hold the kibana_url and api_key. The script fetches
   each deployment's secret at runtime via boto3, using the AMBIENT AWS
   credentials of the AWX execution environment (whatever role AWX assumed). No
   credentials or URLs live on disk.

2. The AWX survey passes ONE OR MORE deployment names (--deployments). For each
   name, the script looks up the same-named secret, reads its kibana_url +
   api_key, and scans it. Multiple deployments are processed in one run.

3. verify_ssl is supplied as an AWX argument (--verify-ssl / --no-verify-ssl)
   and applied to all deployments in the run, since there is no per-cluster
   config file to carry it anymore.

The scanning, labeling, reporting, CSV/JSON export, dry-run-delete preview, and
top-offenders logic are unchanged from the original tool.

AWX SURVEY MAPPING
------------------
  Deployment name(s)     -> --deployments "FISMA Scorecard" "applogging-v4"   (required, 1+)
  Spaces (optional)      -> --spaces "FISMA Team" "Default"
  Verify SSL             -> --verify-ssl (default) / --no-verify-ssl
  AWS region (optional)  -> --aws-region us-east-2
  Output format          -> --output {table,csv,json}
  Verbose                -> --verbose
  Dry-run delete preview -> --dry-run-delete
  Top offenders          -> --top-offenders

CLI USAGE (for engineers debugging outside AWX)
-----------------------------------------------
    # One deployment
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard"

    # Multiple deployments in one run
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" "applogging-v4"

    # Restrict to specific spaces
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --spaces "FISMA Team"

    # Disable SSL verification
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --no-verify-ssl

    # Connectivity check
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --connectivity-check

    # Export
    python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --output csv
"""

import sys
import os
import requests
import logging
import json
import csv
import time
import shutil
from collections import defaultdict
from argparse import ArgumentParser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Shared Secrets Manager resolution (AWX edition)
from elk_secrets import (
    resolve_deployments,
    get_headers,
)


# ==============================================================================
# PROGRESS BAR
# ==============================================================================

class ProgressBar:
    """A simple terminal progress bar. Auto-detects terminal width."""

    def __init__(self, total, prefix="Progress"):
        self.total = total
        self.prefix = prefix
        self.start_time = time.time()
        self.current = 0
        self.terminal_width = shutil.get_terminal_size((80, 20)).columns

    def update(self, current, status=""):
        self.current = current
        elapsed = time.time() - self.start_time
        pct = current / self.total if self.total > 0 else 1.0
        filled = int(30 * pct)
        bar = "█" * filled + "░" * (30 - filled)

        if pct > 0 and current > 0:
            eta = elapsed / pct - elapsed
            time_str = f"ETA {self._fmt_time(eta)}"
        else:
            time_str = "ETA --:--"

        elapsed_str = self._fmt_time(elapsed)
        status_display = f" | {status}" if status else ""

        line = f"\r  {self.prefix} |{bar}| {current}/{self.total} ({pct:.0%}) [{elapsed_str} < {time_str}]{status_display}"
        line = line[:self.terminal_width - 1]
        line = line.ljust(self.terminal_width - 1)
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self, summary=""):
        elapsed = time.time() - self.start_time
        elapsed_str = self._fmt_time(elapsed)
        line = f"\r  {self.prefix} |{'█' * 30}| {self.total}/{self.total} (100%) [{elapsed_str}] ✅ Done"
        if summary:
            line += f" — {summary}"
        line = line[:self.terminal_width - 1].ljust(self.terminal_width - 1)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    @staticmethod
    def _fmt_time(seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m{s:02d}s"
        else:
            h, remainder = divmod(int(seconds), 3600)
            m, s = divmod(remainder, 60)
            return f"{h}h{m:02d}m"


# ==============================================================================
# KIBANA API HELPERS
# ==============================================================================

def get_object_types():
    return [
        "config", "config-global", "url", "index-pattern", "action", "query",
        "tag", "graph-workspace", "alert", "search", "visualization",
        "event-annotation-group", "dashboard", "lens", "cases",
        "metrics-data-source", "links", "canvas-element", "canvas-workpad",
        "osquery-saved-query", "osquery-pack", "csp-rule-template", "map",
        "infrastructure-monitoring-log-view", "threshold-explorer-view",
        "uptime-dynamic-settings", "synthetics-privates-locations",
        "apm-indices", "infrastructure-ui-source", "inventory-view",
        "infra-custom-dashboards", "metrics-explorer-view", "apm-service-group",
        "apm-custom-dashboards"
    ]


def get_all_spaces(headers, kibana_url, verify_ssl=True):
    spaces_endpoint = f"{kibana_url}/api/spaces/space"
    try:
        response = requests.get(spaces_endpoint, headers=headers, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        spaces = response.json()
        logging.info(f"  Found {len(spaces)} spaces")
        return spaces
    except requests.exceptions.RequestException as e:
        logging.error(f"  Failed to retrieve spaces: {e}")
        return []


def get_all_dataviews(space_id, headers, kibana_url, verify_ssl=True):
    dataview_url = f'{kibana_url}/s/{space_id}/api/data_views'
    try:
        response = requests.get(dataview_url, headers=headers, verify=verify_ssl, timeout=30)
        if response.status_code == 200:
            return response.json().get('data_view', [])
        else:
            logging.warning(f"    Failed to get data views in space '{space_id}': HTTP {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        logging.warning(f"    Failed to get data views in space '{space_id}': {e}")
        return []


def get_default_dataview_id(space_id, headers, kibana_url, verify_ssl=True):
    default_url = f'{kibana_url}/s/{space_id}/api/data_views/default'
    try:
        response = requests.get(default_url, headers=headers, verify=verify_ssl, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return data.get("data_view_id") or None
        return None
    except requests.exceptions.RequestException:
        return None


def find_duplicated_data_views(data_views):
    title_to_ids = defaultdict(list)
    for dv in data_views:
        title = dv.get("title")
        if not title:
            logging.warning(f"    Skipping data view '{dv.get('id', 'unknown')}' — missing title")
            continue
        title_to_ids[title].append(dv["id"])
    return {title: ids for title, ids in title_to_ids.items() if len(ids) > 1}


def _request_with_retry(url, headers, params=None, verify=True, timeout=30, max_retries=3):
    response = None
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url, headers=headers, params=params,
                verify=verify, timeout=timeout
            )
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            wait = 2 ** attempt
            logging.warning(f"    Timeout on {url} (attempt {attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.ConnectionError:
            wait = 2 ** attempt
            logging.warning(f"    Connection error on {url} (attempt {attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            if response is not None and 400 <= response.status_code < 500 and response.status_code != 429:
                logging.debug(f"    HTTP {response.status_code} on {url} — not retrying")
                return response
            wait = 2 ** attempt
            logging.warning(f"    HTTP error on {url} (attempt {attempt+1}/{max_retries}): {e}, retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            logging.warning(f"    Request failed on {url}: {e}")
            return None
    logging.error(f"    All {max_retries} retries exhausted for {url}")
    return None


def get_object_references(data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl=True):
    objects_endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    reference_counts = defaultdict(int)
    data_view_id_set = set(data_view_ids)

    base_params = [('fields', 'references'), ('per_page', '10000')]
    for ot in object_types:
        base_params.append(('type', ot))

    page = 1
    total_fetched = 0

    while True:
        params = base_params + [('page', str(page))]
        response = _request_with_retry(
            objects_endpoint, headers=headers, params=params,
            verify=verify_ssl, timeout=30, max_retries=3
        )

        if response is None or response.status_code != 200:
            logging.debug(f"    Batched _find failed for space '{space_id}', falling back to per-type queries")
            return _get_object_references_fallback(
                data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl
            )

        data = response.json()
        saved_objects = data.get("saved_objects", [])
        total = data.get("total", 0)

        for obj in saved_objects:
            for ref in obj.get("references", []):
                if ref.get("type") == "index-pattern" and ref.get("id") in data_view_id_set:
                    reference_counts[ref["id"]] += 1

        total_fetched += len(saved_objects)
        if total_fetched >= total or len(saved_objects) == 0:
            break
        page += 1

    return reference_counts


def _get_object_references_fallback(data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl=True):
    objects_endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    reference_counts = defaultdict(int)
    data_view_id_set = set(data_view_ids)

    for object_type in object_types:
        params = {'fields': 'references', 'type': object_type, 'per_page': 10000}
        response = _request_with_retry(
            objects_endpoint, headers=headers, params=params,
            verify=verify_ssl, timeout=30, max_retries=2
        )
        if response is None or response.status_code != 200:
            continue
        data = response.json()
        for obj in data.get("saved_objects", []):
            for ref in obj.get("references", []):
                if ref.get("type") == "index-pattern" and ref.get("id") in data_view_id_set:
                    reference_counts[ref["id"]] += 1

    return reference_counts


# ==============================================================================
# CONNECTIVITY CHECK
# ==============================================================================

def check_connectivity(clusters):
    """Test connectivity to the given (already credential-resolved) clusters."""
    results = {}
    for name, cluster in clusters.items():
        if not cluster.get("api_key") or not cluster.get("kibana_url"):
            print(f"  ❌ {name:30s} — missing api_key/kibana_url")
            results[name] = False
            continue

        headers = get_headers(cluster["api_key"])
        verify_ssl = cluster.get("verify_ssl", True)
        kibana_url = cluster["kibana_url"]
        try:
            response = requests.get(
                f"{kibana_url}/api/spaces/space",
                headers=headers, verify=verify_ssl, timeout=15
            )
            if response.status_code == 200:
                space_count = len(response.json())
                print(f"  ✅ {name:30s} — Connected ({space_count} spaces)")
                results[name] = True
            else:
                print(f"  ❌ {name:30s} — HTTP {response.status_code}")
                results[name] = False
        except requests.exceptions.RequestException as e:
            print(f"  ❌ {name:30s} — {e}")
            results[name] = False
    return results


# ==============================================================================
# CORE: SCAN A SINGLE CLUSTER
# ==============================================================================

def scan_cluster(name, cluster, object_types, progress_info=None, space_filter=None):
    kibana_url = cluster["kibana_url"]
    api_key = cluster["api_key"]
    verify_ssl = cluster.get("verify_ssl", True)
    headers = get_headers(api_key)
    results = []

    logging.info(f"[{name}] Scanning {kibana_url} ...")
    spaces = get_all_spaces(headers, kibana_url, verify_ssl)

    if not spaces:
        logging.warning(f"[{name}] No spaces found or unable to connect.")
        if progress_info:
            with progress_info["lock"]:
                progress_info["counter"][0] += 1
                progress_info["bar"].update(progress_info["counter"][0], status=f"{name} — no spaces")
        return results

    if space_filter:
        spaces = [s for s in spaces
                  if s.get("id") in space_filter or s.get("name") in space_filter]
        if not spaces:
            logging.warning(f"[{name}] No matching spaces after filter. Skipping.")
            if progress_info:
                with progress_info["lock"]:
                    progress_info["counter"][0] += 1
                    progress_info["bar"].update(progress_info["counter"][0], status=f"{name} — no matching spaces")
            return results
        logging.info(f"  Filtered to {len(spaces)} space(s)")

    for i, space in enumerate(spaces):
        space_id = space["id"]
        space_name = space.get("name", space_id)

        if progress_info:
            with progress_info["lock"]:
                progress_info["bar"].update(
                    progress_info["counter"][0],
                    status=f"{name} > {space_name} ({i+1}/{len(spaces)})"
                )

        data_views = get_all_dataviews(space_id, headers, kibana_url, verify_ssl)
        if not data_views:
            continue

        duplicates = find_duplicated_data_views(data_views)
        if not duplicates:
            continue

        default_dv_id = get_default_dataview_id(space_id, headers, kibana_url, verify_ssl)

        for title, ids in duplicates.items():
            reference_counts = get_object_references(
                ids, kibana_url, space_id, object_types, headers, verify_ssl
            )
            for dv_id in ids:
                results.append({
                    "deployment": name,
                    "kibana_url": kibana_url,
                    "space_id": space_id,
                    "space_name": space_name,
                    "data_view_title": title,
                    "data_view_id": dv_id,
                    "reference_count": reference_counts.get(dv_id, 0),
                    "duplicate_count": len(ids),
                    "is_default": dv_id == default_dv_id if default_dv_id else False,
                })

    if progress_info:
        with progress_info["lock"]:
            progress_info["counter"][0] += 1
            progress_info["bar"].update(
                progress_info["counter"][0],
                status=f"{name} — done ({len(results)} duplicates)"
            )

    return results


# ==============================================================================
# LABELING / OUTPUT / EXPORT / DRY-RUN / TOP OFFENDERS
# (unchanged from original)
# ==============================================================================

def label_results(all_results):
    groups = defaultdict(list)
    for r in all_results:
        key = (r["deployment"], r["space_id"], r["data_view_title"])
        groups[key].append(r)

    for key, entries in groups.items():
        entries_sorted = sorted(entries, key=lambda e: e["reference_count"], reverse=True)
        keep_id = entries_sorted[0]["data_view_id"]
        for entry in entries:
            if entry["is_default"]:
                entry["action"] = "KEEP (DEFAULT)"
            elif entry["data_view_id"] == keep_id:
                entry["action"] = "KEEP"
            elif entry["reference_count"] == 0:
                entry["action"] = "SAFE TO DELETE"
            else:
                entry["action"] = "REVIEW"


def print_results(all_results, scan_stats=None):
    if not all_results:
        print("\n" + "=" * 90)
        print("✅ ALL CLEAR: No duplicate data views found.")
        print("=" * 90)
        if scan_stats:
            _print_scan_stats(scan_stats)
        return

    grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in all_results:
        grouped[r["deployment"]][r["space_name"]][r["data_view_title"]].append(r)

    total_duplicates = 0
    total_deployments_affected = len(grouped)

    print("\n" + "=" * 90)
    print("DUPLICATE DATA VIEWS REPORT")
    print("=" * 90)

    for deployment in sorted(grouped.keys()):
        spaces = grouped[deployment]
        print(f"\n{'─' * 90}")
        print(f"📦 DEPLOYMENT: {deployment.upper()}")
        print(f"{'─' * 90}")

        for space_name in sorted(spaces.keys()):
            titles = spaces[space_name]
            print(f"\n  🔹 Space: {space_name}")

            for title in sorted(titles.keys()):
                entries = titles[title]
                total_duplicates += 1
                print(f"\n    Data View Title: {title}")
                print(f"    Copies: {entries[0]['duplicate_count']}")

                action_order = {"KEEP (DEFAULT)": 0, "KEEP": 1, "REVIEW": 2, "SAFE TO DELETE": 3}
                entries_sorted = sorted(entries, key=lambda e: (
                    action_order.get(e.get("action", ""), 99),
                    -e["reference_count"]
                ))

                for entry in entries_sorted:
                    ref_count = entry['reference_count']
                    ref_label = f"{ref_count} refs"
                    action = entry.get("action", "")
                    if action == "KEEP (DEFAULT)":
                        tag = "  ← KEEP (DEFAULT)"
                    elif action == "KEEP":
                        tag = "  ← KEEP"
                    elif action == "SAFE TO DELETE":
                        tag = "  ← SAFE TO DELETE"
                    elif action == "REVIEW":
                        tag = "  ← REVIEW (has refs)"
                    else:
                        tag = ""
                    print(f"      ID: {entry['data_view_id']:45s}  ({ref_label}){tag}")

    total_entries = len(all_results)
    safe_to_delete = sum(1 for r in all_results if r.get("action") == "SAFE TO DELETE")
    review_count = sum(1 for r in all_results if r.get("action") == "REVIEW")

    print(f"\n{'=' * 90}")
    print("SUMMARY")
    print(f"{'=' * 90}")
    print(f"  Deployments with duplicates : {total_deployments_affected}")
    print(f"  Duplicate title groups       : {total_duplicates}")
    print(f"  Total duplicate data view IDs: {total_entries}")
    print(f"  Safe to delete (0 refs)      : {safe_to_delete}")
    print(f"  Needs review (has refs)      : {review_count}")

    if scan_stats:
        _print_scan_stats(scan_stats)
    else:
        print(f"{'=' * 90}")


def _print_scan_stats(scan_stats):
    print(f"{'─' * 90}")
    total = scan_stats.get("total", 0)
    clean = scan_stats.get("clean", 0)
    with_dups = scan_stats.get("with_duplicates", 0)
    failed = scan_stats.get("failed", 0)
    elapsed = scan_stats.get("elapsed", 0)
    incomplete = scan_stats.get("incomplete", 0)
    interrupted = scan_stats.get("interrupted", False)

    status_parts = [
        f"Clusters scanned: {total}",
        f"Clean: {clean}",
        f"With duplicates: {with_dups}",
        f"Failed: {failed}",
    ]
    if interrupted:
        status_parts.append(f"Incomplete: {incomplete}")
    print(f"  {'  |  '.join(status_parts)}")

    if interrupted:
        print(f"  ⚠️  Scan was interrupted — results above are PARTIAL")

    if elapsed >= 3600:
        h, remainder = divmod(int(elapsed), 3600)
        m, s = divmod(remainder, 60)
        print(f"  Total scan time: {h}h {m}m {s}s")
    elif elapsed >= 60:
        m, s = divmod(int(elapsed), 60)
        print(f"  Total scan time: {m}m {s}s")
    else:
        print(f"  Total scan time: {elapsed:.1f}s")
    print(f"{'=' * 90}")


def print_dry_run_delete(all_results):
    candidates = [r for r in all_results if r.get("action") == "SAFE TO DELETE"]

    print(f"\n{'=' * 90}")
    print("DRY-RUN DELETE PREVIEW")
    print("The following data views have 0 references and are NOT the space default.")
    print("These would be deleted in an auto-delete run.")
    print(f"{'=' * 90}")

    if not candidates:
        print("\n  ✅ No orphaned duplicates found — nothing to delete.")
        print(f"{'=' * 90}")
        return

    grouped = defaultdict(lambda: defaultdict(list))
    for c in candidates:
        grouped[c["deployment"]][c["space_name"]].append(c)

    total = 0
    for deployment in sorted(grouped.keys()):
        spaces = grouped[deployment]
        print(f"\n  📦 {deployment.upper()}")
        for space_name in sorted(spaces.keys()):
            entries = spaces[space_name]
            print(f"    🔹 {space_name}")
            for entry in sorted(entries, key=lambda e: e["data_view_title"]):
                total += 1
                print(f"      DELETE  {entry['data_view_id']:45s}  (title: {entry['data_view_title']})")
                dv_url = f"{entry['kibana_url']}/s/{entry['space_id']}/api/data_views/data_view/{entry['data_view_id']}"
                print(f"              → DELETE {dv_url}")

    print(f"\n{'─' * 90}")
    print(f"  Total data views that would be deleted: {total}")
    print(f"  ⚠️  This is a PREVIEW only — no changes were made.")
    print(f"{'=' * 90}")


def print_top_offenders(all_results, top_n=15):
    if not all_results:
        return

    space_stats = defaultdict(lambda: {"groups": set(), "ids": 0, "safe_to_delete": 0})
    for r in all_results:
        key = (r["deployment"], r["space_name"])
        space_stats[key]["groups"].add(r["data_view_title"])
        space_stats[key]["ids"] += 1
        if r.get("action") == "SAFE TO DELETE":
            space_stats[key]["safe_to_delete"] += 1

    ranked = sorted(space_stats.items(), key=lambda x: x[1]["ids"], reverse=True)

    print(f"\n{'=' * 90}")
    print(f"TOP OFFENDERS — Spaces with the most duplicate data views")
    print(f"{'=' * 90}")
    print(f"  {'#':<4} {'Deployment':<30} {'Space':<28} {'Groups':>7} {'IDs':>6} {'Deletable':>10}")
    print(f"  {'─' * 86}")

    for i, (key, stats) in enumerate(ranked[:top_n]):
        deployment, space_name = key
        groups = len(stats["groups"])
        ids = stats["ids"]
        deletable = stats["safe_to_delete"]
        print(f"  {i+1:<4} {deployment:<30} {space_name:<28} {groups:>7} {ids:>6} {deletable:>10}")

    if len(ranked) > top_n:
        print(f"  ... and {len(ranked) - top_n} more spaces with duplicates")
    print(f"{'=' * 90}")


def export_csv(all_results, output_file):
    if not all_results:
        print("No results to export.")
        return
    fieldnames = [
        "deployment", "space_id", "space_name", "data_view_title",
        "data_view_id", "reference_count", "duplicate_count",
        "is_default", "action"
    ]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n📄 CSV report exported to: {output_file}")


def export_json(all_results, output_file):
    if not all_results:
        print("No results to export.")
        return
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n📄 JSON report exported to: {output_file}")


# ==============================================================================
# LOGGING SETUP
# ==============================================================================

def setup_logging(verbose=False, log_file=None):
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        if log_file == "auto":
            log_file = f"duplicate_dataviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    logging.basicConfig(level=log_level, format=log_format, handlers=handlers)
    if log_file:
        logging.info(f"Logging to file: {log_file}")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = ArgumentParser(
        description='Find duplicate data views in a Kibana deployment (AWX edition).'
    )
    parser.add_argument(
        '--deployments', nargs='+', default=None,
        help='One or more deployment names to scan (the AWX survey value). Each '
             'name must match its AWS Secrets Manager secret name; the secret '
             'supplies that deployment\'s kibana_url and api_key. May also be '
             'provided via the DEPLOYMENT_NAMES env var (comma- or space-separated).'
    )
    parser.add_argument(
        '--aws-region', default=None,
        help='AWS region for Secrets Manager (default: AWS_REGION env or built-in default)'
    )
    parser.add_argument(
        '--verify-ssl', dest='verify_ssl', action='store_true', default=True,
        help='Verify Kibana SSL certificates (default: enabled)'
    )
    parser.add_argument(
        '--no-verify-ssl', dest='verify_ssl', action='store_false',
        help='Disable Kibana SSL certificate verification'
    )
    parser.add_argument(
        '--spaces', nargs='+', default=None,
        help='Specific space IDs or names to scan (default: scan all spaces)'
    )
    parser.add_argument(
        '--output', choices=['table', 'csv', 'json'], default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--output-file', default=None,
        help='Output file path for csv/json (auto-generated if not specified)'
    )
    parser.add_argument(
        '--connectivity-check', action='store_true',
        help='Only test connectivity to the selected deployment(s), then exit'
    )
    parser.add_argument(
        '--workers', type=int, default=1,
        help='Concurrent workers for scanning multiple deployments (default: 1)'
    )
    parser.add_argument('--verbose', action='store_true', help='Enable debug logging')
    parser.add_argument('--dry-run-delete', action='store_true',
                        help='Preview which orphaned data views would be deleted')
    parser.add_argument('--top-offenders', action='store_true',
                        help='Show a ranking of spaces with the most duplicates')
    parser.add_argument('--log-file', nargs='?', const='auto', default=None,
                        help='Write logs to a file (default: auto-timestamped)')

    args = parser.parse_args()

    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Resolve the list of deployment names: CLI flag first, then env var.
    deployment_names = args.deployments
    if not deployment_names:
        env_val = os.environ.get("DEPLOYMENT_NAMES", "").strip()
        if env_val:
            # Accept comma- or space-separated names from the env var.
            deployment_names = [n for n in env_val.replace(",", " ").split() if n]

    if not deployment_names:
        logging.error(
            "No deployments specified. Pass one or more names via --deployments "
            "\"<name1>\" \"<name2>\" (the AWX survey value), or set DEPLOYMENT_NAMES."
        )
        sys.exit(1)

    # Resolve each deployment from its same-named secret in Secrets Manager,
    # using AWX's ambient AWS credentials. Bad/missing secrets are skipped.
    valid_clusters = resolve_deployments(
        deployment_names, region_name=args.aws_region, verify_ssl=args.verify_ssl
    )
    if not valid_clusters:
        logging.error("No deployments could be resolved from Secrets Manager. Aborting.")
        sys.exit(3)

    # Connectivity check mode
    if args.connectivity_check:
        print("\n🔌 CONNECTIVITY CHECK")
        print("=" * 60)
        results = check_connectivity(valid_clusters)
        success = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"\n  Result: {success}/{total} deployment(s) reachable")
        sys.exit(0 if success == total else 1)

    object_types = get_object_types()
    all_results = []
    cluster_results = {}

    print(f"\n🔍 Scanning {len(valid_clusters)} deployment(s) for duplicate data views...\n")
    start_time = time.time()

    import threading
    progress_bar = ProgressBar(total=len(valid_clusters), prefix="Deployments")
    progress_counter = [0]
    progress_lock = threading.Lock()
    progress_info = {"bar": progress_bar, "counter": progress_counter, "lock": progress_lock}

    failed_clusters = []
    interrupted = False

    try:
        if args.workers > 1 and len(valid_clusters) > 1:
            logging.info(f"Using {args.workers} concurrent workers")
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(scan_cluster, name, cluster, object_types, progress_info, args.spaces): name
                    for name, cluster in valid_clusters.items()
                }
                for future in as_completed(futures):
                    cluster_name = futures[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                        cluster_results[cluster_name] = len(results)
                    except Exception as e:
                        logging.error(f"[{cluster_name}] Scan failed: {e}")
                        failed_clusters.append(cluster_name)
                        with progress_lock:
                            progress_counter[0] += 1
                            progress_bar.update(progress_counter[0], status=f"{cluster_name} — FAILED")
        else:
            for name, cluster in valid_clusters.items():
                try:
                    results = scan_cluster(name, cluster, object_types, progress_info, args.spaces)
                    all_results.extend(results)
                    cluster_results[name] = len(results)
                except Exception as e:
                    logging.error(f"[{name}] Scan failed: {e}")
                    failed_clusters.append(name)
                    with progress_lock:
                        progress_counter[0] += 1
                        progress_bar.update(progress_counter[0], status=f"{name} — FAILED")

    except KeyboardInterrupt:
        interrupted = True
        elapsed = time.time() - start_time
        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"\n{'!' * 90}")
        print(f"⚠️  INTERRUPTED — Scan stopped after {elapsed:.1f}s")
        print(f"   Completed {progress_counter[0]}/{len(valid_clusters)} deployments before interruption.")
        print(f"   Partial results ({len(all_results)} duplicate entries) will be printed below.")
        print(f"{'!' * 90}")

    elapsed = time.time() - start_time

    if not interrupted:
        progress_bar.finish(summary=f"{len(all_results)} duplicate entries found")

    completed_clusters = len(cluster_results)
    with_dups = sum(1 for c, count in cluster_results.items() if count > 0)
    clean = sum(1 for c, count in cluster_results.items() if count == 0)
    incomplete = len(valid_clusters) - completed_clusters - len(failed_clusters)
    scan_stats = {
        "total": len(valid_clusters),
        "clean": clean,
        "with_duplicates": with_dups,
        "failed": len(failed_clusters),
        "elapsed": elapsed,
    }
    if interrupted:
        scan_stats["interrupted"] = True
        scan_stats["incomplete"] = incomplete

    logging.info(f"Scan completed in {elapsed:.1f} seconds")

    label_results(all_results)

    if args.output in ('table', 'csv'):
        print_results(all_results, scan_stats=scan_stats)

    if args.output == 'csv':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_file or f"duplicate_dataviews_{timestamp}.csv"
        export_csv(all_results, output_file)

    if args.output == 'json':
        print_results(all_results, scan_stats=scan_stats)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_file or f"duplicate_dataviews_{timestamp}.json"
        export_json(all_results, output_file)

    if args.dry_run_delete:
        print_dry_run_delete(all_results)

    if args.top_offenders:
        print_top_offenders(all_results)


if __name__ == "__main__":
    main()
