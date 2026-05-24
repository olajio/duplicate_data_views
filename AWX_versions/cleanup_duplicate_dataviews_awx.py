#!/usr/bin/env python3
"""
Cleanup Duplicate Data Views — AWX Edition

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
   api_key, and cleans up that deployment. Multiple deployments per run.

3. verify_ssl is supplied as an AWX argument (--verify-ssl / --no-verify-ssl)
   and applied to all deployments in the run.

4. AWX-friendly approval: in AWX there is no interactive TTY. Set --yes (survey
   checkbox "Auto-confirm deletions") to approve non-interactively, OR keep the
   default dry-run. The interactive prompt is preserved for CLI use; if --execute
   is set without --yes and stdin is not a TTY (i.e. running under AWX), the
   script refuses to delete and tells you to set --yes. This prevents a job from
   silently hanging on input().

Everything else — duplicate detection, KEEP-candidate selection, reference
re-pointing, NDJSON backups, per-data-view backups, deletion verification, and
the audit log — is unchanged from the original tool. Dry-run remains the default.

AWX SURVEY MAPPING
------------------
  Deployment name(s)     -> --deployments "FISMA Scorecard" "applogging-v4"   (required, 1+)
  Spaces (optional)      -> --spaces "FISMA Team"
  Verify SSL             -> --verify-ssl (default) / --no-verify-ssl
  AWS region (optional)  -> --aws-region us-east-2
  Execute changes        -> --execute        (checkbox; default OFF = dry-run)
  Auto-confirm deletions -> --yes            (checkbox; REQUIRED under AWX to delete)
  Verbose                -> --verbose
  Backup directory       -> --backup-dir /path

CLI USAGE (for engineers debugging outside AWX)
-----------------------------------------------
    # Dry-run for one deployment (safe default)
    python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard"

    # Dry-run across multiple deployments
    python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" "applogging-v4"

    # Dry-run, specific space
    python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --spaces "FISMA Team"

    # Execute with interactive validation (TTY)
    python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --execute

    # Execute non-interactively (the AWX path)
    python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --execute --yes
"""

import sys
import os
import requests
import logging
import json
import time
from collections import defaultdict
from argparse import ArgumentParser
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Shared Secrets Manager resolution (AWX edition)
from elk_secrets import (
    resolve_deployments,
    get_headers,
)


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logging(log_file=None, verbose=False):
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        if log_file == "auto":
            log_file = f"cleanup_dataviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    logging.basicConfig(level=log_level, format=log_format, handlers=handlers)
    if log_file:
        logging.info(f"Audit log: {log_file}")
    return log_file


# ==============================================================================
# KIBANA OBJECT TYPES
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


# ==============================================================================
# KIBANA API HELPERS (with retry logic)
# ==============================================================================

def _request_with_retry(method, url, headers, params=None, json_body=None,
                        verify=True, timeout=30, max_retries=3):
    response = None
    for attempt in range(max_retries):
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=params,
                                        verify=verify, timeout=timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=json_body,
                                        verify=verify, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=json_body,
                                         verify=verify, timeout=timeout)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers,
                                           verify=verify, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            wait = 2 ** attempt
            logging.warning(f"  Timeout ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.ConnectionError:
            wait = 2 ** attempt
            logging.warning(f"  Connection error ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            if response is not None and 400 <= response.status_code < 500 and response.status_code != 429:
                return response
            wait = 2 ** attempt
            logging.warning(f"  HTTP {response.status_code} ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            logging.error(f"  Request failed: {e}")
            return None
    logging.error(f"  All {max_retries} retries exhausted for {url}")
    return None


def get_all_spaces(headers, kibana_url, verify_ssl=True):
    response = _request_with_retry("GET", f"{kibana_url}/api/spaces/space",
                                   headers, verify=verify_ssl)
    if response and response.status_code == 200:
        return response.json()
    return []


def get_all_dataviews(space_id, headers, kibana_url, verify_ssl=True):
    url = f'{kibana_url}/s/{space_id}/api/data_views'
    response = _request_with_retry("GET", url, headers, verify=verify_ssl)
    if response and response.status_code == 200:
        return response.json().get('data_view', [])
    return []


def get_default_dataview_id(space_id, headers, kibana_url, verify_ssl=True):
    url = f'{kibana_url}/s/{space_id}/api/data_views/default'
    try:
        response = requests.get(url, headers=headers, verify=verify_ssl, timeout=15)
        if response.status_code == 200:
            return response.json().get("data_view_id") or None
    except requests.exceptions.RequestException:
        pass
    return None


def find_duplicated_data_views(data_views):
    title_to_ids = defaultdict(list)
    for dv in data_views:
        title = dv.get("title")
        if not title:
            continue
        title_to_ids[title].append(dv["id"])
    return {title: ids for title, ids in title_to_ids.items() if len(ids) > 1}


def get_all_saved_objects(kibana_url, space_id, headers, object_types, verify_ssl=True):
    endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    base_params = [('fields', 'references'), ('per_page', '10000')]
    for ot in object_types:
        base_params.append(('type', ot))

    all_objects = []
    page = 1
    while True:
        params = base_params + [('page', str(page))]
        response = _request_with_retry("GET", endpoint, headers, params=params,
                                       verify=verify_ssl)
        if response is None or response.status_code != 200:
            logging.warning(f"  Failed to retrieve saved objects for space '{space_id}'")
            break

        data = response.json()
        objects = data.get("saved_objects", [])
        all_objects.extend(objects)
        total = data.get("total", 0)
        if len(all_objects) >= total or not objects:
            break
        page += 1

    return all_objects


def count_references(data_view_ids, all_objects):
    counts = defaultdict(int)
    dv_set = set(data_view_ids)
    for obj in all_objects:
        for ref in obj.get("references", []):
            if ref.get("type") == "index-pattern" and ref.get("id") in dv_set:
                counts[ref["id"]] += 1
    return counts


# ==============================================================================
# BACKUP FUNCTIONS
# ==============================================================================

def backup_space_objects(kibana_url, space_id, headers, all_kibana_objects, verify_ssl=True, backup_dir="backups"):
    os.makedirs(backup_dir, exist_ok=True)
    export_url = f"{kibana_url}/s/{space_id}/api/saved_objects/_export"

    export_objects = [{"id": obj["id"], "type": obj["type"]} for obj in all_kibana_objects]
    if not export_objects:
        logging.info(f"  No objects to backup in space '{space_id}'")
        return None

    payload = {"objects": export_objects, "includeReferencesDeep": True}
    response = _request_with_retry("POST", export_url, headers, json_body=payload,
                                   verify=verify_ssl, timeout=60)

    if response and response.status_code == 200:
        safe_space = space_id.replace("/", "_").replace(" ", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"space_{safe_space}_{ts}.ndjson")
        with open(backup_file, "w") as f:
            f.write(response.text)
        logging.info(f"  ✅ Space backup saved: {backup_file} ({len(export_objects)} objects)")
        return backup_file
    else:
        logging.error(f"  ❌ Failed to backup space '{space_id}'")
        return None


def backup_data_view(kibana_url, space_id, headers, data_view_id, verify_ssl=True, backup_dir="backups"):
    os.makedirs(backup_dir, exist_ok=True)
    export_url = f"{kibana_url}/s/{space_id}/api/saved_objects/_export"
    payload = {
        "objects": [{"id": data_view_id, "type": "index-pattern"}],
        "includeReferencesDeep": True
    }
    response = _request_with_retry("POST", export_url, headers, json_body=payload,
                                   verify=verify_ssl, timeout=30)
    if response and response.status_code == 200:
        safe_id = data_view_id.replace("/", "_")
        backup_file = os.path.join(backup_dir, f"dataview_{safe_id}.ndjson")
        with open(backup_file, "w") as f:
            f.write(response.text)
        logging.info(f"    Backup: {backup_file}")
        return backup_file
    logging.warning(f"    ⚠️ Could not backup data view {data_view_id}")
    return None


# ==============================================================================
# REFERENCE RE-POINTING
# ==============================================================================

def repoint_references(all_objects, old_id, new_id, kibana_url, space_id, headers,
                       verify_ssl=True, dry_run=True):
    updated_count = 0
    for obj in all_objects:
        refs = obj.get("references", [])
        needs_update = False
        new_refs = []
        for ref in refs:
            if ref.get("type") == "index-pattern" and ref.get("id") == old_id:
                new_ref = ref.copy()
                new_ref["id"] = new_id
                new_refs.append(new_ref)
                needs_update = True
            else:
                new_refs.append(ref)

        if needs_update:
            obj_id = obj["id"]
            obj_type = obj["type"]
            if dry_run:
                logging.info(f"    [DRY-RUN] Would repoint {obj_type}/{obj_id}: {old_id} → {new_id}")
            else:
                endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/{obj_type}/{obj_id}"
                payload = {"attributes": {}, "references": new_refs}
                resp = _request_with_retry("PUT", endpoint, headers, json_body=payload,
                                           verify=verify_ssl)
                if resp and resp.status_code == 200:
                    logging.info(f"    ✅ Repointed {obj_type}/{obj_id}: {old_id} → {new_id}")
                    obj["references"] = new_refs
                else:
                    status = resp.status_code if resp else "no response"
                    logging.error(f"    ❌ Failed to repoint {obj_type}/{obj_id}: HTTP {status}")
            updated_count += 1
    return updated_count


# ==============================================================================
# DELETION
# ==============================================================================

def delete_data_view(kibana_url, space_id, headers, data_view_id, verify_ssl=True):
    url = f"{kibana_url}/s/{space_id}/api/data_views/data_view/{data_view_id}"
    response = _request_with_retry("DELETE", url, headers, verify=verify_ssl)
    if response and response.status_code == 200:
        logging.info(f"    ✅ DELETED data view: {data_view_id}")
        return True
    else:
        status = response.status_code if response else "no response"
        logging.error(f"    ❌ Failed to delete {data_view_id}: HTTP {status}")
        return False


# ==============================================================================
# VALIDATION / INTERACTIVE APPROVAL
# ==============================================================================

def present_cleanup_plan(plan, dry_run=True):
    mode = "DRY-RUN" if dry_run else "EXECUTE"
    print(f"\n{'=' * 90}")
    print(f"CLEANUP PLAN — [{mode}]")
    print(f"{'=' * 90}")

    if not plan:
        print("\n  ✅ Nothing to clean up — no deletable duplicates found.")
        print(f"{'=' * 90}")
        return []

    total_repoints = 0
    total_deletions = 0

    for item in plan:
        print(f"\n  📦 {item['deployment'].upper()} > {item['space_name']}")
        print(f"    Data View Title: {item['title']}")
        print(f"    KEEP:   {item['keep_id']:45s}  ({item['keep_refs']} refs)"
              + (" ← DEFAULT" if item.get('keep_is_default') else ""))

        for dup in item['duplicates']:
            action = dup['action']
            if action == "REPOINT + DELETE":
                print(f"    DELETE: {dup['id']:45s}  ({dup['refs']} refs → repoint to KEEP, then delete)")
                total_repoints += dup['refs']
            elif action == "DELETE":
                print(f"    DELETE: {dup['id']:45s}  (0 refs → delete)")
            elif action == "SKIP (DEFAULT)":
                print(f"    SKIP:   {dup['id']:45s}  ({dup['refs']} refs — is space DEFAULT)")
            total_deletions += 1 if action in ("DELETE", "REPOINT + DELETE") else 0

    print(f"\n{'─' * 90}")
    print(f"  Total reference re-points : {total_repoints}")
    print(f"  Total data views to delete: {total_deletions}")
    print(f"{'=' * 90}")

    return plan


def get_user_approval(plan, auto_yes=False):
    """
    Prompt user for approval. Returns list of approved plan items.

    AWX-safe: if auto_yes is False AND stdin is not a TTY (running under AWX),
    we refuse rather than block on input(). The caller (process_space) guards
    the --execute path so this is only reached interactively or with --yes.
    """
    if auto_yes:
        logging.info("Auto-confirm enabled (--yes): all deletions approved.")
        return plan

    deletable = [item for item in plan
                 if any(d['action'] in ("DELETE", "REPOINT + DELETE") for d in item['duplicates'])]
    if not deletable:
        return []

    if not sys.stdin.isatty():
        logging.error(
            "No interactive terminal and --yes not set. Refusing to delete. "
            "Under AWX, enable the 'Auto-confirm deletions' (--yes) survey option."
        )
        return []

    print(f"\n⚠️  You are about to modify {len(deletable)} duplicate group(s).")
    approval = input("  Proceed with cleanup? [y/N/item-by-item]: ").strip().lower()

    if approval == 'y':
        logging.info("User approved ALL deletions.")
        return deletable
    elif approval == 'item-by-item':
        approved = []
        for item in deletable:
            desc = f"{item['deployment']} > {item['space_name']} > {item['title']}"
            choice = input(f"  Delete duplicates for '{desc}'? [y/N]: ").strip().lower()
            if choice == 'y':
                approved.append(item)
                logging.info(f"User approved: {desc}")
            else:
                logging.info(f"User skipped: {desc}")
        return approved
    else:
        logging.info("User declined all deletions. No changes made.")
        return []


# ==============================================================================
# CORE: PROCESS ONE SPACE
# ==============================================================================

def process_space(deployment_name, kibana_url, space_id, space_name, headers,
                  object_types, verify_ssl, dry_run, auto_yes, backup_dir):
    stats = {"repointed": 0, "deleted": 0, "skipped": 0, "backed_up": 0, "errors": 0}
    logging.info(f"[{deployment_name}] Processing space: {space_name} ({space_id})")

    data_views = get_all_dataviews(space_id, headers, kibana_url, verify_ssl)
    if not data_views:
        logging.info(f"  No data views in space '{space_name}'. Skipping.")
        return stats

    duplicates = find_duplicated_data_views(data_views)
    if not duplicates:
        logging.info(f"  No duplicates in space '{space_name}'. Skipping.")
        return stats

    logging.info(f"  Found {len(duplicates)} duplicate group(s) in '{space_name}'")

    all_objects = get_all_saved_objects(kibana_url, space_id, headers, object_types, verify_ssl)
    logging.info(f"  Loaded {len(all_objects)} saved objects for reference analysis")

    default_dv_id = get_default_dataview_id(space_id, headers, kibana_url, verify_ssl)

    space_plan = []
    for title, ids in duplicates.items():
        ref_counts = count_references(ids, all_objects)

        if default_dv_id in ids:
            keep_id = default_dv_id
        else:
            keep_id = max(ids, key=lambda x: ref_counts.get(x, 0))

        plan_item = {
            "deployment": deployment_name,
            "kibana_url": kibana_url,
            "space_id": space_id,
            "space_name": space_name,
            "title": title,
            "keep_id": keep_id,
            "keep_refs": ref_counts.get(keep_id, 0),
            "keep_is_default": keep_id == default_dv_id,
            "duplicates": []
        }

        for dv_id in ids:
            if dv_id == keep_id:
                continue
            refs = ref_counts.get(dv_id, 0)
            is_default = dv_id == default_dv_id

            if is_default:
                action = "SKIP (DEFAULT)"
            elif refs > 0:
                action = "REPOINT + DELETE"
            else:
                action = "DELETE"

            plan_item["duplicates"].append({
                "id": dv_id, "refs": refs, "is_default": is_default, "action": action
            })

        space_plan.append(plan_item)

    present_cleanup_plan(space_plan, dry_run=dry_run)

    if dry_run:
        logging.info("  [DRY-RUN] No changes made. Re-run with --execute to apply.")
        return stats

    approved = get_user_approval(space_plan, auto_yes=auto_yes)
    if not approved:
        logging.info("  No items approved. Skipping space.")
        return stats

    logging.info(f"  Backing up all objects in space '{space_name}'...")
    backup_space_objects(kibana_url, space_id, headers, all_objects, verify_ssl, backup_dir)
    stats["backed_up"] += 1

    for item in approved:
        keep_id = item["keep_id"]
        for dup in item["duplicates"]:
            dv_id = dup["id"]
            action = dup["action"]

            if action == "SKIP (DEFAULT)":
                stats["skipped"] += 1
                continue

            if action == "REPOINT + DELETE":
                logging.info(f"  Re-pointing {dup['refs']} references: {dv_id} → {keep_id}")
                count = repoint_references(all_objects, dv_id, keep_id,
                                           kibana_url, space_id, headers, verify_ssl,
                                           dry_run=False)
                stats["repointed"] += count

            backup_data_view(kibana_url, space_id, headers, dv_id, verify_ssl, backup_dir)

            fresh_refs = count_references([dv_id], all_objects)
            remaining = fresh_refs.get(dv_id, 0)
            if remaining > 0:
                logging.error(f"    ⚠️ {dv_id} still has {remaining} references after repoint! Skipping delete.")
                stats["errors"] += 1
                continue

            success = delete_data_view(kibana_url, space_id, headers, dv_id, verify_ssl)
            if success:
                stats["deleted"] += 1
            else:
                stats["errors"] += 1

    return stats


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = ArgumentParser(
        description='Safely clean up duplicate data views in Kibana deployment(s) (AWX edition).'
    )
    parser.add_argument(
        '--deployments', nargs='+', default=None,
        help='One or more deployment names to clean up (the AWX survey value). '
             'Each name must match its AWS Secrets Manager secret name; the secret '
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
    parser.add_argument('--spaces', nargs='+', default=None,
                        help='Specific space IDs or names to process (default: all)')
    parser.add_argument('--execute', action='store_true',
                        help='Actually perform changes (default is dry-run)')
    parser.add_argument('--yes', action='store_true',
                        help='Auto-confirm all deletions (REQUIRED under AWX, no TTY)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--log-file', nargs='?', const='auto', default='auto',
                        help='Write audit log to file (default: auto-timestamped)')
    parser.add_argument('--backup-dir', default='backups',
                        help='Directory for NDJSON backups (default: ./backups)')

    args = parser.parse_args()
    dry_run = not args.execute

    log_file = setup_logging(log_file=args.log_file, verbose=args.verbose)

    # Resolve the list of deployment names: CLI flag first, then env var.
    deployment_names = args.deployments
    if not deployment_names:
        env_val = os.environ.get("DEPLOYMENT_NAMES", "").strip()
        if env_val:
            deployment_names = [n for n in env_val.replace(",", " ").split() if n]

    if not deployment_names:
        logging.error(
            "No deployments specified. Pass one or more names via --deployments "
            "\"<name1>\" \"<name2>\" (the AWX survey value), or set DEPLOYMENT_NAMES."
        )
        sys.exit(1)

    if dry_run:
        print("\n" + "=" * 90)
        print("🔒 DRY-RUN MODE — No changes will be made. Use --execute to apply changes.")
        print("=" * 90)
    else:
        print("\n" + "=" * 90)
        print("⚠️  EXECUTE MODE — Changes WILL be applied to your Kibana deployment(s)!")
        print("=" * 90)
        # AWX guard: executing without --yes in a non-interactive context would
        # otherwise stall on input(). Fail fast with a clear message.
        if not args.yes and not sys.stdin.isatty():
            logging.error(
                "--execute was set but --yes was not, and there is no interactive "
                "terminal. Under AWX, enable the 'Auto-confirm deletions' (--yes) "
                "survey option to perform deletions. Aborting."
            )
            sys.exit(1)

    # Resolve each deployment from its same-named secret in Secrets Manager,
    # using AWX's ambient AWS credentials. Bad/missing secrets are skipped.
    clusters = resolve_deployments(
        deployment_names, region_name=args.aws_region, verify_ssl=args.verify_ssl
    )
    if not clusters:
        logging.error("No deployments could be resolved from Secrets Manager. Aborting.")
        sys.exit(3)

    object_types = get_object_types()
    total_stats = {"repointed": 0, "deleted": 0, "skipped": 0, "backed_up": 0, "errors": 0}
    start_time = time.time()

    for cluster_name, cluster in clusters.items():
        if not cluster.get("api_key"):
            logging.warning(f"[{cluster_name}] No API key resolved. Skipping.")
            continue

        kibana_url = cluster["kibana_url"]
        headers = get_headers(cluster["api_key"])
        verify_ssl = cluster.get("verify_ssl", True)

        logging.info(f"[{cluster_name}] Scanning {kibana_url} ...")
        spaces = get_all_spaces(headers, kibana_url, verify_ssl)

        if not spaces:
            logging.warning(f"[{cluster_name}] No spaces found. Skipping.")
            continue

        logging.info(f"[{cluster_name}] Found {len(spaces)} spaces")

        if args.spaces:
            spaces = [s for s in spaces
                      if s.get("id") in args.spaces or s.get("name") in args.spaces]
            if not spaces:
                logging.warning(f"[{cluster_name}] No matching spaces after filter.")
                continue

        for space in spaces:
            space_id = space["id"]
            space_name = space.get("name", space_id)
            try:
                stats = process_space(
                    cluster_name, kibana_url, space_id, space_name,
                    headers, object_types, verify_ssl,
                    dry_run, args.yes, args.backup_dir
                )
                for k in total_stats:
                    total_stats[k] += stats[k]
            except Exception as e:
                logging.error(f"[{cluster_name}] Error processing space '{space_name}': {e}")
                total_stats["errors"] += 1

    elapsed = time.time() - start_time

    print(f"\n{'=' * 90}")
    print(f"CLEANUP {'DRY-RUN ' if dry_run else ''}SUMMARY")
    print(f"{'=' * 90}")
    print(f"  References re-pointed : {total_stats['repointed']}")
    print(f"  Data views deleted    : {total_stats['deleted']}")
    print(f"  Skipped (default/safe): {total_stats['skipped']}")
    print(f"  Spaces backed up      : {total_stats['backed_up']}")
    print(f"  Errors                : {total_stats['errors']}")
    print(f"  Total time            : {elapsed:.1f}s")
    if log_file:
        print(f"  Audit log             : {log_file}")
    print(f"{'=' * 90}")


if __name__ == "__main__":
    main()
