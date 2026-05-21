# Kibana Duplicate Data View Management Toolkit

A pair of Python utilities for **detecting** and **safely cleaning up** duplicate Kibana data views across multiple Elasticsearch/Kibana deployments. Built for multi-tenant federal dashboard environments where data view sprawl can lead to broken references, inconsistent reporting, and operational toil.

| Script | Purpose | Mode |
|---|---|---|
| `find_duplicate_dataviews.py` | Read-only scanner that identifies duplicate data views and labels them with `KEEP` / `SAFE TO DELETE` / `REVIEW` recommendations | **Read-only** |
| `cleanup_duplicate_dataviews.py` | Safe cleanup engine that re-points saved-object references and deletes orphaned duplicates with full backups | **Dry-run by default**, opt-in `--execute` |

Both scripts share the same `clusters.json` configuration file and the same set of Kibana saved-object types, so output from the finder maps cleanly onto inputs for the cleanup tool.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Configuration: `clusters.json`](#configuration-clustersjson)
3. [`find_duplicate_dataviews.py`](#find_duplicate_dataviewspy)
4. [`cleanup_duplicate_dataviews.py`](#cleanup_duplicate_dataviewspy)
5. [Recommended Workflow](#recommended-workflow)
6. [Safety Features](#safety-features)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Python 3.8 or later
- `requests` and `urllib3` Python packages
- A valid Kibana API key with read access (for the finder) or read/write access (for the cleanup tool) on every target deployment
- Network reachability to each Kibana endpoint listed in `clusters.json`

Install dependencies:

```bash
pip install requests urllib3
```

---

## Configuration: `clusters.json`

Both scripts read deployment definitions from a JSON config file (default: `clusters.json` in the working directory). Each cluster entry needs a Kibana URL, an API key, and an optional `verify_ssl` flag.

```json
{
  "clusters": {
    "FISMA Scorecard": {
      "kibana_url": "https://fismaxxxxxx.kb.ps.cdm-db.com:9243",
      "api_key": "ektEZXXXXXXXXXX==",
      "verify_ssl": true
    },
    "(DBaaS) Agency Dashboard": {
      "kibana_url": "https://dbaaxxxxxx.kb.ps.cdm-db.com:9243",
      "api_key": "Ym95S2xxxxxxxx==",
      "verify_ssl": true
    }
  }
}
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `kibana_url` | Yes | Base Kibana URL (no trailing slash needed — scripts strip it automatically) |
| `api_key` | Yes | A Kibana API key, OR an environment variable reference in the form `"$ENV_VAR_NAME"` |
| `verify_ssl` | No | Defaults to `true`. Set `false` only for dev environments with self-signed certs |
| `description` | No | Optional human-readable description |

### Environment variable references

To keep secrets out of the file, prefix the key name with `$`:

```json
"api_key": "$FISMA_KIBANA_API_KEY"
```

The script resolves the variable at runtime. If it's unset, that cluster is skipped with a warning.

> ⚠️ **Security note:** the current `clusters.json` checked into the repo stores API keys in plain text. A DevSecOps refactor to retrieve these from AWS Secrets Manager is in progress — see the accompanying refactor request document.

---

## `find_duplicate_dataviews.py`

A **read-only** scanner that walks every space in every configured cluster, identifies data views sharing the same title within a space, and counts how many saved objects (dashboards, lenses, visualizations, alerts, etc.) reference each duplicate ID.

### What it produces

For every duplicate group it reports:

- Deployment name, Kibana space, and shared data view title
- Each duplicate data view ID and its reference count
- Whether the ID is the **space default** data view
- An action label per ID: `KEEP (DEFAULT)`, `KEEP`, `REVIEW`, or `SAFE TO DELETE`

### Common usage

```bash
# Scan all clusters with the default clusters.json
python find_duplicate_dataviews.py

# Scan a specific cluster
python find_duplicate_dataviews.py --clusters "FISMA Scorecard"

# Scan a specific space inside a specific cluster
python find_duplicate_dataviews.py --clusters "FISMA Scorecard" --spaces "FISMA Team"

# Connectivity smoke test only — no scanning
python find_duplicate_dataviews.py --connectivity-check

# Export results to CSV (auto-timestamped filename)
python find_duplicate_dataviews.py --output csv

# Run multiple clusters in parallel
python find_duplicate_dataviews.py --workers 5

# Preview what would be deleted by an auto-delete pass
python find_duplicate_dataviews.py --dry-run-delete

# Rank spaces by duplicate count (most problematic first)
python find_duplicate_dataviews.py --top-offenders

# Write all logs to a timestamped file in addition to stdout
python find_duplicate_dataviews.py --log-file
```

### All command-line arguments

| Argument | Description |
|---|---|
| `--config PATH` | Path to the JSON config file (default: `clusters.json`) |
| `--clusters NAME [NAME ...]` | Scan only the named clusters (default: all) |
| `--spaces ID [ID ...]` | Scan only specific space IDs or names (default: all) |
| `--output {table,csv,json}` | Output format (default: `table`) |
| `--output-file PATH` | Override the auto-generated CSV/JSON filename |
| `--connectivity-check` | Test connectivity to each cluster, then exit |
| `--workers N` | Number of concurrent cluster workers (default: 1) |
| `--dry-run-delete` | Print the data views an auto-delete pass would remove |
| `--top-offenders` | Print a ranking of spaces with the most duplicates |
| `--log-file [PATH]` | Write logs to a file (auto-timestamped if no path given) |
| `--verbose` | Enable DEBUG-level logging |

### Action labels explained

| Label | Meaning |
|---|---|
| `KEEP (DEFAULT)` | This ID is the space's default data view — never delete |
| `KEEP` | Highest reference count in the group — the consolidation target |
| `REVIEW` | Has references but isn't the highest — needs re-pointing before deletion |
| `SAFE TO DELETE` | Zero references and not the default — safe for orphan cleanup |

### Performance notes

- Saved-object references are fetched using a **single batched `_find` call per space**, sending all 30+ Kibana object types as repeated `type=` query parameters. This avoids the original "30 HTTP calls per space" overhead.
- A graceful fallback to per-type queries kicks in automatically if the batched call fails (older Kibana versions).
- Retries with exponential backoff handle transient timeouts and connection errors (3 attempts by default).
- Use `--workers N` to scan multiple clusters in parallel. A live progress bar shows cluster/space status, ETA, and elapsed time.
- `Ctrl+C` triggers a graceful interrupt: partial results are still printed and labeled.

---

## `cleanup_duplicate_dataviews.py`

A **write-capable** cleanup tool that picks up where the finder leaves off. For each duplicate group it identifies a `KEEP` candidate, re-points all saved-object references from the duplicates to the keeper, backs up everything affected, and then deletes the orphaned IDs.

**Defaults to dry-run.** No changes are ever made unless `--execute` is passed.

### How KEEP is chosen

For each duplicate group within a space:

1. If one of the duplicate IDs is the **space default**, that ID wins.
2. Otherwise the ID with the **highest reference count** wins.
3. Every other duplicate is queued for re-pointing and deletion (or skipped if it's the default).

### What it does, step by step

1. Scan the cluster/space for duplicates (same engine as the finder)
2. For each duplicate group:
   - Identify the KEEP candidate
   - Decide an action for every other ID: `REPOINT + DELETE`, `DELETE`, or `SKIP (DEFAULT)`
3. Present the full cleanup plan and (unless `--yes`) prompt for approval
4. Export an NDJSON backup of every saved object in the space before any change
5. For each approved deletion:
   - PUT updates to every saved object that references the duplicate, repointing to the KEEP ID
   - Verify the reference count is now zero
   - Export an NDJSON backup of the data view itself
   - DELETE the data view via the Kibana API
6. Print a full summary: re-points performed, deletions performed, items skipped, errors

### Common usage

```bash
# Dry-run preview (no changes made — default mode)
python cleanup_duplicate_dataviews.py

# Dry-run scoped to one cluster and one space
python cleanup_duplicate_dataviews.py \
    --clusters "FISMA Scorecard" --spaces "FISMA Team"

# Execute with interactive approval (recommended for first real run)
python cleanup_duplicate_dataviews.py --execute

# Execute with no prompts (for automation — be careful)
python cleanup_duplicate_dataviews.py --execute --yes

# Use a custom config and backup directory
python cleanup_duplicate_dataviews.py \
    --config /path/to/my_clusters.json \
    --backup-dir /var/backups/kibana
```

### All command-line arguments

| Argument | Description |
|---|---|
| `--config PATH` | Path to the JSON config file (default: `clusters.json`) |
| `--clusters NAME [NAME ...]` | Process only the named clusters (default: all) |
| `--spaces ID [ID ...]` | Process only specific space IDs or names (default: all) |
| `--execute` | Actually perform changes. Without this, no writes happen |
| `--yes` | Auto-confirm all deletions (skip interactive prompts) |
| `--backup-dir PATH` | Directory for NDJSON backups (default: `./backups`) |
| `--log-file [PATH]` | Audit log path (auto-timestamped by default) |
| `--verbose` | Enable DEBUG-level logging |

### Interactive approval

When run with `--execute` (and without `--yes`), the script presents the cleanup plan and asks:

```
Proceed with cleanup? [y/N/item-by-item]:
```

- `y` — approve every item in the plan
- `N` — abort all deletions, no changes made
- `item-by-item` — prompt separately for each duplicate group

---

## Recommended Workflow

A safe progression for a new environment:

1. **Connectivity check.** Confirm every cluster in the config is reachable and the API keys are valid.
   ```bash
   python find_duplicate_dataviews.py --connectivity-check
   ```
2. **Inventory.** Run the finder against the full estate and save the report.
   ```bash
   python find_duplicate_dataviews.py --output csv --log-file
   ```
3. **Triage.** Use `--top-offenders` to find which spaces are worst.
   ```bash
   python find_duplicate_dataviews.py --top-offenders
   ```
4. **Preview deletes.** See exactly what an auto-cleanup would touch.
   ```bash
   python find_duplicate_dataviews.py --dry-run-delete
   ```
5. **Dry-run cleanup on one space.** Scope tightly first.
   ```bash
   python cleanup_duplicate_dataviews.py \
       --clusters "FISMA Scorecard" --spaces "FISMA Team"
   ```
6. **Execute on one space.** With interactive approval and backups.
   ```bash
   python cleanup_duplicate_dataviews.py \
       --clusters "FISMA Scorecard" --spaces "FISMA Team" --execute
   ```
7. **Verify.** Re-run the finder to confirm the duplicates are gone and references are intact.
8. **Roll out.** Once one space is clean, broaden scope cluster-by-cluster.

---

## Safety Features

The cleanup tool is built around the assumption that **a broken reference is worse than a leftover duplicate.** Multiple guardrails reflect that:

- **Dry-run by default.** `--execute` is opt-in.
- **Default data view protection.** The space default is never deleted, even if it has zero references.
- **Reference re-pointing before deletion.** Saved objects pointing at a duplicate are migrated to the KEEP candidate first, so dashboards and visualizations keep working.
- **Post-repoint verification.** Before deleting any data view, the script re-counts references in memory; if any remain, the delete is aborted for that ID.
- **Two-tier backups.** A full NDJSON export of every saved object in the space is taken before any change, and a per-data-view NDJSON export is taken immediately before each deletion.
- **Audit log.** Every action is timestamped and written to a log file (default: auto-timestamped).
- **Retry with backoff.** Transient API errors are retried up to 3 times with exponential backoff before failing.
- **Interactive approval.** Unless `--yes` is passed, the operator must explicitly approve the plan before any write happens.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No spaces found or unable to connect` | Bad URL, network block, or invalid API key | Run `--connectivity-check`; verify firewall rules and API key permissions |
| `Environment variable 'X' not set` | `clusters.json` references `$X` but the env var is missing | `export X=...` before running, or replace `$X` with the literal key |
| `verification_exception` | Index referenced by the data view doesn't exist on the cluster | Expected for orphaned data views — they're often exactly what these tools are meant to find |
| `HTTP 403` on cleanup | API key has read-only privileges | Re-issue the key with write permissions for the cleanup script |
| Long scan times | Single-threaded run against many clusters | Use `--workers N` (finder only) to parallelize |
| Interrupted scan | `Ctrl+C` mid-run | Partial results print automatically; re-run when ready |

---

## File Outputs

| File | Produced by | Contents |
|---|---|---|
| `duplicate_dataviews_<timestamp>.log` | finder | Per-action audit log |
| `duplicate_dataviews_<timestamp>.csv` | finder (with `--output csv`) | Tabular duplicate report |
| `duplicate_dataviews_<timestamp>.json` | finder (with `--output json`) | JSON duplicate report |
| `cleanup_dataviews_<timestamp>.log` | cleanup | Per-action audit log |
| `backups/space_<id>_<timestamp>.ndjson` | cleanup | Full space backup before any change |
| `backups/dataview_<id>.ndjson` | cleanup | Per-data-view backup before deletion |
