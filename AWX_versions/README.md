# Duplicate Data Views Toolkit — AWX Edition

Two Python tools for finding and safely removing duplicate Kibana data views
(index patterns) across one or more Elasticsearch/Kibana deployments, packaged
to run as **Ansible AWX** job templates.

| File | Purpose |
|---|---|
| `find_duplicate_dataviews_awx.py` | **Read-only scanner.** Reports duplicate data views, counts references, and recommends KEEP / SAFE TO DELETE / REVIEW. Never modifies anything. |
| `cleanup_duplicate_dataviews_awx.py` | **Remediation.** Re-points saved-object references from duplicates onto a KEEP candidate, backs everything up, then deletes orphaned duplicates. Dry-run by default. |
| `elk_secrets.py` | **Shared module.** Resolves each deployment's Kibana URL + API key from AWS Secrets Manager. Imported by both scripts. |

---

## How it works

Each Kibana deployment has its **own secret** in AWS Secrets Manager. The
**secret name is identical to the deployment name**, and the secret's JSON
contents hold the connection details.

```
AWX survey argument:  "FISMA Scorecard"
                              │
                              ▼
        Secrets Manager: GetSecretValue(SecretId="FISMA Scorecard")
                              │
                              ▼
        {
          "deployment_name": "FISMA Scorecard",
          "kibana_url":      "https://fisma-xxxxxx.kb.ps.cdm-db.com:9243",
          "api_key":         "Ym95S2x...=="
        }
                              │
                              ▼
        Scanner / cleanup runs against that Kibana deployment
```

There is **no `clusters.json` config file**. The deployment name you type in
AWX is the only pointer needed — it is passed verbatim to Secrets Manager as the
`SecretId`, and the secret supplies everything else.

You can pass **one or more** deployment names in a single run. Each is resolved
and processed independently; if one secret is missing or malformed it is logged
and skipped, and the remaining deployments still run.

### AWS authentication

The scripts use **boto3's default credential chain**, which means they
automatically use whatever AWS IAM role the **AWX execution environment has
assumed**. No access keys are stored in or passed through the code, and no
specific role is hard-coded. The IAM role AWX runs under must allow
`secretsmanager:GetSecretValue` on the relevant secrets.

---

## Requirements

- Python 3.6+
- `requests`
- `boto3` / `botocore`

In AWX, make sure the execution environment image includes `boto3` and
`requests`, and that the job template is attached to an AWS credential (or runs
on an instance/role) able to read the secrets.

---

## Secret format

Each secret is a JSON document. The scripts read these fields:

| Field | Required | Notes |
|---|---|---|
| `kibana_url` | **Yes** | Base Kibana URL, e.g. `https://host:9243`. Trailing slash is trimmed automatically. |
| `api_key` | **Yes** | Base64 Kibana API key. Sent as `Authorization: ApiKey <value>`. |
| `deployment_name` | No | Cosmetic/canonical label. Falls back to the lookup name if absent. |

> **Field names are configurable.** They are defined as constants at the top of
> `elk_secrets.py` (`SECRET_FIELD_KIBANA_URL`, `SECRET_FIELD_API_KEY`,
> `SECRET_FIELD_DEPLOYMENT_NAME`). If the real secrets use different keys (e.g.
> `kibanaUrl`, `apiKey`), update those three lines — no other code changes
> needed.

`verify_ssl` is **not** stored in the secret. It is supplied per run via the
`--verify-ssl` / `--no-verify-ssl` argument and applied to all deployments in
that run.

---

## Arguments

### Common to both scripts

| Argument | Default | Description |
|---|---|---|
| `--deployments NAME [NAME ...]` | — (required) | One or more deployment names. Each must match its Secrets Manager secret name. |
| `--aws-region REGION` | `AWS_REGION` env, else built-in default | Region for Secrets Manager. |
| `--verify-ssl` / `--no-verify-ssl` | verify on | Toggle Kibana TLS certificate verification. |
| `--spaces NAME [NAME ...]` | all spaces | Restrict to specific Kibana space IDs or names. |
| `--verbose` | off | Debug logging. |

Deployment names may also be supplied via the `DEPLOYMENT_NAMES` environment
variable (comma- or space-separated) if you prefer wiring it as an extra-var.

### Scanner only (`find_duplicate_dataviews_awx.py`)

| Argument | Default | Description |
|---|---|---|
| `--output {table,csv,json}` | `table` | Output format. |
| `--output-file PATH` | auto-named | Where to write csv/json. |
| `--connectivity-check` | off | Test connectivity to the selected deployment(s) and exit. |
| `--workers N` | `1` | Concurrent workers when scanning multiple deployments. |
| `--dry-run-delete` | off | Preview which orphaned (0-reference, non-default) data views *would* be deleted. |
| `--top-offenders` | off | Rank spaces by number of duplicates. |
| `--log-file [PATH]` | off | Also write logs to a file. |

### Cleanup only (`cleanup_duplicate_dataviews_awx.py`)

| Argument | Default | Description |
|---|---|---|
| `--execute` | off (**dry-run**) | Actually perform changes. Without this, nothing is modified. |
| `--yes` | off | Auto-confirm deletions. **Required under AWX** (see Safety). |
| `--backup-dir PATH` | `./backups` | Where NDJSON backups are written. |
| `--log-file [PATH]` | auto-timestamped | Audit log path. |

---

## Safety model (cleanup)

The cleanup tool is conservative by design:

1. **Dry-run is the default.** Without `--execute`, it prints the full plan and
   changes nothing.
2. **KEEP selection.** Within each group of same-titled data views, the space's
   default data view is always kept; otherwise the one with the most references
   wins. The space default is never deleted.
3. **Reference re-pointing.** Any saved object pointing at a duplicate is
   migrated onto the KEEP data view *before* deletion, so nothing breaks.
4. **Backups.** The whole space is exported to NDJSON before any change, and
   each data view is exported again immediately before it is deleted.
5. **Post-repoint verification.** A duplicate is only deleted after a re-check
   confirms it has zero remaining references.
6. **Audit log.** Every run writes a timestamped log of what happened.

### Non-interactive (AWX) behavior

AWX has no interactive terminal. The original interactive confirmation prompt
would hang a job forever, so:

- Running with `--execute` but **without** `--yes` in a non-interactive context
  causes the script to **refuse and exit** with a clear message.
- To actually delete under AWX, enable **both** the "Execute" (`--execute`) and
  "Auto-confirm deletions" (`--yes`) survey options.
- From an interactive shell, `--execute` alone still works and will prompt you.

---

## AWX setup

1. Place the three files (`find_duplicate_dataviews_awx.py`,
   `cleanup_duplicate_dataviews_awx.py`, `elk_secrets.py`) in the project repo so
   the two scripts can import `elk_secrets`.
2. Ensure the execution environment has `boto3` and `requests`.
3. Attach an AWS credential / role to the job template with
   `secretsmanager:GetSecretValue` permission on the deployment secrets.
4. Build a survey that maps to the arguments above. Recommended fields:
   - **Deployment name(s)** → `--deployments` (multiselect or multi-line text)
   - **Spaces** (optional) → `--spaces`
   - **Verify SSL** (checkbox) → `--verify-ssl` / `--no-verify-ssl`
   - Cleanup template only: **Execute** → `--execute`, **Auto-confirm** → `--yes`

Schedule the scanner freely (it's read-only). Gate the cleanup template behind
AWX RBAC and run it intentionally.

---

## CLI usage (debugging outside AWX)

```bash
# Scan one deployment
python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard"

# Scan several at once, with concurrency
python find_duplicate_dataviews_awx.py \
    --deployments "FISMA Scorecard" "applogging-v4" --workers 3

# Connectivity check only
python find_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --connectivity-check

# Cleanup dry-run (safe; shows the plan)
python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard"

# Cleanup, interactive execute (TTY)
python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --execute

# Cleanup, non-interactive execute (the AWX path)
python cleanup_duplicate_dataviews_awx.py --deployments "FISMA Scorecard" --execute --yes
```

---

## Recommended workflow

1. **Scan** with `find_duplicate_dataviews_awx.py` to see the duplicates and
   recommendations.
2. **Preview** deletions with `--dry-run-delete`.
3. **Dry-run the cleanup** to review the full re-point + delete plan.
4. **Execute the cleanup** with `--execute --yes` once you're satisfied.
5. Keep the NDJSON backups until you've confirmed everything still works.

---

## Notes

- Reference counting batches all Kibana object types into a single `_find`
  request per page, with a per-type fallback for older Kibana versions.
- Both scripts retry transient HTTP errors with exponential backoff.
- The scanner handles `Ctrl+C` gracefully, printing partial results before exit.
