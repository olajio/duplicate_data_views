# DevSecOps Refactor Request: Secrets Management and AWX Integration for Kibana Duplicate Data View Toolkit

**Requestor:** Olamide Olajide, Observability Engineer
**Team:** Observability / ELK Platform
**Date:** May 21, 2026
**Priority:** Medium — operational hardening, not blocking
**Target completion:** Q3 2026

---

## 1. Executive Summary

The Observability team maintains a two-script toolkit (`find_duplicate_dataviews.py` and `cleanup_duplicate_dataviews.py`) used to detect and safely clean up duplicate Kibana data views across our multi-tenant Elasticsearch deployments. The scripts are currently functional but have two operational gaps that we'd like the DevSecOps team's help to close:

1. **Plain-text credentials.** The `clusters.json` configuration file stores Kibana API keys in plain text, which is incompatible with our FedRAMP/FISMA secret-management posture and creates an unnecessary blast radius if the file is ever exposed.
2. **Local execution only.** The scripts run from individual engineers' workstations, which makes audit, scheduling, repeatability, and access control harder than it needs to be.

We'd like to refactor the toolkit so that:

- Kibana API keys are retrieved from **AWS Secrets Manager** at runtime, not stored in a config file
- The scripts can be run as **Ansible AWX templates** with cluster names, space filters, dry-run flags, and other arguments exposed as AWX variables

This document describes the requested changes, the proposed design, the access control model we'd like to use, and the testing/rollback plan.

---

## 2. Current State

### 2.1 Scripts

| Script | Function | Writes? |
|---|---|---|
| `find_duplicate_dataviews.py` | Scans every space in every configured Kibana deployment, reports duplicate data views | No (read-only) |
| `cleanup_duplicate_dataviews.py` | Re-points saved-object references and deletes orphaned duplicates with full backups | Yes (writes to Kibana) |

### 2.2 Configuration

Both scripts share `clusters.json`. Each cluster entry contains a Kibana URL and an API key:

```json
{
  "clusters": {
    "FISMA Scorecard": {
      "kibana_url": "https://fismaxxxxxx.kb.ps.cdm-db.com:9243",
      "api_key": "ektEZXXXXXXXXXX==",
      "verify_ssl": true
    }
  }
}
```

The scripts already support environment-variable references (`"api_key": "$ENV_VAR_NAME"`), but in practice the file is checked in with literal keys for nine production clusters.

### 2.3 Execution

The scripts are run interactively from engineers' laptops or from the ELK bastion. There is no central scheduler, no execution audit log beyond each operator's terminal, and no per-engineer access control on the cleanup script.

---

## 3. Requested Changes

### 3.1 Secrets Manager integration

Replace plain-text `api_key` values with references to AWS Secrets Manager secrets. The scripts should:

- Authenticate to AWS using the IAM Roles Anywhere identity that AWX is already wired up to use (or via the instance role on the AWX execution node — whichever pattern DevSecOps prefers)
- Fetch each cluster's Kibana API key from Secrets Manager at runtime via `boto3.client('secretsmanager').get_secret_value()`
- Cache fetched secrets in memory for the lifetime of the run only — no on-disk caching
- Fail fast and loud if a secret is missing, with a clear log message identifying which cluster
- Continue to support an opt-out path (env-var or literal key) for local development, gated behind a CLI flag like `--allow-plaintext-secrets`

### 3.2 AWX integration

Wrap both scripts as AWX job templates so that operations can be:

- Launched on a schedule (for the finder — weekly inventory scan)
- Launched on demand by approved operators (for the cleanup tool)
- Audited centrally through AWX job history
- Restricted by RBAC (read-only operators get the finder; only senior operators get the cleanup)

Arguments currently passed on the command line should map to **AWX survey variables** so that they can be filled in via the AWX UI. Specifically:

| CLI argument | AWX variable | Type | Notes |
|---|---|---|---|
| `--clusters` | `target_clusters` | multi-select | Pre-populated from the config |
| `--spaces` | `target_spaces` | free-form list | Optional |
| `--execute` | `execute_mode` | boolean | **Cleanup script only.** Default `false` |
| `--yes` | `auto_confirm` | boolean | **Cleanup script only.** Default `false` |
| `--workers` | `worker_count` | integer | Finder only. Default `1` |
| `--output` | `output_format` | choice (`table`/`csv`/`json`) | Finder only |
| `--top-offenders` | `show_top_offenders` | boolean | Finder only |
| `--dry-run-delete` | `show_delete_preview` | boolean | Finder only |
| `--verbose` | `verbose` | boolean | Default `false` |
| `--log-file` | `log_to_file` | boolean | Default `true` in AWX |

### 3.3 Configuration file changes

Proposed new `clusters.json` shape (no secrets in this file at all):

```json
{
  "aws_region": "us-east-1",
  "clusters": {
    "FISMA Scorecard": {
      "kibana_url": "https://fismaxxxxxx.kb.ps.cdm-db.com:9243",
      "secret_id": "elk/kibana/api-keys/fisma-scorecard",
      "verify_ssl": true
    },
    "(DBaaS) Agency Dashboard": {
      "kibana_url": "https://dbaaxxxxxx.kb.ps.cdm-db.com:9243",
      "secret_id": "elk/kibana/api-keys/dbaas-agency",
      "verify_ssl": true
    }
  }
}
```

Each `secret_id` points to a Secrets Manager secret whose value is the Kibana API key string.

---

## 4. Proposed Design

### 4.1 Secret retrieval layer

A new helper module `secrets_loader.py` would centralize the boto3 logic so both scripts can share it:

```python
import boto3
from botocore.exceptions import ClientError

def get_kibana_api_key(secret_id: str, region: str) -> str:
    """Fetch a Kibana API key from AWS Secrets Manager."""
    client = boto3.client('secretsmanager', region_name=region)
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except ClientError as e:
        raise RuntimeError(f"Failed to fetch secret '{secret_id}': {e}")
    return response['SecretString']
```

`load_config()` in each script would call this for every cluster instead of reading `api_key` directly.

### 4.2 IAM / access pattern

We'd like to follow the same IAM Roles Anywhere + ABAC pattern already in use for the `aws_ELK` role on `ms51-22elkalt01`. Specifically:

- A dedicated IAM role (e.g. `kibana-dataview-toolkit`) trusted by Roles Anywhere
- An IAM policy granting `secretsmanager:GetSecretValue` scoped to `arn:aws:secretsmanager:<region>:<account>:secret:elk/kibana/api-keys/*`
- ABAC tag matching (`tag:Environment=prod` / `tag:Team=observability`) to align with the existing model
- KMS decrypt permission on the CMK that encrypts the Secrets Manager values

### 4.3 AWX execution environment

We'd recommend a custom AWX execution environment image containing:

- Python 3.11
- `boto3`, `botocore`, `requests`, `urllib3`
- The two scripts and `secrets_loader.py` (pulled from the team's Git repo at build time)
- The Roles Anywhere helper binary (`aws_signing_helper`) so the execution environment can sign STS requests

The AWX job templates would mount the IAM Roles Anywhere certificate and private key from AWX credential types as files at runtime, with the AWS config pointing at them via `credential_process`.

### 4.4 Output artifacts in AWX

CSV/JSON reports and NDJSON backups currently land in the working directory. In AWX we'd like them to be:

- Written to a job-scoped temp directory
- Uploaded to an S3 bucket (e.g. `s3://hedgeserv-elk-toolkit-artifacts/dataview-cleanup/<job_id>/`)
- Referenced as artifact links in the AWX job output

This gives us a durable, central audit trail that survives execution environment teardown.

---

## 5. Access Control Model

| Role | Finder template | Cleanup template (dry-run) | Cleanup template (`execute=true`) |
|---|---|---|---|
| Observability operator (L1) | ✅ Run | ✅ Run | ❌ |
| Observability senior (L2) | ✅ Run | ✅ Run | ✅ Run |
| ELK platform lead | ✅ All | ✅ All | ✅ All |
| External read-only | ✅ View job history only | ❌ | ❌ |

We'd like to enforce the `execute=true` boundary via AWX RBAC on the template itself rather than relying solely on the CLI flag.

---

## 6. Migration / Rollout Plan

1. **DevSecOps creates Secrets Manager secrets** for all nine production clusters under a consistent naming convention (`elk/kibana/api-keys/<cluster-slug>`).
2. **DevSecOps provisions the IAM role and policy** scoped to those secrets via Terraform (consistent with how Jesse's team manages our Roles Anywhere infrastructure).
3. **Observability refactors the scripts** to add the secrets loader, the new config schema, and the `--allow-plaintext-secrets` opt-out.
4. **DevSecOps builds the custom AWX execution environment image** and publishes it to our internal ECR.
5. **Both teams co-author the AWX job templates** with the surveys defined above.
6. **Pilot on the DR cluster** for two weeks before rolling production templates out.
7. **Rotate API keys** stored in the old `clusters.json` so any leaked copies are invalidated.
8. **Decommission the local-execution path** for the cleanup script. The finder may remain runnable locally for ad-hoc investigation.

---

## 7. Testing Plan

| Test | Owner | Pass criteria |
|---|---|---|
| Unit: secrets loader returns string for valid secret | Observability | API key returned, length > 0 |
| Unit: secrets loader raises on missing secret | Observability | `RuntimeError` with secret ID in message |
| Integration: finder against DR cluster via AWX | Both | Same duplicate count as local run |
| Integration: cleanup dry-run via AWX | Both | Plan matches local dry-run output |
| Integration: cleanup `--execute` via AWX on test space | Both | NDJSON backups uploaded to S3, references re-pointed, deletions confirmed |
| Negative: operator without execute permission cannot launch execute template | DevSecOps | AWX denies job launch |
| Negative: stale IAM cert is rejected | DevSecOps | Job fails with clear error in AWX output |

---

## 8. Rollback Plan

The refactor is additive — the old `clusters.json` with literal keys continues to work behind the `--allow-plaintext-secrets` flag during migration. If any blocker emerges:

1. Revert AWX templates to the previous version
2. Continue running scripts locally with the legacy config until the issue is resolved
3. No production data is lost: the cleanup script's NDJSON backups remain available regardless of which execution path produced them

---

## 9. Open Questions for DevSecOps

1. Should the IAM role be reused for both the finder and the cleanup template, or split per-template for finer-grained IAM auditing?
2. Do you want backups uploaded to a dedicated S3 bucket per team, or to the existing shared observability bucket with prefixes?
3. Should we use the existing `aws_ELK` role pattern verbatim, or take this as an opportunity to define a new toolkit-specific role with tighter scope?
4. Is there a preferred AWX credential type for delivering the Roles Anywhere certificate and private key, or should we define a custom one?
5. What is the team's preference for secret rotation cadence? We'd suggest 90 days for the Kibana API keys with automated rotation triggers if available.

---

## 10. Appendix: Current and Proposed Script Snippets

### Current `load_config()` excerpt

```python
def load_config(config_path):
    with open(config_path, 'r') as f:
        config = json.load(f)
    clusters = config.get("clusters", {})
    for name, cluster in clusters.items():
        api_key = cluster.get("api_key", "")
        if api_key.startswith("$"):
            env_var = api_key[1:]
            cluster["api_key"] = os.environ.get(env_var)
    return config
```

### Proposed `load_config()` excerpt

```python
def load_config(config_path, allow_plaintext=False):
    with open(config_path, 'r') as f:
        config = json.load(f)
    region = config.get("aws_region", "us-east-1")
    for name, cluster in config["clusters"].items():
        secret_id = cluster.get("secret_id")
        legacy_key = cluster.get("api_key")
        if secret_id:
            cluster["api_key"] = get_kibana_api_key(secret_id, region)
        elif legacy_key and allow_plaintext:
            # Honor existing env-var resolution for local dev only
            if legacy_key.startswith("$"):
                cluster["api_key"] = os.environ.get(legacy_key[1:])
        else:
            raise RuntimeError(
                f"[{name}] No 'secret_id' configured and "
                f"--allow-plaintext-secrets not set"
            )
    return config
```

---

**Contact:** Olamide Olajide — Observability Engineering — for clarifications or design discussion.
