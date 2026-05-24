#!/usr/bin/env python3
"""
elk_secrets.py — Shared AWS Secrets Manager resolution for the
Duplicate Data Views Toolkit (AWX edition).

Imported by both:
  - find_duplicate_dataviews.py
  - cleanup_duplicate_dataviews.py

DESIGN
------
* There is NO local clusters.json. Each Elastic/Kibana deployment already has
  its own secret in AWS Secrets Manager.

* The SECRET NAME is identical to the DEPLOYMENT NAME that the operator enters
  as the AWX argument. AWX may pass one OR MORE deployment names; the toolkit
  loops over them and looks up each secret by that exact name.

* The SECRET CONTENTS (a JSON document) hold everything the script needs to talk
  to that deployment's Kibana — at minimum the kibana_url and api_key. Field
  names are centralized in SECRET_FIELD_* constants below so they can be updated
  in one place once the real key names are validated.

* AWS authentication uses the AMBIENT credentials of the AWX execution
  environment — i.e. whatever IAM role AWX has assumed. boto3's default
  credential chain picks these up automatically; no keys are passed in code and
  no specific role is referenced here.

Expected secret payload (placeholder field names — confirm and adjust constants):
    {
      "deployment_name": "fisma-scorecard",
      "kibana_url": "https://fisma-xxxxxx.kb.ps.cdm-db.com:9243",
      "api_key": "Ym95S2x...=="
    }
"""

import os
import logging
import json as _json

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
except ImportError:
    boto3 = None
    ClientError = BotoCoreError = NoCredentialsError = Exception


# ==============================================================================
# SECRET FIELD NAMES  (update these once the real JSON keys are validated)
# ==============================================================================
# Centralizing the field names means that if the actual secret uses, say,
# "kibanaUrl" or "apiKey" instead, you change ONE line here and both scripts
# pick it up — no need to hunt through the code.

SECRET_FIELD_DEPLOYMENT_NAME = "deployment_name"
SECRET_FIELD_KIBANA_URL = "kibana_url"
SECRET_FIELD_API_KEY = "api_key"


# ==============================================================================
# AWS REGION
# ==============================================================================
# Resolution order:
#   1. explicit region_name argument (e.g. from an AWX --aws-region survey field)
#   2. AWS_REGION / AWS_DEFAULT_REGION env vars (normally set by the AWX EE)
#   3. this fallback
DEFAULT_AWS_REGION = "us-east-2"


# In-process cache so the same deployment isn't fetched twice in one run.
_SECRET_CACHE = {}


# ==============================================================================
# CORE: FETCH A DEPLOYMENT'S CONFIG FROM ITS SECRET
# ==============================================================================

def get_deployment_config(deployment_name, region_name=None, verify_ssl=True):
    """
    Resolve one deployment's Kibana connection details from Secrets Manager.

    The secret is looked up by `deployment_name` directly (secret name ==
    deployment name). Its JSON contents are parsed and the kibana_url + api_key
    are extracted.

    Args:
        deployment_name (str): The AWX argument; also the Secrets Manager secret name.
        region_name (str): AWS region (optional; falls back to env/default).
        verify_ssl (bool): SSL verification flag, supplied via AWX argument and
                           attached to the returned config (the secret itself
                           does not carry this).

    Returns:
        dict: {
            "deployment_name": <str>,   # canonical name from the secret if present,
                                        # otherwise the name we looked up
            "kibana_url": <str>,
            "api_key": <str>,
            "verify_ssl": <bool>,
        }

    Raises:
        RuntimeError on any failure (no boto3, no creds, secret/field missing,
        malformed JSON). Callers decide whether to skip that deployment or abort.
    """
    if boto3 is None:
        raise RuntimeError(
            "boto3 is not installed in this environment. The AWX execution "
            "environment must include boto3/botocore."
        )

    region = (
        region_name
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or DEFAULT_AWS_REGION
    )

    cache_key = (deployment_name, region)
    if cache_key in _SECRET_CACHE:
        cfg = dict(_SECRET_CACHE[cache_key])
        cfg["verify_ssl"] = verify_ssl
        return cfg

    logging.debug(f"  Fetching secret '{deployment_name}' from Secrets Manager (region={region})")

    # --- Call Secrets Manager using AWX's ambient (assumed-role) credentials ---
    try:
        session = boto3.session.Session()
        client = session.client(service_name="secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=deployment_name)
    except NoCredentialsError as e:
        raise RuntimeError(
            f"No AWS credentials available for Secrets Manager. Confirm the AWX "
            f"job template is running with an assumed AWS role/credential. ({e})"
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "ResourceNotFoundException":
            raise RuntimeError(
                f"No secret named '{deployment_name}' in region {region}. "
                f"The deployment name must exactly match the Secrets Manager secret name."
            )
        if code == "AccessDeniedException":
            raise RuntimeError(
                f"Access denied to secret '{deployment_name}'. Check the IAM policy "
                f"on the role AWX assumed for secretsmanager:GetSecretValue."
            )
        raise RuntimeError(f"Secrets Manager error for '{deployment_name}': {code} — {e}")
    except BotoCoreError as e:
        raise RuntimeError(f"boto3 error retrieving '{deployment_name}': {e}")

    secret_string = response.get("SecretString")
    if not secret_string:
        raise RuntimeError(
            f"Secret '{deployment_name}' has no SecretString (binary secrets unsupported)."
        )

    # --- Parse the secret JSON and pull the fields we need ---
    try:
        secret = _json.loads(secret_string)
    except _json.JSONDecodeError:
        raise RuntimeError(
            f"Secret '{deployment_name}' is not valid JSON. Expected a JSON document "
            f"with at least '{SECRET_FIELD_KIBANA_URL}' and '{SECRET_FIELD_API_KEY}'."
        )

    kibana_url = secret.get(SECRET_FIELD_KIBANA_URL)
    api_key = secret.get(SECRET_FIELD_API_KEY)

    missing = []
    if not kibana_url:
        missing.append(SECRET_FIELD_KIBANA_URL)
    if not api_key:
        missing.append(SECRET_FIELD_API_KEY)
    if missing:
        raise RuntimeError(
            f"Secret '{deployment_name}' is missing required field(s): {missing}. "
            f"Available keys: {list(secret.keys())}"
        )

    cfg = {
        "deployment_name": secret.get(SECRET_FIELD_DEPLOYMENT_NAME, deployment_name),
        "kibana_url": kibana_url.rstrip("/"),
        "api_key": api_key,
        "verify_ssl": verify_ssl,
    }

    # Cache the AWS-derived part (without verify_ssl, which is a per-run arg).
    cacheable = {k: v for k, v in cfg.items() if k != "verify_ssl"}
    _SECRET_CACHE[cache_key] = cacheable

    logging.info(
        f"[{cfg['deployment_name']}] Resolved from Secrets Manager "
        f"(url={cfg['kibana_url']})"
    )
    return cfg


def resolve_deployments(deployment_names, region_name=None, verify_ssl=True):
    """
    Resolve a LIST of deployment names into ready-to-use cluster configs.

    For each name, fetch its secret and build a config dict. A failure on one
    deployment is logged and that deployment is skipped, so a single bad/missing
    secret doesn't abort the whole multi-deployment run.

    Returns:
        dict: { deployment_name: config_dict, ... } for every name that resolved.
              Empty dict if none resolved.
    """
    resolved = {}
    for name in deployment_names:
        name = name.strip()
        if not name:
            continue
        try:
            cfg = get_deployment_config(name, region_name=region_name, verify_ssl=verify_ssl)
            # Key the result by the name the operator supplied so logs/reports
            # line up with the AWX input.
            resolved[name] = cfg
        except RuntimeError as e:
            logging.error(f"[{name}] Skipping — {e}")
    return resolved


def get_headers(api_key):
    """Standard Kibana auth headers."""
    return {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
    }
