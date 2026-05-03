"""Shared constants and helpers for namespace-scoped RBAC tests.

Used by `test_namespace_rbac_cli.py` (kubetail serve / desktop env) and
`test_namespace_rbac_cluster.py` (in-cluster dashboard + cluster-api-proxy).
"""

import socket
import string
import subprocess
from pathlib import Path

import requests

KUBECONFIG = "/tmp/kubetail-e2e.kubeconfig"
ALLOWED_NS = "e2e-rbac-allowed"
FORBIDDEN_NS = "e2e-rbac-forbidden"
SA_NAME = "restricted-user"
POD_IMAGE = "busybox:1.36"

_MANIFEST_PATH = Path(__file__).parent / "manifests" / "namespace_rbac.yaml.tmpl"

AUTHZ_DENIAL_KEYWORDS = ("permission denied", "forbidden", "unauthorized")


def kubectl(*args, check=True, input=None):
    return subprocess.run(
        ["kubectl", f"--kubeconfig={KUBECONFIG}", *args],
        check=check,
        capture_output=True,
        text=True,
        input=input,
    )


def rendered_manifest():
    return string.Template(_MANIFEST_PATH.read_text()).substitute(
        ALLOWED_NS=ALLOWED_NS,
        FORBIDDEN_NS=FORBIDDEN_NS,
        SA_NAME=SA_NAME,
        POD_IMAGE=POD_IMAGE,
    )


def has_authz_denial(body):
    text = " ".join(e.get("message", "") for e in body.get("errors") or []).lower()
    return any(kw in text for kw in AUTHZ_DENIAL_KEYWORDS)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def session(base_url):
    """Open an /api/auth/session and return (requests.Session, csrf-token)."""
    s = requests.Session()
    r = s.get(f"{base_url}/api/auth/session")
    assert r.status_code == 200, r.text
    tok = r.headers.get("X-CSRF-Token", "")
    assert tok, "X-CSRF-Token missing from session response"
    return s, tok
