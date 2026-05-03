"""Shared constants and helpers for namespace-scoped RBAC tests.

Used by test_namespace_rbac.py and the `restricted_sa_tokens` fixture in
conftest.py.
"""

import socket
import string
import subprocess
from pathlib import Path

import requests

KUBECONFIG = "/tmp/kubetail-e2e.kubeconfig"
SA1_NS = "e2e-rbac-ns-1"
SA2_NS = "e2e-rbac-ns-2"
# pods/log access granted via a Group subject (system:serviceaccounts:SA1_NS),
# not a ServiceAccount subject — exercises group-header propagation.
GROUP_NS = "e2e-rbac-group-ns"
SA1_NAME = "restricted-user-1"
SA2_NAME = "restricted-user-2"
# Lives in GROUP_NS; its sole access path is the group binding there.
GROUP_SA_NAME = "group-bound-user"
POD_IMAGE = "busybox:1.36"
BASELINE_CLUSTER_ROLE = "e2e-rbac-baseline"

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
        SA1_NS=SA1_NS,
        SA2_NS=SA2_NS,
        GROUP_NS=GROUP_NS,
        SA1_NAME=SA1_NAME,
        SA2_NAME=SA2_NAME,
        GROUP_SA_NAME=GROUP_SA_NAME,
        POD_IMAGE=POD_IMAGE,
        BASELINE_CLUSTER_ROLE=BASELINE_CLUSTER_ROLE,
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
