"""End-to-end namespace-scoped RBAC tests.

A user whose RBAC only grants `pods/log` in `_ALLOWED_NS` must be denied
when querying any other namespace's logs. Three paths are exercised:

* `TestCliDashboard` — `kubetail serve` (desktop env). The kubeconfig's
  credentials *are* the identity; the dashboard's `DefaultDesktopAuthorizer`
  checks via SelfSubjectAccessReview before opening informers.

* `TestClusterDashboard` — in-cluster dashboard's `/graphql`. The user's
  bearer token is forwarded to the kube-apiserver per request, so the same
  SAR-based authorization applies.

* `TestClusterApiProxy` — in-cluster dashboard's `/cluster-api-proxy/graphql`.
  Token rides through kube-apiserver aggregation to the cluster-api, which
  fans out gRPC to the cluster-agent; the cluster-agent runs SAR for
  `pods/log` in the requested namespace as the user.
"""

import json
import os
import subprocess
import tempfile
import time

import pytest
import requests

from _namespace_rbac import (
    ALLOWED_NS,
    FORBIDDEN_NS,
    SA_NAME,
    free_port,
    has_authz_denial,
    kubectl,
    session,
)

# Both env tracks need the kubetail-api backend (cluster mode needs it for
# the cluster-api-proxy; cli is collapsed to canonical backend anyway).
pytestmark = [pytest.mark.kubetail_api]


_DASHBOARD_LOG_FETCH = (
    "query Q($sources:[String!]!){"
    "logRecordsFetch(sources:$sources, mode:TAIL, limit:1)"
    "{records{message}}}"
)

_CLUSTER_API_LOG_METADATA = (
    "query Q($namespace:String){"
    "logMetadataList(namespace:$namespace)"
    "{items{id}}}"
)


def _post_graphql(base_url, path, query, variables, *, bearer=None):
    s, csrf = session(base_url)
    headers = {"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    r = s.post(
        f"{base_url}{path}",
        headers=headers,
        json={"query": query, "variables": variables},
        timeout=20,
    )
    assert r.status_code == 200, r.text
    return r.json()


_NAMESPACE_CASES = pytest.mark.parametrize(
    "namespace,expect_denial",
    [(FORBIDDEN_NS, True), (ALLOWED_NS, False)],
    ids=["forbidden-denied", "allowed-not-denied"],
)


# ---------------------------------------------------------------------------
# CLI / desktop env — kubetail serve with a namespace-restricted kubeconfig.
# ---------------------------------------------------------------------------


def _build_restricted_kubeconfig(token):
    """Take the e2e admin kubeconfig and swap the user for the SA token.

    Uses `kubectl config view --raw --minify --flatten -o json` so we get the
    cluster entry (with embedded CA data) without adding a YAML dependency.
    """
    cfg = json.loads(
        kubectl(
            "config", "view", "--raw", "--minify", "--flatten", "-o", "json"
        ).stdout
    )
    cluster_entry = cfg["clusters"][0]
    context_name = cfg["contexts"][0]["name"]
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [cluster_entry],
        "users": [{"name": SA_NAME, "user": {"token": token}}],
        "contexts": [
            {
                "name": context_name,
                "context": {"cluster": cluster_entry["name"], "user": SA_NAME},
            }
        ],
        "current-context": context_name,
    }


@pytest.fixture(scope="module")
def restricted_serve_url(restricted_sa_token, cli):
    kubeconfig = _build_restricted_kubeconfig(restricted_sa_token)
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".kubeconfig", delete=False
    )
    json.dump(kubeconfig, fh)
    fh.close()

    port = free_port()
    env = os.environ.copy()
    env["KUBECONFIG"] = fh.name
    serve_proc = subprocess.Popen(
        [cli, "serve", "--port", str(port), "--skip-open"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    base_url = f"http://localhost:{port}"
    try:
        deadline = time.monotonic() + 15
        ready = False
        while time.monotonic() < deadline:
            try:
                if requests.get(f"{base_url}/healthz", timeout=1).status_code == 200:
                    ready = True
                    break
            except requests.RequestException:
                pass
            time.sleep(0.2)
        if not ready:
            raise RuntimeError("kubetail serve never became healthy")
        yield base_url
    finally:
        serve_proc.terminate()
        try:
            serve_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            serve_proc.kill()
            serve_proc.wait()
        os.unlink(fh.name)


class TestCliDashboard:
    pytestmark = [pytest.mark.cli]

    @_NAMESPACE_CASES
    def test_log_records_fetch(self, restricted_serve_url, namespace, expect_denial):
        body = _post_graphql(
            restricted_serve_url, "/graphql",
            _DASHBOARD_LOG_FETCH, {"sources": [f"{namespace}:pods/chatter"]},
        )
        assert has_authz_denial(body) == expect_denial, body


# ---------------------------------------------------------------------------
# Cluster env — in-cluster dashboard. Bearer token rides on each request.
# ---------------------------------------------------------------------------


class TestClusterDashboard:
    pytestmark = [pytest.mark.cluster]

    @_NAMESPACE_CASES
    def test_log_records_fetch(
        self, target_url, restricted_sa_token, namespace, expect_denial
    ):
        body = _post_graphql(
            target_url, "/graphql",
            _DASHBOARD_LOG_FETCH, {"sources": [f"{namespace}:pods/chatter"]},
            bearer=restricted_sa_token,
        )
        assert has_authz_denial(body) == expect_denial, body


class TestClusterApiProxy:
    pytestmark = [pytest.mark.cluster]

    @_NAMESPACE_CASES
    def test_log_metadata_list(
        self, target_url, restricted_sa_token, namespace, expect_denial
    ):
        body = _post_graphql(
            target_url, "/cluster-api-proxy/graphql",
            _CLUSTER_API_LOG_METADATA, {"namespace": namespace},
            bearer=restricted_sa_token,
        )
        assert has_authz_denial(body) == expect_denial, body
