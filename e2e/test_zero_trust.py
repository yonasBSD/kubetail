"""Zero-trust ingress tests: cluster-api only honors aggregated requests
through kube-apiserver; cluster-agent only honors mTLS clients."""

import asyncio
import base64
import json
import socket
import ssl
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests
import websockets
import websockets.exceptions

pytestmark = [pytest.mark.cluster, pytest.mark.kubetail_api]

_KUBECONFIG = "/tmp/kubetail-e2e.kubeconfig"
_NS = "kubetail-system"
_AGGREGATED_BASE = "/apis/api.kubetail.com/v1"

# Self-signed cert that chains to neither the cluster-api's client-CA pool
# nor its requestheader-client-CA pool. Used to exercise the middleware's
# "no valid certificate found" branch — see e2e/tls/README.md.
_UNTRUSTED_CLIENT_CERT = (
    str(Path(__file__).parent / "tls" / "untrusted-client.crt"),
    str(Path(__file__).parent / "tls" / "untrusted-client.key"),
)


@pytest.fixture(scope="session")
def admin_client_cert(tmp_path_factory):
    """Extract the e2e admin's client cert+key from the kubeconfig.

    The k3d admin cert is signed by the same CA the cluster-api loads
    into its ClientCAs pool (extension-apiserver-authentication's
    client-ca-file), so a request bearing it takes the middleware's
    direct-cert path."""
    cfg = json.loads(subprocess.run(
        ["kubectl", f"--kubeconfig={_KUBECONFIG}", "config", "view",
         "--raw", "--minify", "--flatten", "-o", "json"],
        check=True, capture_output=True, text=True,
    ).stdout)
    user = cfg["users"][0]["user"]
    d = tmp_path_factory.mktemp("admin-cert")
    crt = d / "client.crt"
    key = d / "client.key"
    crt.write_bytes(base64.b64decode(user["client-certificate-data"]))
    key.write_bytes(base64.b64decode(user["client-key-data"]))
    return (str(crt), str(key))


class TestClusterAPIAggregationGate:
    def test_direct_aggregated_healthz_unauthorized(self, cluster_api_url):
        r = requests.get(f"{cluster_api_url}{_AGGREGATED_BASE}/healthz", verify=False)
        assert r.status_code == 401

    def test_direct_aggregated_graphql_unauthorized(self, cluster_api_url):
        r = requests.post(
            f"{cluster_api_url}{_AGGREGATED_BASE}/graphql",
            json={"query": "{__typename}"},
            verify=False,
        )
        assert r.status_code == 401

    def test_direct_aggregated_download_unauthorized(self, cluster_api_url):
        r = requests.post(f"{cluster_api_url}{_AGGREGATED_BASE}/download", verify=False)
        assert r.status_code == 401

    def test_root_healthz_open(self, cluster_api_url):
        # Unaggregated root /healthz is intentionally open for the kubelet probe.
        r = requests.get(f"{cluster_api_url}/healthz", verify=False)
        assert r.status_code == 200

    def test_spoofed_front_proxy_headers_rejected(self, cluster_api_url):
        """Front-proxy impersonation headers without any client cert must
        not grant identity. Trips the middleware's first gate
        (`len(r.TLS.PeerCertificates) == 0`) before header parsing."""
        r = requests.post(
            f"{cluster_api_url}{_AGGREGATED_BASE}/graphql",
            json={"query": "{__typename}"},
            headers={
                "X-Remote-User": "system:masters",
                "X-Remote-Group": "system:masters",
                "X-Remote-Extra-foo": "bar",
            },
            verify=False,
        )
        assert r.status_code == 401

    def test_untrusted_client_cert_with_spoofed_headers_rejected(self, cluster_api_url):
        """Same spoofed headers but with an arbitrary self-signed cert that
        doesn't chain to the front-proxy CA pool. Exercises the middleware's
        `no valid certificate found` branch — proves *having* a cert isn't
        sufficient to reach the header-parsing path."""
        r = requests.post(
            f"{cluster_api_url}{_AGGREGATED_BASE}/graphql",
            json={"query": "{__typename}"},
            headers={
                "X-Remote-User": "system:masters",
                "X-Remote-Group": "system:masters",
            },
            cert=_UNTRUSTED_CLIENT_CERT,
            verify=False,
        )
        assert r.status_code == 401

    def test_legitimate_cluster_cert_not_front_proxy_rejected(
        self, cluster_api_url, admin_client_cert,
    ):
        """A holder of a legitimate cluster cert (kubectl admin, controller,
        system:node, etc.) is NOT kube-apiserver — they must be rejected at
        the gate. The cluster-api accepts requests only via the front-proxy
        chain. Spoofed headers in particular are never read because the cert
        itself fails verification against the requestheader-client-ca-file
        pool (the only trust anchor we honor)."""
        r = requests.post(
            f"{cluster_api_url}{_AGGREGATED_BASE}/graphql",
            json={"query": '{ logMetadataList(namespace: "kubetail-system") { items { id } } }'},
            headers={
                "X-Remote-User": "spoofed-attacker",
                "X-Remote-Group": "system:masters",
                "X-Remote-Extra-Scopes": "openid",
            },
            cert=admin_client_cert,
            verify=False,
        )
        assert r.status_code == 401, r.text

    def test_direct_ws_upgrade_rejected(self, cluster_api_url):
        """The aggregation middleware fires on every protected route — including
        WebSocket upgrades. A direct upgrade attempt without a client cert must
        get the same 401 the HTTP path returns; otherwise a WS-only auth bypass
        would let an attacker stream subscriptions without identity."""
        ws_url = (
            cluster_api_url.replace("https://", "wss://")
            + f"{_AGGREGATED_BASE}/graphql"
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        async def upgrade():
            async with websockets.connect(
                ws_url,
                ssl=ctx,
                subprotocols=["graphql-transport-ws"],
                open_timeout=5,
            ):
                pass

        with pytest.raises(websockets.exceptions.InvalidStatus) as exc:
            asyncio.run(upgrade())
        assert exc.value.response.status_code == 401

    @pytest.mark.usefixtures("cluster_api_url")
    def test_through_kube_apiserver_authorized(self):
        out = subprocess.run(
            ["kubectl", f"--kubeconfig={_KUBECONFIG}", "get", "--raw", f"{_AGGREGATED_BASE}/healthz"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert json.loads(out.stdout) == {"status": "ok"}


def _cluster_agent_pod():
    out = subprocess.run(
        [
            "kubectl", f"--kubeconfig={_KUBECONFIG}", "-n", _NS,
            "get", "pods",
            "-l", "app.kubernetes.io/component=cluster-agent",
            "-o", "jsonpath={.items[0].metadata.name}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    name = out.stdout.strip()
    assert name, "no cluster-agent pod found"
    return name


@contextmanager
def _port_forward(pod, remote_port):
    # Bind :0 to grab a free port, then release it before kubectl claims it.
    # Racy in theory; fine on a dev/CI host where nothing else is squatting.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        local_port = s.getsockname()[1]
    proc = subprocess.Popen(
        [
            "kubectl", f"--kubeconfig={_KUBECONFIG}", "-n", _NS,
            "port-forward", f"pod/{pod}", f"{local_port}:{remote_port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("port-forward never came up")
        yield local_port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def cluster_agent_local_port(cluster_api_url):
    del cluster_api_url  # only used to sequence with the kubetail-api cluster fixture
    with _port_forward(_cluster_agent_pod(), 50051) as port:
        yield port


class TestClusterAgentMTLSGate:
    def test_tls_without_client_cert_rejected(self, cluster_agent_local_port):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", cluster_agent_local_port), timeout=5) as raw:
            with pytest.raises(OSError):
                with ctx.wrap_socket(raw, server_hostname="kubetail-cluster-agent.kubetail-system.svc") as tls:
                    # Some servers defer the cert demand to the first record.
                    tls.send(b"\x00")
                    tls.recv(1)
