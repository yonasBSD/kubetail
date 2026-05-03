"""Zero-trust ingress tests: cluster-api only honors aggregated requests
through kube-apiserver; cluster-agent only honors mTLS clients."""

import json
import socket
import ssl
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests

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
        """Same spoofed headers but with a TLS client cert that chains to
        neither the client-CA nor requestheader-client-CA pool. Exercises
        the middleware's `no valid certificate found` branch — proves the
        listener actually presents both CA pools and that *having* a cert
        isn't sufficient to reach the header-parsing path."""
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
