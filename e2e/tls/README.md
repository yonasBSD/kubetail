# Test-only TLS material

`untrusted-client.{crt,key}` is a self-signed certificate that is *not*
trusted by anything in the cluster — its only purpose is to be rejected by
the cluster-api's `aggregationAuthMiddleware` so we can exercise the
"valid TLS handshake but cert chains to neither CA pool" branch end-to-end
(see `e2e/test_zero_trust.py::test_untrusted_client_cert_with_spoofed_headers_rejected`).

Long validity (100 years) so it doesn't need rotation. The middleware's
`Verify()` calls fail on chain mismatch, not expiry, so even an expired
cert would still drive the same code path — but a permanent one keeps the
test robust against clock drift.

**Do not** add this cert to any trust store. It carries no privileges and
is never used outside this test.
