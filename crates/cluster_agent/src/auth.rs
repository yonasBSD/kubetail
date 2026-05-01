// Copyright 2024 The Kubetail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trust-chain authenticator: validates the peer certificate's CN against an
//! allowlist and extracts the forwarded identity (user/groups/extras) from
//! gRPC metadata. Mirrors the front-proxy behavior in cluster-api's
//! `newAggregationAuthMiddleware`.

use std::collections::HashMap;
use std::sync::Arc;

use tonic::Status;
use tonic::metadata::{KeyRef, MetadataMap};
use x509_parser::prelude::{FromDer, X509Certificate};

pub const USER_HEADER: &str = "x-remote-user";
pub const GROUP_HEADER: &str = "x-remote-group";
pub const EXTRA_HEADER_PREFIX: &str = "x-remote-extra-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user: String,
    pub groups: Vec<String>,
    pub extras: HashMap<String, Vec<String>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("client certificate required")]
    MissingPeerCert,
    #[error("proxy CN {0:?} not in allowed list")]
    DisallowedCn(String),
    #[error("missing user header")]
    MissingUser,
    #[error("invalid metadata for {0}")]
    InvalidMetadata(String),
}

/// Authenticate a request given the peer-cert CN (extracted by the caller
/// from the verified TLS chain) and the request metadata. An empty
/// `allowed_names` accepts any CN (matches kube-apiserver's
/// `requestheader-allowed-names` semantics).
pub fn authenticate(
    peer_cn: Option<&str>,
    metadata: &MetadataMap,
    allowed_names: &[String],
) -> Result<Identity, AuthError> {
    let cn = peer_cn.ok_or(AuthError::MissingPeerCert)?;

    if !allowed_names.is_empty() && !allowed_names.iter().any(|n| n == cn) {
        return Err(AuthError::DisallowedCn(cn.to_string()));
    }

    let user_val = metadata.get(USER_HEADER).ok_or(AuthError::MissingUser)?;
    let user = user_val
        .to_str()
        .map_err(|_| AuthError::InvalidMetadata(USER_HEADER.to_string()))?;
    if user.is_empty() {
        return Err(AuthError::MissingUser);
    }

    let mut groups = Vec::new();
    for v in metadata.get_all(GROUP_HEADER).iter() {
        let s = v
            .to_str()
            .map_err(|_| AuthError::InvalidMetadata(GROUP_HEADER.to_string()))?;
        if !s.is_empty() {
            groups.push(s.to_string());
        }
    }

    let mut extras: HashMap<String, Vec<String>> = HashMap::new();
    for key in metadata.keys() {
        if let KeyRef::Ascii(k) = key {
            let name = k.as_str();
            if let Some(suffix) = name.strip_prefix(EXTRA_HEADER_PREFIX) {
                let mut vals = Vec::new();
                for v in metadata.get_all(name).iter() {
                    let s = v
                        .to_str()
                        .map_err(|_| AuthError::InvalidMetadata(name.to_string()))?;
                    vals.push(s.to_string());
                }
                if !vals.is_empty() {
                    extras.insert(suffix.to_string(), vals);
                }
            }
        }
    }

    Ok(Identity {
        user: user.to_string(),
        groups,
        extras,
    })
}

/// Extract the leaf certificate's Common Name. Returns `None` if parsing
/// fails or the subject has no CN attribute.
pub fn cn_from_cert_der(der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(str::to_owned))
}

/// Translate an `AuthError` into a `tonic::Status`.
fn auth_error_to_status(err: &AuthError) -> Status {
    match err {
        AuthError::MissingPeerCert | AuthError::MissingUser => {
            Status::unauthenticated(err.to_string())
        }
        AuthError::DisallowedCn(_) => Status::permission_denied(err.to_string()),
        AuthError::InvalidMetadata(_) => Status::invalid_argument(err.to_string()),
    }
}

/// Authenticate a request given the verified peer-cert chain (TLS layer has
/// already chained it to the trusted CA) and the request metadata. Returns a
/// gRPC `Status` on rejection.
pub fn check(
    peer_certs: Option<&[impl AsRef<[u8]>]>,
    metadata: &MetadataMap,
    allowed_names: &[String],
) -> Result<Identity, Status> {
    let cn = peer_certs
        .and_then(|certs| certs.first())
        .and_then(|c| cn_from_cert_der(c.as_ref()));
    authenticate(cn.as_deref(), metadata, allowed_names).map_err(|e| auth_error_to_status(&e))
}

/// Build a tonic interceptor closure that runs `check` against each request
/// and stashes the resulting `Identity` on request extensions.
pub fn interceptor(
    allowed_names: Arc<Vec<String>>,
) -> impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, Status> + Clone {
    move |mut req: tonic::Request<()>| {
        let certs = req.peer_certs();
        let id = check(
            certs.as_deref().map(|v| v.as_slice()),
            req.metadata(),
            &allowed_names,
        )?;
        req.extensions_mut().insert(id);
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::{MetadataKey, MetadataValue};

    fn md(pairs: &[(&str, &str)]) -> MetadataMap {
        let mut m = MetadataMap::new();
        for (k, v) in pairs {
            let key = MetadataKey::from_bytes(k.as_bytes()).unwrap();
            let val: MetadataValue<_> = v.parse().unwrap();
            m.append(key, val);
        }
        m
    }

    #[test]
    fn missing_peer_cert_rejected() {
        let err = authenticate(None, &md(&[("x-remote-user", "alice")]), &[]).unwrap_err();
        assert_eq!(err, AuthError::MissingPeerCert);
    }

    #[test]
    fn cn_not_in_allowlist_rejected() {
        let allowed = vec!["kubetail-cluster-api".to_string()];
        let err = authenticate(
            Some("rogue-proxy"),
            &md(&[("x-remote-user", "alice")]),
            &allowed,
        )
        .unwrap_err();
        assert_eq!(err, AuthError::DisallowedCn("rogue-proxy".to_string()));
    }

    #[test]
    fn empty_allowlist_accepts_any_cn() {
        let id = authenticate(Some("any-cn"), &md(&[("x-remote-user", "alice")]), &[]).unwrap();
        assert_eq!(id.user, "alice");
        assert!(id.groups.is_empty());
        assert!(id.extras.is_empty());
    }

    #[test]
    fn cn_in_allowlist_accepted() {
        let allowed = vec!["a".to_string(), "kubetail-cluster-api".to_string()];
        let id = authenticate(
            Some("kubetail-cluster-api"),
            &md(&[("x-remote-user", "alice")]),
            &allowed,
        )
        .unwrap();
        assert_eq!(id.user, "alice");
    }

    #[test]
    fn missing_user_header_rejected() {
        let err = authenticate(Some("cn"), &md(&[]), &[]).unwrap_err();
        assert_eq!(err, AuthError::MissingUser);
    }

    #[test]
    fn empty_user_header_rejected() {
        let err = authenticate(Some("cn"), &md(&[("x-remote-user", "")]), &[]).unwrap_err();
        assert_eq!(err, AuthError::MissingUser);
    }

    #[test]
    fn repeated_groups_collected() {
        let id = authenticate(
            Some("cn"),
            &md(&[
                ("x-remote-user", "alice"),
                ("x-remote-group", "system:authenticated"),
                ("x-remote-group", "devs"),
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(id.groups, vec!["system:authenticated", "devs"]);
    }

    #[test]
    fn extras_grouped_by_suffix() {
        let id = authenticate(
            Some("cn"),
            &md(&[
                ("x-remote-user", "alice"),
                ("x-remote-extra-scopes", "read"),
                ("x-remote-extra-scopes", "write"),
                ("x-remote-extra-tenant", "acme"),
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(
            id.extras.get("scopes").unwrap(),
            &vec!["read".to_string(), "write".to_string()]
        );
        assert_eq!(id.extras.get("tenant").unwrap(), &vec!["acme".to_string()]);
        assert_eq!(id.extras.len(), 2);
    }

    #[test]
    fn no_groups_no_extras_yields_empty_collections() {
        let id = authenticate(Some("cn"), &md(&[("x-remote-user", "alice")]), &[]).unwrap();
        assert!(id.groups.is_empty());
        assert!(id.extras.is_empty());
    }

    fn mint_cert(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn cn_from_cert_der_extracts_common_name() {
        let der = mint_cert("kubetail-cluster-api");
        assert_eq!(
            cn_from_cert_der(&der).as_deref(),
            Some("kubetail-cluster-api"),
        );
    }

    #[test]
    fn cn_from_cert_der_returns_none_on_garbage() {
        assert_eq!(cn_from_cert_der(&[0u8, 1, 2, 3]), None);
    }

    #[test]
    fn check_accepts_valid_request() {
        let der = mint_cert("kubetail-cluster-api");
        let certs: [Vec<u8>; 1] = [der];
        let allowed = vec!["kubetail-cluster-api".to_string()];
        let id = check(
            Some(&certs[..]),
            &md(&[("x-remote-user", "alice"), ("x-remote-group", "devs")]),
            &allowed,
        )
        .unwrap();
        assert_eq!(id.user, "alice");
        assert_eq!(id.groups, vec!["devs"]);
    }

    #[test]
    fn check_rejects_missing_peer_certs_with_unauthenticated() {
        let no_certs: Option<&[Vec<u8>]> = None;
        let status = check(no_certs, &md(&[("x-remote-user", "alice")]), &[]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn check_rejects_disallowed_cn_with_permission_denied() {
        let der = mint_cert("rogue-proxy");
        let certs: [Vec<u8>; 1] = [der];
        let allowed = vec!["kubetail-cluster-api".to_string()];
        let status = check(
            Some(&certs[..]),
            &md(&[("x-remote-user", "alice")]),
            &allowed,
        )
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn check_rejects_missing_user_with_unauthenticated() {
        let der = mint_cert("kubetail-cluster-api");
        let certs: [Vec<u8>; 1] = [der];
        let status = check(Some(&certs[..]), &md(&[]), &[]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn interceptor_stashes_identity_on_extensions() {
        // peer_certs() reads a tonic-private extension type, so we can't
        // exercise the cert-bearing path without spinning up a TLS server.
        // Verify the no-cert case behaves as expected: rejection.
        let allowed = Arc::new(Vec::<String>::new());
        let mut intercept = interceptor(allowed);
        let mut req = tonic::Request::new(());
        req.metadata_mut()
            .insert("x-remote-user", "alice".parse().unwrap());
        let status = intercept(req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }
}
