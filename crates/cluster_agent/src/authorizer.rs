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

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};

use kube::Config;

#[cfg(not(test))]
use kube::api::PostParams;
use tonic::Status;

use crate::auth::Identity;
use moka::future::Cache;
use std::time::Duration;

/// Key for the authorization cache: (identity, namespace, verb)
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    identity: Identity,
    namespace: String,
    verb: String,
}

type AuthCache = Cache<CacheKey, bool>;

fn create_auth_cache() -> AuthCache {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(30))
        .build()
}

#[derive(Debug, Clone)]
pub struct Authorizer {
    k8s_config: Config,
    auth_cache: AuthCache,
}

/// Build a `SubjectAccessReview` for an identity asking to perform `verb`
/// on `pods/log` in the given namespace (`None` = cluster-scoped).
pub fn build_sar(identity: &Identity, namespace: Option<&str>, verb: &str) -> SubjectAccessReview {
    let extra = if identity.extras.is_empty() {
        None
    } else {
        Some(
            identity
                .extras
                .iter()
                .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
                .collect(),
        )
    };
    let groups = if identity.groups.is_empty() {
        None
    } else {
        Some(identity.groups.iter().cloned().collect())
    };
    SubjectAccessReview {
        spec: SubjectAccessReviewSpec {
            user: Some(identity.user.clone()),
            groups,
            extra,
            resource_attributes: Some(ResourceAttributes {
                namespace: namespace.map(str::to_owned),
                verb: Some(verb.to_owned()),
                resource: Some("pods".to_owned()),
                subresource: Some("log".to_owned()),
                ..ResourceAttributes::default()
            }),
            non_resource_attributes: None,
            uid: None,
        },
        ..SubjectAccessReview::default()
    }
}

fn permission_denied(verb: &str, namespace: Option<&str>) -> Status {
    Status::new(
        tonic::Code::PermissionDenied,
        format!(
            "permission denied: `{verb} pods/log` in namespace `{}`",
            namespace.unwrap_or("all")
        ),
    )
}

#[cfg(not(test))]
impl Authorizer {
    pub async fn new() -> Result<Self, Status> {
        let k8s_config = Config::infer().await.map_err(|error| {
            Status::new(
                tonic::Code::Unknown,
                format!("unable to infer k8s config {error}"),
            )
        })?;
        Ok(Self {
            k8s_config,
            auth_cache: create_auth_cache(),
        })
    }

    pub async fn is_authorized(
        &self,
        identity: &Identity,
        namespaces: &[String],
        verb: &str,
    ) -> Result<(), Status> {
        let client = kube::Client::try_from(self.k8s_config.clone())
            .map_err(|error| Status::new(tonic::Code::Unauthenticated, error.to_string()))?;
        let access_reviews: kube::Api<SubjectAccessReview> = kube::Api::all(client);

        let namespaces_to_check: Vec<Option<&str>> = if namespaces.is_empty() {
            vec![None]
        } else {
            namespaces.iter().map(|ns| Some(ns.as_str())).collect()
        };

        for namespace in namespaces_to_check {
            let cache_key = CacheKey {
                identity: identity.clone(),
                namespace: namespace.unwrap_or("").to_owned(),
                verb: verb.to_owned(),
            };

            let allowed = if let Some(cached) = self.auth_cache.get(&cache_key).await {
                cached
            } else {
                let sar = build_sar(identity, namespace, verb);
                let response = access_reviews
                    .create(&PostParams::default(), &sar)
                    .await
                    .map_err(|error| {
                        Status::new(
                            tonic::Code::Unknown,
                            format!("failed to authenticate {error}"),
                        )
                    })?;
                let allowed = response.status.as_ref().is_some_and(|s| s.allowed);
                self.auth_cache.insert(cache_key, allowed).await;
                allowed
            };

            if !allowed {
                return Err(permission_denied(verb, namespace));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
impl Authorizer {
    pub async fn new() -> Result<Self, Status> {
        Ok(Self {
            k8s_config: Config::new(http::Uri::from_static("http://k8s.url")),
            auth_cache: create_auth_cache(),
        })
    }

    pub async fn is_authorized(
        &self,
        _identity: &Identity,
        _namespaces: &[String],
        _verb: &str,
    ) -> Result<(), Status> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn id(user: &str) -> Identity {
        Identity {
            user: user.to_owned(),
            groups: BTreeSet::new(),
            extras: BTreeMap::new(),
        }
    }

    #[test]
    fn build_sar_user_only() {
        let sar = build_sar(&id("alice"), Some("default"), "get");
        assert_eq!(sar.spec.user.as_deref(), Some("alice"));
        assert!(sar.spec.groups.is_none());
        assert!(sar.spec.extra.is_none());
        let attrs = sar.spec.resource_attributes.as_ref().unwrap();
        assert_eq!(attrs.namespace.as_deref(), Some("default"));
        assert_eq!(attrs.verb.as_deref(), Some("get"));
        assert_eq!(attrs.resource.as_deref(), Some("pods"));
        assert_eq!(attrs.subresource.as_deref(), Some("log"));
    }

    #[test]
    fn build_sar_with_groups_and_extras() {
        let identity = Identity {
            user: "alice".into(),
            groups: BTreeSet::from(["devs".to_string(), "system:authenticated".to_string()]),
            extras: BTreeMap::from([(
                "scopes".to_string(),
                BTreeSet::from(["read".to_string(), "write".to_string()]),
            )]),
        };
        let sar = build_sar(&identity, Some("ns"), "list");
        assert_eq!(sar.spec.groups.as_ref().unwrap().len(), 2);
        let extra = sar.spec.extra.as_ref().unwrap();
        assert_eq!(
            extra.get("scopes").unwrap(),
            &vec!["read".to_string(), "write".to_string()]
        );
    }

    #[test]
    fn build_sar_cluster_scoped_when_namespace_none() {
        let sar = build_sar(&id("alice"), None, "get");
        let attrs = sar.spec.resource_attributes.as_ref().unwrap();
        assert!(attrs.namespace.is_none());
    }

    fn key(identity: Identity) -> CacheKey {
        CacheKey {
            identity,
            namespace: "ns".to_owned(),
            verb: "get".to_owned(),
        }
    }

    #[test]
    fn cache_key_equal_for_reordered_groups() {
        let a = Identity {
            user: "alice".into(),
            groups: BTreeSet::from(["x".to_string(), "y".to_string()]),
            extras: BTreeMap::new(),
        };
        let b = Identity {
            user: "alice".into(),
            groups: ["y", "x"].iter().map(|s| s.to_string()).collect(),
            extras: BTreeMap::new(),
        };
        assert_eq!(key(a.clone()), key(b.clone()));

        use std::hash::{BuildHasher, Hash, Hasher};
        let state = std::collections::hash_map::RandomState::new();
        let mut h1 = state.build_hasher();
        let mut h2 = state.build_hasher();
        key(a).hash(&mut h1);
        key(b).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn cache_key_equal_for_reordered_extras() {
        let a = Identity {
            user: "alice".into(),
            groups: BTreeSet::new(),
            extras: BTreeMap::from([(
                "scopes".to_string(),
                BTreeSet::from(["read".to_string(), "write".to_string()]),
            )]),
        };
        let b = Identity {
            user: "alice".into(),
            groups: BTreeSet::new(),
            extras: BTreeMap::from([(
                "scopes".to_string(),
                ["write", "read"].iter().map(|s| s.to_string()).collect(),
            )]),
        };
        assert_eq!(key(a), key(b));
    }
}
