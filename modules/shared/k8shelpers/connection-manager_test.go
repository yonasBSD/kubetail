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

package k8shelpers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// MockDesktopAuthorizer is a mock implementation of DesktopAuthorizer for testing
type MockDesktopAuthorizer struct {
	mock.Mock
}

// IsAllowedInformer is a mock implementation of the DesktopAuthorizer.IsAllowedInformer method
func (m *MockDesktopAuthorizer) IsAllowedInformer(ctx context.Context, clientset kubernetes.Interface, namespace string, gvr schema.GroupVersionResource) error {
	args := m.Called(ctx, clientset, namespace, gvr)
	return args.Error(0)
}

func TestDesktopConnectionManager_NewInformer_AuthorizationFailure(t *testing.T) {
	// Set up the expected error
	expectedError := errors.New("authorization failed")

	// Create a mock authorizer
	mockAuthorizer := new(MockDesktopAuthorizer)
	mockAuthorizer.On("IsAllowedInformer",
		mock.Anything,    // context
		mock.Anything,    // clientset
		"test-namespace", // namespace
		mock.MatchedBy(func(gvr schema.GroupVersionResource) bool {
			return gvr.Group == "apps" && gvr.Version == "v1" && gvr.Resource == "deployments"
		}), // gvr
	).Return(expectedError)

	// Create DesktopConnectionManager with the mock authorizer
	cm := &DesktopConnectionManager{
		authorizer: mockAuthorizer,
	}

	cm.csCache.LoadOrCompute("test-context", func() (*kubernetes.Clientset, error) {
		return &kubernetes.Clientset{}, nil
	})

	// Set up test parameters
	ctx := context.Background()
	kubeContext := "test-context"
	token := "" // Empty as tokens are not used in DesktopConnectionManager
	namespace := "test-namespace"
	gvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	}

	// Call the method under test
	informer, startFn, err := cm.NewInformer(ctx, kubeContext, token, namespace, gvr)
	assert.Nil(t, informer)
	assert.Nil(t, startFn)
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)

	// Verify that the mock was called as expected
	mockAuthorizer.AssertExpectations(t)
}

// MockInClusterAuthorizer is a mock implementation of InClusterAuthorizer for testing
type MockInClusterAuthorizer struct {
	mock.Mock
}

// IsAllowedInformer is a mock implementation of the InClusterAuthorizer.IsAllowedInformer method
func (m *MockInClusterAuthorizer) IsAllowedInformer(ctx context.Context, restConfig *rest.Config, token string, namespace string, gvr schema.GroupVersionResource) error {
	args := m.Called(ctx, restConfig, token, namespace, gvr)
	return args.Error(0)
}

func TestInClusterConnectionManager_NewInformer_AuthorizationFailure(t *testing.T) {
	// Set up the expected error
	expectedError := errors.New("authorization failed")

	// Create a mock authorizer
	mockAuthorizer := new(MockInClusterAuthorizer)
	mockAuthorizer.On("IsAllowedInformer",
		mock.Anything,    // context
		mock.Anything,    // restConfig
		"test-token",     // token
		"test-namespace", // namespace
		mock.MatchedBy(func(gvr schema.GroupVersionResource) bool {
			return gvr.Group == "apps" && gvr.Version == "v1" && gvr.Resource == "deployments"
		}), // gvr
	).Return(expectedError)

	// Create InClusterConnectionManager with the mock authorizer
	cm := &InClusterConnectionManager{
		restConfig:   &rest.Config{},
		authorizer:   mockAuthorizer,
		stopCh:       make(chan struct{}),
		factoryCache: make(map[string]informers.SharedInformerFactory),
	}

	// Set up test parameters
	ctx := context.Background()
	kubeContext := "" // Empty as it's not supported in InClusterConnectionManager
	token := "test-token"
	namespace := "test-namespace"
	gvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	}

	// Call the method under test
	informer, startFn, err := cm.NewInformer(ctx, kubeContext, token, namespace, gvr)

	// Verify the results
	assert.Nil(t, informer)
	assert.Nil(t, startFn)
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)

	// Verify that the mock was called as expected
	mockAuthorizer.AssertExpectations(t)
}

// Pins the wiring that propagates the originating user's identity to
// kube-apiserver: the in-cluster REST config must wrap its transport with
// ImpersonatingRoundTripper. A regression that swaps or drops this wrap
// would silently downgrade every cluster-api → kube-apiserver call to run
// as the cluster-api ServiceAccount, bypassing the user's RBAC.
func TestInClusterConnectionManager_RestConfigWrapsTransportWithImpersonation(t *testing.T) {
	orig := inClusterConfigFn
	t.Cleanup(func() { inClusterConfigFn = orig })
	inClusterConfigFn = func() (*rest.Config, error) {
		return &rest.Config{Host: "https://example.invalid"}, nil
	}

	cm, err := NewInClusterConnectionManager()
	require.NoError(t, err)

	rc, err := cm.GetOrCreateRestConfig("")
	require.NoError(t, err)
	require.NotNil(t, rc.WrapTransport, "WrapTransport must be set so per-request Impersonate-* headers reach kube-apiserver")

	inner := http.DefaultTransport
	wrapped := rc.WrapTransport(inner)
	impRT, ok := wrapped.(*ImpersonatingRoundTripper)
	require.Truef(t, ok, "WrapTransport must produce *ImpersonatingRoundTripper; got %T", wrapped)
	assert.Same(t, inner, impRT.Transport, "ImpersonatingRoundTripper must wrap the underlying transport, not replace it")
}

func TestInClusterConnectionManager_NewInformer_KubeContextNotSupported(t *testing.T) {
	// Create a mock authorizer
	mockAuthorizer := new(MockInClusterAuthorizer)

	// Create InClusterConnectionManager with the mock authorizer
	cm := &InClusterConnectionManager{
		authorizer:   mockAuthorizer,
		stopCh:       make(chan struct{}),
		factoryCache: make(map[string]informers.SharedInformerFactory),
	}

	// Set up test parameters with a non-empty kubeContext
	ctx := context.Background()
	kubeContext := "some-context" // This should cause an error as it's not supported
	token := "test-token"
	namespace := "test-namespace"
	gvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	}

	// Call the method under test
	informer, startFn, err := cm.NewInformer(ctx, kubeContext, token, namespace, gvr)

	// Verify the results
	assert.Nil(t, informer)
	assert.Nil(t, startFn)
	assert.Error(t, err)

	// The mock should not have been called since the error happens before authorization check
	mockAuthorizer.AssertNotCalled(t, "IsAllowedInformer")
}
