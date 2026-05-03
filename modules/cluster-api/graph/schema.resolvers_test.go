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

package graph

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/kubetail-org/kubetail/modules/shared/clusteragentpb"
	"github.com/kubetail-org/kubetail/modules/shared/grpchelpers"
	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

type recordingMetadataServer struct {
	clusteragentpb.UnimplementedLogMetadataServiceServer
	mu  sync.Mutex
	got metadata.MD
}

func (s *recordingMetadataServer) List(ctx context.Context, _ *clusteragentpb.LogMetadataListRequest) (*clusteragentpb.LogMetadataList, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.got = md.Copy()
	s.mu.Unlock()
	return &clusteragentpb.LogMetadataList{}, nil
}

func (s *recordingMetadataServer) capturedMetadata() metadata.MD {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}

func startRecordingAgent(t *testing.T) (string, *recordingMetadataServer) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	rec := &recordingMetadataServer{}
	srv := grpc.NewServer()
	clusteragentpb.RegisterLogMetadataServiceServer(srv, rec)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return lis.Addr().String(), rec
}

// dialAgent installs the same impersonation interceptors mustNewGrpcDispatcher
// uses in production. The dispatcher itself is bypassed: its own tests cover
// Fanout's context preservation, and its endpoint-discovery informer doesn't
// sync against a fake k8s clientset. What we lock down here is the wire-level
// chain: ctx-with-ImpersonateInfo → ImpersonateUnaryClientInterceptor →
// x-remote-* metadata. A regression that drops the interceptor would silently
// downgrade every call to run as the cluster-api ServiceAccount.
func dialAgent(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		addr,
		grpc.WithUnaryInterceptor(grpchelpers.ImpersonateUnaryClientInterceptor),
		grpc.WithStreamInterceptor(grpchelpers.ImpersonateStreamClientInterceptor),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestImpersonateInfoOnContextReachesAgentAsRemoteHeaders(t *testing.T) {
	t.Parallel()
	addr, rec := startRecordingAgent(t)
	conn := dialAgent(t, addr)
	c := clusteragentpb.NewLogMetadataServiceClient(conn)

	info := &k8shelpers.ImpersonateInfo{
		User:   "alice@example.com",
		Groups: []string{"system:authenticated", "devs"},
		Extras: map[string][]string{"scopes": {"read", "write"}},
	}
	ctx, cancel := context.WithTimeout(
		context.WithValue(context.Background(), k8shelpers.K8SImpersonateCtxKey, info),
		5*time.Second,
	)
	defer cancel()

	_, err := c.List(ctx, &clusteragentpb.LogMetadataListRequest{})
	require.NoError(t, err)

	got := rec.capturedMetadata()
	require.Equal(t, []string{"alice@example.com"}, got.Get("x-remote-user"))
	require.ElementsMatch(t, []string{"system:authenticated", "devs"}, got.Get("x-remote-group"))
	// Extras ride in a single JSON header — see grpchelpers.withImpersonateMetadata.
	require.Len(t, got.Get("x-remote-extras"), 1)
	require.Contains(t, got.Get("x-remote-extras")[0], `"scopes"`)
}

// Inverse of the above: with no ImpersonateInfo on ctx, the chain must not
// synthesize a default identity — letting the agent reject is the right
// outcome.
func TestNoImpersonateInfoOnContextSendsNoRemoteHeaders(t *testing.T) {
	t.Parallel()
	addr, rec := startRecordingAgent(t)
	conn := dialAgent(t, addr)
	c := clusteragentpb.NewLogMetadataServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.List(ctx, &clusteragentpb.LogMetadataListRequest{})
	require.NoError(t, err)

	got := rec.capturedMetadata()
	require.Empty(t, got.Get("x-remote-user"))
	require.Empty(t, got.Get("x-remote-group"))
	require.Empty(t, got.Get("x-remote-extras"))
}
