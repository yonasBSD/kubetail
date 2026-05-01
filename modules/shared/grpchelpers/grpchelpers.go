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

package grpchelpers

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

const (
	userHeader        = "x-remote-user"
	groupHeader       = "x-remote-group"
	extraHeaderPrefix = "x-remote-extra-"
)

func withImpersonateMetadata(ctx context.Context) context.Context {
	info, _ := ctx.Value(k8shelpers.K8SImpersonateCtxKey).(*k8shelpers.ImpersonateInfo)
	if info == nil || info.User == "" {
		return ctx
	}
	var kv []string
	info.ForEach(userHeader, groupHeader, extraHeaderPrefix, func(k, v string) {
		kv = append(kv, k, v)
	})
	return metadata.AppendToOutgoingContext(ctx, kv...)
}

// ImpersonateUnaryClientInterceptor forwards the *ImpersonateInfo on the
// context to the downstream gRPC server as x-remote-* metadata.
func ImpersonateUnaryClientInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(withImpersonateMetadata(ctx), method, req, reply, cc, opts...)
}

// ImpersonateStreamClientInterceptor is the streaming counterpart of
// [ImpersonateUnaryClientInterceptor].
func ImpersonateStreamClientInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(withImpersonateMetadata(ctx), desc, cc, method, opts...)
}
