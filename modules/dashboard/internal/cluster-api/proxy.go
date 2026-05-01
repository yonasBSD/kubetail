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

package clusterapi

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"k8s.io/kubectl/pkg/proxy"

	"github.com/kubetail-org/kubetail/modules/shared/httphelpers"
	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

// hijackTrackingResponseWriter wraps an http.ResponseWriter to intercept
// Hijack() and capture the underlying net.Conn so it can be closed on shutdown.
type hijackTrackingResponseWriter struct {
	http.ResponseWriter
	mu   sync.Mutex
	conn net.Conn
}

func (w *hijackTrackingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil {
		w.mu.Lock()
		w.conn = conn
		w.mu.Unlock()
	}
	return conn, rw, err
}

func (w *hijackTrackingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *hijackTrackingResponseWriter) closeConn() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		w.conn.Close()
	}
}

// For parsing paths of the form /:kubeContext/*relPath
var desktopProxyPathRegex = regexp.MustCompile(`^/([^/]+)/(.*)$`)

// For parsing cookie paths
var cookiepathRegex = regexp.MustCompile(`Path=[^;]*`)

// Proxy interface
type Proxy interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	NotifyShutdown()
	DrainWithContext(ctx context.Context) error
}

// Represents DesktopProxy
type DesktopProxy struct {
	cm             k8shelpers.ConnectionManager
	pathPrefix     string
	allowedOrigins []string
	phCache        map[string]http.Handler
	mu             sync.Mutex
	shutdownCh     chan struct{}
	wg             sync.WaitGroup
}

// ServeHTTP
func (p *DesktopProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Track connections for graceful shutdown
	p.wg.Add(1)
	defer p.wg.Done()

	// CSWSH defense for WebSocket upgrades. Chrome does not send
	// Sec-Fetch-Site on upgrade requests, so the app-level CSRF middleware
	// can't gate them; check Origin directly here instead.
	if r.Header.Get("Upgrade") != "" && !httphelpers.IsAllowedOrigin(r, p.allowedOrigins) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	origPath := r.URL.Path

	// Trim prefix
	proxyPath := strings.TrimPrefix(origPath, p.pathPrefix)

	// Parse url
	matches := desktopProxyPathRegex.FindStringSubmatch(proxyPath)
	if matches == nil {
		http.Error(w, fmt.Sprintf("did not understand url: %s", origPath), http.StatusInternalServerError)
		return
	}
	kubeContext, relPath := matches[1], matches[2]

	// Get Kubernetes proxy handler. The handler authenticates against
	// kube-apiserver using whatever credentials the kubeconfig supplies
	// (typically the user's bearer token or client cert), so the
	// aggregation auth path identifies the originating user.
	h, err := p.getOrCreateKubernetesProxyHandler(kubeContext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Rewrite to the cluster-api's APIService path.
	u := *r.URL
	u.Path = path.Join(APIServicePath, relPath)
	r.URL = &u

	// Strip the browser-supplied Origin so the cluster-api can treat its
	// presence as a CSWSH signal. Cross-origin browser upgrades are already
	// rejected by the same-origin gate above; cross-site non-upgrade browser
	// requests are rejected by csrfProtectionMiddleware before reaching here.
	r.Header.Del("Origin")

	// Drop any client-supplied auth headers — kubectl proxy attaches its own
	// based on the kubeconfig, and X-Forwarded-Authorization is no longer
	// honored by the cluster-api.
	r.Header.Del("Authorization")
	r.Header.Del("X-Forwarded-Authorization")

	// Passthrough upgrade requests, closing the hijacked connection on shutdown
	if r.Header.Get("Upgrade") != "" {
		hw := &hijackTrackingResponseWriter{ResponseWriter: w}
		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			select {
			case <-doneCh:
			case <-p.shutdownCh:
				hw.closeConn()
			}
		}()
		h.ServeHTTP(hw, r)
		return
	}

	// Execute
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	// Re-write cookie path
	cookiePath := strings.TrimSuffix(origPath, relPath)
	for k, v := range rec.Header() {
		if k == "Set-Cookie" {
			for _, cookie := range v {
				modifiedCookie := cookiepathRegex.ReplaceAllString(cookie, fmt.Sprintf("Path=%s", cookiePath))
				w.Header().Add("Set-Cookie", modifiedCookie)
			}
		} else {
			w.Header()[k] = v
		}
	}

	// Send result to client
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}

// NotifyShutdown signals active connections to begin closing.
func (p *DesktopProxy) NotifyShutdown() {
	close(p.shutdownCh)
}

// DrainWithContext waits for all active WebSocket connections to finish, respecting ctx.
func (p *DesktopProxy) DrainWithContext(ctx context.Context) error {
	doneCh := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Get or create Kubernetes proxy handler
func (p *DesktopProxy) getOrCreateKubernetesProxyHandler(kubeContext string) (http.Handler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check cache
	h, exists := p.phCache[kubeContext]
	if !exists {
		// Get rest config
		restConfig, err := p.cm.GetOrCreateRestConfig(kubeContext)
		if err != nil {
			return nil, err
		}

		// Create proxy handler
		h, err = proxy.NewProxyHandler("/", nil, restConfig, 0, false)
		if err != nil {
			return nil, err
		}

		// Add to cache
		p.phCache[kubeContext] = h
	}

	return h, nil
}

// Create new DesktopProxy. allowedOrigins is forwarded to the WebSocket
// upgrade origin check (see httphelpers.IsAllowedOrigin).
func NewDesktopProxy(cm k8shelpers.ConnectionManager, pathPrefix string, allowedOrigins []string) (*DesktopProxy, error) {
	return &DesktopProxy{
		cm:             cm,
		pathPrefix:     pathPrefix,
		allowedOrigins: allowedOrigins,
		phCache:        make(map[string]http.Handler),
		shutdownCh:     make(chan struct{}),
	}, nil
}

// Represents InClusterProxy
type InClusterProxy struct {
	*httputil.ReverseProxy
	allowedOrigins []string
	shutdownCh     chan struct{}
	wg             sync.WaitGroup
}

// ServeHTTP wraps the reverse proxy to track active requests for graceful
// shutdown. For upgrade requests the hijacked connection is closed on shutdown.
func (p *InClusterProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.wg.Add(1)
	defer p.wg.Done()

	// CSWSH defense for WebSocket upgrades. Chrome does not send
	// Sec-Fetch-Site on upgrade requests, so the app-level CSRF middleware
	// can't gate them; check Origin directly here instead.
	if r.Header.Get("Upgrade") != "" && !httphelpers.IsAllowedOrigin(r, p.allowedOrigins) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.Header.Get("Upgrade") != "" {
		hw := &hijackTrackingResponseWriter{ResponseWriter: w}
		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			select {
			case <-doneCh:
			case <-p.shutdownCh:
				hw.closeConn()
			}
		}()
		p.ReverseProxy.ServeHTTP(hw, r)
		return
	}

	p.ReverseProxy.ServeHTTP(w, r)
}

// NotifyShutdown signals active connections to begin closing.
func (p *InClusterProxy) NotifyShutdown() {
	close(p.shutdownCh)
}

// DrainWithContext waits for all active WebSocket connections to finish, respecting ctx.
func (p *InClusterProxy) DrainWithContext(ctx context.Context) error {
	doneCh := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// newInClusterProxy creates an InClusterProxy with injectable transport (used in
// tests). The endpoint must point at the kube-apiserver; aggregation forwards
// the request to the cluster-api via the v1.api.kubetail.com APIService.
func newInClusterProxy(kubeAPIServerEndpoint string, pathPrefix string, allowedOrigins []string, transport http.RoundTripper) (*InClusterProxy, error) {
	endpointUrl, err := url.Parse(kubeAPIServerEndpoint)
	if err != nil {
		return nil, err
	}

	// Init reverseProxy
	reverseProxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Rewrite to the cluster-api APIService path on the apiserver.
			rel := strings.TrimPrefix(r.URL.Path, pathPrefix)
			targetUrl := endpointUrl
			targetUrl.Path = path.Join(APIServicePath, rel)
			r.URL = targetUrl

			// Drop client-supplied auth headers so a malicious upstream
			// header can't ride through. Then forward the session user's
			// token as Authorization (kube-apiserver auths the caller as
			// that user; aggregation then attaches front-proxy headers).
			r.Header.Del("Authorization")
			r.Header.Del("X-Forwarded-Authorization")
			if token, ok := r.Context().Value(k8shelpers.K8STokenCtxKey).(string); ok && token != "" {
				r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}

			// Strip the browser-supplied Origin so the cluster-api can treat its
			// presence as a CSWSH signal. Cross-origin browser upgrades are
			// already rejected by the same-origin gate; cross-site non-upgrade
			// browser requests are rejected by csrfProtectionMiddleware before
			// reaching here.
			r.Header.Del("Origin")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Re-write cookie path
			pathArg := fmt.Sprintf("Path=%s", path.Join("/", pathPrefix)+"/")
			cookies := resp.Header["Set-Cookie"]
			for i, cookie := range cookies {
				cookies[i] = cookiepathRegex.ReplaceAllString(cookie, pathArg)
			}
			resp.Header["Set-Cookie"] = cookies

			return nil
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	return &InClusterProxy{
		ReverseProxy:   reverseProxy,
		allowedOrigins: allowedOrigins,
		shutdownCh:     make(chan struct{}),
	}, nil
}

// Create new InClusterProxy. allowedOrigins is forwarded to the WebSocket
// upgrade origin check (see httphelpers.IsAllowedOrigin).
func NewInClusterProxy(clusterAPIEndpoint string, pathPrefix string, allowedOrigins []string) (*InClusterProxy, error) {
	rt, err := k8shelpers.NewInClusterSATRoundTripper(http.DefaultTransport)
	if err != nil {
		return nil, err
	}
	return newInClusterProxy(clusterAPIEndpoint, pathPrefix, allowedOrigins, rt)
}
