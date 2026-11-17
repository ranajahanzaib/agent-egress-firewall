package routing

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/config"
)

type Route struct {
	ID          string
	PathPrefix  string
	Methods     []string
	Upstream    *url.URL
	StripPrefix bool
	Policy      string
	Headers     []string
	QueryParams []string
}

type Router struct {
	routes []*Route
}

func NewRouter(routeConfigs []config.RouteConfig) (*Router, error) {
	var routes []*Route
	for _, rc := range routeConfigs {
		u, err := url.Parse(rc.Upstream)
		if err != nil {
			return nil, fmt.Errorf("parsing upstream URL for route '%s': %w", rc.ID, err)
		}

		routes = append(routes, &Route{
			ID:          rc.ID,
			PathPrefix:  rc.Match.PathPrefix,
			Methods:     rc.Match.Methods,
			Upstream:    u,
			StripPrefix: rc.StripPrefix,
			Policy:      rc.Policy,
			Headers:     rc.Headers,
			QueryParams: rc.QueryParams,
		})
	}
	return &Router{routes: routes}, nil
}

// Match finds the route matching the request path.
// When multiple path prefixes match, the longest prefix takes precedence.
func (r *Router) Match(req *http.Request) (*Route, error) {
	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	var bestRoute *Route
	for _, route := range r.routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			// Check HTTP method if route specifies methods
			if len(route.Methods) > 0 {
				methodMatches := false
				for _, m := range route.Methods {
					if strings.EqualFold(req.Method, m) {
						methodMatches = true
						break
					}
				}
				if !methodMatches {
					continue
				}
			}

			if bestRoute == nil || len(route.PathPrefix) > len(bestRoute.PathPrefix) {
				bestRoute = route
			}
		}
	}

	if bestRoute == nil {
		return nil, fmt.Errorf("no configured route matches path '%s' (open-proxy blocked)", path)
	}

	return bestRoute, nil
}

// RewriteRequest rewrites the outbound request to target the upstream destination safely.
func (r *Route) RewriteRequest(req *http.Request) {
	target := r.Upstream
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	reqPath := req.URL.Path
	if r.StripPrefix && strings.HasPrefix(reqPath, r.PathPrefix) {
		reqPath = strings.TrimPrefix(reqPath, r.PathPrefix)
		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}
	}

	// Join upstream path prefix with request path
	if target.Path != "" && target.Path != "/" {
		req.URL.Path = singleJoiningSlash(target.Path, reqPath)
	} else {
		req.URL.Path = reqPath
	}

	// Hop-by-hop headers to strip
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopByHopHeaders {
		req.Header.Del(h)
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
