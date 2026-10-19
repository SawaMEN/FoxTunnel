package tunnel

import (
	"context"
	"errors"
	"net/http"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Access == nil {
		s.serveHTTP(w, r)
		return
	}
	settings, err := xhttp.Normalize(s.XHTTPSettings.Path, s.XHTTPSettings.Host)
	candidate := r.Method == http.MethodConnect || (r.Method == http.MethodPost && (r.URL.Path == postPath || r.URL.Path == bond.Path)) || (r.Method == http.MethodGet && (r.URL.Path == wsPath || r.URL.Path == cluster.Path)) || (err == nil && xhttp.MatchesAt(r, settings))
	if !candidate {
		s.cover(w, r)
		return
	}
	ctx, done, err := s.Access.Begin(r)
	if err != nil {
		if errors.Is(err, access.ErrLimited) || errors.Is(err, access.ErrQuota) {
			http.Error(w, "access limit reached", http.StatusTooManyRequests)
		} else {
			s.cover(w, r)
		}
		return
	}
	defer done()
	r = r.WithContext(ctx)
	stop := context.AfterFunc(ctx, func() {
		if r.Body != nil {
			r.Body.Close()
		}
	})
	defer stop()
	s.serveHTTP(w, r)
}
func (s *Server) cover(w http.ResponseWriter, r *http.Request) {
	if s.Cover == nil {
		http.NotFound(w, r)
		return
	}
	public := r.Clone(r.Context())
	public.Header.Del("Proxy-Authorization")
	public.Header.Del(paddingHeader)
	public.Header.Del(targetHeader)
	s.Cover.ServeHTTP(w, public)
}
