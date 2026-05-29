// Package middleware provides HTTP middleware for the webauthn-proxy.
package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter enforces a per-client-IP token-bucket rate limit.
type IPRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientEntry
	rps     rate.Limit
	burst   int
}

// NewIPRateLimiter returns a limiter allowing rps requests/second (burst size
// burst) per unique client IP.  Stale entries are pruned every 5 minutes.
func NewIPRateLimiter(rps float64, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		clients: make(map[string]*clientEntry),
		rps:     rate.Limit(rps),
		burst:   burst,
	}
	go rl.prune()
	return rl
}

func (rl *IPRateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.clients[ip]
	if !ok {
		e = &clientEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.clients[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter
}

func (rl *IPRateLimiter) prune() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		for ip, e := range rl.clients {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit wraps h, returning 429 when the per-IP token bucket is exhausted.
func (rl *IPRateLimiter) Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.get(clientIP(r)).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP from X-Forwarded-For (set by Traefik)
// or falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// X-Forwarded-For may be a comma-separated chain; leftmost is the client.
		if i := strings.IndexByte(fwd, ','); i != -1 {
			fwd = fwd[:i]
		}
		if ip := strings.TrimSpace(fwd); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
