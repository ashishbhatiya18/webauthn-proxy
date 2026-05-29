// Package server wires together configuration, handlers, and the HTTP router.
package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"webauthn-proxy/internal/config"
	"webauthn-proxy/internal/handler"
	"webauthn-proxy/internal/middleware"
	"webauthn-proxy/internal/session"
	"webauthn-proxy/internal/store"
	"webauthn-proxy/internal/token"
	webfiles "webauthn-proxy/web"
)

func New(cfg *config.Config) (http.Handler, error) {
	// ── WebAuthn core ─────────────────────────────────────────────────────────
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPId,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	// ── User store ────────────────────────────────────────────────────────────
	us, err := store.New(cfg.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("store init: %w", err)
	}

	// ── Session manager ───────────────────────────────────────────────────────
	sameSite := parseSameSite(cfg.CookieSameSite)
	maxAge := int(cfg.CookieExpire.Seconds())
	sess := session.NewManager(
		cfg.CookieSecret,
		cfg.CookieName,
		cfg.CookieDomain,
		cfg.CookieSecure,
		cfg.CookieHTTPOnly,
		sameSite,
		maxAge,
	)

	// ── Bootstrap nonce store ─────────────────────────────────────────────────
	nonceStore := token.NewNonceStore()

	// ── Templates ─────────────────────────────────────────────────────────────
	tmpl, err := template.ParseFS(webfiles.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	// ── Handlers ──────────────────────────────────────────────────────────────
	authH := handler.NewAuthHandler(sess, tmpl, cfg.WhitelistDomains, cfg.ProxyURL)
	wanH := handler.NewWebAuthnHandler(
		wa, us, sess, tmpl,
		cfg.CookieSecret,
		nonceStore,
		cfg.AllowRegistration,
		cfg.RegistrationToken,
		cfg.WhitelistDomains,
		protocol.AuthenticatorAttachment(cfg.AuthenticatorAttachment),
	)

	// ── Rate limiter (optional) ───────────────────────────────────────────────
	var rateLimiter *middleware.IPRateLimiter
	if cfg.RateLimitRPS > 0 {
		rateLimiter = middleware.NewIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	}

	// withLimit wraps h with per-IP rate limiting when the limiter is enabled.
	withLimit := func(h http.HandlerFunc) http.Handler {
		if rateLimiter == nil {
			return h
		}
		return rateLimiter.Limit(h)
	}

	// ── Router ────────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Forward-auth endpoint — called by Traefik for every proxied request.
	// Not rate-limited: callers are internal Traefik instances, not end users.
	mux.HandleFunc("GET /_webauthn/auth", authH.ForwardAuth)

	// Login / logout / register pages
	mux.HandleFunc("GET /_webauthn/login", authH.Login)
	mux.HandleFunc("GET /_webauthn/logout", authH.Logout)
	mux.HandleFunc("GET /_webauthn/register", wanH.RegisterPage)

	// WebAuthn JSON API — rate-limited (C-2).
	mux.Handle("POST /_webauthn/api/register/begin", withLimit(wanH.RegisterBegin))
	mux.Handle("POST /_webauthn/api/register/finish", withLimit(wanH.RegisterFinish))
	mux.Handle("POST /_webauthn/api/authenticate/begin", withLimit(wanH.AuthBegin))
	mux.Handle("POST /_webauthn/api/authenticate/finish", withLimit(wanH.AuthFinish))

	// Credential management (requires authenticated session).
	mux.Handle("DELETE /_webauthn/api/credentials/{id}", withLimit(wanH.DeleteCredential))

	// Root — 200 if authenticated, redirect to login otherwise.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s := sess.Get(r)
		if s.Authenticated {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "logged in as %s", s.Username)
			return
		}
		http.Redirect(w, r, "/_webauthn/login", http.StatusFound)
	})

	// Health check
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Wrap the entire mux with defensive security headers (H-4).
	return middleware.SecureHeaders(mux), nil
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
