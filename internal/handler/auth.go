// Package handler contains HTTP handlers for forward-auth and WebAuthn flows.
package handler

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"webauthn-proxy/internal/session"
)

// AuthHandler handles the Traefik forward-auth endpoint and the login/logout pages.
type AuthHandler struct {
	sessions         *session.Manager
	tmpl             *template.Template
	whitelistDomains []string
	proxyURL         string
}

func NewAuthHandler(sessions *session.Manager, tmpl *template.Template, whitelistDomains []string, proxyURL string) *AuthHandler {
	return &AuthHandler{
		sessions:         sessions,
		tmpl:             tmpl,
		whitelistDomains: whitelistDomains,
		proxyURL:         strings.TrimRight(proxyURL, "/"),
	}
}

// ForwardAuth is called by Traefik's forwardAuth middleware.
// Returns 200 (with X-Webauthn-User header) when the session is valid,
// or 302 to the login page otherwise.
// Every call is audit-logged to stdout.
func (h *AuthHandler) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.Get(r)

	src := r.Header.Get("X-Forwarded-For")
	if src == "" {
		src = r.RemoteAddr
	}
	method := r.Header.Get("X-Forwarded-Method")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")

	if sess.Authenticated {
		slog.Info("forward-auth allowed",
			"user", sess.Username,
			"src", src,
			"method", method,
			"host", host,
			"uri", uri,
		)
		w.Header().Set("X-Webauthn-User", sess.Username)
		w.WriteHeader(http.StatusOK)
		return
	}

	slog.Info("forward-auth denied",
		"src", src,
		"method", method,
		"host", host,
		"uri", uri,
	)

	rd := buildOriginalURL(r)

	base := h.proxyURL
	if base == "" {
		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
		if proto != "" && host != "" {
			base = proto + "://" + host
		}
	}
	loginURL := base + "/_webauthn/login"
	if rd != "" {
		loginURL += "?rd=" + url.QueryEscape(rd)
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// Login renders the login page, or redirects immediately if already authenticated.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.Get(r)
	if sess.Authenticated {
		http.Redirect(w, r, safeRedirect(r.URL.Query().Get("rd"), h.whitelistDomains), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl.ExecuteTemplate(w, "login.html", nil)
}

// Logout clears the session and redirects to the login page.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.sessions.Clear(w)
	http.Redirect(w, r, "/_webauthn/login", http.StatusFound)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildOriginalURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if proto == "" || host == "" {
		return ""
	}
	if uri == "" {
		uri = "/"
	}
	return proto + "://" + host + uri
}

// safeRedirect validates rd against the whitelist and falls back to "/" on
// open-redirect attempts.  Mirrors oauth2-proxy's --whitelist-domain logic.
//
// Fail-closed: absolute URLs are only allowed when the whitelist is non-empty
// and the target host matches.  An empty whitelist does NOT mean "allow all" —
// it means no absolute redirects are permitted.  Configure --whitelist-domain
// to allow cross-origin post-login redirects.
func safeRedirect(rd string, whitelist []string) string {
	if rd == "" {
		return "/"
	}
	// Relative paths (not protocol-relative) are always safe.
	if strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") {
		return rd
	}
	u, err := url.Parse(rd)
	if err != nil {
		return "/"
	}
	if len(whitelist) == 0 {
		// No whitelist → refuse absolute redirects (fail closed).
		return "/"
	}
	host := u.Hostname()
	for _, domain := range whitelist {
		d := strings.TrimPrefix(domain, ".")
		if host == d || strings.HasSuffix(host, "."+d) {
			return rd
		}
	}
	return "/"
}
