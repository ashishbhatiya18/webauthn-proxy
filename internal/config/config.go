// Package config loads proxy configuration from flags and environment variables.
// Flag names mirror oauth2-proxy conventions where applicable.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// AuthenticatorAttachment controls which authenticator types are accepted at registration.
type AuthenticatorAttachment string

const (
	AttachmentAny      AuthenticatorAttachment = ""               // any authenticator
	AttachmentPlatform AuthenticatorAttachment = "platform"       // built-in fingerprint/face
	AttachmentCross    AuthenticatorAttachment = "cross-platform" // security key
)

type Config struct {
	// Server
	HTTPAddress string

	// Cookie — same names as oauth2-proxy
	CookieSecret   string
	CookieName     string
	CookieDomain   string
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite string // lax | strict | none

	// ProxyURL is the public base URL of this proxy (scheme://host[:port]).
	ProxyURL string

	// Upstream redirect
	RedirectURL      string
	WhitelistDomains []string // required for absolute post-login redirects

	// WebAuthn relying party
	RPId                    string
	RPDisplayName           string
	RPOrigins               []string
	AuthenticatorAttachment AuthenticatorAttachment

	// Storage
	UsersFile string

	// Features
	AllowRegistration bool
	RegistrationToken string

	// Rate limiting (applied per client IP to the WebAuthn API endpoints).
	// RateLimitRPS=0 disables rate limiting.
	RateLimitRPS   float64
	RateLimitBurst int
}

func Load() (*Config, error) {
	cfg := &Config{}

	var (
		origins          string
		whitelistDomains string
		attachment       string
	)

	// ── Server ────────────────────────────────────────────────────────────────
	flag.StringVar(&cfg.HTTPAddress, "http-address", env("HTTP_ADDRESS", ":4180"),
		"[HOST]:PORT to listen on")

	// ── Cookie (oauth2-proxy naming) ──────────────────────────────────────────
	flag.StringVar(&cfg.CookieSecret, "cookie-secret", env("COOKIE_SECRET", ""),
		"Seed string for secure cookies (min 32 bytes)")
	flag.StringVar(&cfg.CookieName, "cookie-name", env("COOKIE_NAME", "_webauthn_proxy"),
		"Name of the session cookie")
	flag.StringVar(&cfg.CookieDomain, "cookie-domain", env("COOKIE_DOMAIN", ""),
		"Optional domain for the session cookie")
	flag.DurationVar(&cfg.CookieExpire, "cookie-expire",
		envDuration("COOKIE_EXPIRE", 168*time.Hour),
		"Session cookie expiry (env: COOKIE_EXPIRE, default 7d)")
	flag.DurationVar(&cfg.CookieRefresh, "cookie-refresh",
		envDuration("COOKIE_REFRESH", 0),
		"Refresh the cookie after this duration (env: COOKIE_REFRESH, 0 = disabled)")
	flag.BoolVar(&cfg.CookieSecure, "cookie-secure", envBool("COOKIE_SECURE", true),
		"Set Secure flag on the session cookie")
	flag.BoolVar(&cfg.CookieHTTPOnly, "cookie-httponly", true,
		"Set HttpOnly flag on the session cookie")
	flag.StringVar(&cfg.CookieSameSite, "cookie-samesite", "lax",
		"SameSite attribute: lax | strict | none")

	// ── Proxy self-URL ────────────────────────────────────────────────────────
	flag.StringVar(&cfg.ProxyURL, "proxy-url", env("PROXY_URL", ""),
		"Public base URL of this proxy (e.g. http://localhost:8000)")

	// ── Redirect / allow-list ─────────────────────────────────────────────────
	flag.StringVar(&cfg.RedirectURL, "redirect-url", env("REDIRECT_URL", ""),
		"After-login redirect URL (defaults to the original request URL)")
	flag.StringVar(&whitelistDomains, "whitelist-domain", env("WHITELIST_DOMAIN", ""),
		"Comma-separated domains valid as absolute redirect targets (required for cross-origin redirects)")

	// ── WebAuthn ──────────────────────────────────────────────────────────────
	flag.StringVar(&cfg.RPId, "rp-id", env("RP_ID", "localhost"),
		"WebAuthn Relying Party ID")
	flag.StringVar(&cfg.RPDisplayName, "rp-display-name", env("RP_DISPLAY_NAME", "WebAuthn Proxy"),
		"Human-readable Relying Party name shown in browser prompts")
	flag.StringVar(&origins, "rp-origins", env("RP_ORIGINS", "http://localhost:4180"),
		"Comma-separated allowed WebAuthn origins (scheme://host[:port])")
	flag.StringVar(&attachment, "authenticator-attachment", env("AUTHENTICATOR_ATTACHMENT", ""),
		"Restrict authenticator type: '' (any) | 'platform' (fingerprint/face) | 'cross-platform' (security key)")

	// ── Storage ───────────────────────────────────────────────────────────────
	flag.StringVar(&cfg.UsersFile, "users-file", env("USERS_FILE", "/data/users.json"),
		"Path to the JSON file that persists registered users and credentials")

	// ── Features ──────────────────────────────────────────────────────────────
	flag.BoolVar(&cfg.AllowRegistration, "allow-registration", envBool("ALLOW_REGISTRATION", false),
		"Allow new usernames to be created via the web UI (requires --registration-token)")
	flag.StringVar(&cfg.RegistrationToken, "registration-token", env("REGISTRATION_TOKEN", ""),
		"Required when --allow-registration is true; gate token for web-based registration")

	// ── Rate limiting ─────────────────────────────────────────────────────────
	flag.Float64Var(&cfg.RateLimitRPS, "rate-limit-rps",
		envFloat("RATE_LIMIT_RPS", 5),
		"Max WebAuthn API requests per second per IP (env: RATE_LIMIT_RPS, 0 = disabled)")
	flag.IntVar(&cfg.RateLimitBurst, "rate-limit-burst",
		envInt("RATE_LIMIT_BURST", 10),
		"Burst allowance for rate limiting (env: RATE_LIMIT_BURST)")

	flag.Parse()

	// ── Validation ────────────────────────────────────────────────────────────
	if cfg.CookieSecret == "" {
		return nil, fmt.Errorf("--cookie-secret is required (min 32 bytes)")
	}
	if len(cfg.CookieSecret) < 32 {
		return nil, fmt.Errorf("--cookie-secret must be at least 32 characters")
	}
	if cfg.AllowRegistration && cfg.RegistrationToken == "" {
		return nil, fmt.Errorf(
			"--allow-registration requires --registration-token; " +
				"set a strong random secret to gate web-based registrations")
	}

	cfg.RPOrigins = splitTrimmed(origins)
	cfg.WhitelistDomains = splitTrimmed(whitelistDomains)
	cfg.AuthenticatorAttachment = AuthenticatorAttachment(attachment)

	return cfg, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
			return f
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i
		}
	}
	return fallback
}

func splitTrimmed(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
