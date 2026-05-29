package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"webauthn-proxy/internal/config"
	"webauthn-proxy/internal/server"
	"webauthn-proxy/internal/store"
	"webauthn-proxy/internal/token"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "create-user":
			runCreateUser(os.Args[2:])
			return
		case "bootstrap-token":
			runBootstrapToken(os.Args[2:])
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}
	runServe()
}

// runServe is the default (no-subcommand) path: start the proxy.
func runServe() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}
	h, err := server.New(cfg)
	if err != nil {
		slog.Error("server init error", "err", err)
		os.Exit(1)
	}

	// H-7: explicit timeouts prevent slow-loris and resource-exhaustion attacks.
	srv := &http.Server{
		Addr:         cfg.HTTPAddress,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("webauthn-proxy started", "addr", cfg.HTTPAddress)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// runCreateUser pre-creates a user entry (no credentials) in the store.
//
//	webauthn-proxy create-user --users-file /data/users.json --username alice [--display-name "Alice Smith"]
func runCreateUser(args []string) {
	fs := flag.NewFlagSet("create-user", flag.ExitOnError)
	usersFile := fs.String("users-file", "/data/users.json", "Path to users JSON file")
	username := fs.String("username", "", "Username to create (required)")
	displayName := fs.String("display-name", "", "Display name (defaults to username)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *username == "" {
		fmt.Fprintln(os.Stderr, "error: --username is required")
		fs.Usage()
		os.Exit(1)
	}
	if *displayName == "" {
		*displayName = *username
	}

	s, err := store.New(*usersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening store: %v\n", err)
		os.Exit(1)
	}
	u, err := s.CreateUser(*username, *displayName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("User %q created (id=%x).\n", u.Name, u.ID)
	fmt.Println("Register their WebAuthn credential via the web UI to complete setup.")
}

// runBootstrapToken generates a signed, time-limited, single-use registration URL
// bound to a specific username.  The token encodes the username so the
// registration form is pre-filled and locked.
//
//	webauthn-proxy bootstrap-token --cookie-secret $COOKIE_SECRET --username alice [--duration 15m] [--proxy-url http://localhost:8000]
func runBootstrapToken(args []string) {
	fs := flag.NewFlagSet("bootstrap-token", flag.ExitOnError)
	cookieSecret := fs.String("cookie-secret", os.Getenv("COOKIE_SECRET"), "Cookie secret (must match the running proxy)")
	usersFile := fs.String("users-file", envOr("USERS_FILE", "/data/users.json"), "Path to users JSON file")
	username := fs.String("username", "", "Username to bind the token to (required)")
	duration := fs.Duration("duration", 15*time.Minute, "How long the URL is valid")
	proxyURL := fs.String("proxy-url", envOr("PROXY_URL", "http://localhost:8000"), "Public base URL of the proxy")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *cookieSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --cookie-secret is required (or set COOKIE_SECRET)")
		fs.Usage()
		os.Exit(1)
	}
	if len(*cookieSecret) < 32 {
		fmt.Fprintln(os.Stderr, "error: --cookie-secret must be at least 32 characters")
		os.Exit(1)
	}
	if *username == "" {
		fmt.Fprintln(os.Stderr, "error: --username is required; the token is bound to a specific user")
		fs.Usage()
		os.Exit(1)
	}

	// Refuse if the store already has credentials — bootstrap is for initial setup only.
	s, err := store.New(*usersFile)
	if err == nil && s.HasAnyCredentials() {
		fmt.Fprintln(os.Stderr, "error: the store already contains credentials — the proxy is initialised.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "To add another device, sign in and visit /_webauthn/register.")
		fmt.Fprintln(os.Stderr, "bootstrap-token is only valid before the first credential is registered.")
		os.Exit(1)
	}

	// C-1 fix: token encodes username and includes a random nonce for single-use enforcement.
	tok := token.Generate(*cookieSecret, *username, *duration)
	fmt.Printf("\nBootstrap registration URL for user %q (valid for %s):\n\n  %s/_webauthn/register?bst=%s\n\n",
		*username, *duration, *proxyURL, tok)
	fmt.Println("Open this URL in a browser and tap your fingerprint to register the first passkey.")
	fmt.Println("The URL is single-use and expires — run this command again if it times out or is replayed.")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printUsage() {
	fmt.Println(`webauthn-proxy — WebAuthn forward-auth proxy for Traefik

USAGE
  webauthn-proxy [flags]                   Start the proxy server
  webauthn-proxy create-user [flags]       Pre-create a user (no credentials)
  webauthn-proxy bootstrap-token [flags]   Generate a first-passkey URL (pre-init only)

SUBCOMMANDS
  create-user
    Create a user entry without credentials. Run offline before first start.
    --users-file    path to users.json  (default /data/users.json)
    --username      username (required)
    --display-name  human-readable name

  bootstrap-token
    Generate a signed, time-limited, single-use URL to register the first passkey.
    The token is bound to --username; the registration form locks to that user.
    Exits with an error if the store already contains credentials.
    --cookie-secret  shared secret (required, or COOKIE_SECRET env var)
    --users-file     path to users.json  (default /data/users.json)
    --username       username to bind the token to (required)
    --proxy-url      public base URL    (default http://localhost:8000)
    --duration       token validity     (default 15m)

KEY ENVIRONMENT VARIABLES (serve mode)
  COOKIE_SECRET        32+ char random secret (required)
  COOKIE_EXPIRE        session TTL, e.g. 24h, 168h (default 168h)
  COOKIE_REFRESH       re-issue cookie after this duration (default 0 = off)
  RATE_LIMIT_RPS       WebAuthn API requests/sec per IP (default 5, 0 = off)
  RATE_LIMIT_BURST     burst allowance (default 10)

  Run 'webauthn-proxy --help' for all server flags.`)
}
