// Package token generates and validates signed, time-limited, single-use bootstrap tokens.
//
// Token format — four dot-separated fields:
//
//	<unix_expiry>.<nonce_hex>.<username_b64url>.<hmac_sha256_hex>
//
// The HMAC covers the first three fields joined by dots, so tampering with
// any field (including the username) is detected.  NonceStore enforces
// single-use: each nonce may be consumed exactly once during its validity window.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Claims holds the decoded, verified fields from a bootstrap token.
type Claims struct {
	Expiry   int64  // unix timestamp
	Nonce    string // hex-encoded random bytes (single-use key)
	Username string // username the token was issued for
}

// Generate creates a token for username that expires after duration.
func Generate(cookieSecret, username string, duration time.Duration) string {
	expiry := strconv.FormatInt(time.Now().Add(duration).Unix(), 10)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("token: crypto/rand unavailable: " + err.Error())
	}
	nonceHex := hex.EncodeToString(nonce)
	userB64 := base64.RawURLEncoding.EncodeToString([]byte(username))

	mac := sign(cookieSecret, expiry+"."+nonceHex+"."+userB64)
	return expiry + "." + nonceHex + "." + userB64 + "." + mac
}

// Parse decodes and verifies a token's signature and expiry, returning its claims.
// It does NOT enforce single-use — call NonceStore.Consume after a successful Parse.
func Parse(cookieSecret, tok string) (Claims, error) {
	parts := strings.SplitN(tok, ".", 4)
	if len(parts) != 4 {
		return Claims{}, fmt.Errorf("malformed bootstrap token")
	}
	expiry, nonceHex, userB64, mac := parts[0], parts[1], parts[2], parts[3]

	ts, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return Claims{}, fmt.Errorf("malformed bootstrap token")
	}
	if time.Now().Unix() > ts {
		return Claims{}, fmt.Errorf("bootstrap token has expired")
	}

	expected := sign(cookieSecret, expiry+"."+nonceHex+"."+userB64)
	if !hmac.Equal([]byte(mac), []byte(expected)) {
		return Claims{}, fmt.Errorf("invalid bootstrap token signature")
	}

	usernameBytes, err := base64.RawURLEncoding.DecodeString(userB64)
	if err != nil {
		return Claims{}, fmt.Errorf("malformed bootstrap token")
	}

	return Claims{
		Expiry:   ts,
		Nonce:    nonceHex,
		Username: string(usernameBytes),
	}, nil
}

func sign(secret, data string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// NonceStore enforces single-use on bootstrap tokens.
// Each nonce may be Consume'd exactly once within its validity window.
// Safe for concurrent use.
type NonceStore struct {
	mu   sync.Mutex
	used map[string]int64 // nonce → expiry unix
}

// NewNonceStore returns a ready-to-use NonceStore.
func NewNonceStore() *NonceStore {
	return &NonceStore{used: make(map[string]int64)}
}

// Consume atomically marks the nonce as used.
// Returns an error if the nonce was already consumed (replay attack) or the
// token has expired.  Expired entries are pruned on each call to bound memory.
func (ns *NonceStore) Consume(nonce string, expiry int64) error {
	now := time.Now().Unix()

	ns.mu.Lock()
	defer ns.mu.Unlock()

	for n, exp := range ns.used {
		if now > exp {
			delete(ns.used, n)
		}
	}

	if _, seen := ns.used[nonce]; seen {
		return fmt.Errorf("bootstrap token already used")
	}
	if now > expiry {
		return fmt.Errorf("bootstrap token has expired")
	}

	ns.used[nonce] = expiry
	return nil
}
