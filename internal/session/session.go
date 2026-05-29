// Package session manages encrypted, signed session cookies using
// gorilla/securecookie with JSON serialisation.
package session

import (
	"crypto/sha256"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/hkdf"
)

// Data is the full content of a session cookie.
type Data struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	// RedirectURL is the destination after a successful login (the "rd" param).
	RedirectURL string `json:"rd,omitempty"`
	// WANSession holds JSON-encoded webauthn.SessionData during an in-flight
	// registration or authentication ceremony.
	WANSession string `json:"wan,omitempty"`
	// DeviceName is the human-readable label the user gave to the passkey being
	// registered, carried from register/begin to register/finish.
	DeviceName string `json:"device_name,omitempty"`
}

// Manager encodes/decodes session cookies.
type Manager struct {
	codec      *securecookie.SecureCookie
	cookieName string
	domain     string
	secure     bool
	httpOnly   bool
	sameSite   http.SameSite
	maxAge     int // seconds
}

func NewManager(secret, cookieName, domain string, secure, httpOnly bool, sameSite http.SameSite, maxAge int) *Manager {
	// Derive independent hash and encryption keys from the shared secret using
	// HKDF-SHA256 with distinct info strings.  Using raw SHA-256 (previous
	// approach) provided no domain separation: both keys were recoverable from
	// the same input, and SHA-256 is not a proper KDF.
	//
	// NOTE: changing this derivation invalidates all existing session cookies;
	// all users will be prompted to re-authenticate once after an upgrade.
	hashKey := derive(secret, "webauthn-proxy:hash-key")
	blockKey := derive(secret, "webauthn-proxy:block-key")

	codec := securecookie.New(hashKey, blockKey)
	codec.SetSerializer(securecookie.JSONEncoder{})
	codec.MaxAge(maxAge)

	return &Manager{
		codec:      codec,
		cookieName: cookieName,
		domain:     domain,
		secure:     secure,
		httpOnly:   httpOnly,
		sameSite:   sameSite,
		maxAge:     maxAge,
	}
}

// derive produces a 32-byte key from secret using HKDF-SHA256 with info as
// domain-separation label.
func derive(secret, info string) []byte {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic("session: HKDF read failed: " + err.Error())
	}
	return key
}

// Get decodes the session cookie from the request.  Returns an empty Data on
// any error (missing cookie, tampered value, expired).
func (m *Manager) Get(r *http.Request) *Data {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return &Data{}
	}
	var data Data
	if err := m.codec.Decode(m.cookieName, cookie.Value, &data); err != nil {
		return &Data{}
	}
	return &data
}

// Save encodes and sets the session cookie on the response.
func (m *Manager) Save(w http.ResponseWriter, data *Data) error {
	encoded, err := m.codec.Encode(m.cookieName, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   m.domain,
		MaxAge:   m.maxAge,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
	})
	return nil
}

// Clear expires the session cookie immediately.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   m.domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: m.httpOnly,
	})
}
