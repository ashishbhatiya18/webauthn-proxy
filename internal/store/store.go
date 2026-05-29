// Package store persists registered WebAuthn users and their credentials in a
// JSON file.  All public methods are safe for concurrent use.
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// validUsername restricts usernames to a safe character set and bounded length.
// Enforced at creation time to prevent log injection and header injection downstream.
var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._@-]{1,64}$`)

// NamedCredential wraps a WebAuthn credential with a human-readable label so
// users can tell their registered devices apart (e.g. "MacBook Touch ID").
type NamedCredential struct {
	Name       string              `json:"name"`
	Credential webauthn.Credential `json:"credential"`
}

// User satisfies webauthn.User and is JSON-serialisable.
type User struct {
	ID          []byte            `json:"id"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Credentials []NamedCredential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte          { return u.ID }
func (u *User) WebAuthnName() string        { return u.Name }
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }
func (u *User) WebAuthnIcon() string        { return "" } // deprecated but required by v0.10.x
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Credentials))
	for i, nc := range u.Credentials {
		out[i] = nc.Credential
	}
	return out
}

// Store is a thread-safe, JSON-file-backed user store.
type Store struct {
	mu    sync.RWMutex
	users map[string]*User // keyed by username
	path  string
}

func New(path string) (*Store, error) {
	s := &Store{
		users: make(map[string]*User),
		path:  path,
	}
	return s, s.load()
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading users file %s: %w", s.path, err)
	}
	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("parsing users file: %w", err)
	}
	for _, u := range users {
		s.users[u.Name] = u
	}
	return nil
}

// save must be called with s.mu held (write lock).
// Uses an atomic write (temp file + fsync + rename) to prevent partial writes
// from corrupting the credential counter — a lost counter update would allow
// a cloned authenticator to authenticate with a replayed counter value.
func (s *Store) save() error {
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".users-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	// fsync before rename so a crash after rename still yields a complete file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// GetUser returns a shallow copy of the user, or false if not found.
func (s *Store) GetUser(name string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// GetUserByHandle looks up a user by their WebAuthn user handle (== User.ID).
func (s *Store) GetUserByHandle(handle []byte) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if bytes.Equal(u.ID, handle) {
			cp := *u
			return &cp, true
		}
	}
	return nil, false
}

// CreateUser creates a new user, returning an error if the username already
// exists or fails the character-set/length validation.
func (s *Store) CreateUser(name, displayName string) (*User, error) {
	if !validUsername.MatchString(name) {
		return nil, fmt.Errorf("username must be 1-64 characters: letters, digits, and . _ @ - only")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; exists {
		return nil, fmt.Errorf("user %q already exists", name)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	u := &User{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: []NamedCredential{},
	}
	s.users[name] = u
	if err := s.save(); err != nil {
		delete(s.users, name)
		return nil, err
	}
	return u, nil
}

// HasAnyCredentials returns true if at least one user has at least one registered
// credential.  Used to detect the zero-credential bootstrap state.
func (s *Store) HasAnyCredentials() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if len(u.Credentials) > 0 {
			return true
		}
	}
	return false
}

// CredentialCount returns the number of registered credentials for a user.
func (s *Store) CredentialCount(username string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return 0, false
	}
	return len(u.Credentials), true
}

// CredentialIDs returns the IDs of all credentials registered for a user,
// as hex strings, so the UI can display them without exposing raw bytes.
func (s *Store) CredentialIDs(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	ids := make([]string, len(u.Credentials))
	for i, nc := range u.Credentials {
		ids[i] = fmt.Sprintf("%x", nc.Credential.ID)
	}
	return ids
}

// CredentialNames returns the human-readable labels for all credentials of a
// user, in the same order as CredentialIDs.
func (s *Store) CredentialNames(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	names := make([]string, len(u.Credentials))
	for i, nc := range u.Credentials {
		names[i] = nc.Name
	}
	return names
}

// CredentialName returns the human-readable label for a single credential
// identified by its hex-encoded ID.  Returns "" if not found.
// Acquires a single read lock, avoiding the race between CredentialIDs and
// CredentialNames when used together in auth audit logging.
func (s *Store) CredentialName(username, credIDHex string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return ""
	}
	for _, nc := range u.Credentials {
		if fmt.Sprintf("%x", nc.Credential.ID) == credIDHex {
			return nc.Name
		}
	}
	return ""
}

// SaveCredential upserts a credential for the given user (matched by credential ID).
// name labels the passkey (e.g. "MacBook Touch ID"); pass "" on auth counter
// updates to preserve the existing name.
func (s *Store) SaveCredential(username, name string, cred webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}
	for i, nc := range u.Credentials {
		if bytes.Equal(nc.Credential.ID, cred.ID) {
			kept := nc.Name
			if name != "" {
				kept = name
			}
			u.Credentials[i] = NamedCredential{Name: kept, Credential: cred}
			return s.save()
		}
	}
	if name == "" {
		name = "unnamed device"
	}
	u.Credentials = append(u.Credentials, NamedCredential{Name: name, Credential: cred})
	return s.save()
}

// DeleteCredential removes the credential identified by credIDHex from the
// user's account.  Returns an error if the user or credential is not found.
// The caller must ensure at least one other credential remains; this method
// does not enforce that invariant.
func (s *Store) DeleteCredential(username, credIDHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}
	for i, nc := range u.Credentials {
		if fmt.Sprintf("%x", nc.Credential.ID) == credIDHex {
			u.Credentials = append(u.Credentials[:i], u.Credentials[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("credential not found")
}
