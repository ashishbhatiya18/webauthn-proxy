package handler

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"webauthn-proxy/internal/session"
	"webauthn-proxy/internal/store"
	"webauthn-proxy/internal/token"
)

// maxBodyBytes caps all API request bodies to prevent memory-exhaustion DoS.
const maxBodyBytes = 64 * 1024

// validUsernameRE mirrors store.validUsername for belt-and-suspenders validation
// at the handler boundary before any store interaction.
var validUsernameRE = regexp.MustCompile(`^[a-zA-Z0-9._@-]{1,64}$`)

// WebAuthnHandler handles the WebAuthn registration and authentication ceremonies.
type WebAuthnHandler struct {
	wa                *webauthn.WebAuthn
	store             *store.Store
	sessions          *session.Manager
	tmpl              *template.Template
	cookieSecret      string
	nonceStore        *token.NonceStore
	allowReg          bool
	registrationToken string
	whitelistDomains  []string
	attachment        protocol.AuthenticatorAttachment
}

func NewWebAuthnHandler(
	wa *webauthn.WebAuthn,
	s *store.Store,
	sess *session.Manager,
	tmpl *template.Template,
	cookieSecret string,
	nonceStore *token.NonceStore,
	allowReg bool,
	registrationToken string,
	whitelistDomains []string,
	attachment protocol.AuthenticatorAttachment,
) *WebAuthnHandler {
	return &WebAuthnHandler{
		wa:                wa,
		store:             s,
		sessions:          sess,
		tmpl:              tmpl,
		cookieSecret:      cookieSecret,
		nonceStore:        nonceStore,
		allowReg:          allowReg,
		registrationToken: registrationToken,
		whitelistDomains:  whitelistDomains,
		attachment:        attachment,
	}
}

// RegisterPage serves the registration UI.
//
// Access tiers (checked in order):
//  1. Authenticated session → allowed (adding a device to own account).
//  2. Valid CLI bootstrap token (?bst=) → allowed (first-passkey setup).
//     The token encodes the username; the field is locked in the form.
//  3. allowReg=true + valid static token → allowed (admin invite mode).
//  4. Everything else → 404 (endpoint not discoverable without a token).
func (h *WebAuthnHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	type pageData struct {
		LockedUsername  string
		Token           string
		BST             string
		Bootstrap       bool
		ExistingDevices int
	}

	sess := h.sessions.Get(r)

	// Tier 1: already authenticated → add another device.
	if sess.Authenticated {
		count, _ := h.store.CredentialCount(sess.Username)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.tmpl.ExecuteTemplate(w, "register.html", pageData{
			LockedUsername:  sess.Username,
			ExistingDevices: count,
		})
		return
	}

	// Tier 2: CLI bootstrap token — validate sig+expiry only (nonce consumed in RegisterBegin).
	// The username is extracted from the token claims and locked in the UI.
	if bst := r.URL.Query().Get("bst"); bst != "" {
		claims, err := token.Parse(h.cookieSecret, bst)
		if err != nil {
			http.Error(w, "bootstrap token invalid or expired — generate a new one with `bootstrap-token`", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.tmpl.ExecuteTemplate(w, "register.html", pageData{
			LockedUsername: claims.Username,
			BST:            bst,
			Bootstrap:      true,
		})
		return
	}

	// Tier 3: allowReg mode with optional static token.
	if h.allowReg {
		regToken := r.URL.Query().Get("token")
		if h.registrationToken != "" && !tokenEqual(regToken, h.registrationToken) {
			http.Error(w, "registration requires a valid token (?token=…)", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.tmpl.ExecuteTemplate(w, "register.html", pageData{Token: regToken})
		return
	}

	http.NotFound(w, r)
}

// ── Registration ──────────────────────────────────────────────────────────────

type registerBeginReq struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	DeviceName  string `json:"device_name"`
	Token       string `json:"token"`
	BST         string `json:"bst"`
}

// RegisterBegin starts a credential registration ceremony.
// POST /_webauthn/api/register/begin
func (h *WebAuthnHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req registerBeginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		jsonError(w, "username is required", http.StatusBadRequest)
		return
	}
	if !validUsernameRE.MatchString(req.Username) {
		jsonError(w, "username must be 1-64 characters: letters, digits, and . _ @ - only", http.StatusBadRequest)
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}

	sess := h.sessions.Get(r)
	selfService := sess.Authenticated && sess.Username == req.Username

	if !selfService {
		if req.BST != "" {
			// C-1 fix: validate sig+expiry, enforce username binding, consume nonce.
			claims, err := token.Parse(h.cookieSecret, req.BST)
			if err != nil {
				jsonError(w, "bootstrap token invalid or expired", http.StatusForbidden)
				return
			}
			if claims.Username != req.Username {
				jsonError(w, "token not valid for this username", http.StatusForbidden)
				return
			}
			if err := h.nonceStore.Consume(claims.Nonce, claims.Expiry); err != nil {
				jsonError(w, "bootstrap token already used", http.StatusForbidden)
				return
			}
		} else if err := h.checkRegistrationToken(r, req.Token); err != nil {
			jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	user, exists := h.store.GetUser(req.Username)
	if !exists {
		if req.BST == "" && !h.allowReg {
			// Return the same error regardless of whether the user exists to
			// prevent username enumeration via distinct messages.
			jsonError(w, "registration not permitted", http.StatusForbidden)
			return
		}
		var err error
		user, err = h.store.CreateUser(req.Username, req.DisplayName)
		if err != nil {
			jsonError(w, "create user: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	sel := protocol.AuthenticatorSelection{
		ResidentKey:      protocol.ResidentKeyRequirementRequired,
		UserVerification: protocol.VerificationRequired,
	}
	if h.attachment != "" {
		sel.AuthenticatorAttachment = h.attachment
	}

	options, sessionData, err := h.wa.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		jsonError(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	wanJSON, err := json.Marshal(sessionData)
	if err != nil {
		jsonError(w, "session error", http.StatusInternalServerError)
		return
	}
	sess.WANSession = string(wanJSON)
	sess.Username = req.Username
	sess.DeviceName = req.DeviceName
	if err := h.sessions.Save(w, sess); err != nil {
		jsonError(w, "session error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, options)
}

// RegisterFinish completes the credential registration ceremony.
// POST /_webauthn/api/register/finish
func (h *WebAuthnHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	sess := h.sessions.Get(r)
	if sess.Username == "" || sess.WANSession == "" {
		jsonError(w, "no pending registration session", http.StatusBadRequest)
		return
	}

	user, ok := h.store.GetUser(sess.Username)
	if !ok {
		jsonError(w, "user not found", http.StatusBadRequest)
		return
	}

	sessionData, err := unmarshalWANSession(sess.WANSession)
	if err != nil {
		jsonError(w, "invalid session data", http.StatusBadRequest)
		return
	}

	credential, err := h.wa.FinishRegistration(user, sessionData, r)
	if err != nil {
		jsonError(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.store.SaveCredential(sess.Username, sess.DeviceName, *credential); err != nil {
		jsonError(w, "save credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	credCount, _ := h.store.CredentialCount(sess.Username)
	slog.Info("credential registered", "user", sess.Username, "device", sess.DeviceName, "total_credentials", credCount)

	sess.WANSession = ""
	sess.DeviceName = ""
	_ = h.sessions.Save(w, sess)

	jsonOK(w, map[string]any{
		"status":           "ok",
		"credential_count": credCount,
	})
}

// ── Authentication (discoverable / fingerprint-only) ─────────────────────────

type authBeginReq struct {
	RD string `json:"rd"`
}

// AuthBegin starts a discoverable-credential authentication ceremony.
// POST /_webauthn/api/authenticate/begin
func (h *WebAuthnHandler) AuthBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req authBeginReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	options, sessionData, err := h.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		jsonError(w, "begin authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.saveWANSession(w, r, "", req.RD, sessionData); err != nil {
		jsonError(w, "session error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, options)
}

// AuthFinish completes the authentication ceremony and issues an authenticated session.
// POST /_webauthn/api/authenticate/finish
func (h *WebAuthnHandler) AuthFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	sess := h.sessions.Get(r)
	if sess.WANSession == "" {
		jsonError(w, "no pending authentication session", http.StatusBadRequest)
		return
	}

	sessionData, err := unmarshalWANSession(sess.WANSession)
	if err != nil {
		jsonError(w, "invalid session data", http.StatusBadRequest)
		return
	}

	src := r.Header.Get("X-Forwarded-For")
	if src == "" {
		src = r.RemoteAddr
	}

	var foundUsername string
	var usedCredIDHex string

	credential, err := h.wa.FinishDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			user, ok := h.store.GetUserByHandle(userHandle)
			if !ok {
				return nil, fmt.Errorf("user not found for handle")
			}
			foundUsername = user.Name
			usedCredIDHex = fmt.Sprintf("%x", rawID)
			return user, nil
		},
		sessionData,
		r,
	)
	if err != nil {
		// Uniform error message prevents distinguishing "wrong user" from
		// "bad signature" (C-4 / username enumeration via auth flow).
		slog.Warn("authentication failed", "src", src, "err", err)
		jsonError(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Persist updated sign counter (replay-attack defence).
	if err := h.store.SaveCredential(foundUsername, "", *credential); err != nil {
		slog.Warn("failed to update credential counter", "user", foundUsername, "err", err)
	}

	// Atomic single-lock lookup — avoids the race between CredentialIDs and
	// CredentialNames that existed when they were called in separate lock scopes.
	deviceName := h.store.CredentialName(foundUsername, usedCredIDHex)

	rd := safeRedirect(sess.RedirectURL, h.whitelistDomains)

	if err := h.sessions.Save(w, &session.Data{
		Authenticated: true,
		Username:      foundUsername,
	}); err != nil {
		jsonError(w, "session save failed", http.StatusInternalServerError)
		return
	}

	slog.Info("user authenticated",
		"user", foundUsername,
		"device", deviceName,
		"credential", usedCredIDHex,
		"src", src,
	)
	jsonOK(w, map[string]string{"status": "ok", "redirect": rd})
}

// DeleteCredential removes a passkey from the authenticated user's account.
// The last credential cannot be deleted (would permanently lock out the user).
// DELETE /_webauthn/api/credentials/{id}
func (h *WebAuthnHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.Get(r)
	if !sess.Authenticated {
		jsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	credID := r.PathValue("id")
	if credID == "" {
		jsonError(w, "credential id required", http.StatusBadRequest)
		return
	}

	count, _ := h.store.CredentialCount(sess.Username)
	if count <= 1 {
		jsonError(w, "cannot delete the last credential — you would be permanently locked out", http.StatusConflict)
		return
	}

	if err := h.store.DeleteCredential(sess.Username, credID); err != nil {
		jsonError(w, "delete credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("credential deleted", "user", sess.Username, "credential", credID)
	jsonOK(w, map[string]string{"status": "ok"})
}

// ── internal helpers ──────────────────────────────────────────────────────────

// checkRegistrationToken enforces the optional registration token gate.
// Accepts the token from (priority order): body field, X-Registration-Token
// header, Authorization: Bearer header.
// Uses constant-time comparison to prevent timing-oracle attacks (H-1).
func (h *WebAuthnHandler) checkRegistrationToken(r *http.Request, bodyToken string) error {
	if !h.allowReg {
		return fmt.Errorf("registration not permitted")
	}
	if h.registrationToken == "" {
		return nil
	}
	got := bodyToken
	if got == "" {
		got = r.Header.Get("X-Registration-Token")
	}
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if !tokenEqual(got, h.registrationToken) {
		return fmt.Errorf("invalid or missing registration token")
	}
	return nil
}

// tokenEqual compares two tokens in constant time to prevent timing oracles.
func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (h *WebAuthnHandler) saveWANSession(
	w http.ResponseWriter, r *http.Request,
	username, rd string,
	sessionData *webauthn.SessionData,
) error {
	wanJSON, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	sess := h.sessions.Get(r)
	sess.WANSession = string(wanJSON)
	if username != "" {
		sess.Username = username
	}
	if rd != "" {
		sess.RedirectURL = rd
	}
	return h.sessions.Save(w, sess)
}

func unmarshalWANSession(raw string) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	return sd, json.Unmarshal([]byte(raw), &sd)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
