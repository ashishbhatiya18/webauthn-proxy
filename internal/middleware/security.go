package middleware

import "net/http"

// SecureHeaders adds defensive HTTP response headers to every response.
// These mitigate clickjacking, MIME-sniffing, and credential-API abuse from
// cross-origin frames.
//
// CSP note: templates use inline <style> and <script> blocks, so both
// 'unsafe-inline' directives are required until scripts are moved to external
// files and nonces are injected per-request.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy",
			"publickey-credentials-get=(self), publickey-credentials-create=(self)")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}
