package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

const (
	UserIDHeader    = "X-User-ID"
	SignatureHeader = "X-User-Signature"
	APIKeyHeader    = "X-API-Key"
)

// Verify checks that signature = HMAC-SHA256(userID, secret).
func Verify(userID, signature, secret string) bool {
	if secret == "" || signature == "" || userID == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// Middleware returns middleware that checks auth via HMAC (X-User-ID + X-User-Signature)
// with fallback to legacy X-API-Key. If secret is empty, passes all requests (dev mode).
// onReject is called when auth fails (write 401 response).
func Middleware(secret string, onReject func(w http.ResponseWriter, r *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Try HMAC first
			userID := r.Header.Get(UserIDHeader)
			signature := r.Header.Get(SignatureHeader)
			if userID != "" && signature != "" {
				if Verify(userID, signature, secret) {
					next.ServeHTTP(w, r)
					return
				}
				if onReject != nil {
					onReject(w, r)
				}
				return
			}
			// Fallback: legacy X-API-Key
			key := r.Header.Get(APIKeyHeader)
			if key != secret {
				if onReject != nil {
					onReject(w, r)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
