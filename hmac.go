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

// Middleware returns an HTTP middleware that validates X-User-ID via X-User-Signature.
// If secret is empty, the middleware passes all requests (dev mode).
// onReject is called when auth fails (write 401 response).
func Middleware(secret string, onReject func(w http.ResponseWriter, r *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}
			userID := r.Header.Get(UserIDHeader)
			signature := r.Header.Get(SignatureHeader)
			if !Verify(userID, signature, secret) {
				if onReject != nil {
					onReject(w, r)
				} else {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
