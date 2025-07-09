package router

import (
	"log"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"

	"01-Authorization-RS256/middleware"
)

// New sets up our routes and returns a *http.ServeMux.
func New() *http.ServeMux {
	router := http.NewServeMux()

	// This route is always accessible.
	router.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Hello from a public endpoint! You don't need to be authenticated to see this."}`))
	}))

	// This route is only accessible if the user has a valid access_token.
	router.Handle("/api/private", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this."}`))
		}),
	))

	// This route is only accessible if the user has a
	// valid access_token with the read:messages scope.
	router.Handle("/api/private-scoped", middleware.EnsureValidToken()(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS Headers.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")

			w.Header().Set("Content-Type", "application/json")

			// OPTIONSのリクエストの場合、無条件で成功で返す。
			if r.Method == http.MethodOptions {
				log.Printf("OPTIONS request to %s", r.URL.Path)
				w.WriteHeader(http.StatusOK)
				return
			}

			// token, err := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
			t := r.Context().Value(jwtmiddleware.ContextKey{})
			log.Printf("Token: %+v", t)
			token, ok := t.(*validator.ValidatedClaims)
			if !ok {
				log.Printf("Failed to cast token to ValidatedClaims")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"message":"Failed to cast token to ValidatedClaims."}`))
				return
			}

			claims := token.CustomClaims.(*middleware.CustomClaims)
			log.Printf("Custom claims: %+v", claims)
			if !claims.HasPermission("read:messages") {
				log.Printf("Insufficient permission: read:messages")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"message":"Insufficient permission."}`))
				return
			}

			// Extract and log user roles from the token

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this."}`))
		}),
	))

	return router
}
