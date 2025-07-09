package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// CustomClaims contains custom data we want from the token.
//
//	type CustomClaims struct {
//		Scope string `json:"scope"`
//		Role  string `json:"https://dev.ocx-compute-fabric.com/role"`
//	}
type CustomClaims map[string]interface{}

// Validate does nothing for this example, but we need
// it to satisfy validator.CustomClaims interface.
func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

// HasScope checks whether our claims have a specific scope.
func (c CustomClaims) HasScope(expectedScope string) bool {
	scope, ok := c["scope"].(string)
	if !ok {
		log.Printf("Scope not found in claims: %v", c)
		return false
	}

	// result := strings.Split(c.Scope, " ")
	result := strings.Split(scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}

func (c CustomClaims) HasPermission(permission string) bool {
	perms, ok := c["permissions"].([]interface{})
	if !ok {
		log.Printf("Permissions not found or invalid in claims: %v", c)
		return false
	}
	for _, p := range perms {
		fmt.Printf("Checking permission: %v, expected: %s\n", p, permission)
		if permStr, ok := p.(string); ok && permStr == permission {
			return true
		}
	}
	return false
}

// EnsureValidToken is a middleware that will check the validity of our JWT.
func EnsureValidToken() func(next http.Handler) http.Handler {
	issuerURL, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/")
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{os.Getenv("AUTH0_AUDIENCE")},
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &CustomClaims{}
			},
		),
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		log.Fatalf("Failed to set up the jwt validator %v", err)
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Encountered error while validating JWT: %v", err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Failed to validate JWT."}`))
	}

	middleware := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
		jwtmiddleware.WithValidateOnOptions(false),
	)

	return func(next http.Handler) http.Handler {
		return middleware.CheckJWT(next)
	}
}
