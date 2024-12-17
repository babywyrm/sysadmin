//
//
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
)

const (
	keycloakIssuer = "http://keycloak:8080/auth/realms/warbird-realm"
	clientID       = "warbird-api"
)

var (
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
)

func main() {
	var err error

	// Initialize OIDC Provider
	provider, err = oidc.NewProvider(context.Background(), keycloakIssuer)
	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// API Routes
	http.HandleFunc("/api/schematics", validateToken(schematicsHandler))

	// Start API
	fmt.Println("Warbird API running on :8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// Middleware: Validate OAuth2 Token
func validateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, "Malformed Authorization Header", http.StatusUnauthorized)
			return
		}

		idToken, err := verifier.Verify(context.Background(), token)
		if err != nil {
			http.Error(w, "Invalid Token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Extract scope from claims
		var claims struct {
			Scope string `json:"scope"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		// Pass scope to next handler
		r.Header.Set("X-User-Scope", claims.Scope)
		next(w, r)
	}
}

// Handler: Fetch Warbird Schematics
func schematicsHandler(w http.ResponseWriter, r *http.Request) {
	scope := r.Header.Get("X-User-Scope")

	// Determine access level based on scope
	var accessLevel string
	if strings.Contains(scope, "admin") {
		accessLevel = "admin"
	} else if strings.Contains(scope, "engineer") {
		accessLevel = "engineer"
	} else {
		accessLevel = "user"
	}

	// Retrieve schematics
	schematic := GetSchematics(accessLevel)

	// Respond with JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schematic)
}

//
// warbird-api/
//  │
//  ├── main.go            # Entry point and routing logic
//  ├── schematics.go      # Contains Warbird schematics and details
//  └── Dockerfile         # Builds the API container
//
