package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
)

const (
	// Defaults if you don't set environment variables
	defaultKeycloakIssuer = "http://things.edu:8080/auth/realms/lol-realm"
	defaultClientID       = "lol-api"
)

// Global references (populated in main)
var (
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
)

func main() {
	keycloakIssuer := getEnvOrDefault("KEYCLOAK_ISSUER", defaultKeycloakIssuer)
	clientID := getEnvOrDefault("KEYCLOAK_CLIENT_ID", defaultClientID)

	var err error
	// Initialize OIDC Provider
	provider, err = oidc.NewProvider(context.Background(), keycloakIssuer)
	if err != nil {
		log.Printf("Warning: OIDC provider init failed: %v\n", err)
		log.Println("If you are in DEMO_MODE=true, you can ignore this error.")
	}

	// Create a verifier that checks tokens for the given client ID
	if provider != nil {
		verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	}

	// Register routes
	http.HandleFunc("/api/schematics", validateToken(schematicsHandler))

	// Start the HTTP server
	fmt.Println("Warbird API running on :8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// validateToken is our middleware that verifies the bearer token,
// or skips verification if DEMO_MODE=true
func validateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		demoMode := strings.ToLower(os.Getenv("DEMO_MODE"))
		if demoMode == "true" {
			// DEMO mode: skip OIDC verification
			// Allow an override scope via X-Demo-Scope, default to "public"
			scope := r.Header.Get("X-Demo-Scope")
			if scope == "" {
				scope = "public" // Default scope for DEMO mode
			}
			r.Header.Set("X-User-Scope", scope)
			next(w, r)
			return
		}

		// Normal mode: check Authorization header and OIDC token
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

		if verifier == nil {
			http.Error(w, "OIDC verifier not initialized", http.StatusInternalServerError)
			return
		}

		// Verify the token's signature, issuer, etc.
		idToken, err := verifier.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "Invalid Token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Extract the scope claim
		var claims struct {
			Scope string `json:"scope"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		// Store the scope in the request for the next handler
		r.Header.Set("X-User-Scope", claims.Scope)
		next(w, r)
	}
}

// schematicsHandler reads the scope from the header and returns schematics
func schematicsHandler(w http.ResponseWriter, r *http.Request) {
	scope := r.Header.Get("X-User-Scope")

	// Get schematics based on access level
	schematic := GetSchematics(scope, "")

	// If the scope is classified, include the override password
	if scope == "classified" {
		schematic.OverridePass = "COMMANDER_ACCESS_PASSWORD"
	}

	// If no valid schematics found, return an error
	if schematic.ShipName == "Unknown Vessel" {
		http.Error(w, "Insufficient scope; need at least 'public'", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schematic)
}

// Helper function to get env var or use a default
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
