package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type tokenInfo struct {
	AccessToken string
	Expiry      time.Time
}

var (
	codes  = make(map[string]string) // Authorization codes mapped to client IDs
	tokens = make(map[string]tokenInfo)
)

var oauth2Config = oauth2.Config{
	ClientID:     os.Getenv("OAUTH2_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH2_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("OAUTH2_REDIRECT_URL"),
	Scopes:       []string{"read", "write"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "/authorize",
		TokenURL: "/token",
	},
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", readyHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		log.Println("Starting server on :8080")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown on SIGTERM or SIGINT
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	log.Println("Server gracefully stopped")
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if clientID == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "Missing client_id or redirect_uri")
		return
	}

	// Generate an authorization code
	code := uuid.New().String()
	codes[code] = clientID

	redirect := fmt.Sprintf("%s?code=%s", redirectURI, code)
	http.Redirect(w, r, redirect, http.StatusFound)
	log.Printf("Issued authorization code: %s", code)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if code == "" || clientID == "" || clientSecret == "" {
		writeError(w, http.StatusBadRequest, "Missing required parameters")
		return
	}

	// Validate the authorization code
	storedClientID, exists := codes[code]
	if !exists || storedClientID != clientID {
		writeError(w, http.StatusUnauthorized, "Invalid authorization code")
		return
	}

	// Generate an access token
	token := uuid.New().String()
	expiry := time.Now().Add(5 * time.Minute)
	tokens[token] = tokenInfo{
		AccessToken: token,
		Expiry:      expiry,
	}

	delete(codes, code) // Invalidate the authorization code

	response := map[string]interface{}{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   int(time.Until(expiry).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Issued access token: %s", token)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "READY")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
	log.Printf("Error [%d]: %s", status, msg)
}


//
//  export OAUTH2_CLIENT_ID="your-client-id"
//  export OAUTH2_CLIENT_SECRET="your-client-secret"
//  export OAUTH2_REDIRECT_URL="http://localhost:8080/callback"
//
//   go build -o oauth2_server
//   ./oauth2_server
//

