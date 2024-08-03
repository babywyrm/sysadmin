package main

//
//

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "golang.org/x/oauth2"
)

var (
    codes   = map[string]time.Time{}
    tokens  = map[string]time.Time{}
    mu      sync.Mutex
    logger  *log.Logger
)

const (
    codeExpiry   = 90 * time.Second  // Authorization code expiry time
    tokenExpiry  = 5 * time.Minute   // Access token expiry time
)

var oauth2Config = oauth2.Config{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    RedirectURL:  "http://localhost:8080/callback",
    Scopes:       []string{"read", "write"},
    Endpoint:     oauth2.Endpoint{},
}

func generateCode() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

func generateToken() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

func authHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.URL.Query().Get("client_id")
    redirectURI := r.URL.Query().Get("redirect_uri")
    responseType := r.URL.Query().Get("response_type")

    logger.Printf("Received auth request: client_id=%s, redirect_uri=%s, response_type=%s", clientID, redirectURI, responseType)

    if clientID != oauth2Config.ClientID || redirectURI != oauth2Config.RedirectURL || responseType != "code" {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    code, err := generateCode()
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    mu.Lock()
    codes[code] = time.Now().Add(codeExpiry)
    mu.Unlock()

    http.Redirect(w, r, fmt.Sprintf("%s?code=%s", redirectURI, code), http.StatusFound)
    logger.Printf("Redirecting to callback with code: %s", code)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Authorization code not found", http.StatusBadRequest)
        return
    }

    // Inform the user that the code was received and they should exchange it for a token.
    fmt.Fprintf(w, "Authorization code received: %s\n", code)
    logger.Printf("Received authorization code: %s", code)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    code := r.PostFormValue("code")
    if code == "" {
        http.Error(w, "Missing code", http.StatusBadRequest)
        return
    }

    mu.Lock()
    expiry, valid := codes[code]
    mu.Unlock()

    if !valid || time.Now().After(expiry) {
        http.Error(w, "Invalid or expired authorization code", http.StatusUnauthorized)
        logger.Printf("Invalid or expired authorization code: %s", code)
        return
    }

    token, err := generateToken()
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    mu.Lock()
    tokens[token] = time.Now().Add(tokenExpiry)
    mu.Unlock()

    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"access_token": "%s", "token_type": "bearer"}`, token)
    logger.Printf("Generated access token: %s", token)
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    if token == "" || len(token) < 8 || token[:7] != "Bearer " {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        logger.Printf("Unauthorized access attempt with token: %s", token)
        return
    }

    mu.Lock()
    _, valid := tokens[token[7:]]
    mu.Unlock()

    if !valid {
        http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
        logger.Printf("Invalid or expired token: %s", token)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"resource": "Protected Resource"}`)
    logger.Printf("Access granted to protected resource with token: %s", token)
}

func main() {
    file, err := openLogFile("oauth2.log")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
    logger = log.New(io.MultiWriter(file, os.Stdout), "", log.LstdFlags)

    http.HandleFunc("/auth", authHandler)
    http.HandleFunc("/callback", callbackHandler)
    http.HandleFunc("/token", tokenHandler)
    http.HandleFunc("/resource", resourceHandler)

    logger.Println("OAuth2 server is running on port 8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func openLogFile(filename string) (*os.File, error) {
    return os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

//
//
