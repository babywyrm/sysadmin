package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// CustomClaims defines the custom JWT claims for your application
type CustomClaims struct {
	ClientID string `json:"client_id"`
	ServerID string `json:"server_id"`
	jwt.StandardClaims
}

func generateJWT(clientID, serverID string) (string, error) {
	// Create custom claims
	claims := CustomClaims{
		ClientID: clientID,
		ServerID: serverID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
		},
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	secretKey := []byte("your_secret_key") // Change this to your actual secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func parseJWT(signedToken string) (*CustomClaims, error) {
	// Parse JWT token
	token, err := jwt.ParseWithClaims(signedToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your_secret_key"), nil // Change this to your actual secret key
	})
	if err != nil {
		return nil, err
	}

	// Extract custom claims
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	return claims, nil
}

func main() {
	// Example usage
	clientID := "your_client_id"
	serverID := "your_server_id"

	// Generate JWT token
	token, err := generateJWT(clientID, serverID)
	if err != nil {
		fmt.Println("Error generating JWT token:", err)
		return
	}
	fmt.Println("JWT Token:", token)

	// Parse and validate JWT token
	claims, err := parseJWT(token)
	if err != nil {
		fmt.Println("Error parsing JWT token:", err)
		return
	}
	fmt.Println("Client ID:", claims.ClientID)
	fmt.Println("Server ID:", claims.ServerID)
}

