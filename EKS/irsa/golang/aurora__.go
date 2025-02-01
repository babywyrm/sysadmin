// main.go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	// AWS SDK v2 packages for configuration and STS API.
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	// HashiCorp Vault client for secret management.
	vault "github.com/hashicorp/vault/api"

	// MySQL driver for Aurora connection.
	_ "github.com/go-sql-driver/mysql"
)

// ----------------------------------------------
// Secret Management Abstraction
// ----------------------------------------------

// SecretManager defines the operations for secret retrieval and rotation.
type SecretManager interface {
	GetSecret(secretPath string) (map[string]interface{}, error)
	RotateSecret(secretPath string) error
}

// VaultSecretManager implements SecretManager for HashiCorp Vault.
type VaultSecretManager struct {
	client *vault.Client
}

// GetSecret retrieves a secret from Vault. For KV v2, the data is stored under "data".
func (v *VaultSecretManager) GetSecret(secretPath string) (map[string]interface{}, error) {
	secret, err := v.client.Logical().Read(secretPath)
	if err != nil {
		return nil, fmt.Errorf("error reading secret: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret found at path: %s", secretPath)
	}
	// For Vault KV version 2, the actual data is usually nested under the "data" key.
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		return data, nil
	}
	return secret.Data, nil
}

// RotateSecret is a stub for the secret rotation logic.
func (v *VaultSecretManager) RotateSecret(secretPath string) error {
	// Implement your actual rotation logic here.
	log.Printf("Rotating secret at %s (stub)", secretPath)
	return nil
}

// CyberArkSecretManager is provided as a stub for future CyberArk integration.
type CyberArkSecretManager struct{}

func (c *CyberArkSecretManager) GetSecret(secretPath string) (map[string]interface{}, error) {
	return nil, fmt.Errorf("CyberArk integration not implemented")
}

func (c *CyberArkSecretManager) RotateSecret(secretPath string) error {
	return fmt.Errorf("CyberArk integration not implemented")
}

// getSecretManager selects the secret management backend based on the SECRET_PROVIDER env var.
// Defaults to Vault if not set.
func getSecretManager() (SecretManager, error) {
	secretProvider := os.Getenv("SECRET_PROVIDER")
	switch secretProvider {
	case "cyberark":
		return &CyberArkSecretManager{}, nil
	default:
		client, err := connectToVault()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Vault: %w", err)
		}
		return &VaultSecretManager{client: client}, nil
	}
}

// connectToVault initializes and returns a Vault client.
// VAULT_ADDR and VAULT_TOKEN must be set in the environment.
func connectToVault() (*vault.Client, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		// Default value for local testing.
		vaultAddr = "http://127.0.0.1:8200"
	}
	config := vault.DefaultConfig()
	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating Vault client: %w", err)
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is not set")
	}
	client.SetToken(token)
	return client, nil
}

// ----------------------------------------------
// Customer IRSA Assume Role Management
// ----------------------------------------------

// AssumeRoleDetails holds the IRSA assume role configuration for a customer.
type AssumeRoleDetails struct {
	CustomerID      string
	RoleArn         string
	ExternalID      string
	DurationSeconds int32
}

// Global database connection pool.
// In a production system, consider using dependency injection instead.
var db *sql.DB

// connectToAurora initializes a connection to the Aurora database.
// The connection string (DSN) must be provided via the AURORA_DSN environment variable.
func connectToAurora() (*sql.DB, error) {
	dsn := os.Getenv("AURORA_DSN")
	if dsn == "" {
		return nil, fmt.Errorf("AURORA_DSN environment variable not set")
	}
	// Open a new DB connection using the MySQL driver.
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB: %w", err)
	}
	// Optional: Configure the connection pool.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping DB: %w", err)
	}
	return db, nil
}

// getCustomerAssumeRole retrieves the IRSA assume role details for a given customer from Aurora.
// It expects a table "customer_assume_roles" with columns:
// customer_id, role_arn, external_id, and duration_seconds.
func getCustomerAssumeRole(ctx context.Context, customerID string) (*AssumeRoleDetails, error) {
	query := `
        SELECT customer_id, role_arn, external_id, duration_seconds
        FROM customer_assume_roles
        WHERE customer_id = ?
        LIMIT 1
    `
	row := db.QueryRowContext(ctx, query, customerID)
	var details AssumeRoleDetails
	if err := row.Scan(&details.CustomerID, &details.RoleArn, &details.ExternalID, &details.DurationSeconds); err != nil {
		return nil, fmt.Errorf("failed to scan assume role details: %w", err)
	}
	return &details, nil
}

// assumeRoleForCustomer calls AWS STS to assume the role for the given customer using the provided details.
func assumeRoleForCustomer(ctx context.Context, stsClient *sts.Client, details *AssumeRoleDetails) (*sts.AssumeRoleOutput, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &details.RoleArn,
		RoleSessionName: &details.CustomerID, // Using the customer ID as the session name.
		ExternalId:      &details.ExternalID,
		DurationSeconds: &details.DurationSeconds,
	}
	output, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role for customer %s: %w", details.CustomerID, err)
	}
	log.Printf("Assumed role for customer %s: ARN=%s", details.CustomerID, details.RoleArn)
	return output, nil
}

// ----------------------------------------------
// AWS Identity Verification
// ----------------------------------------------

// getCallerIdentity calls AWS STS to verify the service's own identity (using IRSA if on EKS).
func getCallerIdentity(ctx context.Context, stsClient *sts.Client) error {
	input := &sts.GetCallerIdentityInput{}
	output, err := stsClient.GetCallerIdentity(ctx, input)
	if err != nil {
		return fmt.Errorf("GetCallerIdentity failed: %w", err)
	}
	log.Printf("AWS Caller Identity: Account=%s, Arn=%s", *output.Account, *output.Arn)
	return nil
}

// ----------------------------------------------
// HTTP Handlers
// ----------------------------------------------

// rotateHandler handles requests for secret rotation and customer-specific IRSA assume roles.
// If a "customer_id" query parameter is provided, the handler will retrieve the assume role details
// for that customer and attempt to assume the role using AWS STS.
func rotateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Load AWS configuration; IRSA credentials will be automatically used if available.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to load AWS config: %v", err), http.StatusInternalServerError)
		return
	}

	// Create an STS client.
	stsClient := sts.NewFromConfig(cfg)

	// Verify the service's AWS identity.
	if err := getCallerIdentity(ctx, stsClient); err != nil {
		http.Error(w, fmt.Sprintf("failed to get caller identity: %v", err), http.StatusInternalServerError)
		return
	}

	// Check if a customer_id is provided as a query parameter.
	customerID := r.URL.Query().Get("customer_id")
	if customerID != "" {
		// Retrieve the customer's IRSA assume role details from Aurora.
		details, err := getCustomerAssumeRole(ctx, customerID)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get assume role details for customer %s: %v", customerID, err), http.StatusInternalServerError)
			return
		}

		// Attempt to assume the customer's role using AWS STS.
		assumedRole, err := assumeRoleForCustomer(ctx, stsClient, details)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to assume role for customer %s: %v", customerID, err), http.StatusInternalServerError)
			return
		}

		// (Optional) You can create a new AWS config with the assumed credentials here.
		// That new configuration can be used to perform customer-specific AWS operations.
		log.Printf("Assumed role credentials for customer %s will expire at %v", customerID, assumedRole.Credentials.Expiration)
	}

	// Initialize the secret manager (Vault by default, or CyberArk if configured).
	secretManager, err := getSecretManager()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to initialize secret manager: %v", err), http.StatusInternalServerError)
		return
	}

	// Define the secret path (example for Vault KV v2).
	secretPath := "secret/data/myapp/keys"

	// Retrieve the secret.
	secretData, err := secretManager.GetSecret(secretPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get secret: %v", err), http.StatusInternalServerError)
		return
	}

	// Rotate the secret (stub).
	if err := secretManager.RotateSecret(secretPath); err != nil {
		// Log the error but do not block the request.
		log.Printf("Secret rotation error: %v", err)
	}

	// Respond with the secret data.
	// NOTE: In production, avoid returning sensitive data in responses.
	fmt.Fprintf(w, "Secret data: %v", secretData)
}

// ----------------------------------------------
// main function
// ----------------------------------------------

func main() {
	var err error

	// Initialize the Aurora DB connection.
	db, err = connectToAurora()
	if err != nil {
		log.Fatalf("Failed to connect to Aurora: %v", err)
	}
	// Ensure the DB connection is closed when the program exits.
	defer db.Close()

	// Set up HTTP endpoints.
	http.HandleFunc("/rotate", rotateHandler)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	// Determine the port to listen on from the environment variable (default to 8080).
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

//
