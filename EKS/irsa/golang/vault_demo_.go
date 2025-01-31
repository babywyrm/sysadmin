package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/hashicorp/vault/api"
)

//
//
// CustomerVaultConfig stores vault details per customer
type CustomerVaultConfig struct {
	AccountID  string
	VaultAddr  string
	AuthMethod string // "iam", "approle", "token"
	AppRoleID  string
	SecretID   string
	Token      string
}

// AssumeRoleForCustomer dynamically assumes IAM roles for Vault access
func AssumeRoleForCustomer(customerAccountID string) (*stscreds.AssumeRoleProvider, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/IRSA-Vault-Access", customerAccountID)

	creds := stscreds.NewAssumeRoleProvider(stsClient, roleArn)
	return creds, nil
}

// AuthenticateToVault handles multiple auth methods
func AuthenticateToVault(cfg CustomerVaultConfig) (*api.Client, error) {
	client, err := api.NewClient(&api.Config{Address: cfg.VaultAddr})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	switch cfg.AuthMethod {
	case "iam":
		creds, err := AssumeRoleForCustomer(cfg.AccountID)
		if err != nil {
			return nil, err
		}
		awsCreds, _ := creds.Retrieve(context.Background())

		loginData := map[string]interface{}{
			"role":    "vault-role",
			"iam_http_request_method": "POST",
			"iam_request_url":         "https://sts.amazonaws.com/",
			"iam_request_body":        "Action=GetCallerIdentity&Version=2011-06-15",
			"iam_request_headers":     "host=sts.amazonaws.com",
		}
		_, err = client.Logical().Write("auth/aws/login", loginData)
		if err != nil {
			return nil, fmt.Errorf("IAM auth failed: %v", err)
		}

	case "approle":
		loginData := map[string]interface{}{
			"role_id":   cfg.AppRoleID,
			"secret_id": cfg.SecretID,
		}
		secret, err := client.Logical().Write("auth/approle/login", loginData)
		if err != nil {
			return nil, fmt.Errorf("AppRole auth failed: %v", err)
		}
		client.SetToken(secret.Auth.ClientToken)

	case "token":
		client.SetToken(cfg.Token)

	default:
		return nil, fmt.Errorf("unsupported Vault auth method: %s", cfg.AuthMethod)
	}

	log.Println("Vault authentication successful for", cfg.AccountID)
	return client, nil
}

// FetchSecrets retrieves multiple secrets concurrently
func FetchSecrets(client *api.Client, paths []string) map[string]string {
	var wg sync.WaitGroup
	results := make(map[string]string)
	mu := sync.Mutex{}

	for _, path := range paths {
		wg.Add(1)
		go func(secretPath string) {
			defer wg.Done()

			secret, err := client.Logical().Read(secretPath)
			if err != nil || secret == nil {
				log.Printf("Failed to read secret at %s: %v", secretPath, err)
				return
			}

			mu.Lock()
			results[secretPath] = fmt.Sprintf("%v", secret.Data)
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	return results
}

// ProcessCustomer orchestrates authentication and secret retrieval
func ProcessCustomer(cfg CustomerVaultConfig, secretPaths []string) {
	client, err := AuthenticateToVault(cfg)
	if err != nil {
		log.Println("Error authenticating:", err)
		return
	}

	secrets := FetchSecrets(client, secretPaths)

	for path, value := range secrets {
		log.Printf("Secret from %s: %s", path, value)
	}
}

func main() {
	customers := []CustomerVaultConfig{
		{AccountID: "111111111111", VaultAddr: "https://vault.customer1.com", AuthMethod: "iam"},
		{AccountID: "222222222222", VaultAddr: "https://vault.customer2.com", AuthMethod: "approle", AppRoleID: "role123", SecretID: "secret456"},
	}

	secretPaths := []string{"secret/data/db", "secret/data/api"}

	var wg sync.WaitGroup
	for _, customer := range customers {
		wg.Add(1)
		go func(cfg CustomerVaultConfig) {
			defer wg.Done()
			ProcessCustomer(cfg, secretPaths)
		}(customer)
	}
	wg.Wait()
}

//
//
