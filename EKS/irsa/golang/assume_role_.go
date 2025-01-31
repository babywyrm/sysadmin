//
//  apiVersion: v1
// kind: ServiceAccount
// metadata:
//   name: vault-orchestrator-irsa
//   annotations:
//     eks.amazonaws.com/role-arn: arn:aws:iam::YOUR_AWS_ACCOUNT_ID:role/EKS-Orchestrator-BaseRole
//
//

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
)

// AssumeRoleForCustomer dynamically assumes the customer's IAM role
func AssumeRoleForCustomer(customerAccountID string) (string, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx) // IRSA auto-detects AWS creds
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// The customer's IAM role
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/IRSA-Vault-Access", customerAccountID)

	// Assume the customer's role
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleArn)
	awsCreds, err := creds.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to assume role %s: %v", roleArn, err)
	}

	log.Println("confirmed - successfully assumed role:", roleArn)
	return awsCreds.AccessKeyID, nil
}

func main() {
	customerID := "123456789012" // Example Customer AWS Account ID
	_, err := AssumeRoleForCustomer(customerID)
	if err != nil {
		log.Fatal(err)
	}
}

//
//
