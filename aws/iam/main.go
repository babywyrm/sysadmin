package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// auditIAM performs a simple audit of IAM roles and policies.
func auditIAM(ctx context.Context, client *iam.Client) error {
	// List IAM roles
	rolesOutput, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return fmt.Errorf("failed to list IAM roles: %w", err)
	}

	fmt.Println("=== IAM Roles ===")
	for _, role := range rolesOutput.Roles {
		fmt.Printf("Role Name: %s, Arn: %s\n", *role.RoleName, *role.Arn)
		// Example recommendation: flag roles that have 'AdministratorAccess'
		if role.RoleName != nil && *role.RoleName == "AdministratorAccess" {
			fmt.Printf("  [WARNING] Role %s has AdministratorAccess. Consider following the least privilege principle.\n", *role.RoleName)
		}
	}

	// List IAM policies (customer managed policies)
	policiesOutput, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
		Scope: "Local",
	})
	if err != nil {
		return fmt.Errorf("failed to list IAM policies: %w", err)
	}

	fmt.Println("\n=== IAM Policies ===")
	for _, policy := range policiesOutput.Policies {
		fmt.Printf("Policy Name: %s, Arn: %s\n", *policy.PolicyName, *policy.Arn)
		if policy.PolicyName != nil && *policy.PolicyName == "AdministratorAccess" {
			fmt.Printf("  [WARNING] Policy %s is very permissive. Review if it's really needed.\n", *policy.PolicyName)
		}
	}

	// Print generic recommendations
	fmt.Println("\n=== Recommendations ===")
	fmt.Println("- Review roles with broad permissions, such as those with AdministratorAccess.")
	fmt.Println("- Ensure policies follow the principle of least privilege.")
	fmt.Println("- Regularly review and remove unused IAM roles and policies.")
	fmt.Println("- Consider using AWS IAM Access Analyzer and AWS Config for continuous monitoring.")

	return nil
}

func main() {
	ctx := context.Background()

	// Load the AWS default config (e.g. from environment variables or shared config file)
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create an IAM client
	client := iam.NewFromConfig(cfg)

	// Perform IAM audit
	if err := auditIAM(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "Error during audit: %v\n", err)
		os.Exit(1)
	}
}

// go get github.com/aws/aws-sdk-go-v2
// go get github.com/aws/aws-sdk-go-v2/config
// go get github.com/aws/aws-sdk-go-v2/service/iam
