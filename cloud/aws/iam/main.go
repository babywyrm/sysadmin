package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Violation represents a security issue and a corresponding Terraform recommendation.
type Violation struct {
	Issue        string
	ResourceType string
	ResourceName string
	TerraformRec string
}

// PolicyDocument represents a simplified structure of an IAM policy document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement interface{} `json:"Statement"`
}

// checkPolicyForWildcard examines a policy document to see if any statement allows "*" actions.
func checkPolicyForWildcard(doc PolicyDocument) bool {
	switch stmt := doc.Statement.(type) {
	case map[string]interface{}:
		return statementHasWildcard(stmt)
	case []interface{}:
		for _, s := range stmt {
			if m, ok := s.(map[string]interface{}); ok {
				if statementHasWildcard(m) {
					return true
				}
			}
		}
	}
	return false
}

// statementHasWildcard checks if the "Action" field in a statement contains "*".
func statementHasWildcard(statement map[string]interface{}) bool {
	action, exists := statement["Action"]
	if !exists {
		return false
	}

	switch act := action.(type) {
	case string:
		if act == "*" {
			return true
		}
	case []interface{}:
		for _, a := range act {
			if aStr, ok := a.(string); ok && aStr == "*" {
				return true
			}
		}
	}
	return false
}

// printPolicyDetails prints additional details about a policy document.
func printPolicyDetails(policyName string, doc PolicyDocument) {
	fmt.Printf("Policy Document for %s (Version: %s):\n", policyName, doc.Version)
	switch stmt := doc.Statement.(type) {
	case map[string]interface{}:
		fmt.Println(" - 1 statement")
		printStatement(stmt)
	case []interface{}:
		fmt.Printf(" - %d statements\n", len(stmt))
		for i, s := range stmt {
			if m, ok := s.(map[string]interface{}); ok {
				fmt.Printf("   Statement %d:\n", i+1)
				printStatement(m)
			}
		}
	default:
		fmt.Println(" - No statements found or unexpected format.")
	}
}

// printStatement prints the keys of a single statement.
func printStatement(stmt map[string]interface{}) {
	if effect, ok := stmt["Effect"]; ok {
		fmt.Printf("     Effect: %v\n", effect)
	}
	if action, ok := stmt["Action"]; ok {
		fmt.Printf("     Action: %v\n", action)
	}
	if resource, ok := stmt["Resource"]; ok {
		fmt.Printf("     Resource: %v\n", resource)
	}
	if condition, ok := stmt["Condition"]; ok {
		fmt.Printf("     Condition: %v\n", condition)
	}
}

// auditIAM performs a basic audit of IAM roles and policies.
// It returns any serious violations discovered.
func auditIAM(ctx context.Context, client *iam.Client, verbose bool) ([]Violation, error) {
	var violations []Violation

	// List IAM roles
	rolesOutput, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list IAM roles: %w", err)
	}

	fmt.Println("=== IAM Roles ===")
	for _, role := range rolesOutput.Roles {
		roleName := *role.RoleName
		fmt.Printf("Role Name: %s, Arn: %s\n", roleName, *role.Arn)
		// Example violation: roles with names indicating broad privileges.
		if strings.Contains(roleName, "AdministratorAccess") {
			issue := fmt.Sprintf("Role %s appears to have overly broad privileges", roleName)
			tfRec := fmt.Sprintf(`resource "aws_iam_role_policy_attachment" "%s_restrict" {
  role       = "%s"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}`, strings.ToLower(roleName), roleName)
			violations = append(violations, Violation{
				Issue:        issue,
				ResourceType: "IAM Role",
				ResourceName: roleName,
				TerraformRec: tfRec,
			})
		}
	}

	// List IAM Policies (customer managed policies)
	policiesOutput, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
		Scope: "Local",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list IAM policies: %w", err)
	}

	fmt.Println("\n=== IAM Policies ===")
	for _, policy := range policiesOutput.Policies {
		policyName := *policy.PolicyName
		fmt.Printf("Policy Name: %s, Arn: %s\n", policyName, *policy.Arn)

		// If verbose is enabled, print details of the policy document.
		if verbose {
			policyVersionOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: policy.Arn,
			})
			if err != nil {
				fmt.Printf("[WARN] Could not get policy details for %s: %v\n", policyName, err)
			} else {
				defaultVersionId := *policyVersionOutput.Policy.DefaultVersionId
				policyVersion, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
					PolicyArn: policy.Arn,
					VersionId: &defaultVersionId,
				})
				if err != nil {
					fmt.Printf("[WARN] Could not get policy version for %s: %v\n", policyName, err)
				} else {
					decodedDoc, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
					if err != nil {
						fmt.Printf("[WARN] Could not decode policy document for %s: %v\n", policyName, err)
					} else {
						var doc PolicyDocument
						err = json.Unmarshal([]byte(decodedDoc), &doc)
						if err != nil {
							fmt.Printf("[WARN] Could not parse policy document for %s: %v\n", policyName, err)
						} else {
							printPolicyDetails(policyName, doc)
						}
					}
				}
			}
		}

		// Violation check #1: Policies with "AdministratorAccess" in their name.
		if strings.Contains(policyName, "AdministratorAccess") {
			issue := fmt.Sprintf("Policy %s is overly permissive", policyName)
			tfRec := fmt.Sprintf(`resource "aws_iam_policy" "%s_tightened" {
  name   = "%s_Tightened"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
         "s3:ListBucket",
         "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}`, strings.ToLower(policyName), policyName)
			violations = append(violations, Violation{
				Issue:        issue,
				ResourceType: "IAM Policy",
				ResourceName: policyName,
				TerraformRec: tfRec,
			})
		}

		// Violation check #2: Policies that allow wildcard "*" actions.
		policyVersionOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: policy.Arn,
		})
		if err != nil {
			fmt.Printf("[WARN] Could not get policy details for %s: %v\n", policyName, err)
			continue
		}

		defaultVersionId := *policyVersionOutput.Policy.DefaultVersionId
		policyVersion, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: &defaultVersionId,
		})
		if err != nil {
			fmt.Printf("[WARN] Could not get policy version for %s: %v\n", policyName, err)
			continue
		}

		decodedDoc, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
		if err != nil {
			fmt.Printf("[WARN] Could not decode policy document for %s: %v\n", policyName, err)
			continue
		}

		var doc PolicyDocument
		err = json.Unmarshal([]byte(decodedDoc), &doc)
		if err != nil {
			fmt.Printf("[WARN] Could not parse policy document for %s: %v\n", policyName, err)
			continue
		}

		if checkPolicyForWildcard(doc) {
			issue := fmt.Sprintf("Policy %s allows wildcard actions", policyName)
			tfRec := fmt.Sprintf(`resource "aws_iam_policy" "%s_restricted" {
  name   = "%s_Restricted"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
         "s3:ListBucket",
         "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}`, strings.ToLower(policyName), policyName)
			violations = append(violations, Violation{
				Issue:        issue,
				ResourceType: "IAM Policy",
				ResourceName: policyName,
				TerraformRec: tfRec,
			})
		}
	}

	return violations, nil
}

func main() {
	terraformOutput := flag.Bool("terraform", false, "Output Terraform recommendations for remediation")
	verbose := flag.Bool("verbose", false, "Output detailed policy document information")
	profile := flag.String("profile", "", "AWS profile to use for the audit")
	flag.Parse()

	ctx := context.Background()

	// Load the AWS default config, using the specified profile if provided.
	var cfgOpts []func(*config.LoadOptions) error
	if *profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(*profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		log.Fatalf("unable to load SDK config: %v", err)
	}

	client := iam.NewFromConfig(cfg)

	violations, err := auditIAM(ctx, client, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during audit: %v\n", err)
		os.Exit(1)
	}

	// Print generic recommendations.
	fmt.Println("\n=== Recommendations ===")
	fmt.Println("- Regularly review IAM roles and policies.")
	fmt.Println("- Follow the principle of least privilege.")
	fmt.Println("- Remove or restrict any overly permissive roles or policies.")
	fmt.Println("- Use AWS IAM Access Analyzer and AWS Config for continuous monitoring.")

	if len(violations) == 0 {
		fmt.Println("\nNo serious IAM violations detected.")
	} else {
		fmt.Println("\n=== Detected Violations ===")
		for _, v := range violations {
			fmt.Printf("- %s\n", v.Issue)
		}
	}

	// Output Terraform recommendations if the flag is set.
	if *terraformOutput {
		fmt.Println("\n=== Terraform Recommendations ===")
		for _, v := range violations {
			fmt.Println("----")
			fmt.Printf("# %s (%s)\n", v.Issue, v.ResourceType)
			fmt.Println(v.TerraformRec)
			fmt.Println()
		}
	}
}

//
// go get github.com/aws/aws-sdk-go-v2
// go get github.com/aws/aws-sdk-go-v2/config
// go get github.com/aws/aws-sdk-go-v2/service/iam
//
// ./iam-audit --terraform --verbose --profile YOUR-SPECIAL-PROFILE
//
