# AWS IAM Policy for Network-Based Access Control

## Current Policy Overview
The policy examples I've shared focus on:
- Restricting AWS service usage (limiting to specific instance types)
- Enforcing regional boundaries
- Preventing costly resource provisioning
- Protecting security services from modification
- Preventing data exposure

## Adding Network-Based Access Controls

To restrict access to only users connecting from your trusted VPNs or VPC, you need to implement IP-based or VPC endpoint-based conditions. Here's how:

### Option 1: IP-Based Access Control
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAccessFromUntrustedNetworks",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "NotIpAddress": {
                    "aws:SourceIp": [
                        "203.0.113.0/24",    // Your VPN IP range
                        "198.51.100.0/24"    // Your office IP range
                    ]
                },
                "Bool": {
                    "aws:ViaAWSService": "false"
                }
            }
        }
    ]
}
```

### Option 2: VPC Endpoint Access Control
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowVPCEndpointOnly",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:SourceVpc": [
                        "vpc-12345678",      // Your trusted VPC
                        "vpc-87654321"       // Another trusted VPC
                    ]
                },
                "Null": {
                    "aws:SourceVpc": "true"
                }
            }
        }
    ]
}
```

### Option 3: Combining with AWS Organizations SCPs
For organization-wide enforcement:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "RequireIdentityWithinTrustedNetwork",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "NotIpAddress": {
                    "aws:SourceIp": [
                        "10.0.0.0/8",        // Private VPC CIDR blocks
                        "203.0.113.0/24"     // VPN gateway
                    ]
                },
                "Bool": {
                    "aws:ViaAWSService": "false"
                },
                "ArnNotLike": {
                    "aws:PrincipalARN": [
                        "arn:aws:iam::*:role/AWS*",  // Allow AWS service roles
                        "arn:aws:iam::*:role/Service*"
                    ]
                }
            }
        }
    ]
}
```

## Implementation Strategy

1. **For IAM users accessing AWS Console:**
   - Apply the IP-based restrictions (Option 1) to enforce they only connect from trusted networks

2. **For EC2 instances or Lambda accessing AWS APIs:**
   - Use VPC endpoint access control (Option 2) to ensure access only from trusted VPCs

3. **For both approaches:**
   - Test thoroughly before deployment
   - Include exceptions for emergency access accounts
   - Consider the `aws:ViaAWSService` condition to prevent blocking legitimate service-to-service calls

4. **Deployment options:**
   - Apply as IAM boundary policies for specific users/roles
   - Apply as AWS Organizations SCPs for organization-wide enforcement
   - Combine with AWS IAM Identity Center (SSO) for centralized access control



```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyIAMUserAccessFromUntrustedNetworks",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "NotIpAddress": {
                    "aws:SourceIp": [
                        "203.0.113.0/24",    // Your corporate IP range
                        "198.51.100.0/24",   // Your VPN IP range
                        "192.0.2.0/24"       // Another trusted network
                    ]
                },
                "StringLike": {
                    "aws:userId": "*:*"      // Only matches IAM users (not roles)
                }
            }
        }
    ]
}
