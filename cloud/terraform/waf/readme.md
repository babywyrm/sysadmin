# WAF Module Enhancement Guide: Adding Rule Exclusions & Overrides

## 📋 **Overview**

This guide shows how to update your ALB/WAF Terraform module to support:
1. **Excluded Rules** - Completely disable specific rules
2. **Rule Action Overrides** - Change specific rule actions (block → count)
3. **Scope-Based Exclusions** - Apply exclusions only to specific paths/conditions

---

## 🔍 **Step 1: Locate Your Module**

```bash
# Find the WAF module
find stacks/loadbalancing -name "*.tf" -exec grep -l "aws_wafv2_web_acl" {} \;

# Common locations:
# - stacks/loadbalancing/modules/waf/
# - stacks/loadbalancing/modules/alb-waf/
# - stacks/loadbalancing/terraform-modules/waf/
```

Expected structure:
```
modules/waf/
├── main.tf           # Resource definitions
├── variables.tf      # Input variables
├── outputs.tf        # Output values
└── versions.tf       # Provider requirements
```

---

## 🛠️ **Step 2: Update Module Variables**

### **File: `modules/waf/variables.tf`**

**BEFORE:**
```hcl
variable "waf_managed_rules" {
  description = "List of AWS managed rule groups"
  type = list(object({
    vendor_name     = string
    name            = string
    priority        = number
    override_action = string
  }))
  default = []
}
```

**AFTER (Enhanced):**
```hcl
variable "waf_managed_rules" {
  description = "List of AWS managed rule groups with exclusions and overrides"
  type = list(object({
    vendor_name     = string
    name            = string
    priority        = number
    override_action = string
    
    # NEW: Completely exclude specific rules
    excluded_rules = optional(list(string), [])
    
    # NEW: Override actions for specific rules
    rule_action_overrides = optional(list(object({
      name          = string
      action_type   = string  # "count", "allow", "block"
    })), [])
    
    # NEW: Scope down statement (apply rule only to specific conditions)
    scope_down_statement = optional(object({
      uri_path_match = optional(object({
        starts_with = optional(list(string), [])
        equals      = optional(list(string), [])
        contains    = optional(list(string), [])
      }), null)
      
      method_match = optional(list(string), [])  # ["POST", "PUT"]
      
      header_match = optional(object({
        name  = string
        value = string
      }), null)
    }), null)
  }))
  default = []
  
  validation {
    condition = alltrue([
      for rule in var.waf_managed_rules : 
      contains(["none", "count"], rule.override_action)
    ])
    error_message = "override_action must be 'none' or 'count'"
  }
}
```

---

## 🔧 **Step 3: Update Module Main Resource**

### **File: `modules/waf/main.tf`**

Replace your existing `aws_wafv2_web_acl` resource with this enhanced version:

```hcl
resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = var.description
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Managed rule groups with full customization support
  dynamic "rule" {
    for_each = var.waf_managed_rules
    content {
      name     = "${rule.value.vendor_name}-${rule.value.name}"
      priority = rule.value.priority

      # Override action (none = enforce, count = log only)
      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = rule.value.vendor_name
          name        = rule.value.name

          # ===== FEATURE 1: EXCLUDED RULES =====
          # Completely disable specific rules in the rule group
          dynamic "excluded_rule" {
            for_each = try(rule.value.excluded_rules, [])
            content {
              name = excluded_rule.value
            }
          }

          # ===== FEATURE 2: RULE ACTION OVERRIDES =====
          # Change action for specific rules (e.g., block → count)
          dynamic "rule_action_override" {
            for_each = try(rule.value.rule_action_overrides, [])
            content {
              name = rule_action_override.value.name

              action_to_use {
                dynamic "count" {
                  for_each = rule_action_override.value.action_type == "count" ? [1] : []
                  content {}
                }
                dynamic "allow" {
                  for_each = rule_action_override.value.action_type == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value.action_type == "block" ? [1] : []
                  content {}
                }
              }
            }
          }

          # ===== FEATURE 3: SCOPE DOWN STATEMENT =====
          # Apply rule group only to specific requests
          dynamic "scope_down_statement" {
            for_each = try(rule.value.scope_down_statement, null) != null ? [1] : []
            content {
              
              # URI Path matching
              dynamic "byte_match_statement" {
                for_each = try(rule.value.scope_down_statement.uri_path_match.starts_with, [])
                content {
                  search_string         = byte_match_statement.value
                  positional_constraint = "STARTS_WITH"
                  
                  field_to_match {
                    uri_path {}
                  }
                  
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              # Method matching (POST, PUT, etc.)
              dynamic "byte_match_statement" {
                for_each = length(try(rule.value.scope_down_statement.method_match, [])) > 0 ? [1] : []
                content {
                  search_string         = join("|", rule.value.scope_down_statement.method_match)
                  positional_constraint = "EXACTLY"
                  
                  field_to_match {
                    method {}
                  }
                  
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              # Header matching
              dynamic "byte_match_statement" {
                for_each = try(rule.value.scope_down_statement.header_match, null) != null ? [1] : []
                content {
                  search_string         = rule.value.scope_down_statement.header_match.value
                  positional_constraint = "CONTAINS"
                  
                  field_to_match {
                    single_header {
                      name = rule.value.scope_down_statement.header_match.name
                    }
                  }
                  
                  text_transformation {
                    priority = 0
                    type     = "LOWERCASE"
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${rule.value.vendor_name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  # Add your custom rules, rate limiting, geo-blocking here...
  # (existing code)

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }

  tags = var.tags
}
```

---

## 📝 **Step 4: Usage Examples**

Now you can use all three features in your stack configuration:

### **File: `stacks/loadbalancing/layers/stg-sfo2/lb-vips-eks.tf`**

```hcl
locals {
  vips = {
    "app" = {
      owner                       = "shared"
      waf_rules                   = ["Allowed", "Blocked", "Sanctioned"]
      waf_geo_block_country_codes = ["RU"]
      waf_managed_rules = [
        
        # ===== EXAMPLE 1: SIMPLE RULE (No Exclusions) =====
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesAmazonIpReputationList"
          priority        = 10
          override_action = "none"  # Block malicious IPs
        },

        # ===== EXAMPLE 2: EXCLUDED RULES =====
        # Completely disable specific rules in the Common Rule Set
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesCommonRuleSet"
          priority        = 12
          override_action = "none"
          
          # Disable these rules entirely
          excluded_rules = [
            "SizeRestrictions_BODY",              # Allow large uploads
            "EC2MetaDataSSRF_QUERYARGUMENTS",     # App passes URLs in params
            "GenericRFI_QUERYARGUMENTS",          # Legitimate external URLs
            "EC2MetaDataSSRF_COOKIE"              # Legacy cookie usage
          ]
        },

        # ===== EXAMPLE 3: RULE ACTION OVERRIDES =====
        # Keep rules active but change specific ones to COUNT mode
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesSQLiRuleSet"
          priority        = 14
          override_action = "none"  # Block by default
          
          # Override specific rules to COUNT (test for false positives)
          rule_action_overrides = [
            {
              name        = "SQLi_QUERYARGUMENTS"
              action_type = "count"  # Log but don't block
            },
            {
              name        = "SQLiExtendedPatterns_QUERYARGUMENTS"
              action_type = "count"
            }
          ]
        },

        # ===== EXAMPLE 4: SCOPE-BASED EXCLUSIONS =====
        # Apply exclusions only to specific endpoints
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesCommonRuleSet"
          priority        = 12
          override_action = "none"
          
          # Exclude body size restriction ONLY for upload endpoints
          excluded_rules = [
            "SizeRestrictions_BODY"
          ]
          
          # Apply exclusion only to these paths
          scope_down_statement = {
            uri_path_match = {
              starts_with = [
                "/api/v1/upload",
                "/api/v2/bulk-import",
                "/webhooks/ingest"
              ]
            }
            method_match = ["POST", "PUT"]
          }
        },

        # ===== EXAMPLE 5: COMPLEX COMBINED CONFIGURATION =====
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesKnownBadInputsRuleSet"
          priority        = 13
          override_action = "none"
          
          # Exclude rules that cause false positives
          excluded_rules = [
            "JavaDeserializationRCE_BODY"
          ]
          
          # Override specific rules to count mode
          rule_action_overrides = [
            {
              name        = "Log4JRCE_HEADER"
              action_type = "count"
            }
          ]
          
          # Only apply to admin endpoints
          scope_down_statement = {
            uri_path_match = {
              starts_with = ["/admin"]
            }
            header_match = {
              name  = "x-admin-token"
              value = "present"
            }
          }
        },

        # ===== EXAMPLE 6: TESTING MODE =====
        # Enable rule group in COUNT mode for initial testing
        {
          vendor_name     = "AWS"
          name            = "AWSManagedRulesLinuxRuleSet"
          priority        = 15
          override_action = "count"  # Log all matches, don't block
          
          # No exclusions needed - we're just testing
        }
      ]
    }
  }
}

module "alb_waf" {
  source = "../../modules/waf"
  
  for_each = local.vips
  
  name              = "alb-waf-web-acl-${each.key}-eks1"
  waf_managed_rules = each.value.waf_managed_rules
  # ... other variables
}
```

---

## 🧪 **Step 5: Testing & Validation**

### **A. Validate Terraform Configuration**

```bash
cd stacks/loadbalancing/layers/stg-sfo2

# Check syntax
terraform validate

# Preview changes
terraform plan -out=tfplan

# Review what will change
terraform show tfplan | grep -A 20 "aws_wafv2_web_acl"
```

### **B. Verify Exclusions Were Applied**

```bash
#!/bin/bash
# verify-waf-config.sh

REGION="us-west-1"
PROFILE="dcext-stg"
WEBACL_NAME="alb-waf-web-acl-app-eks1"

echo "🔍 Fetching WAF configuration..."

WEBACL_ID=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --profile "$PROFILE" \
  --query "WebACLs[?Name=='$WEBACL_NAME'].Id" \
  --output text)

if [ -z "$WEBACL_ID" ]; then
  echo "❌ Web ACL not found"
  exit 1
fi

echo "✅ Found Web ACL: $WEBACL_ID"
echo ""

# Get Common Rule Set configuration
echo "📋 Common Rule Set Configuration:"
aws wafv2 get-web-acl \
  --scope REGIONAL \
  --id "$WEBACL_ID" \
  --name "$WEBACL_NAME" \
  --region "$REGION" \
  --profile "$PROFILE" \
  --query 'WebACL.Rules[?Statement.ManagedRuleGroupStatement.Name==`AWSManagedRulesCommonRuleSet`].{
    Name: Statement.ManagedRuleGroupStatement.Name,
    OverrideAction: OverrideAction,
    ExcludedRules: Statement.ManagedRuleGroupStatement.ExcludedRules[].Name,
    RuleActionOverrides: Statement.ManagedRuleGroupStatement.RuleActionOverrides[].{Rule: Name, Action: ActionToUse},
    ScopeDown: Statement.ManagedRuleGroupStatement.ScopeDownStatement
  }' \
  --output json | jq '.'

# Check all rule groups
echo ""
echo "📊 All Managed Rule Groups:"
aws wafv2 get-web-acl \
  --scope REGIONAL \
  --id "$WEBACL_ID" \
  --name "$WEBACL_NAME" \
  --region "$REGION" \
  --profile "$PROFILE" \
  --query 'WebACL.Rules[?Statement.ManagedRuleGroupStatement].{
    Priority: Priority,
    Name: Statement.ManagedRuleGroupStatement.Name,
    Action: OverrideAction,
    ExcludedCount: length(Statement.ManagedRuleGroupStatement.ExcludedRules),
    OverrideCount: length(Statement.ManagedRuleGroupStatement.RuleActionOverrides)
  }' \
  --output table
```

**Expected output:**
```
✅ Found Web ACL: 12345678-abcd-efgh-ijkl-123456789012

📋 Common Rule Set Configuration:
[
  {
    "Name": "AWSManagedRulesCommonRuleSet",
    "OverrideAction": {
      "None": {}
    },
    "ExcludedRules": [
      "SizeRestrictions_BODY",
      "EC2MetaDataSSRF_QUERYARGUMENTS",
      "GenericRFI_QUERYARGUMENTS",
      "EC2MetaDataSSRF_COOKIE"
    ],
    "RuleActionOverrides": [],
    "ScopeDown": null
  }
]

📊 All Managed Rule Groups:
--------------------------------------------------------
|  Priority  |  Name                    |  Action     |
--------------------------------------------------------
|  10        |  AmazonIpReputationList  |  none       |
|  12        |  CommonRuleSet           |  none       |
|  13        |  KnownBadInputs          |  none       |
|  14        |  SQLiRuleSet             |  none       |
--------------------------------------------------------
```

---

## 📊 **Step 6: Monitoring & Tuning**

### **Create CloudWatch Dashboard**

```hcl
# modules/waf/cloudwatch.tf (new file)

resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "${var.name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", { stat = "Sum" }],
            [".", "BlockedRequests", { stat = "Sum" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.region
          title  = "WAF Request Status"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            for rule in var.waf_managed_rules : [
              "AWS/WAFV2",
              "CountedRequests",
              "Rule",
              "${rule.vendor_name}-${rule.name}",
              { stat = "Sum" }
            ]
          ]
          period = 300
          stat   = "Sum"
          region = var.region
          title  = "Matched Requests by Rule"
        }
      }
    ]
  })
}
```

### **Set Up Alerts**

```hcl
# modules/waf/alarms.tf (new file)

resource "aws_cloudwatch_metric_alarm" "high_block_rate" {
  alarm_name          = "${var.name}-high-block-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 1000
  alarm_description   = "WAF blocking >1000 requests per 5 min"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.this.name
    Region = var.region
  }

  alarm_actions = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "excluded_rule_activity" {
  for_each = toset(flatten([
    for rule in var.waf_managed_rules : 
    rule.excluded_rules if length(rule.excluded_rules) > 0
  ]))

  alarm_name          = "${var.name}-excluded-${each.key}-active"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CountedRequests"
  namespace           = "AWS/WAFV2"
  period              = 3600
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Excluded rule ${each.key} would have matched requests"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.this.name
    Rule   = each.key
    Region = var.region
  }

  alarm_actions = [var.sns_topic_arn]
}
```

---

## 🔄 **Step 7: Rollout Strategy**

### **Phase 1: Deploy with COUNT Mode (Week 1)**

```hcl
{
  vendor_name     = "AWS"
  name            = "AWSManagedRulesCommonRuleSet"
  priority        = 12
  override_action = "count"  # Safe testing mode
  excluded_rules  = []       # No exclusions yet
}
```

- Monitor CloudWatch for false positives
- Analyze WAF logs in S3/Athena
- Identify rules that need exclusions

### **Phase 2: Add Exclusions in COUNT Mode (Week 2)**

```hcl
{
  vendor_name     = "AWS"
  name            = "AWSManagedRulesCommonRuleSet"
  priority        = 12
  override_action = "count"  # Still testing
  excluded_rules  = [
    "SizeRestrictions_BODY"  # Identified as needed
  ]
}
```

- Verify exclusions work as expected
- Monitor for any unexpected behavior

### **Phase 3: Enable Blocking (Week 3)**

```hcl
{
  vendor_name     = "AWS"
  name            = "AWSManagedRulesCommonRuleSet"
  priority        = 12
  override_action = "none"  # Enable blocking!
  excluded_rules  = [
    "SizeRestrictions_BODY"
  ]
}
```

- Monitor error rates closely
- Have rollback plan ready
- Communicate with stakeholders

### **Phase 4: Fine-Tune (Week 4+)**

```hcl
{
  vendor_name     = "AWS"
  name            = "AWSManagedRulesCommonRuleSet"
  priority        = 12
  override_action = "none"
  
  excluded_rules = [
    "SizeRestrictions_BODY"
  ]
  
  # Add scope-based exclusions for precision
  scope_down_statement = {
    uri_path_match = {
      starts_with = ["/api/v1/upload"]
    }
  }
}
```

---

## 📚 **Step 8: Documentation Template**

Create `docs/waf-exclusions.md` in your repo:

```markdown
# WAF Rule Exclusions Documentation

## Overview
This document tracks all WAF rule exclusions and their justifications.

## Excluded Rules

### SizeRestrictions_BODY
- **Ticket**: PRODENG-1280
- **Date Added**: 2025-01-21
- **Reason**: File upload endpoint requires >8KB request bodies
- **Scope**: `/api/v1/upload`, `/api/v2/bulk-import`
- **Security Mitigation**: Application-level size validation in place (max 50MB)
- **Review Date**: 2025-04-21

### EC2MetaDataSSRF_QUERYARGUMENTS
- **Ticket**: PRODENG-1281
- **Date Added**: 2025-01-21
- **Reason**: Legacy API passes callback URLs in query params
- **Scope**: Global (all endpoints)
- **Security Mitigation**: Backend URL validation whitelist implemented
- **Review Date**: 2025-03-21 (Plan to remove after refactor)

## Review Process
- Exclusions reviewed quarterly
- Security team approval required for SSRF/RFI exclusions
- Metrics tracked: false positive rate, security incidents

## Monitoring
- CloudWatch Dashboard: https://console.aws.amazon.com/cloudwatch/...
- WAF Logs: s3://waf-logs-bucket/AWSLogs/...
```

---

## ✅ **Summary Checklist**

- [ ] Updated `modules/waf/variables.tf` with new optional fields
- [ ] Enhanced `modules/waf/main.tf` with excluded_rules, rule_action_overrides, scope_down_statement
- [ ] Created verification script (`verify-waf-config.sh`)
- [ ] Configured CloudWatch dashboard and alarms
- [ ] Documented exclusions in `docs/waf-exclusions.md`
- [ ] Tested in staging environment
- [ ] Scheduled quarterly review process
- [ ] Got security team approval for SSRF/RFI exclusions
- [ ] Ready to deploy to production! 🚀

---

## 🆘 **Troubleshooting**

### **Error: "Invalid type for variable"**
```
Error: Invalid type for variable
  on variables.tf line 10:
  10: variable "waf_managed_rules" {
```

**Solution**: You need Terraform >= 1.3 for `optional()` type constraints.

```bash
# Check version
terraform version

# Upgrade if needed
brew upgrade terraform  # macOS
# or download from https://www.terraform.io/downloads
```

### **Exclusions not showing in AWS Console**

**Debug:**
```bash
# Check Terraform state
terraform state show 'module.waf.aws_wafv2_web_acl.this'

# Verify API response
aws wafv2 get-web-acl --scope REGIONAL --id <id> --name <name> | jq '.WebACL.Rules[].Statement.ManagedRuleGroupStatement.ExcludedRules'
```

### **Rules still blocking despite exclusions**

1. Check you're using `override_action = "none"` (not "count")
2. Verify rule names match exactly (case-sensitive!)
3. Wait 1-2 minutes for propagation
4. Check CloudWatch metrics for confirmation

---

