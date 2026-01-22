## 📚 **Official Documentation Sources**

### **1. Terraform AWS Provider - WAF v2 Resource**
🔗 **Primary Source**: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl

This is the **source of truth** for all Terraform syntax.

### **2. AWS WAF API Reference**
🔗 https://docs.aws.amazon.com/waf/latest/APIReference/API_WebACL.html

Backend API that Terraform calls.

### **3. AWS WAF Developer Guide**
🔗 https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-use.html

Business logic and examples.

---

## ✅ **Syntax Validation: Excluded Rules**

### **Terraform Documentation Proof**

From: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#managed_rule_group_statement

```hcl
managed_rule_group_statement {
  name        = "AWSManagedRulesCommonRuleSet"
  vendor_name = "AWS"

  # ✅ OFFICIAL SYNTAX: excluded_rule block
  excluded_rule {
    name = "SizeRestrictions_BODY"
  }
  
  excluded_rule {
    name = "GenericRFI_QUERYARGUMENTS"
  }
}
```

**Direct quote from Terraform docs:**
> `excluded_rule` - (Optional) Rules in the referenced rule group whose actions are set to Count. See `excluded_rule` below for details.

**Structure:**
```hcl
excluded_rule {
  name = (Required) The name of the rule whose action you want to override to Count.
}
```

### **Our Dynamic Implementation**

```hcl
# Our Terraform code - VALID ✅
dynamic "excluded_rule" {
  for_each = try(rule.value.excluded_rules, [])
  content {
    name = excluded_rule.value
  }
}
```

**This is valid because:**
- `excluded_rule` is an official block type (documented above)
- `name` is the required argument (documented above)
- `dynamic` blocks are standard Terraform syntax for iteration

---

## ✅ **Syntax Validation: Rule Action Overrides**

### **Terraform Documentation Proof**

From: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#rule_action_override

```hcl
managed_rule_group_statement {
  name        = "AWSManagedRulesCommonRuleSet"
  vendor_name = "AWS"

  # ✅ OFFICIAL SYNTAX: rule_action_override block
  rule_action_override {
    name = "SizeRestrictions_BODY"
    
    action_to_use {
      count {}
    }
  }
}
```

**Direct quote from Terraform docs:**
> `rule_action_override` - (Optional) Action settings to use in the place of the rule actions that are configured inside the rule group. You specify one override for each rule whose action you want to change. See `rule_action_override` below for details.

**Structure:**
```hcl
rule_action_override {
  name = (Required) The name of the rule to override.
  
  action_to_use {
    # One of: allow, block, count, captcha, challenge
    count {}
    # OR
    allow {}
    # OR
    block {}
  }
}
```

### **Our Dynamic Implementation**

```hcl
# Our Terraform code - VALID ✅
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
```

**This is valid because:**
- `rule_action_override` is an official block (documented above)
- `name` is required (documented above)
- `action_to_use` must contain exactly one action type (documented above)
- We use `dynamic` to conditionally create the correct action block

---

## ✅ **Syntax Validation: Scope Down Statement**

### **Terraform Documentation Proof**

From: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#scope_down_statement

```hcl
managed_rule_group_statement {
  name        = "AWSManagedRulesCommonRuleSet"
  vendor_name = "AWS"

  # ✅ OFFICIAL SYNTAX: scope_down_statement
  scope_down_statement {
    byte_match_statement {
      search_string         = "/api/upload"
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
}
```

**Direct quote from Terraform docs:**
> `scope_down_statement` - (Optional) Narrows the scope of the statement to matching web requests. This can be any nestable statement, and you can nest statements at any level below this scope-down statement. See `statement` above for details.

**Supported statements inside `scope_down_statement`:**
- `byte_match_statement`
- `geo_match_statement`
- `ip_set_reference_statement`
- `regex_pattern_set_reference_statement`
- `size_constraint_statement`
- `sqli_match_statement`
- `xss_match_statement`
- `and_statement` / `or_statement` / `not_statement`

### **Field to Match Options**

From: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#field_to_match

```hcl
field_to_match {
  # One of:
  uri_path {}
  
  query_string {}
  
  method {}
  
  single_header {
    name = "content-type"
  }
  
  body {
    oversize_handling = "CONTINUE"  # or "MATCH"
  }
  
  cookies {
    match_pattern {
      all {}
    }
    match_scope       = "ALL"
    oversize_handling = "CONTINUE"
  }
}
```

### **Our Simplified Implementation**

```hcl
# Our Terraform code - VALID ✅
dynamic "scope_down_statement" {
  for_each = try(rule.value.scope_down_statement, null) != null ? [1] : []
  content {
    
    # URI path matching
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
  }
}
```

**This is valid because:**
- `scope_down_statement` is documented (above)
- `byte_match_statement` is a valid nested statement
- `positional_constraint = "STARTS_WITH"` is documented as valid option
- `field_to_match { uri_path {} }` is documented (above)
- `text_transformation` is required (at least one, documented)

---

## 🔍 **Complete Validated Example**

Here's a **fully documented, syntax-validated** example:

```hcl
resource "aws_wafv2_web_acl" "example" {
  name  = "example-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # ===== MANAGED RULE GROUP WITH ALL FEATURES =====
  rule {
    name     = "AWS-CommonRuleSet"
    priority = 1

    # Override action: "none" means enforce, "count" means log only
    # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#override_action
    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # ===== FEATURE 1: EXCLUDED RULES =====
        # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#excluded_rule
        # Quote: "Rules in the referenced rule group whose actions are set to Count"
        excluded_rule {
          name = "SizeRestrictions_BODY"
        }

        excluded_rule {
          name = "EC2MetaDataSSRF_QUERYARGUMENTS"
        }

        # ===== FEATURE 2: RULE ACTION OVERRIDES =====
        # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#rule_action_override
        # Quote: "Action settings to use in the place of the rule actions"
        rule_action_override {
          name = "GenericRFI_QUERYARGUMENTS"

          action_to_use {
            count {}  # Override to count instead of block
          }
        }

        # ===== FEATURE 3: SCOPE DOWN STATEMENT =====
        # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#scope_down_statement
        # Quote: "Narrows the scope of the statement to matching web requests"
        scope_down_statement {
          # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#byte_match_statement
          byte_match_statement {
            search_string         = "/api/upload"
            positional_constraint = "STARTS_WITH"  # Valid: EXACTLY, STARTS_WITH, ENDS_WITH, CONTAINS, CONTAINS_WORD

            # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#field_to_match
            field_to_match {
              uri_path {}
            }

            # Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#text_transformation
            # Quote: "At least one transformation is required"
            text_transformation {
              priority = 0
              type     = "NONE"  # Valid: NONE, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE, LOWERCASE, etc.
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "example-web-acl"
    sampled_requests_enabled   = true
  }
}
```

---

## 🧪 **Testing Syntax Validity**

### **Method 1: Terraform Validate**

```bash
# Create test configuration
cat > test.tf <<'EOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-1"
}

resource "aws_wafv2_web_acl" "test" {
  name  = "test-syntax"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "test-rule"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # Test excluded_rule syntax
        excluded_rule {
          name = "SizeRestrictions_BODY"
        }

        # Test rule_action_override syntax
        rule_action_override {
          name = "GenericRFI_QUERYARGUMENTS"
          action_to_use {
            count {}
          }
        }

        # Test scope_down_statement syntax
        scope_down_statement {
          byte_match_statement {
            search_string         = "/test"
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
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "test"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "test-acl"
    sampled_requests_enabled   = true
  }
}
EOF

# Validate syntax
terraform init
terraform validate

# Check provider schema
terraform providers schema -json | jq '.provider_schemas."registry.terraform.io/hashicorp/aws".resource_schemas.aws_wafv2_web_acl'
```

**Expected output:**
```
Success! The configuration is valid.
```

### **Method 2: AWS CLI Dry-Run**

Unfortunately, AWS WAF doesn't support dry-run, but you can test in a sandbox account:

```bash
# Create minimal test Web ACL
aws wafv2 create-web-acl \
  --scope REGIONAL \
  --region us-west-1 \
  --name test-exclusions \
  --default-action Allow={} \
  --visibility-config \
    SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=test \
  --rules file://test-rule.json

# test-rule.json:
{
  "Name": "test-common-rules",
  "Priority": 1,
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesCommonRuleSet",
      "ExcludedRules": [
        {"Name": "SizeRestrictions_BODY"}
      ],
      "RuleActionOverrides": [
        {
          "Name": "GenericRFI_QUERYARGUMENTS",
          "ActionToUse": {"Count": {}}
        }
      ],
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/test",
          "FieldToMatch": {"UriPath": {}},
          "TextTransformations": [
            {"Priority": 0, "Type": "NONE"}
          ],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "OverrideAction": {"None": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "test-rule"
  }
}
```

---

## 📖 **Cross-Reference Table**

| Feature | Terraform Syntax | AWS API Equivalent | Documentation |
|---------|------------------|-------------------|---------------|
| Excluded Rules | `excluded_rule { name = "..." }` | `ExcludedRules: [{Name: "..."}]` | [Link](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#excluded_rule) |
| Rule Action Overrides | `rule_action_override { ... }` | `RuleActionOverrides: [...]` | [Link](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#rule_action_override) |
| Scope Down | `scope_down_statement { ... }` | `ScopeDownStatement: {...}` | [Link](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#scope_down_statement) |
| Byte Match | `byte_match_statement { ... }` | `ByteMatchStatement: {...}` | [Link](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#byte_match_statement) |
| URI Path Field | `field_to_match { uri_path {} }` | `FieldToMatch: {UriPath: {}}` | [Link](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#field_to_match) |

---

## ✅ **Verification Checklist**

Before deploying, verify:

- [ ] **Terraform version** >= 1.3 (for `optional()` type)
  ```bash
  terraform version  # Should be >= 1.3.0
  ```

- [ ] **AWS Provider version** >= 4.0 (for full WAF v2 support)
  ```bash
  grep 'version.*aws' versions.tf  # Should be ~> 4.0 or ~> 5.0
  ```

- [ ] **Syntax validation** passes
  ```bash
  terraform validate  # Should return "Success!"
  ```

- [ ] **Plan shows expected changes**
  ```bash
  terraform plan | grep "excluded_rule\|rule_action_override"
  ```

- [ ] **Documentation links** saved for reference
  - Bookmark: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl
  - Save to wiki/confluence

---

## 🎓 **Key Takeaways**

1. **Every block type is officially documented** in Terraform AWS provider docs
2. **Dynamic blocks** are standard Terraform feature for iteration
3. **Syntax maps 1:1** to AWS API (Terraform is just a wrapper)
4. **Test in sandbox** before production deployment
5. **Keep documentation links** in your code comments
