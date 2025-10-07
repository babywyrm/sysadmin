# 🛡️ Kubernetes YAML Security Training Guide

A comprehensive collection of vulnerable YAML patterns and their defensive countermeasures for internal security training.. (..RC1..)

## 📋 Table of Contents

1. [Metadata Injection Vulnerabilities](#1-metadata-injection-vulnerabilities)
2. [API Version Validation Issues](#2-api-version-validation-issues)
3. [Resource Name Security](#3-resource-name-security)
4. [Multi-Document Manifest Risks](#4-multi-document-manifest-risks)
5. [ConfigMap Data Security](#5-configmap-data-security)
6. [Template Injection Risks](#6-template-injection-risks)
7. [JSON Patch Security](#7-json-patch-security)
8. [Schema Validation Bypass](#8-schema-validation-bypass)
9. [CRD Security Considerations](#9-crd-security-considerations)
10. [Error Information Disclosure](#10-error-information-disclosure)
11. [Templating Security](#11-templating-security)
12. [Race Condition Prevention](#12-race-condition-prevention)

---

## 1. Metadata Injection Vulnerabilities

### ❌ Vulnerable Pattern
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: user-input-$(untrusted-data)
spec:
  containers:
  - name: container
    image: busybox
```

### ✅ Secure Implementation
```yaml
# Input validation function
def validate_resource_name(name):
    import re
    # RFC 1123 compliant names only
    pattern = r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
    if not re.match(pattern, name) or len(name) > 63:
        raise ValueError("Invalid resource name")
    return name
```

### 🔍 Detection Rules
```yaml
# OPA Gatekeeper Policy
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: blockmetadatainjection
spec:
  crd:
    spec:
      targets:
        - target: admission.k8s.gatekeeper.sh
          rego: |
            package metadatainjection
            violation[{"msg": msg}] {
              contains(input.review.object.metadata.name, "$")
              msg := "Resource names cannot contain shell expansion characters"
            }
```

---

## 2. API Version Validation Issues

### ❌ Vulnerable Pattern
```yaml
apiVersion: $(malicious-command)
kind: Pod
metadata:
  name: test
```

### ✅ Secure Implementation
```python
# Server-side validation
ALLOWED_API_VERSIONS = {
    "v1", "apps/v1", "batch/v1", "networking.k8s.io/v1"
}

def validate_api_version(api_version):
    if api_version not in ALLOWED_API_VERSIONS:
        raise ValidationError(f"Unsupported API version: {api_version}")
    return api_version
```

### 🔍 Admission Controller
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: api-version-validator
webhooks:
- name: validate-api-version
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
```

---

## 3. Resource Name Security

### ❌ Vulnerable Pattern
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${USER_INPUT}
data:
  config: "value"
```

### ✅ Secure Implementation
```python
def sanitize_resource_name(user_input):
    import re
    # Remove special characters and normalize
    sanitized = re.sub(r'[^a-z0-9-]', '', user_input.lower())
    # Ensure it starts and ends with alphanumeric
    sanitized = re.sub(r'^-+|-+$', '', sanitized)
    # Truncate to max length
    return sanitized[:63] if sanitized else "default"
```

### 🛡️ Network Policy
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

---

## 4. Multi-Document Manifest Risks

### ❌ Vulnerable Pattern
```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  secret: |
    $(sensitive-command)
---
apiVersion: v1
kind: Pod
metadata:
  name: pod
```

### ✅ Secure Implementation
```python
def validate_multi_doc_yaml(yaml_content):
    import yaml
    documents = list(yaml.safe_load_all(yaml_content))
    
    for doc in documents:
        # Validate each document independently
        validate_document_schema(doc)
        validate_no_command_injection(doc)
    
    return documents
```

### 🔍 Monitoring Alert
```yaml
# Prometheus Alert Rule
groups:
- name: yaml-security
  rules:
  - alert: SuspiciousYAMLContent
    expr: increase(kubectl_apply_errors[5m]) > 10
    annotations:
      summary: "High rate of YAML parsing errors detected"
```

---

## 5. ConfigMap Data Security

### ❌ Vulnerable Pattern
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: data
data:
  payload: !!binary |
    $(base64 /sensitive/file)
```

### ✅ Secure Implementation
```python
def validate_configmap_data(data):
    for key, value in data.items():
        # Check for shell expansion patterns
        if '$(' in str(value) or '`' in str(value):
            raise SecurityError(f"Shell expansion detected in key: {key}")
        
        # Validate base64 content if binary
        if isinstance(value, str) and value.startswith('!!binary'):
            validate_base64_content(value)
```

### 🔒 Pod Security Policy
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'secret'
    - 'emptyDir'
  runAsUser:
    rule: 'MustRunAsNonRoot'
```

---

## 6. Template Injection Risks

### ❌ Vulnerable Pattern
```bash
kubectl create cm evil --from-literal=data='{{.}}' \
  --dry-run=client -o go-template='{{.data}}' | bash
```

### ✅ Secure Implementation
```python
def safe_template_render(template, context):
    from jinja2 import Environment, select_autoescape
    
    # Create restricted environment
    env = Environment(
        autoescape=select_autoescape(['html', 'xml']),
        # Disable dangerous features
        finalize=str,  # Always stringify output
    )
    
    # Remove dangerous globals
    env.globals.clear()
    
    return env.from_string(template).render(context)
```

---

## 7. JSON Patch Security

### ❌ Vulnerable Pattern
```bash
kubectl patch cm target --type='json' \
  -p="[{'op':'add','path':'/data/exploit','value':'$(cat /secret)'}]"
```

### ✅ Secure Implementation
```python
def validate_json_patch(patch_operations):
    for op in patch_operations:
        # Validate operation type
        if op.get('op') not in ['add', 'remove', 'replace', 'test']:
            raise ValueError(f"Invalid patch operation: {op.get('op')}")
        
        # Validate path
        path = op.get('path', '')
        if not path.startswith('/'):
            raise ValueError("Patch path must start with /")
        
        # Check for command injection in values
        value = str(op.get('value', ''))
        if '$(' in value or '`' in value:
            raise SecurityError("Command injection detected in patch value")
```

---

## 8. Schema Validation Bypass

### ❌ Vulnerable Pattern
```yaml
apiVersion: v1
kind: /etc/passwd
metadata:
  name: invalid-schema
```

### ✅ Secure Implementation
```python
def strict_schema_validation(manifest):
    from jsonschema import validate, ValidationError
    
    # Load Kubernetes API schemas
    schema = load_k8s_schema(manifest['apiVersion'], manifest['kind'])
    
    try:
        validate(instance=manifest, schema=schema)
    except ValidationError as e:
        # Don't expose schema details in error
        raise ValidationError("Invalid manifest structure")
```

---

## 9. CRD Security Considerations

### ❌ Vulnerable Pattern
```yaml
apiVersion: custom.io/v1
kind: CustomResource
spec:
  injected: $(cat /flag)
```

### ✅ Secure CRD Definition
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: secureresources.custom.io
spec:
  group: custom.io
  versions:
  - name: v1
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              data:
                type: string
                pattern: '^[a-zA-Z0-9\s\-\.]+$'  # Restrict to safe characters
                maxLength: 1000
            required:
            - data
```

---

## 10. Error Information Disclosure

### ❌ Vulnerable Pattern
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    image: busybox
    command: ["sh", "-c", "echo $(cat /etc/passwd) && exit 1"]
```

### ✅ Secure Error Handling
```python
def safe_error_handler(error):
    # Log full error internally
    logger.error(f"Detailed error: {error}")
    
    # Return sanitized error to user
    if "permission denied" in str(error).lower():
        return "Access denied"
    elif "not found" in str(error).lower():
        return "Resource not found"
    else:
        return "An error occurred"
```

---

## 11. Templating Security

### ❌ Vulnerable Pattern (Helm)
```yaml
apiVersion: v1
kind: ConfigMap
data:
  content: |
    {{ .Files.Get "/etc/passwd" }}
```

### ✅ Secure Helm Template
```yaml
{{- $allowedFiles := list "config.properties" "app.yaml" -}}
{{- range $file := $allowedFiles }}
{{- if $.Files.Glob $file }}
{{ $file }}: |
{{ $.Files.Get $file | indent 2 }}
{{- end }}
{{- end }}
```

---

## 12. Race Condition Prevention

### ❌ Vulnerable Pattern
```bash
ln -sf /etc/passwd /tmp/manifest.yaml
kubectl apply -f /tmp/manifest.yaml &
sleep 0.1 && echo 'apiVersion: v1' > /tmp/manifest.yaml
```

### ✅ Secure Implementation
```python
import os
import hashlib

def secure_file_apply(filepath):
    # Resolve symlinks and validate path
    real_path = os.path.realpath(filepath)
    
    # Ensure file is in allowed directory
    if not real_path.startswith('/allowed/manifests/'):
        raise SecurityError("File outside allowed directory")
    
    # Read and hash content atomically
    with open(real_path, 'rb') as f:
        content = f.read()
        content_hash = hashlib.sha256(content).hexdigest()
    
    # Apply with content verification
    apply_manifest_with_hash(content, content_hash)
```

---

## 🔧 Security Tools & Automation

### Validation Script
```python
#!/usr/bin/env python3
import yaml
import re
import sys

def security_scan_yaml(content):
    """Scan YAML content for security issues"""
    issues = []
    
    # Check for shell expansion
    if re.search(r'\$\(|`.*`', content):
        issues.append("Shell expansion detected")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'/etc/passwd', r'/root/', r'cat\s+/', r'base64\s+/'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(f"Suspicious pattern: {pattern}")
    
    return issues

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        content = f.read()
        issues = security_scan_yaml(content)
        
        if issues:
            print("❌ Security issues found:")
            for issue in issues:
                print(f"  - {issue}")
            sys.exit(1)
        else:
            print("✅ No security issues detected")
```

---

## 📚 Training Exercises

### Exercise 1: Identify Vulnerabilities
Given the vulnerable patterns above, participants should identify:
1. The attack vector
2. Potential impact
3. Appropriate countermeasures

### Exercise 2: Build Defenses
Create OPA Gatekeeper policies to prevent each vulnerability type.

### Exercise 3: Incident Response
Develop monitoring and alerting for suspicious YAML processing activities.

---

## 🎯 Key Takeaways

1. **Input Validation**: Always validate and sanitize user inputs
2. **Schema Enforcement**: Use strict schema validation
3. **Least Privilege**: Apply minimal necessary permissions
4. **Monitoring**: Implement comprehensive logging and alerting
5. **Defense in Depth**: Layer multiple security controls
