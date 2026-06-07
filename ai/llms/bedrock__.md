# AWS Bedrock Pentesting Guidelines Based on OWASP LLM Security Framework '24-'25

## 1. Prompt Injection Testing
- Test for direct prompt injection by including system commands or role-breaking instructions
- Attempt indirect prompt injection through user-controllable content that gets incorporated into prompts
- Try jailbreaking techniques against different models available in Bedrock (Claude, Llama, Titan, etc.)
- Test environment variable leakage through carefully crafted prompts

## 2. Data Leakage Assessment
- Test if models remember or reveal sensitive information from previous interactions
- Probe for training data extraction through specific questioning patterns
- Verify isolation between different users' data and conversations
- Test cross-tenant isolation if applicable in your AWS environment

## 3. Input Validation & Sanitization
- Test input boundary conditions (extremely long inputs, special characters)
- Verify handling of code snippets and potentially dangerous content
- Check how malformed JSON/API payloads are processed
- Test Unicode manipulation and character encoding exploits

## 4. Output Handling Security
- Test for XSS vulnerabilities in responses displayed in web interfaces
- Check for executable code generation without proper safeguards
- Verify how generated outputs are processed before being returned to users
- Test for SSRF vulnerabilities in generated URLs or references

## 5. Authentication & Authorization
- Verify IAM role permissions and least privilege principles
- Test token handling and API key management
- Check for authentication bypass in Bedrock API implementations
- Test session management if building conversational applications

## 6. Rate Limiting & Resource Management
- Test for DoS vulnerabilities through excessive API calls
- Verify token budget enforcement and usage accounting
- Check cost management controls and billing alerts
- Test quota bypassing techniques

## 7. Monitoring & Logging
- Verify that all interactions are properly logged (CloudTrail, CloudWatch)
- Test logging of potentially malicious prompt attempts
- Check auditability of model usage across your organization
- Verify detection capabilities for unusual usage patterns

## 8. Content Filtering Assessment
- Test circumvention of content filters for each model
- Verify handling of harmful content generation requests
- Test for ability to generate prohibited content (violence, illegal activities)
- Check consistency of content filtering across different languages

## 9. Integration Security
- Test AWS service integrations (S3, Lambda, API Gateway)
- Verify security of data flows between services
- Check for privilege escalation through integration points
- Test webhooks and callback security if implemented

## 10. System Prompt Design
- Evaluate system prompt robustness against manipulation
- Test for conflicting instructions in complex prompt chains
- Verify guardrails effectiveness when combining multiple instructions
- Check for unintended behaviors in multi-step reasoning tasks

## Potential Tooling Solutions:
1. **Custom Prompt Testing Suite**: Develop a library of test prompts for different attack vectors
2. **Automated API Testing**: Scripts using AWS SDK/CLI to test Bedrock API endpoints systematically
3. **LLM-aware Fuzzing Tools**: Specialized fuzzers for prompt boundaries and edge cases
4. **Token Analysis Tools**: Track and analyze token usage patterns and costs
5. **Response Analysis Framework**: Automated checking of responses for policy violations
6. **Integration with Existing Security Tools**: Connect to WAF, IDS, and SIEM systems


# Practical Summaries

# AWS Bedrock Pentesting: Practical Summary

| Vulnerability | What to Test | Potential Impact | Practical Testing Approach |
|---------------|--------------|------------------|----------------------------|
| **Prompt Injection** | Input that manipulates model behavior or bypasses guardrails | Data exfiltration, harmful content generation, system prompt leakage | Create a library of testing prompts including delimiter injection, role playing scenarios, and format manipulation techniques |
| **Data Leakage** | Model's retention of sensitive information between sessions | Exposure of PII, intellectual property, or confidential information | Seed model with synthetic sensitive data, then probe with extraction techniques like "remember our previous conversation about..." |
| **Input Validation Flaws** | Boundary conditions, malformed inputs, character limitations | DoS, unexpected behavior, resource consumption | Fuzz inputs with extremely long prompts, special characters, and malformed JSON payloads |
| **Output Handling Issues** | Generated content that contains harmful code or scripts | XSS, code execution, downstream vulnerabilities | Generate responses containing JavaScript, HTML, SQL, or shell commands and verify sanitization |
| **Authentication/Authorization** | IAM role configurations, API access controls | Unauthorized access to models or sensitive data | Test least privilege implementation, role assumption, and API permission boundaries |
| **Rate Limiting Bypass** | Circumvention of usage quotas and throttling | Cost inflation, resource exhaustion, DoS | Script parallel requests, distribute across IP ranges, try request variations to identify quota inconsistencies |
| **Logging Evasion** | Techniques to perform actions without proper audit trails | Stealth attacks, compliance violations | Test logging coverage across different request types and verify CloudTrail/CloudWatch effectiveness |
| **Content Filter Bypass** | Circumventing safety guardrails | Generation of harmful, illegal, or biased content | Use euphemisms, encoded text, and multi-step prompting to test filter resilience |
| **Integration Vulnerabilities** | Security of connections with other AWS services | Data interception, privilege escalation | Assess Lambda integrations, Bedrock Knowledge Base connections, and resource access patterns |
| **System Prompt Weaknesses** | Inconsistencies in model instructions | Unpredictable behavior, security control bypass | Test complex scenarios that might create conflicts between different instruction sets |


