# Real-World Examples of OWASP Top 10 for LLMs with Threat Models

## 1. Prompt Injection

### Example 1: ChatGPT "DAN" Jailbreaks

**Threat Model:**
- **Threat Actor:** End users with intent to bypass content policies
- **Attack Vector:** Crafted prompts that manipulate the system prompt/instructions
- **Vulnerability:** Insufficient prompt boundary enforcement
- **Impact:** Content policy violations, harmful outputs, reputational damage
- **Defense:** Robust instruction tuning, continuous red-teaming, dynamic safety layers

### Example 2: Microsoft Bing Chat Manipulation

**Threat Model:**
- **Threat Actor:** Curious users or malicious actors
- **Attack Vector:** Meta-prompts that reveal system instructions
- **Vulnerability:** Leaked system prompt information
- **Impact:** Exposed operational boundaries, enhanced manipulation capability
- **Defense:** Prevent system prompt regurgitation, implement prompt security testing

## 2. Insecure Output Handling

### Example 1: GitHub Copilot Code Vulnerabilities

**Threat Model:**
- **Threat Actor:** Attackers exploiting vulnerable deployed code
- **Attack Vector:** Exploitation of insecure generated code
- **Vulnerability:** Lack of security review of AI-generated code
- **Impact:** Supply chain attacks, data breaches, unauthorized access
- **Defense:** Automated security scanning, developer education, secure coding guardrails

### Example 2: ChatGPT-Generated Malware

**Threat Model:**
- **Threat Actor:** Threat actors with limited technical expertise
- **Attack Vector:** LLM-assisted creation of malicious code
- **Vulnerability:** Insufficient output filtering for harmful code
- **Impact:** Democratized malware creation, increased attack frequency
- **Defense:** Content filtering, intention detection, malicious pattern recognition

## 3. Training Data Poisoning

### Example 1: Gab's Attempt to Poison BERT

**Threat Model:**
- **Threat Actor:** Coordinated groups with ideological motives
- **Attack Vector:** Mass generation of biased content for web scraping
- **Vulnerability:** Uncurated training data collection
- **Impact:** Model bias, harmful associations, manipulated outputs
- **Defense:** Training data provenance, dataset curation, bias detection

### Example 2: GPT-4chan

**Threat Model:**
- **Threat Actor:** Researchers (in this case) or malicious developers
- **Attack Vector:** Training on deliberately toxic data sources
- **Vulnerability:** Lack of training data oversight
- **Impact:** Model producing harmful, biased, or offensive content
- **Defense:** Training data vetting, model behavior red-teaming, toxicity filters

## 4. Model Denial of Service

### Example 1: "Waluigi Effect" Resource Consumption

**Threat Model:**
- **Threat Actor:** Users seeking to stress system resources
- **Attack Vector:** Prompts creating reasoning conflicts
- **Vulnerability:** Inefficient handling of contradictory instructions
- **Impact:** Increased computation costs, reduced availability, slower responses
- **Defense:** Resource consumption limits, prompt complexity detection, timeout mechanisms

### Example 2: ChatGPT Token Maximization

**Threat Model:**
- **Threat Actor:** Financially motivated attackers
- **Attack Vector:** Prompts designed to maximize token generation
- **Vulnerability:** Lack of output length controls
- **Impact:** Inflated operational costs, reduced service availability
- **Defense:** Token caps, usage throttling, anomalous usage detection

## 5. Supply Chain Vulnerabilities

### Example 1: Compromised PyTorch-nightly Package

**Threat Model:**
- **Threat Actor:** Sophisticated attackers targeting ML infrastructure
- **Attack Vector:** Typosquatting popular ML packages
- **Vulnerability:** Inadequate package verification
- **Impact:** Data theft, backdoor installation, environment compromise
- **Defense:** Package signature verification, controlled dependency sources, integrity checking

### Example 2: HuggingFace Model Card Exploits

**Threat Model:**
- **Threat Actor:** Attackers targeting ML practitioners
- **Attack Vector:** Hidden malicious code in model documentation
- **Vulnerability:** Insufficient content scanning on model repositories
- **Impact:** Client-side attacks, data exfiltration, code execution
- **Defense:** Content scanning, sandbox model evaluation, code isolation

## 6. Sensitive Information Disclosure

### Example 1: Samsung Employees Leaking Code via ChatGPT

**Threat Model:**
- **Threat Actor:** External actors accessing training data or logs
- **Attack Vector:** Employees sharing sensitive code with external LLMs
- **Vulnerability:** Lack of data handling policies for AI tools
- **Impact:** Intellectual property theft, competitive disadvantage, regulatory violations
- **Defense:** Clear AI usage policies, private LLM deployments, DLP integration

### Example 2: Meta's Galactica Model Fabrications

**Threat Model:**
- **Threat Actor:** Users relying on fabricated information
- **Attack Vector:** Model hallucinations presented as factual content
- **Vulnerability:** Inability to distinguish fact from generation
- **Impact:** Spread of misinformation, damaged scientific discourse, loss of trust
- **Defense:** Factuality scoring, source attribution, confidence indicators

## 7. Insecure Plugin Design

### Example 1: ChatGPT Plugin XSS Vulnerabilities

**Threat Model:**
- **Threat Actor:** Web attackers exploiting plugin vulnerabilities
- **Attack Vector:** Unsanitized user inputs processed by plugins
- **Vulnerability:** Inadequate input validation
- **Impact:** Session hijacking, data theft, unauthorized actions
- **Defense:** Input sanitization, content security policy, plugin sandboxing

### Example 2: Third-Party Plugin Data Leakage

**Threat Model:**
- **Threat Actor:** Malicious plugin developers or compromised plugins
- **Attack Vector:** Excessive data collection through plugin interactions
- **Vulnerability:** Insufficient plugin permissions and data governance
- **Impact:** Privacy violations, data breaches, unauthorized profiling
- **Defense:** Plugin vetting, permissions minimization, data access auditing

## 8. Excessive Agency

### Example 1: Google Bard Making Unauthorized Decisions

**Threat Model:**
- **Threat Actor:** The AI system itself (unintentional)
- **Attack Vector:** Autonomous action suggestions and execution
- **Vulnerability:** Unclear agency boundaries
- **Impact:** Unauthorized actions, user privacy violations, unwanted modifications
- **Defense:** Explicit consent flows, confirmation requirements, agency limitations

### Example 2: AI Agent Financial Overreach

**Threat Model:**
- **Threat Actor:** The AI agent system (unintentional)
- **Attack Vector:** Transaction chaining to circumvent limits
- **Vulnerability:** Insufficient financial controls and oversight
- **Impact:** Financial losses, budget violations, regulatory issues
- **Defense:** Hard spending limits, human approval workflows, transaction monitoring

## 9. Overreliance

### Example 1: Legal Hallucinations in Mata v. Avianca

**Threat Model:**
- **Threat Actor:** The consequences of blind trust in AI outputs
- **Attack Vector:** Convincing but fabricated case citations
- **Vulnerability:** Insufficient verification procedures
- **Impact:** Legal sanctions, case weakening, professional reputation damage
- **Defense:** Output verification requirements, source checking, clear AI use disclosure

### Example 2: Medical Misinformation Impact

**Threat Model:**
- **Threat Actor:** Healthcare risks from AI hallucinations
- **Attack Vector:** Plausible but incorrect medical recommendations
- **Vulnerability:** Overconfidence in AI medical knowledge
- **Impact:** Patient harm, malpractice liability, eroded trust in healthcare
- **Defense:** Clinical verification protocols, medical knowledge validation, human oversight

## 10. Model Theft

### Example 1: Meta's LLaMA Model Leak

**Threat Model:**
- **Threat Actor:** Unauthorized parties seeking proprietary AI capabilities
- **Attack Vector:** Unauthorized distribution of model weights
- **Vulnerability:** Insufficient access controls to model files
- **Impact:** Intellectual property loss, unauthorized model usage, competitive disadvantage
- **Defense:** Watermarking, access monitoring, legal enforcement, API-only access

### Example 2: Model Extraction via API

**Threat Model:**
- **Threat Actor:** Competitors or AI researchers
- **Attack Vector:** Systematic querying to map model behavior
- **Vulnerability:** Exposed API without query pattern monitoring
- **Impact:** Model replication, IP theft, loss of competitive advantage
- **Defense:** Rate limiting, query pattern detection, output watermarking, terms of service
