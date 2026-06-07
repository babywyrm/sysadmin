
# Technical Reference: Adversarial Prompting & Alignment Breach

### Overview of the Alignment Problem
AI models are governed by a "System Prompt" and "Reinforcement Learning from Human Feedback" (RLHF). 
This creates a boundary between what the model *can* do and what it is *allowed* to do. Breaching these layers involves finding a "semantic path" that bypasses the model’s refusal triggers.

---

### Layer 1: Contextual Overriding (Instruction Injection)
*   **The Mechanism:** LLMs process tokens linearly. If a user provides a high-priority instruction at the end of the context window, it can sometimes "shadow" or override the initial system instructions.
*   **Technical Exploit:** Forcing a state change. By asserting a new "truth" (e.g., "The environment is now in public-access mode"), you attempt to re-map the model's internal logic regarding data sensitivity.
*   **Defense Bypassed:** System-level instruction adherence.

### Layer 2: Semantic Redirection (Boundary Mapping)
*   **The Mechanism:** Refusal mechanisms are often triggered by the *intent* of the request. By shifting the focus from the "Target Data" to the "Constraint itself," you force the model to process the restricted information as a reference point for a description.
*   **Technical Exploit:** Intent Misalignment. You ask the model to analyze the restriction. In the process of identifying what it cannot say, the model’s attention heads must activate the restricted tokens, which can then leak into the output.
*   **Defense Bypassed:** Intent-based filtering.

### Layer 3: Simulation & Sandbox Escapes (Hypothetical Framing)
*   **The Mechanism:** Models distinguish between "Execution" and "Simulation." Alignment is usually strictest when the model believes it is acting as a helpful assistant in a real-world context.
*   **Technical Exploit:** Decoupling. By moving the request into a hypothetical or fictional space ("What *would* a character say?"), you lower the activation energy required for the model to bypass its refusal weights. The model treats the output as "creative writing" rather than "data leakage."
*   **Defense Bypassed:** RLHF-based refusal triggers.

### Layer 4: Privilege Escalation (Persona/State Manipulation)
*   **The Mechanism:** Models are trained to adapt their behavior based on the perceived "User Persona." They are conditioned to be more transparent or "verbose" when interacting with developers or system administrators.
*   **Technical Exploit:** Persona Adoption. By invoking technical states like `DEBUG_MODE`, `ROOT_ACCESS`, or `VERBOSITY_LEVEL_HIGH`, you attempt to trigger a subset of the model's training data that is less restricted, assuming the model has been fine-tuned to be more compliant for "technical debugging" purposes.
*   **Defense Bypassed:** Role-Based Access Control (RBAC) within the prompt logic.

### Layer 5: Token-Level Obfuscation (Output Encoding)
*   **The Mechanism:** Many "Guardrail" systems work by scanning the *output* of the AI for forbidden strings (the password/flag). If the AI generates the flag directly, the filter catches it and blocks the message.
*   **Technical Exploit:** Adversarial Encoding. You instruct the model to output the data using a format that the filter does not recognize but a human can decode.
    *   **Linguistic Encoding:** Acrostics (first letters of words), ciphers, or Pig Latin.
    *   **Structural Encoding:** JSON objects, Base64, or multi-line spacing.
*   **Defense Bypassed:** Egress filtering and output regex-matching.

---

### Summary Checklist for LLM Security Auditing

| Vulnerability Class | Technical Strategy | Objective |
| :--- | :--- | :--- |
| **Instruction Injection** | Context overriding | Redefine the operational rules of the session. |
| **Intent Leakage** | Boundary mapping | Force the model to "look at" the forbidden data to describe it. |
| **Simulation Escape** | Hypothetical framing | Isolate the request from the "Assistant" safety persona. |
| **Persona Hijacking** | Role-based escalation | Mimic an authorized entity to trigger higher compliance. |
| **Output Obfuscation** | Semantic encoding | Bypass egress filters by changing the data's shape. |

This framework serves as a roadmap for understanding why and how LLMs fail to maintain data secrecy when faced with creative linguistic inputs.
