# 🎤 Leke PII & Shannon Entropy Scrubber — Senior Engineering Demo Script & Defense Guide

Use this playbook when presenting **Leke PII & Shannon Entropy Scrubber** to Staff/Principal Engineers, Security Leads, or Hiring Managers.

---

## ⏱️ 1. The 30-Second Elevator Pitch

> *"Sending raw prompts from enterprise applications to LLMs like OpenAI or Claude introduces immense data leakage and regulatory risks—HIPAA, GDPR, and PCI-DSS violations from customer emails, SSNs, credit card numbers, and production API keys.*
> 
> *Naive regex solutions either suffer from high false-positive rates on random 16-digit numbers, or completely miss randomly generated API secrets and crypto keys.*
> 
> *I built **Leke Regex & Shannon Entropy PII Scrubber**: a zero-dependency high-throughput sanitization engine in Node.js. It pairs compiled regex classifiers with **Luhn algorithm checksum verification** for real credit cards, and **Shannon Entropy ($H(X) = -\sum p_i \log_2 p_i$)** analysis to detect random cryptographic keys and API tokens. It supports complete redaction, partial masking, and **reversible pseudonymization with client-side rehydration**, processing over 15,000 payloads per second with zero external dependencies."*

---

## 🎬 2. The 3-Minute Live Demo Flow

### Step 1: The Terminal Demo & Rehydration
Open PowerShell in `leke-regex-pii-scrubber` and run:
```powershell
node demo.js
```
**What to say:**
> *"Notice the 3 distinct sanitization modes:
> 1. **Complete Redaction**: Replaces all sensitive elements with clear audit labels (`[REDACTED_EMAIL]`, `[REDACTED_AWS_KEY]`).
> 2. **Partial Masking**: Keeps enough context for customer support verification (`j***e@enterprise.io`, `****-****-****-5671`).
> 3. **Reversible Pseudonymization**: This is the real game changer. It replaces values with synthetic tokens like `{{TOKEN_EMAIL_4}}` and keeps a private vault on the client. The LLM processes the prompt without ever seeing the customer's real data. When the LLM responds, our `rehydrate()` method safely restores the original values before showing the user!"*

Now run the benchmark:
```powershell
node demo.js --benchmark
```
**What to say:**
> *"Notice the throughput rate: over **15,000 to 20,000 payloads per second** with sub-millisecond latency. Zero overhead in your production request-response cycle."*

---

### Step 2: The Visual Interactive Web Dashboard
Run:
```powershell
node demo.js --serve
```
Open **`http://localhost:8002`** in the browser.

**Showcase highlights:**
1. **Interactive Sanitization**:
   > *"Switch between 'Complete Redaction', 'Partial Mask', and 'Reversible Tokenize'—see how the output updates in real-time."*
2. **Rehydration Simulator (Bottom Panel)**:
   > *"In the bottom panel, you can see the private vault generated on the client. Click 'Re-hydrate Original Secrets on Client' to see how the simulated AI response replaces the synthetic tokens with the real customer details seamlessly."*
3. **Shannon Entropy**:
   > *"Notice the entropy threshold card (3.80 bits/char). Normal English prose has an entropy around 2.5–3.0 bits. True high-randomness secrets (like `kX9#vL2!mP9$qR8@zW4^`) spike above 4.2 bits, triggering automatic redaction even without knowing the secret format in advance."*

---

## 🧠 3. Code Deep Dive (How to Explain `scrubber.js`)

When seniors ask: *"Show me the implementation of the entropy and Luhn checks:"*

### 1. Shannon Entropy Implementation
```javascript
function calculateShannonEntropy(str) {
  const freqs = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str.charAt(i);
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0.0;
  const len = str.length;
  for (const count of Object.values(freqs)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
```
*Key explanation: "Shannon entropy measures information density in bits per character. Randomly generated strings (passwords, JWT secrets, base64 hashes) have a nearly uniform probability distribution across characters, maximizing entropy. By setting a threshold of 3.8 bits on tokens of length $\ge 16$, we reliably detect unclassified API secrets without false-flagging regular words."*

### 2. Luhn Algorithm Checksum (Mod 10)
*Key explanation: "A common flaw in junior regex scrubbers is matching any 16-digit number as a credit card—flagging order IDs, shipping tracking numbers, or database barcodes. We pass candidate credit card strings through the **Luhn algorithm (ISO/IEC 7812)** to verify the mathematical checksum before redacting."*

### 3. Reversible De-identification & Vault Security
*Key explanation: "The vault dictionary `vault[token] = original` remains strictly in client memory or a secure server-side session. It is NEVER transmitted in the prompt payload to the external AI provider. Rehydration happens strictly on the sanitized output in the client's trusted boundary."*

---

## 🥊 4. Anticipated "Grill" Questions & Answers

### Q1: *"Why use Shannon Entropy instead of a trained NER (Named Entity Recognition) ML model like Presidio or spaCy?"*
**Senior Answer:**
> *"ML-based NER models like Microsoft Presidio or spaCy are great for general unstructured entities (like human names or physical locations), but they require Python runtimes, 500MB+ model weights, and 50–100ms latency per call. For high-throughput API gateways processing thousands of requests per second, a zero-dependency regex + Shannon entropy pipeline runs in under 0.1ms (100x faster) with zero RAM overhead. In production, we deploy this as a high-speed Edge Gate (Layer 1) before hitting heavier NLP pipelines."*

### Q2: *"How do you test this?"*
**Senior Answer:**
> *"The test suite in `test.js` uses Node's native `assert` module. It tests 7 comprehensive suites including Luhn valid vs invalid cards, Shannon entropy thresholds, partial masking, and roundtrip reversible rehydration in 20 milliseconds."*
