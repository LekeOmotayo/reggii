# 🛡️ Leke PII & Shannon Entropy Scrubber — LLM Sanitization Gateway

> **Zero-dependency regex and Shannon entropy PII scrubbing middleware in Node.js.** Pre-screens and sanitizes prompts before transmission to external AI models (OpenAI, Anthropic, Gemini). Detects emails, phones, SSNs, credit cards (Luhn-validated), IPs, API tokens, and raw cryptographic secrets with **reversible pseudonymization and client rehydration**.

---

## 🏗️ Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │             Raw Untrusted Prompt             │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │          Compiled Pattern Matching           │
                      │  • AWS, OpenAI, GitHub, Slack, JWT Tokens    │
                      │  • Emails, SSNs, Phones, IPv4                │
                      │  • Credit Cards (with Luhn Algorithm Check)  │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │          Shannon Entropy Analysis            │
                      │    H(X) = -Σ p_i log2(p_i) on Tokens >= 16   │
                      │   Flags Unclassified Random Crypto Secrets   │
                      └──────────────────────┬───────────────────────┘
                                             │
                     ┌───────────────────────┴───────────────────────┐
                     │                                               │
                     ▼ Mode: MASK / PARTIAL                          ▼ Mode: TOKENIZE
       ┌───────────────────────────┐                   ┌───────────────────────────┐
       │   Clean Masked Payload    │                   │   Pseudonymized Payload   │
       │  [REDACTED_EMAIL], etc.   │                   │   {{TOKEN_EMAIL_1}}, etc. │
       └───────────────────────────┘                   └─────────────┬─────────────┘
                                                                     │ (Prompt sent to AI)
                                                                     ▼
                                                       ┌───────────────────────────┐
                                                       │   LLM Generates Answer    │
                                                       │   (Preserving {{TOKEN}})  │
                                                       └─────────────┬─────────────┘
                                                                     │
                                                                     ▼
                                                       ┌───────────────────────────┐
                                                       │     Client Rehydrate      │
                                                       │  Replaces Tokens with     │
                                                       │  Original Vault Secrets   │
                                                       └───────────────────────────┘
```

---

## 🚀 Key Engineering Highlights

- **Luhn Algorithm Checksum (ISO/IEC 7812)**: Validates credit card number checksums before masking to avoid false-flagging random 16-digit order or tracking numbers.
- **Shannon Entropy Analysis**: Computes mathematical information entropy ($H(X) \ge 3.80$ bits/character) to detect arbitrary high-randomness API keys and passwords without requiring predefined regexes.
- **Reversible Pseudonymization & De-identification**: Replaces PII with synthetic tokens (`{{TOKEN_EMAIL_1}}`), allowing LLMs to process contextually rich prompts without ever seeing real customer data, and re-hydrates the original secrets on the client side.
- **Extreme Throughput**: Pure zero-dependency Node.js processing over 15,000 payloads per second with sub-millisecond latency.

---

## ⚡ Quick Start & Commands

Built strictly on Node.js **Standard Library**. No `npm install` required!

### 1. Interactive Web Dashboard
```bash
node demo.js --serve
# Or specify custom port
node demo.js --serve --port 8002
```
Open **`http://localhost:8002`** in any browser.

### 2. Run CLI Demonstration
```bash
node demo.js
```

### 3. Run Throughput Benchmark
```bash
node demo.js --benchmark
```

### 4. Run Unit Test Suite
```bash
node test.js
# 7 comprehensive test suites covering all rules and roundtrip rehydration
```

---

## 📂 Project Structure

```
leke-regex-pii-scrubber/
├── scrubber.js            # Core scrubber, Luhn algorithm, Shannon entropy, rehydrate
├── demo.js                # CLI runner, benchmark harness, and server launcher
├── server.js              # Embedded HTTP server & REST API (/api/scrub, /api/rehydrate)
├── index.html             # Component-based dark-mode web dashboard
├── test.js                # Comprehensive test suite (7 tests)
├── SENIOR_DEMO_SCRIPT.md  # Presentation script & interview defense talking points
├── README.md              # Architectural documentation
└── static/
    ├── css/styles.css     # Design system tokens and card styling
    └── js/
        ├── api.js         # API client with offline simulation fallback
        ├── app.js         # Main application controller
        └── components/
            ├── InputPanel.js        # Prompt input & mode selector
            ├── OutputPanel.js       # Sanitized output & findings chips
            └── RehydrationPanel.js  # Round-trip de-identification simulator
```
