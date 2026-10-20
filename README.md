# Leke Zero-Dependency Regex & Entropy PII Scrubber

A high-throughput, zero-dependency Node.js/TypeScript PII redaction middleware engineered for LLM prompt sanitation. Combines deterministic regular expressions with Shannon entropy calculation to catch both standard PII formats and random high-entropy credential leaks.

## Supported Redaction Formats
- Emails (`[REDACTED_EMAIL]`)
- US Social Security Numbers (`[REDACTED_SSN]`)
- E.164 & US Phone Numbers (`[REDACTED_PHONE]`)
- Credit Card Luhn Numbers (`[REDACTED_CREDIT_CARD]`)
- IPv4 Host Addresses (`[REDACTED_IP]`)
- AWS Access Keys (`[REDACTED_AWS_KEY]`)
- High-Entropy Passwords & Tokens (`[REDACTED_HIGH_ENTROPY_SECRET]`)

## Quick Start
```bash
# Run demo
node demo.js

# Run test suite
node test.js
```
