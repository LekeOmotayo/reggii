/**
 * Comprehensive Unit Tests for Leke PII & Shannon Entropy Scrubber
 * Covers regex patterns, Luhn algorithm, Shannon entropy, partial masking,
 * and reversible pseudonymization rehydration.
 */

'use strict';

const assert = require('assert');
const { PiiScrubber, isValidLuhn, calculateShannonEntropy } = require('../core/scrubber');

console.log("============================================================");
console.log("🧪 Running Leke PiiScrubber Comprehensive Test Suite");
console.log("============================================================\n");

// Test 1: Email Redaction
{
  const input = "Contact the CEO at alex.smith@acme-corp.com immediately.";
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_EMAIL]'));
  assert.strictEqual(res.cleanText.includes('alex.smith@acme-corp.com'), false);
  assert.strictEqual(res.totalRedacted, 1);
  console.log("✔ Test 1: Email redaction passed");
}

// Test 2: Credit Card with Luhn Checksum Validation
{
  // Valid Luhn test card (Visa)
  const validCard = "4532-0150-1234-5671"; // Luhn valid
  assert.strictEqual(isValidLuhn(validCard), true);

  const inputValid = `Payment with card ${validCard} authorized.`;
  const resValid = PiiScrubber.scrub(inputValid);
  assert.ok(resValid.cleanText.includes('[REDACTED_CREDIT_CARD]'));
  assert.strictEqual(resValid.totalRedacted, 1);

  // Invalid Luhn number (should NOT be masked to avoid false positives)
  const invalidCard = "4532-0150-1234-5679";
  assert.strictEqual(isValidLuhn(invalidCard), false);
  const inputInvalid = `Tracking code: ${invalidCard}`;
  const resInvalid = PiiScrubber.scrub(inputInvalid);
  assert.strictEqual(resInvalid.cleanText.includes('[REDACTED_CREDIT_CARD]'), false);
  assert.strictEqual(resInvalid.totalRedacted, 0);

  console.log("✔ Test 2: Credit card Luhn checksum validation passed");
}

// Test 3: SSN and Phone Redaction
{
  const input = "SSN: 342-88-1294, Direct: (415) 555-2671";
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_SSN]'));
  assert.ok(res.cleanText.includes('[REDACTED_PHONE]'));
  assert.strictEqual(res.totalRedacted, 2);
  console.log("✔ Test 3: SSN & phone redaction passed");
}

// Test 4: Cloud API Secrets (AWS, OpenAI, GitHub)
{
  const input = `
    AWS: AKIAIOSFODNN7EXAMPLE
    OPENAI: sk-proj-948102948192384910283491
    GITHUB: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB
  `;
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_AWS_KEY]'));
  assert.ok(res.cleanText.includes('[REDACTED_OPENAI_KEY]'));
  assert.ok(res.cleanText.includes('[REDACTED_GITHUB_TOKEN]'));
  assert.strictEqual(res.totalRedacted, 3);
  console.log("✔ Test 4: Cloud API secrets (AWS, OpenAI, GitHub) passed");
}

// Test 5: Shannon Entropy Detection
{
  const lowEntropy = "standardproseword";
  const highEntropy = "xK9!mP8$vL2@zW4#qR7%";
  assert.ok(calculateShannonEntropy(lowEntropy) < 3.8);
  assert.ok(calculateShannonEntropy(highEntropy) > 3.8);

  const input = `export VAULT_SECRET = "${highEntropy}";`;
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_HIGH_ENTROPY_SECRET]'));
  console.log("✔ Test 5: Shannon Entropy high-randomness secret detection passed");
}

// Test 6: Partial Masking Mode
{
  const input = "User: john.doe@enterprise.io, Card: 4532-0150-1234-5671";
  const res = PiiScrubber.scrub(input, { mode: 'partial' });
  assert.ok(res.cleanText.includes('j***e@enterprise.io'));
  assert.ok(res.cleanText.includes('****-****-****-5671'));
  console.log("✔ Test 6: Partial masking mode passed");
}

// Test 7: Reversible Pseudonymization & De-identification Roundtrip
{
  const originalPrompt = "Please generate an email reply to sarah.connor@cyberdyne.com regarding SSN 452-82-9182.";
  const scrubbed = PiiScrubber.scrub(originalPrompt, { mode: 'tokenize' });

  // Verify tokens were inserted
  assert.ok(scrubbed.cleanText.includes('{{TOKEN_EMAIL_1}}'));
  assert.ok(scrubbed.cleanText.includes('{{TOKEN_SSN_2}}'));
  assert.strictEqual(scrubbed.cleanText.includes('sarah.connor@cyberdyne.com'), false);

  // Simulate LLM output using the tokenized prompt
  const simulatedLlmOutput = `Dear {{TOKEN_EMAIL_1}},\nWe have received your verification for {{TOKEN_SSN_2}}.`;

  // Re-hydrate the tokens back into original values
  const rehydrated = PiiScrubber.rehydrate(simulatedLlmOutput, scrubbed.vault);
  assert.ok(rehydrated.includes('sarah.connor@cyberdyne.com'));
  assert.ok(rehydrated.includes('452-82-9182'));
  console.log("✔ Test 7: Reversible pseudonymization and rehydration roundtrip passed");
}

console.log("\n============================================================");
console.log("🎉 All 7 PiiScrubber test suites passed successfully!");
console.log("============================================================\n");

