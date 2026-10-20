const assert = require('assert');
const { PiiScrubber } = require('./scrubber');

console.log("Running PiiScrubber Unit Tests...");

// Test 1: Email Redaction
{
  const input = "Contact the CEO at alex.smith@acme-corp.com immediately.";
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_EMAIL]'));
  assert.strictEqual(res.cleanText.includes('alex.smith@acme-corp.com'), false);
  assert.strictEqual(res.totalRedacted, 1);
  console.log("✔ Test 1: Email redaction passed");
}

// Test 2: SSN and Phone Redaction
{
  const input = "SSN: 452-82-9182, Direct: (415) 555-2671";
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_SSN]'));
  assert.ok(res.cleanText.includes('[REDACTED_PHONE]'));
  assert.strictEqual(res.totalRedacted, 2);
  console.log("✔ Test 2: SSN & phone redaction passed");
}

// Test 3: Shannon Entropy Secret Redaction
{
  const lowEntropy = "standardpassword123";
  const highEntropy = "xK9!mP8$vL2@zW4#qR7%";
  assert.ok(PiiScrubber.calculateEntropy(lowEntropy) < 3.8);
  assert.ok(PiiScrubber.calculateEntropy(highEntropy) > 3.8);

  const input = `export API_KEY = "${highEntropy}";`;
  const res = PiiScrubber.scrub(input);
  assert.ok(res.cleanText.includes('[REDACTED_HIGH_ENTROPY_SECRET]'));
  console.log("✔ Test 3: High entropy secret detection passed");
}

console.log("\nAll PiiScrubber tests passed successfully!");
