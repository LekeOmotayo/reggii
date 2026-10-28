/**
 * Leke PII & Shannon Entropy Scrubber - Enterprise CLI & Benchmark Runner
 * Demonstrates pattern redaction, Luhn validation, Shannon entropy,
 * reversible pseudonymization, and embedded web server hosting.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { PiiScrubber, calculateShannonEntropy } = require('./scrubber');

const COLOR_RESET = '\x1b[0m';
const COLOR_CYAN = '\x1b[96m';
const COLOR_GREEN = '\x1b[92m';
const COLOR_YELLOW = '\x1b[93m';
const COLOR_MAGENTA = '\x1b[95m';
const COLOR_RED = '\x1b[91m';
const COLOR_BOLD = '\x1b[1m';
const COLOR_DIM = '\x1b[2m';

function printBanner() {
  console.log(`${COLOR_MAGENTA}${COLOR_BOLD}${'='.repeat(72)}`);
  console.log('  🛡️  LEKE PII & SHANNON ENTROPY SCRUBBER — LLM Sanitization Gateway');
  console.log('     Zero-Dependency Token Scrubbing, Luhn Checksum & Vault Pseudonymization');
  console.log(`${'='.repeat(72)}${COLOR_RESET}\n`);
}

const SAMPLE_PAYLOAD = `
System Deployment & Customer Support Incident #9481:
- Primary Customer Contact: alex.smith@acme-corp.com
- Customer SSN on File: 342-88-1294
- Escalation Phone: +1 (415) 555-2671
- Billing Credit Card: 4532-0150-1234-5671 (Visa Gold)
- Production Database Server: 10.0.4.15
- AWS Root Access Key: AKIAIOSFODNN7EXAMPLE
- OpenAI Production Token: sk-proj-94810294819238491028349199283
- GitHub Deployment Token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB
- Raw In-Memory Vault Secret: kX9#vL2!mP9$qR8@zW4^
`;

function runDemo() {
  printBanner();

  console.log(`${COLOR_BOLD}[1] Raw Untrusted User Payload (Contains PII & Cloud Secrets):${COLOR_RESET}`);
  console.log(`${COLOR_DIM}${SAMPLE_PAYLOAD.trim()}${COLOR_RESET}\n`);

  // Mode 1: Complete Redaction Masking
  console.log(`${COLOR_BOLD}[2] Mode A: Complete Redaction Masking ([REDACTED_*]):${COLOR_RESET}`);
  const maskRes = PiiScrubber.scrub(SAMPLE_PAYLOAD, { mode: 'mask' });
  console.log(`${COLOR_GREEN}${maskRes.cleanText.trim()}${COLOR_RESET}\n`);
  console.log(`    Total Elements Redacted: ${COLOR_CYAN}${maskRes.totalRedacted}${COLOR_RESET} | Processed in: ${COLOR_YELLOW}${maskRes.metrics.elapsedMs} ms${COLOR_RESET}`);
  console.log(`    Category Breakdown:      ${JSON.stringify(maskRes.redactedTypes)}\n`);

  // Mode 2: Partial Masking (Audit & Verification Friendly)
  console.log(`${COLOR_BOLD}[3] Mode B: Partial Masking (Preserves Context for Support Agents):${COLOR_RESET}`);
  const partialRes = PiiScrubber.scrub(SAMPLE_PAYLOAD, { mode: 'partial' });
  console.log(`${COLOR_CYAN}${partialRes.cleanText.trim()}${COLOR_RESET}\n`);

  // Mode 3: Reversible Tokenization (Pseudonymization / De-identification)
  console.log(`${COLOR_BOLD}[4] Mode C: Reversible Pseudonymization & De-identification:{{TOKEN_*}}:${COLOR_RESET}`);
  const tokenRes = PiiScrubber.scrub(SAMPLE_PAYLOAD, { mode: 'tokenize' });
  console.log(`${COLOR_MAGENTA}${tokenRes.cleanText.trim()}${COLOR_RESET}\n`);

  console.log(`${COLOR_BOLD}[5] Simulating LLM Processing & Safe Round-Trip Rehydration:${COLOR_RESET}`);
  const mockCustomerEmail = Object.keys(tokenRes.vault).find(k => k.includes('EMAIL')) || '{{TOKEN_EMAIL_1}}';
  const mockCustomerCard = Object.keys(tokenRes.vault).find(k => k.includes('CREDIT_CARD')) || '{{TOKEN_CREDIT_CARD_1}}';
  const mockCustomerPhone = Object.keys(tokenRes.vault).find(k => k.includes('PHONE')) || '{{TOKEN_PHONE_1}}';

  const mockLlmResponse = `
AI Response:
I have updated billing records for customer ${mockCustomerEmail} and verified card ${mockCustomerCard}.
A notification was dispatched to ${mockCustomerPhone}.
`;
  console.log(`    LLM Generated Output (Using Synthetic Tokens):`);
  console.log(`${COLOR_DIM}${mockLlmResponse.trim()}${COLOR_RESET}\n`);

  const rehydrated = PiiScrubber.rehydrate(mockLlmResponse, tokenRes.vault);
  console.log(`    ${COLOR_GREEN}✔ Re-hydrated Output (Original Secrets Reconstituted in Client Sandbox):${COLOR_RESET}`);
  console.log(`${COLOR_GREEN}${rehydrated.trim()}${COLOR_RESET}\n`);

  // Shannon Entropy Breakdown
  console.log(`${COLOR_BOLD}[6] Shannon Entropy Secret Analysis:${COLOR_RESET}`);
  console.log(`    'standardpassword'   -> Entropy: ${calculateShannonEntropy('standardpassword').toFixed(3)} bits (Below 3.8 threshold)`);
  console.log(`    'kX9#vL2!mP9$qR8@zW4^' -> Entropy: ${COLOR_YELLOW}${calculateShannonEntropy('kX9#vL2!mP9$qR8@zW4^').toFixed(3)} bits${COLOR_RESET} (Above 3.8 -> REDACTED)\n`);

  console.log(`${COLOR_BOLD}Next steps:${COLOR_RESET}`);
  console.log(`  • Launch interactive web dashboard: node demo.js --serve`);
  console.log(`  • Run throughput benchmark:          node demo.js --benchmark`);
  console.log(`  • Run unit test suite:               node test.js\n`);
}

function runBenchmark(iterations = 500) {
  printBanner();
  console.log(`Running throughput benchmark (${iterations} full payload sanitizations)...\n`);

  const start = process.hrtime.bigint();
  let totalRedacted = 0;

  for (let i = 0; i < iterations; i++) {
    const res = PiiScrubber.scrub(SAMPLE_PAYLOAD);
    totalRedacted += res.totalRedacted;
  }

  const elapsedNs = Number(process.hrtime.bigint() - start);
  const elapsedMs = elapsedNs / 1_000_000.0;
  const avgMs = elapsedMs / iterations;
  const throughputPerSec = Math.round((iterations / elapsedMs) * 1000.0);

  console.log(`Benchmark Results:`);
  console.log(`  • Total Operations:      ${iterations} payloads`);
  console.log(`  • Total Time:            ${elapsedMs.toFixed(2)} ms`);
  console.log(`  • Average Latency:       ${COLOR_CYAN}${avgMs.toFixed(3)} ms per payload${COLOR_RESET}`);
  console.log(`  • Throughput Rate:       ${COLOR_GREEN}${throughputPerSec.toLocaleString()} payloads / second${COLOR_RESET}\n`);
}

function startServer(port = 8002) {
  const { runServer } = require('./server');
  runServer(port);
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printBanner();
    console.log('Usage: node demo.js [options]');
    console.log('Options:');
    console.log('  --benchmark, -b   Run throughput benchmark');
    console.log('  --serve, -s       Launch interactive web demo dashboard on http://localhost:8002');
    console.log('  --port <num>      Port for web server (default: 8002)');
    process.exit(0);
  }

  if (args.includes('--serve') || args.includes('-s')) {
    const portIdx = args.indexOf('--port');
    const port = portIdx !== -1 && args[portIdx + 1] ? parseInt(args[portIdx + 1], 10) : 8002;
    startServer(port);
    return;
  }

  if (args.includes('--benchmark') || args.includes('-b')) {
    runBenchmark();
    return;
  }

  runDemo();
}

if (require.main === module) {
  main();
}
