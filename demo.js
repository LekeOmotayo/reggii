const { PiiScrubber } = require('./scrubber');

console.log("=" .repeat(60));
console.log("🛡️  Leke Zero-Dependency PII & Shannon Entropy Scrubber Demo");
console.log("=" .repeat(60));

const samplePrompt = `
System Deployment Config:
- Admin contact: devops-lead@cloudnet.io
- Backup Phone: +1 (555) 392-1920
- Customer SSN: 981-22-4819
- Database Server IP: 192.168.1.150
- AWS Root Access: AKIAIOSFODNN7EXAMPLE
- Production Secret: kX9#vL2!mP9$qR8@zW4^
`;

console.log("\n[1] Original Raw Input:");
console.log(samplePrompt);

const result = PiiScrubber.scrub(samplePrompt);

console.log("[2] Scrubbed LLM-Safe Output:");
console.log(result.cleanText);

console.log("[3] Telemetry & Redaction Summary:");
console.log(`Total Redacted Elements: ${result.totalRedacted}`);
console.log("Breakdown by Category:", JSON.stringify(result.redactedTypes, null, 2));
