'use strict';

const { PII_RULES } = require('../core/scrubber');

const SAMPLE_PAYLOADS = {
  customer_record: {
    title: "Customer Support Chat Record",
    text: `User Alex Smith (alex.smith@example.com, phone 555-234-5678) contacted support regarding charge on Visa 4532-0150-1234-5671. SSN on file: 123-45-6789. Client IP 192.168.1.100.
Diagnostic auth header: Bearer ya29.a0AfH6SMAa8123984712938471928374192834`
  },
  devops_log: {
    title: "DevOps & Cloud API Credentials",
    text: `Deploy failed on AWS cluster.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
OPENAI_API_KEY=sk-proj-abcde12345FGHIJ67890klmnoPQRSTUvwxyz1234567890ABCDEFGHIJKL
GITHUB_PAT=ghp_ABCDefgh1234567890ijklmnopQRSTUV1234`
  },
  mixed_entropy: {
    title: "High Shannon Entropy Token Leak",
    text: `Database connection pool initialization string:
postgresql://postgres:xK9#mQ2$vL8*pW4!zR7@prod-db.internal:5432/finance
JWT_SIGNING_SECRET=dGhpc19pc19hX3Zlcnlfc2VjdXJlX2tleV9mb3Jfc2lnbmluZw==`
  }
};

class PatternRepository {
  static getRules() {
    return PII_RULES.map(r => ({
      type: r.type,
      title: r.title,
      mask: r.mask
    }));
  }

  static getSamplePayloads() {
    return SAMPLE_PAYLOADS;
  }
}

module.exports = { PatternRepository };
