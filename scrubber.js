/**
 * Zero-Dependency Regex & Shannon Entropy PII Scrubber Middleware.
 * Cleanses emails, phone numbers, SSNs, credit cards, IPs, and high-entropy API secrets.
 */

class PiiScrubber {
  static RULES = [
    { type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, mask: '[REDACTED_EMAIL]' },
    { type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, mask: '[REDACTED_SSN]' },
    { type: 'PHONE', regex: /(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, mask: '[REDACTED_PHONE]' },
    { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[- ]){3}\d{4}\b/g, mask: '[REDACTED_CREDIT_CARD]' },
    { type: 'IP_ADDRESS', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, mask: '[REDACTED_IP]' },
    { type: 'AWS_KEY', regex: /\bAKIA[0-9A-Z]{16}\b/g, mask: '[REDACTED_AWS_KEY]' },
  ];

  static calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freqs = {};
    for (const ch of str) {
      freqs[ch] = (freqs[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freqs)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  static scrub(text, entropyThreshold = 3.8) {
    let clean = text;
    let count = 0;
    const counts = {};

    for (const rule of PiiScrubber.RULES) {
      clean = clean.replace(rule.regex, () => {
        count++;
        counts[rule.type] = (counts[rule.type] || 0) + 1;
        return rule.mask;
      });
    }

    const words = clean.split(/(\s+|["'=,:;()\[\]{}]+)/);
    for (let i = 0; i < words.length; i++) {
      const token = words[i];
      if (token && token.length >= 16 && !token.startsWith('[REDACTED_')) {
        const ent = PiiScrubber.calculateEntropy(token);
        if (ent >= entropyThreshold) {
          words[i] = '[REDACTED_HIGH_ENTROPY_SECRET]';
          count++;
          counts['HIGH_ENTROPY_SECRET'] = (counts['HIGH_ENTROPY_SECRET'] || 0) + 1;
        }
      }
    }
    clean = words.join('');

    return {
      cleanText: clean,
      totalRedacted: count,
      redactedTypes: counts
    };
  }
}

module.exports = { PiiScrubber };
