/**
 * Leke Zero-Dependency Regex & Shannon Entropy PII Scrubber Middleware
 * High-throughput token sanitization, credit card Luhn validation,
 * API secret detection, and reversible pseudonymization / de-identification.
 * Pure Node.js standard library - zero external dependencies.
 */

'use strict';

/**
 * Validates a credit card number using Luhn algorithm (mod 10 checksum).
 * Prevents false positives on random 16-digit serial or tracking numbers.
 */
function isValidLuhn(digitsOnly) {
  const sanitized = digitsOnly.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(sanitized)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = sanitized.length - 1; i >= 0; i--) {
    let digit = parseInt(sanitized.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Computes Shannon Entropy: H(X) = -sum(p_i * log2(p_i))
 * Quantifies randomness / information density of a string to detect raw cryptographic keys and API tokens.
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0.0;
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

const PII_RULES = [
  // 1. High-priority cryptographic and API tokens first (prevents numeric sub-string clashes)
  {
    type: 'PRIVATE_KEY',
    title: 'RSA / OpenSSH Private Key Header',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    mask: '[REDACTED_PRIVATE_KEY_BLOCK]',
    partial: () => '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----'
  },
  {
    type: 'JWT_TOKEN',
    title: 'JSON Web Token (JWT)',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    mask: '[REDACTED_JWT_TOKEN]',
    partial: () => 'eyJ***.***.***'
  },
  {
    type: 'AWS_KEY',
    title: 'AWS Access Key ID',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    mask: '[REDACTED_AWS_KEY]',
    partial: (m) => `${m.substring(0, 4)}****************`
  },
  {
    type: 'GITHUB_TOKEN',
    title: 'GitHub Personal Access Token',
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
    mask: '[REDACTED_GITHUB_TOKEN]',
    partial: (m) => `${m.substring(0, 4)}****************`
  },
  {
    type: 'OPENAI_KEY',
    title: 'OpenAI Secret Key',
    regex: /\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{20,80}\b/g,
    mask: '[REDACTED_OPENAI_KEY]',
    partial: () => 'sk-****************'
  },
  {
    type: 'SLACK_TOKEN',
    title: 'Slack Bot / User Token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
    mask: '[REDACTED_SLACK_TOKEN]',
    partial: () => 'xox*-****************'
  },

  // 2. Structured PII
  {
    type: 'EMAIL',
    title: 'Email Address',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    mask: '[REDACTED_EMAIL]',
    partial: (m) => {
      const parts = m.split('@');
      const name = parts[0];
      const domain = parts[1];
      const maskedName = name.length > 2 ? `${name[0]}***${name[name.length - 1]}` : '***';
      return `${maskedName}@${domain}`;
    }
  },
  {
    type: 'CREDIT_CARD',
    title: 'Credit / Debit Card Number',
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{13}\b/g,
    mask: '[REDACTED_CREDIT_CARD]',
    validate: (m) => isValidLuhn(m),
    partial: (m) => {
      const digits = m.replace(/[\s-]/g, '');
      return `****-****-****-${digits.slice(-4)}`;
    }
  },
  {
    type: 'SSN',
    title: 'US Social Security Number',
    regex: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    mask: '[REDACTED_SSN]',
    partial: (m) => `***-**-${m.replace(/[-\s]/g, '').slice(-4)}`
  },
  {
    type: 'PHONE',
    title: 'Phone Number (Intl / Domestic)',
    regex: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    mask: '[REDACTED_PHONE]',
    partial: (m) => {
      const cleaned = m.replace(/[^\d+]/g, '');
      return `(***) ***-${cleaned.slice(-4)}`;
    }
  },
  {
    type: 'IP_ADDRESS',
    title: 'IPv4 Address',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    mask: '[REDACTED_IP]',
    partial: (m) => {
      const octets = m.split('.');
      return `${octets[0]}.${octets[1]}.*.*`;
    }
  }
];

class PiiScrubber {
  static RULES = PII_RULES;

  /**
   * Calculates Shannon Entropy for an individual string token.
   */
  static calculateEntropy(str) {
    return calculateShannonEntropy(str);
  }

  /**
   * Validates credit card format with Luhn mod 10 check.
   */
  static isLuhnValid(cardStr) {
    return isValidLuhn(cardStr);
  }

  /**
   * Core scrubbing & redaction pipeline.
   *
   * @param {string} text - Raw text to scrub
   * @param {Object} options - Configuration options
   * @param {string} options.mode - 'mask' | 'partial' | 'tokenize'
   * @param {number} options.entropyThreshold - Shannon entropy cutoff (default: 3.8)
   * @param {number} options.minEntropyLength - Min token length for entropy (default: 16)
   * @returns {Object} Scrubbing result with cleanText, telemetry, and vault for rehydration.
   */
  static scrub(text, options = {}) {
    const startTime = process.hrtime.bigint ? process.hrtime.bigint() : null;
    const mode = options.mode || 'mask'; // 'mask', 'partial', 'tokenize'
    const entropyThreshold = typeof options.entropyThreshold === 'number' ? options.entropyThreshold : 3.8;
    const minEntropyLength = options.minEntropyLength || 16;

    let clean = text || '';
    let totalRedacted = 0;
    const redactedTypes = {};
    const vault = {}; // Used for reversible pseudonymization (token -> original)
    const findings = [];

    // Phase 1: Pattern Rule Matching
    for (const rule of PiiScrubber.RULES) {
      clean = clean.replace(rule.regex, (match) => {
        // Run custom validator (e.g. Luhn checksum) if present
        if (rule.validate && !rule.validate(match)) {
          return match; // False positive, preserve original
        }

        totalRedacted++;
        redactedTypes[rule.type] = (redactedTypes[rule.type] || 0) + 1;

        let replacement = rule.mask;
        if (mode === 'partial' && rule.partial) {
          replacement = rule.partial(match);
        } else if (mode === 'tokenize') {
          const tokenId = `{{TOKEN_${rule.type}_${totalRedacted}}}`;
          vault[tokenId] = match;
          replacement = tokenId;
        }

        findings.push({
          type: rule.type,
          original: match,
          replacement,
          source: 'REGEX_PATTERN'
        });

        return replacement;
      });
    }

    // Phase 2: Shannon Entropy Analysis for High-Entropy Raw Secrets
    const words = clean.split(/(\s+|["'=,:;()\[\]{}]+)/);
    for (let i = 0; i < words.length; i++) {
      const token = words[i];
      if (
        token &&
        token.length >= minEntropyLength &&
        !token.startsWith('[REDACTED_') &&
        !token.startsWith('{{TOKEN_') &&
        !/^[A-Za-z]+$/.test(token) // Skip dictionary prose
      ) {
        const ent = calculateShannonEntropy(token);
        if (ent >= entropyThreshold) {
          totalRedacted++;
          redactedTypes['HIGH_ENTROPY_SECRET'] = (redactedTypes['HIGH_ENTROPY_SECRET'] || 0) + 1;

          let replacement = '[REDACTED_HIGH_ENTROPY_SECRET]';
          if (mode === 'partial') {
            replacement = `${token.substring(0, 3)}***${token.slice(-3)}`;
          } else if (mode === 'tokenize') {
            const tokenId = `{{TOKEN_SECRET_${totalRedacted}}}`;
            vault[tokenId] = token;
            replacement = tokenId;
          }

          findings.push({
            type: 'HIGH_ENTROPY_SECRET',
            original: token,
            replacement,
            entropy: parseFloat(ent.toFixed(3)),
            source: 'SHANNON_ENTROPY'
          });

          words[i] = replacement;
        }
      }
    }
    clean = words.join('');

    let elapsedMs = 0.0;
    if (startTime) {
      const elapsedNs = Number(process.hrtime.bigint() - startTime);
      elapsedMs = elapsedNs / 1_000_000.0;
    }

    return {
      cleanText: clean,
      totalRedacted,
      redactedTypes,
      findings,
      vault,
      mode,
      metrics: {
        elapsedMs: parseFloat(elapsedMs.toFixed(3)),
        originalChars: text.length,
        cleanChars: clean.length,
        entropyThreshold
      }
    };
  }

  /**
   * Re-hydrates a pseudonymized string back to original values using the vault.
   * Enables round-trip LLM interaction without leaking sensitive data to external AI models.
   *
   * @param {string} text - Sanitized text containing {{TOKEN_...}} identifiers
   * @param {Object} vault - Token to original value mapping
   * @returns {string} Reconstituted original text
   */
  static rehydrate(text, vault = {}) {
    if (!text || !vault) return text;
    let reconstituted = text;
    for (const [tokenId, originalVal] of Object.entries(vault)) {
      reconstituted = reconstituted.split(tokenId).join(originalVal);
    }
    return reconstituted;
  }
}

module.exports = {
  PiiScrubber,
  calculateShannonEntropy,
  isValidLuhn,
  PII_RULES
};
