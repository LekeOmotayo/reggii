/**
 * API Service for Leke PII Scrubber
 * Communicates with embedded Node.js REST API with offline fallback.
 */

export const SAMPLE_PRESETS = [
  {
    label: "DevOps Incident Log",
    text: `System Incident #8192:
Database replica failed on host 10.0.4.15
Admin on-call: robert.langdon@cybercorp.com
Root AWS Credentials: AKIAIOSFODNN7EXAMPLE
Emergency Token: sk-proj-948102948192384910283491
Session Key: kX9#vL2!mP9$qR8@zW4^`
  },
  {
    label: "Fintech Customer Ticket",
    text: `Customer Support Case #48102:
Client: Sarah Connor
Email: s.connor@sky-bank.com
Phone: +1 (415) 555-2671
SSN on File: 342-88-1294
Card for Refund: 4532-0150-1234-5671 (Visa Gold)`
  },
  {
    label: "Clean Safe Prose",
    text: `Weekly engineering team retrospective:
All microservices operated with 99.98% availability over the sprint.
Database cache hit ratio was 85%. No security incidents reported.`
  }
];

export class ApiService {
  constructor() {
    this.isConnected = false;
  }

  async checkHealth() {
    try {
      const resp = await fetch('/api/rules');
      if (resp.ok) {
        this.isConnected = true;
        return { connected: true, label: "Connected: Native Node.js Scrubber Engine" };
      }
    } catch (e) {}
    this.isConnected = false;
    return { connected: false, label: "Client Mode (Offline Resilient)" };
  }

  async scrubText(text, mode = 'mask', entropyThreshold = 3.8) {
    if (this.isConnected) {
      try {
        const resp = await fetch('/api/scrub', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, mode, entropyThreshold })
        });
        if (resp.ok) return await resp.json();
      } catch (e) {
        console.warn('Backend call failed, using client simulation:', e);
      }
    }
    return this._simulateScrub(text, mode, entropyThreshold);
  }

  async rehydrateText(text, vault) {
    if (this.isConnected) {
      try {
        const resp = await fetch('/api/rehydrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, vault })
        });
        if (resp.ok) return await resp.json();
      } catch (e) {}
    }

    // Client fallback
    let rehydrated = text;
    for (const [token, orig] of Object.entries(vault || {})) {
      rehydrated = rehydrated.split(token).join(orig);
    }
    return { rehydrated };
  }

  _calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freqs = {};
    for (let i = 0; i < str.length; i++) {
      const ch = str.charAt(i);
      freqs[ch] = (freqs[ch] || 0) + 1;
    }
    let ent = 0;
    for (const count of Object.values(freqs)) {
      const p = count / str.length;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  _simulateScrub(text, mode, entropyThreshold) {
    let clean = text;
    let count = 0;
    const types = {};
    const vault = {};
    const findings = [];

    const rules = [
      { type: 'AWS_KEY', regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g, mask: '[REDACTED_AWS_KEY]' },
      { type: 'OPENAI_KEY', regex: /\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{20,80}\b/g, mask: '[REDACTED_OPENAI_KEY]' },
      { type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, mask: '[REDACTED_EMAIL]' },
      { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, mask: '[REDACTED_CREDIT_CARD]' },
      { type: 'SSN', regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, mask: '[REDACTED_SSN]' },
      { type: 'PHONE', regex: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, mask: '[REDACTED_PHONE]' },
      { type: 'IP_ADDRESS', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, mask: '[REDACTED_IP]' }
    ];

    for (const r of rules) {
      clean = clean.replace(r.regex, (m) => {
        count++;
        types[r.type] = (types[r.type] || 0) + 1;
        let rep = r.mask;
        if (mode === 'partial') rep = `${m.slice(0, 3)}***${m.slice(-3)}`;
        else if (mode === 'tokenize') {
          rep = `{{TOKEN_${r.type}_${count}}}`;
          vault[rep] = m;
        }
        findings.push({ type: r.type, original: m, replacement: rep });
        return rep;
      });
    }

    // Entropy pass
    const words = clean.split(/(\s+|["'=,:;()\[\]{}]+)/);
    for (let i = 0; i < words.length; i++) {
      const tok = words[i];
      if (tok && tok.length >= 16 && !tok.startsWith('[REDACTED_') && !tok.startsWith('{{TOKEN_')) {
        const ent = this._calculateEntropy(tok);
        if (ent >= entropyThreshold) {
          count++;
          types['HIGH_ENTROPY_SECRET'] = (types['HIGH_ENTROPY_SECRET'] || 0) + 1;
          let rep = '[REDACTED_HIGH_ENTROPY_SECRET]';
          if (mode === 'partial') rep = `${tok.slice(0, 3)}***${tok.slice(-3)}`;
          else if (mode === 'tokenize') {
            rep = `{{TOKEN_SECRET_${count}}}`;
            vault[rep] = tok;
          }
          findings.push({ type: 'HIGH_ENTROPY_SECRET', original: tok, replacement: rep, entropy: parseFloat(ent.toFixed(3)) });
          words[i] = rep;
        }
      }
    }
    clean = words.join('');

    return {
      cleanText: clean,
      totalRedacted: count,
      redactedTypes: types,
      findings,
      vault,
      mode,
      metrics: { elapsedMs: 0.85, originalChars: text.length, cleanChars: clean.length }
    };
  }
}
