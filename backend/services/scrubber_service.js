'use strict';

const { PiiScrubber, calculateShannonEntropy } = require('../core/scrubber');
const { PatternRepository } = require('../repositories/pattern_repository');

class ScrubberService {
  constructor(repository = PatternRepository) {
    this.repo = repository;
  }

  scrubText(text, options = {}) {
    const mode = options.mode || 'REPLACE'; // REPLACE, PARTIAL, PSEUDONYMIZE
    const minEntropy = options.minEntropy || 4.2;

    const result = PiiScrubber.scrub(text, {
      mode,
      minEntropyThreshold: minEntropy
    });

    return {
      status: 'success',
      cleanText: result.cleanText,
      totalRedacted: result.totalRedacted,
      redactions: result.redactions,
      pseudonymMap: result.pseudonymMap || null,
      processingTimeMs: result.processingTimeMs
    };
  }

  rehydrateText(scrubbedText, pseudonymMap) {
    if (!pseudonymMap || typeof pseudonymMap !== 'object') {
      return { status: 'error', message: 'Valid pseudonym map is required for rehydration' };
    }
    const original = PiiScrubber.rehydrate(scrubbedText, pseudonymMap);
    return {
      status: 'success',
      rehydratedText: original
    };
  }

  calculateEntropy(text) {
    return {
      status: 'success',
      entropy: calculateShannonEntropy(text)
    };
  }

  getRules() {
    return this.repo.getRules();
  }

  getSamples() {
    return this.repo.getSamplePayloads();
  }
}

module.exports = { ScrubberService };
