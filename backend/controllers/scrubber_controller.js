'use strict';

const { ScrubberService } = require('../services/scrubber_service');

class ScrubberController {
  constructor(service = new ScrubberService()) {
    this.service = service;
  }

  handleScrub(payload) {
    const text = payload.text || '';
    if (!text.trim()) {
      return { status: 'error', message: 'Text payload cannot be empty' };
    }
    return this.service.scrubText(text, {
      mode: payload.mode || 'REPLACE',
      minEntropy: parseFloat(payload.minEntropy) || 4.2
    });
  }

  handleRehydrate(payload) {
    return this.service.rehydrateText(payload.text || '', payload.pseudonymMap || {});
  }

  handleEntropy(payload) {
    return this.service.calculateEntropy(payload.text || '');
  }

  handleRules() {
    return {
      status: 'success',
      rules: this.service.getRules()
    };
  }

  handleSamples() {
    return {
      status: 'success',
      samples: this.service.getSamples()
    };
  }
}

module.exports = { ScrubberController };
