/**
 * Input Panel Component
 * Manages raw prompt text, preset scenarios, mode selector, and scrubbing triggers.
 */

import { SAMPLE_PRESETS } from '../api.js';

export class InputPanelComponent {
  constructor({ onScrub }) {
    this.rawInput = document.getElementById('rawInput');
    this.presetContainer = document.getElementById('presetContainer');
    this.scrubBtn = document.getElementById('scrubBtn');
    this.modePills = document.querySelectorAll('.mode-pill');
    this.onScrub = onScrub;
    this.currentMode = 'mask';

    this._bindEvents();
    this._renderPresets();
  }

  _bindEvents() {
    this.modePills.forEach(pill => {
      pill.addEventListener('click', () => {
        this.modePills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.currentMode = pill.getAttribute('data-mode') || 'mask';
        if (this.onScrub) {
          this.onScrub(this.getText(), this.currentMode);
        }
      });
    });

    if (this.scrubBtn) {
      this.scrubBtn.addEventListener('click', () => {
        if (this.onScrub) {
          this.onScrub(this.getText(), this.currentMode);
        }
      });
    }
  }

  _renderPresets() {
    if (!this.presetContainer) return;
    this.presetContainer.innerHTML = '';

    SAMPLE_PRESETS.forEach(p => {
      const btn = document.createElement('button');
      btn.className = 'preset-btn';
      btn.innerText = p.label;
      btn.addEventListener('click', () => {
        this.setText(p.text);
        if (this.onScrub) {
          this.onScrub(p.text, this.currentMode);
        }
      });
      this.presetContainer.appendChild(btn);
    });
  }

  getText() {
    return this.rawInput ? this.rawInput.value : '';
  }

  setText(text) {
    if (this.rawInput) {
      this.rawInput.value = text;
    }
  }

  getMode() {
    return this.currentMode;
  }

  setLoading(loading) {
    if (this.scrubBtn) {
      this.scrubBtn.disabled = loading;
      this.scrubBtn.innerHTML = loading
        ? '<span>⏳</span> Sanitizing Tokens...'
        : '<span>🛡️</span> Sanitize Payload with PiiScrubber';
    }
  }
}
