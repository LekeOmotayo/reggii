/**
 * Rehydration Panel Component
 * Demonstrates the reversible pseudonymization roundtrip.
 */

export class RehydrationPanelComponent {
  constructor({ onRehydrate }) {
    this.tokenizedInput = document.getElementById('tokenizedInput');
    this.rehydratedOutput = document.getElementById('rehydratedOutput');
    this.rehydrateBtn = document.getElementById('rehydrateBtn');
    this.vaultDisplay = document.getElementById('vaultDisplay');
    this.onRehydrate = onRehydrate;
    this.currentVault = {};

    this._bindEvents();
  }

  _bindEvents() {
    if (this.rehydrateBtn) {
      this.rehydrateBtn.addEventListener('click', () => {
        const text = this.tokenizedInput ? this.tokenizedInput.value : '';
        if (this.onRehydrate) {
          this.onRehydrate(text, this.currentVault);
        }
      });
    }
  }

  updateVault(vault = {}) {
    this.currentVault = vault;
    if (this.vaultDisplay) {
      this.vaultDisplay.innerText = Object.keys(vault).length > 0
        ? JSON.stringify(vault, null, 2)
        : '// Reversible token vault is empty (switch to "Reversible Pseudonymization" mode to populate)';
    }

    if (this.tokenizedInput && Object.keys(vault).length > 0) {
      const tokenKeys = Object.keys(vault);
      const sampleLlmResponse = `AI Assistant Response:
Acknowledging safe receipt for ${tokenKeys[0] || 'token'}.
Confirmation has been recorded in the secure audit log.`;
      this.tokenizedInput.value = sampleLlmResponse;
    }
  }

  renderRehydrated(rehydratedText) {
    if (this.rehydratedOutput) {
      this.rehydratedOutput.innerText = rehydratedText || '';
    }
  }
}
