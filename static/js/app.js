/**
 * Main Application Orchestrator for Leke PII Scrubber
 * Connects InputPanel, OutputPanel, RehydrationPanel, and API service.
 */

import { ApiService } from './api.js';
import { InputPanelComponent } from './components/InputPanel.js';
import { OutputPanelComponent } from './components/OutputPanel.js';
import { RehydrationPanelComponent } from './components/RehydrationPanel.js';

class App {
  constructor() {
    this.api = new ApiService();
    this.output = new OutputPanelComponent();

    this.rehydration = new RehydrationPanelComponent({
      onRehydrate: (text, vault) => this.handleRehydrate(text, vault)
    });

    this.input = new InputPanelComponent({
      onScrub: (text, mode) => this.handleScrub(text, mode)
    });

    this.serverBadge = document.getElementById('serverBadge');
    this.serverBadgeText = document.getElementById('serverBadgeText');
  }

  async init() {
    const health = await this.api.checkHealth();
    this._updateServerStatus(health);

    const initialText = this.input.getText();
    if (initialText) {
      await this.handleScrub(initialText, this.input.getMode());
    }
  }

  async handleScrub(text, mode) {
    if (!text) return;
    this.input.setLoading(true);

    try {
      const result = await this.api.scrubText(text, mode);
      this.output.render(result);
      this.rehydration.updateVault(result.vault);
    } catch (e) {
      console.error('Scrub error:', e);
    } finally {
      this.input.setLoading(false);
    }
  }

  async handleRehydrate(text, vault) {
    if (!text) return;
    try {
      const { rehydrated } = await this.api.rehydrateText(text, vault);
      this.rehydration.renderRehydrated(rehydrated);
    } catch (e) {
      console.error('Rehydration error:', e);
    }
  }

  _updateServerStatus({ connected, label }) {
    if (!this.serverBadge || !this.serverBadgeText) return;
    this.serverBadgeText.innerText = label;

    if (connected) {
      this.serverBadge.style.background = 'rgba(16, 185, 129, 0.15)';
      this.serverBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      this.serverBadge.style.color = '#34d399';
    } else {
      this.serverBadge.style.background = 'rgba(168, 85, 247, 0.15)';
      this.serverBadge.style.borderColor = 'rgba(168, 85, 247, 0.4)';
      this.serverBadge.style.color = '#c084fc';
    }
  }
}

// Boot application
window.addEventListener('DOMContentLoaded', () => {
  const app = new App();
  app.init();
});
