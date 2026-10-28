/**
 * Output Panel Component
 * Displays sanitized clean text, category breakdown chips, and copy buttons.
 */

export class OutputPanelComponent {
  constructor() {
    this.cleanOutput = document.getElementById('cleanOutput');
    this.findingsContainer = document.getElementById('findingsContainer');
    this.metricRedactedCount = document.getElementById('metricRedactedCount');
    this.metricElapsedMs = document.getElementById('metricElapsedMs');
    this.copyCleanBtn = document.getElementById('copyCleanBtn');

    if (this.copyCleanBtn) {
      this.copyCleanBtn.addEventListener('click', () => {
        const txt = this.cleanOutput.innerText;
        navigator.clipboard.writeText(txt).then(() => {
          alert('Sanitized LLM-safe text copied to clipboard!');
        });
      });
    }
  }

  render(scrubResult) {
    if (!scrubResult) return;

    if (this.cleanOutput) {
      this.cleanOutput.innerText = scrubResult.cleanText || '';
    }

    if (this.metricRedactedCount) {
      this.metricRedactedCount.innerHTML = `${scrubResult.totalRedacted || 0} <span class="metric-sub">elements redacted</span>`;
    }

    if (this.metricElapsedMs && scrubResult.metrics) {
      this.metricElapsedMs.innerHTML = `${scrubResult.metrics.elapsedMs || 0} ms <span class="metric-sub">sanitization latency</span>`;
    }

    if (this.findingsContainer) {
      this.findingsContainer.innerHTML = '';
      const types = scrubResult.redactedTypes || {};

      if (Object.keys(types).length === 0) {
        this.findingsContainer.innerHTML = '<span style="font-size: 0.8rem; color: #10b981;">✔ Zero PII or secrets detected in payload. Safe for external LLM dispatch.</span>';
        return;
      }

      Object.entries(types).forEach(([cat, count]) => {
        const chip = document.createElement('span');
        chip.className = 'finding-chip';
        chip.innerText = `${cat}: ${count}`;
        this.findingsContainer.appendChild(chip);
      });
    }
  }
}
