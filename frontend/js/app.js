document.addEventListener('DOMContentLoaded', () => {
  const rawInput = document.getElementById('raw-input');
  const sanitizedOutput = document.getElementById('sanitized-output');
  const modeSelect = document.getElementById('mode-select');
  const scrubBtn = document.getElementById('scrub-btn');
  const rehydrateBtn = document.getElementById('rehydrate-btn');
  const copyBtn = document.getElementById('copy-btn');
  const redactionCount = document.getElementById('redaction-count');
  const processingTime = document.getElementById('processing-time');
  const auditTbody = document.getElementById('audit-tbody');

  let samplesMap = {};
  let currentPseudonymMap = null;

  async function loadSamples() {
    try {
      const res = await fetch('/api/samples');
      const data = await res.json();
      samplesMap = data.samples || {};

      if (samplesMap.customer_record) {
        rawInput.value = samplesMap.customer_record.text;
        runScrub();
      }
    } catch (err) {
      console.error('Failed to load samples:', err);
    }
  }

  document.querySelectorAll('.sample-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const key = pill.getAttribute('data-key');
      if (samplesMap[key]) {
        rawInput.value = samplesMap[key].text;
        runScrub();
      }
    });
  });

  modeSelect.addEventListener('change', () => {
    rehydrateBtn.style.display = modeSelect.value === 'PSEUDONYMIZE' ? 'inline-flex' : 'none';
  });

  async function runScrub() {
    const text = rawInput.value.trim();
    if (!text) return;

    scrubBtn.disabled = true;
    scrubBtn.textContent = 'Sanitizing...';

    try {
      const res = await fetch('/api/scrub', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          mode: modeSelect.value
        })
      });

      const data = await res.json();
      renderScrubResult(data);
    } catch (err) {
      console.error('Scrub failed:', err);
    } finally {
      scrubBtn.disabled = false;
      scrubBtn.innerHTML = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        Sanitize Payload
      `;
    }
  }

  function renderScrubResult(data) {
    if (data.status !== 'success') {
      alert(data.message || 'Error scrubbing text');
      return;
    }

    currentPseudonymMap = data.pseudonymMap;
    redactionCount.textContent = `${data.totalRedacted} items masked`;
    processingTime.textContent = `${(data.processingTimeMs || 0).toFixed(2)} ms`;

    // Highlight redacted placeholders in output
    let htmlClean = escapeHtml(data.cleanText);
    htmlClean = htmlClean.replace(/(\[[A-Z0-9_]+\])/g, '<span class="redacted-tag">$1</span>');
    sanitizedOutput.innerHTML = htmlClean;

    // Render Audit Table
    auditTbody.innerHTML = '';
    if (!data.redactions || data.redactions.length === 0) {
      auditTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Clean payload! Zero sensitive entities found.</td></tr>';
    } else {
      data.redactions.forEach(r => {
        const tr = document.createElement('tr');
        const entropyScore = r.entropy ? `${r.entropy.toFixed(2)} bits/char` : '--';
        tr.innerHTML = `
          <td><strong>${r.type}</strong></td>
          <td><code>${escapeHtml(r.original.length > 28 ? r.original.slice(0, 25) + '...' : r.original)}</code></td>
          <td><span class="redacted-tag">${escapeHtml(r.replacement)}</span></td>
          <td>${entropyScore}</td>
          <td><span class="badge-valid">Verified Pattern</span></td>
        `;
        auditTbody.appendChild(tr);
      });
    }
  }

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  scrubBtn.addEventListener('click', runScrub);

  rehydrateBtn.addEventListener('click', async () => {
    if (!currentPseudonymMap) {
      alert('No pseudonym map exists. Scrub in Pseudonymize mode first.');
      return;
    }

    try {
      const res = await fetch('/api/rehydrate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: sanitizedOutput.textContent,
          pseudonymMap: currentPseudonymMap
        })
      });
      const data = await res.json();
      sanitizedOutput.textContent = data.rehydratedText;
      alert('Rehydrated original text using reversible pseudonym map!');
    } catch (e) {
      console.error(e);
    }
  });

  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(sanitizedOutput.textContent).then(() => {
      const orig = copyBtn.textContent;
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = orig; }, 1500);
    });
  });

  loadSamples();
});
