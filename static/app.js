const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const resultPanel = document.getElementById('result');
const errorPanel = document.getElementById('error-panel');

const verdictBadge = document.getElementById('verdict-badge');
const verdictIcon = document.getElementById('verdict-icon');
const verdictLabel = document.getElementById('verdict-label');
const verdictUrl = document.getElementById('verdict-url');
const confidenceNum = document.getElementById('confidence-num');
const gaugeFill = document.getElementById('gauge-fill');
const signalsList = document.getElementById('signals-list');
const featureGrid = document.getElementById('feature-grid');

document.querySelectorAll('.sample-chip').forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url;
    runScan();
  });
});

scanBtn.addEventListener('click', runScan);
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runScan();
});

async function runScan() {
  const url = urlInput.value.trim();
  errorPanel.classList.add('hidden');
  if (!url) return;

  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Something went wrong.');
    }
    renderResult(data);
  } catch (err) {
    errorPanel.textContent = 'Error: ' + err.message;
    errorPanel.classList.remove('hidden');
    resultPanel.classList.add('hidden');
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan';
  }
}

function renderResult(data) {
  const isPhishing = data.prediction === 'phishing';

  verdictBadge.className = 'verdict-badge ' + (isPhishing ? 'danger' : 'safe');
  verdictIcon.textContent = isPhishing ? '!' : '✓';
  verdictLabel.className = 'verdict-label ' + (isPhishing ? 'danger' : 'safe');
  verdictLabel.textContent = isPhishing ? 'Likely phishing' : 'Looks legitimate';
  verdictUrl.textContent = data.url;

  const conf = isPhishing ? data.phishing_probability : data.legitimate_probability;
  confidenceNum.textContent = conf.toFixed(1) + '%';
  confidenceNum.style.color = isPhishing ? 'var(--red)' : 'var(--green)';

  gaugeFill.style.left = data.phishing_probability + '%';

  signalsList.innerHTML = '';
  data.reasons.forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    signalsList.appendChild(li);
  });

  featureGrid.innerHTML = '';
  Object.entries(data.features).forEach(([k, v]) => {
    const kEl = document.createElement('div');
    kEl.className = 'fk';
    kEl.textContent = k;
    const vEl = document.createElement('div');
    vEl.className = 'fv';
    vEl.textContent = v;
    featureGrid.appendChild(kEl);
    featureGrid.appendChild(vEl);
  });

  resultPanel.classList.remove('hidden');
}
