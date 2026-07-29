// popup.js
// Retrieves the latest analysis result from background.js and renders it.

let currentResult  = null;
let currentEmail   = null;

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function authClass(val) {
  return val === 'pass' ? 'auth-pass' : val === 'fail' ? 'auth-fail' : 'auth-unknown';
}

function renderResult(data) {
  currentResult = data;
  const score   = data.risk_score;
  const circumference = 201; // 2 * π * 32

  // Gauge colour
  const colour = score >= 70 ? '#ea4335' : score >= 40 ? '#f9ab00' : '#00c9a7';

  // Animate gauge
  const fill = document.getElementById('gaugeFill');
  fill.setAttribute('stroke', colour);
  // start at 0 then animate
  setTimeout(() => {
    fill.setAttribute('stroke-dasharray', `${Math.round(score * circumference / 100)} ${circumference}`);
  }, 60);

  document.getElementById('scoreNum').textContent  = score;
  document.getElementById('scoreNum').style.color  = colour;

  // Verdict pill
  const pill = document.getElementById('verdictPill');
  pill.textContent  = data.verdict;
  pill.className    = 'verdict-pill ' + (score >= 70 ? 'verdict-high' : score >= 40 ? 'verdict-med' : 'verdict-low');

  // Method chip
  const chip = document.getElementById('methodChip');
  chip.innerHTML = data.method === 'ml'
    ? '🤖 ML Model' + (data.confidence !== null ? ` · ${Math.round(data.confidence * 100)}% confidence` : '')
    : '📋 Rule-based fallback';

  // Flags / findings
  const flags = data.flags || [];
  const flagsEl = document.getElementById('flagsContainer');
  if (flags.length === 0) {
    flagsEl.innerHTML = '<div class="flag flag-safe">No significant phishing signals detected.</div>';
  } else {
    flagsEl.innerHTML = flags.map(f =>
      `<div class="flag">${f}</div>`
    ).join('');
  }

  // Auth chips — pull from stored email data if available
  const spf   = (data.spf  || 'none');
  const dkim  = (data.dkim || 'none');
  const dmarc = (data.dmarc|| 'none');
  document.getElementById('authRow').innerHTML = [
    ['SPF', spf], ['DKIM', dkim], ['DMARC', dmarc]
  ].map(([label, val]) =>
    `<span class="auth-chip ${authClass(val)}">${label}: ${val.toUpperCase()}</span>`
  ).join('');

  // Footer
  document.getElementById('footerText').textContent =
    `Analysed just now · ${data.method === 'ml' ? 'ML' : 'Rules'} · v1.0`;

  showScreen('screen-result');
}

function setupFeedback() {
  const row = document.getElementById('feedbackRow');

  document.getElementById('fbYes').onclick = () => {
    if (!currentResult) return;
    const predicted = currentResult.risk_score >= 50 ? 1 : 0;
    sendFeedback(predicted, predicted); // correct = same as predicted
    row.innerHTML = '<span style="color:#00c9a7;font-weight:600">✓ Feedback recorded — thank you!</span>';
  };

  document.getElementById('fbNo').onclick = () => {
    if (!currentResult) return;
    const predicted = currentResult.risk_score >= 50 ? 1 : 0;
    const correct   = predicted === 1 ? 0 : 1; // flip
    sendFeedback(predicted, correct);
    row.innerHTML = '<span style="color:#00c9a7;font-weight:600">✓ Feedback recorded — thank you!</span>';
  };
}

function sendFeedback(predictedLabel, correctLabel) {
  chrome.runtime.sendMessage({
    type: 'SEND_FEEDBACK',
    payload: {
      email:           currentEmail || {},
      predicted_label: predictedLabel,
      correct_label:   correctLabel,
    }
  });
}

function loadResult() {
  showScreen('screen-loading');

  // Animate loading steps
  setTimeout(() => {
    document.getElementById('step-auth').className  = 'loading-step done';
    document.getElementById('step-urls').className  = 'loading-step done';
    document.getElementById('step-ml').className    = 'loading-step active';
  }, 400);

  chrome.runtime.sendMessage({ type: 'GET_RESULT' }, (response) => {
    if (chrome.runtime.lastError || !response) {
      showScreen('screen-idle');
      return;
    }

    const result = response.result;

    if (!result) {
      // No email open yet
      showScreen('screen-idle');
      return;
    }

    if (result.error) {
      document.getElementById('errorMsg').textContent = result.error;
      showScreen('screen-error');
      return;
    }

    renderResult(result);
    setupFeedback();
  });
}

// Run on popup open
document.addEventListener('DOMContentLoaded', loadResult);
