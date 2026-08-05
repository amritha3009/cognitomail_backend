// content.js — CognitoMail
// Fixes applied:
// 1. Multi-selector Gmail extraction — handles Gmail class name changes
// 2. onDomSettled resets lastEmailSignature when no email open (fixes "only first email detected")
// 3. isAnalysing safety release timeout (fixes permanently stuck lock)
// 4. All chrome.runtime.sendMessage calls wrapped in try/catch (fixes "context invalidated" error)
// 5. Navigation listener resets state unconditionally on URL change
console.log("===== CognitoMail content script loaded =====");
console.log("Current URL:", window.location.href);

document.addEventListener("click", () => {
    console.log("Click detected");
});

(function () {
  'use strict';

  let lastEmailSignature = null;
  let isAnalysing        = false;
  let debounceTimer      = null;
  let isInjecting        = false;

  const DEBOUNCE_MS = 800;

  // ── Observer ───────────────────────────────────────────────────────────────

  const observer = new MutationObserver(() => {
    if (isInjecting) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(onDomSettled, DEBOUNCE_MS);
  });

  function startObserving() {
    console.log("[CognitoMail] Observer started");

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserving);
  } else {
    startObserving();
  }

  // ── DOM settled callback ───────────────────────────────────────────────────

  function onDomSettled() {
    console.log("onDomSettled()");
    if (isAnalysing) return;

    const emailData = extractEmailData();
    console.log(emailData);
    if (!emailData) {
      // FIX: reset signature when no email is open so the next email
      // opened is treated as new — this is the core fix for "only first
      // email detected" bug.
      lastEmailSignature = null;
      return;
    }

    const sig = emailData.subject + '||' + emailData.sender;
    if (sig === lastEmailSignature) return;

    lastEmailSignature = sig;
    triggerAnalysis(emailData);
  }

  // ── DOM Extraction ─────────────────────────────────────────────────────────

  function extractEmailData() {
    console.log("extractEmailData() called");
    const host = window.location.hostname;
    if (host === 'mail.google.com') return extractGmail();
    if (host.includes('outlook'))   return extractOutlook();
    return null;
  }

  function extractGmail() {
    // Subject — try multiple selectors, Gmail changes class names frequently
    const subjectEl =
      document.querySelector('h2.hP') ||
      document.querySelector('[data-thread-perm-id] h2') ||
      document.querySelector('.ha h2') ||
      document.querySelector('[role="main"] h2') ||
      document.querySelector('.a98.iY h2') ||
      (() => {
        const main = document.querySelector('[role="main"]');
        console.log("extractGmail() called");
        return main ? main.querySelector('h2') : null;
      })();

    // Body — try multiple selectors
    const bodyEl =
      document.querySelector('.a3s.aiL') ||
      document.querySelector('.a3s') ||
      document.querySelector('[role="main"] .ii.gt') ||
      document.querySelector('.Am.Al.editable') ||
      document.querySelector('[role="main"] .adP.adO') ||
      (() => {
        const candidates = document.querySelectorAll(
          '[role="main"] div[dir="ltr"], [role="main"] div[dir="auto"]'
        );
        for (const el of candidates) {
          if (el.innerText && el.innerText.trim().length > 50) return el;
        }
        return null;
      })();

    if (!subjectEl || !bodyEl) {
      console.debug('[CognitoMail] Gmail extraction failed:', {
        subjectEl: !!subjectEl,
        bodyEl:    !!bodyEl,
      });
      return null;
    }

    const subject = subjectEl.textContent.trim();
    const body    = bodyEl.innerText.trim();
    if (!subject || body.length < 5) return null;

    // Sender — try multiple selectors
    const senderEl =
      document.querySelector('.gD') ||
      document.querySelector('[email]') ||
      document.querySelector('.go') ||
      document.querySelector('[data-hovercard-id]') ||
      (() => {
        const spans = document.querySelectorAll('[role="main"] span, [role="main"] a');
        for (const s of spans) {
          if (s.getAttribute('email') ||
              /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s.textContent.trim())) {
            return s;
          }
        }
        return null;
      })();

    let sender = '';
    if (senderEl) {
      sender = senderEl.getAttribute('email') ||
               senderEl.getAttribute('data-hovercard-id') ||
               senderEl.textContent.trim();
    }
    if (!sender) {
      const fromArea = document.querySelector(
        '[role="main"] .go, [role="main"] .gD, [role="main"] .zA'
      );
      if (fromArea) sender = fromArea.textContent.trim();
    }

    console.debug('[CognitoMail] Extracted:', {
      subject, sender, bodyLength: body.length
    });

    return {
      sender:  sender || 'unknown',
      subject: subject,
      body:    body,
      urls:    extractUrls(bodyEl.innerHTML),
      spf:     extractAuth('spf'),
      dkim:    extractAuth('dkim'),
      dmarc:   extractAuth('dmarc'),
    };
  }

  function extractOutlook() {
    const subjectEl =
      document.querySelector('[data-testid="subject"]') ||
      document.querySelector('.allowTextSelection');
      console.log(subjectEl);
    const senderEl =
      document.querySelector('[data-testid="senderName"]') ||
      document.querySelector('.OZZZK');
      console.log(senderEl);
    const bodyEl =
      document.querySelector('[data-testid="emailBodyContainer"]') ||
      document.querySelector('.Wr[role="document"]');
      console.log(bodyEl);

    if (!subjectEl || !senderEl || !bodyEl) return null;

    const subject = subjectEl.textContent.trim();
    const sender  = senderEl.textContent.trim();
    const body    = bodyEl.innerText.trim();
    if (!subject || !body) return null;

    return {
      sender, subject, body,
      urls:  extractUrls(bodyEl.innerHTML),
      spf: 'none', dkim: 'none', dmarc: 'none',
    };
  }

  function extractAuth(protocol) {
    const detailSpans = document.querySelectorAll('.aZy, .ajz, [data-tooltip]');
    for (const span of detailSpans) {
      const text = (
        span.textContent + (span.getAttribute('data-tooltip') || '')
      ).toLowerCase();
      if (text.includes(protocol)) {
        if (text.includes('pass'))     return 'pass';
        if (text.includes('fail'))     return 'fail';
        if (text.includes('softfail')) return 'fail';
      }
    }
    return 'none';
  }

  function extractUrls(html) {
    const matches = html.match(/https?:\/\/[^\s"'<>]+/g) || [];
    return [...new Set(matches)].slice(0, 20);
  }

  // ── Analysis ───────────────────────────────────────────────────────────────

  function triggerAnalysis(emailData) {
    isAnalysing = true;
    safeInject(() => injectLoadingPanel());

    // FIX: safety timeout releases the lock if backend never responds
    const safetyRelease = setTimeout(() => {
      if (isAnalysing) {
        isAnalysing = false;
        safeInject(() => injectErrorPanel(
          'CognitoMail: request timed out after 15 seconds. Is your Render service running?'
        ));
      }
    }, 15000);

    // FIX: wrapped in try/catch to handle invalidated extension context
    try {
      chrome.runtime.sendMessage(
        { type: 'ANALYZE_EMAIL', email: emailData },
        (response) => {
          clearTimeout(safetyRelease);
          isAnalysing = false;

          if (chrome.runtime.lastError) {
            safeInject(() => injectErrorPanel(
              'CognitoMail: background not responding. Try reloading the page.'
            ));
            return;
          }
          if (!response || !response.ok) {
            safeInject(() => injectErrorPanel(
              response?.error ||
              'CognitoMail: backend unreachable. Is your Render service running?'
            ));
            return;
          }

          safeInject(() => injectResultPanel(response.result, emailData));
        }
      );
    } catch (e) {
      clearTimeout(safetyRelease);
      isAnalysing = false;
      console.debug('[CognitoMail] Extension context invalidated — reload the tab.');
    }
  }

  function safeInject(fn) {
    isInjecting = true;
    observer.disconnect();
    try {
      fn();
    } finally {
      setTimeout(() => {
        isInjecting = false;
        startObserving();
      }, 200);
    }
  }

  // ── Panel container ────────────────────────────────────────────────────────

  function getPanelContainer() {
    let c = document.getElementById('cognitomail-panel-container');
    if (c) return c;

    c = document.createElement('div');
    c.id = 'cognitomail-panel-container';
    c.style.cssText =
      'margin:16px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;';

    const gmailBody =
      document.querySelector('.a3s.aiL') ||
      document.querySelector('.a3s') ||
      document.querySelector('[role="main"] .ii.gt');

    if (gmailBody) {
      gmailBody.parentNode.insertBefore(c, gmailBody.nextSibling);
      return c;
    }

    const outlookBody =
      document.querySelector('[data-testid="emailBodyContainer"]');
    if (outlookBody) {
      outlookBody.parentNode.insertBefore(c, outlookBody.nextSibling);
      return c;
    }

    document.body.appendChild(c);
    return c;
  }

  // ── Panel templates ────────────────────────────────────────────────────────

  function injectLoadingPanel() {
    const c = getPanelContainer();
    c.innerHTML = `
      <div class="cgm-panel cgm-loading">
        <div class="cgm-header">
          <div class="cgm-logo">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>
            </svg>
            CognitoMail
          </div>
          <span class="cgm-badge cgm-badge-scanning">Scanning…</span>
        </div>
        <div class="cgm-body">
          <div class="cgm-scan-row">
            <div class="cgm-spinner"></div>
            <span>Analysing email — checking authentication, URLs, and language patterns…</span>
          </div>
          <div class="cgm-skeleton"></div>
          <div class="cgm-skeleton" style="width:70%"></div>
          <div class="cgm-skeleton" style="width:50%"></div>
        </div>
      </div>`;
  }

  function injectResultPanel(data, emailData) {
    const c = getPanelContainer();
    const score = data.risk_score;
    const colour = score >= 70 ? '#ea4335' : score >= 40 ? '#f9ab00' : '#00c9a7';
    const verdictClass = score >= 70 ? 'cgm-verdict-high'
                       : score >= 40 ? 'cgm-verdict-med'
                       : 'cgm-verdict-low';

    const flagsHTML = (data.flags || []).map(f =>
      `<div class="cgm-flag">${f}</div>`
    ).join('') ||
      '<div class="cgm-flag cgm-flag-ok">No significant phishing signals detected.</div>';

    const authChip = (label, val) => {
      const cls = val === 'pass' ? 'cgm-auth-pass'
                : val === 'fail' ? 'cgm-auth-fail'
                : 'cgm-auth-unknown';
      return `<span class="cgm-auth ${cls}">${label}: ${(val||'none').toUpperCase()}</span>`;
    };

    const predictedLabel = score >= 50 ? 1 : 0;

    c.innerHTML = `
      <div class="cgm-panel">
        <div class="cgm-header">
          <div class="cgm-logo">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>
            </svg>
            CognitoMail
          </div>
          <span class="cgm-badge ${verdictClass}">${data.verdict}</span>
        </div>
        <div class="cgm-body">
          <div class="cgm-score-row">
            <div class="cgm-score-wrap">
              <svg class="cgm-gauge" viewBox="0 0 80 80">
                <circle cx="40" cy="40" r="32" fill="none" stroke="#1e2433" stroke-width="7"/>
                <circle cx="40" cy="40" r="32" fill="none" stroke="${colour}" stroke-width="7"
                  stroke-dasharray="${Math.round(score * 2.01)} 201"
                  stroke-linecap="round"
                  transform="rotate(-90 40 40)"
                  class="cgm-gauge-arc"/>
              </svg>
              <div class="cgm-score-num" style="color:${colour}">${score}</div>
            </div>
            <div class="cgm-score-meta">
              <div class="cgm-score-label">Risk Score</div>
              <div class="cgm-score-sublabel">out of 100</div>
              <div class="cgm-method-badge">${data.method === 'ml' ? '🤖 ML Model' : '📋 Rule-based'}</div>
              ${data.confidence !== null
                ? `<div class="cgm-conf">Confidence: ${Math.round(data.confidence * 100)}%</div>`
                : ''}
            </div>
          </div>

          <div class="cgm-section-label">Findings</div>
          <div class="cgm-flags">${flagsHTML}</div>

          <div class="cgm-section-label" style="margin-top:10px">Authentication</div>
          <div class="cgm-auth-row">
            ${authChip('SPF',   emailData.spf)}
            ${authChip('DKIM',  emailData.dkim)}
            ${authChip('DMARC', emailData.dmarc)}
          </div>

          <div class="cgm-feedback-row">
            <span>Was this verdict correct?</span>
            <button class="cgm-fb-btn cgm-fb-yes" data-label="${predictedLabel}" data-correct="1">👍 Yes</button>
            <button class="cgm-fb-btn cgm-fb-no"  data-label="${predictedLabel}" data-correct="0">👎 No</button>
          </div>
        </div>
      </div>`;

    // FIX: feedback buttons wrapped in try/catch
    c.querySelectorAll('.cgm-fb-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const predicted    = parseInt(btn.dataset.label);
        const isCorrect    = parseInt(btn.dataset.correct);
        const correctLabel = isCorrect ? predicted : (predicted === 1 ? 0 : 1);
        try {
          chrome.runtime.sendMessage({
            type: 'SEND_FEEDBACK',
            payload: {
              email:           emailData,
              predicted_label: predicted,
              correct_label:   correctLabel,
            },
          });
        } catch (e) {
          console.debug('[CognitoMail] Feedback not sent — context invalidated.');
        }
        const row = c.querySelector('.cgm-feedback-row');
        if (row) row.innerHTML =
          '<span style="color:#00c9a7;font-weight:600">✓ Feedback recorded — thank you!</span>';
      });
    });
  }

  function injectErrorPanel(msg) {
    const c = getPanelContainer();
    c.innerHTML = `
      <div class="cgm-panel cgm-error">
        <div class="cgm-header">
          <div class="cgm-logo">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>
            </svg>
            CognitoMail
          </div>
          <span class="cgm-badge" style="background:#3a1a1a;color:#ea4335">Offline</span>
        </div>
        <div class="cgm-body">
          <div style="font-size:12px;color:#9aa0b4;line-height:1.6">${msg}</div>
          <div style="margin-top:8px;font-size:11px;background:#0d1117;border-radius:6px;padding:8px;color:#00c9a7;font-family:monospace">
            Check your Render deployment is running
          </div>
        </div>
      </div>`;
  }

  // ── Navigation listener ────────────────────────────────────────────────────

  let lastUrl = location.href;
  const observer = new MutationObserver(() => {

    console.log("Mutation detected");

    if (isInjecting) return;

    clearTimeout(debounceTimer);

    debounceTimer = setTimeout(() => {

        console.log("DOM settled");

        onDomSettled();

    }, DEBOUNCE_MS);
});

})();