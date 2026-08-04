// background.js — CognitoMail (FIXED)
// FIX: Replaced in-memory tabResults with chrome.storage.session.
// In MV3 the service worker is killed after ~30s of inactivity, which
// wiped the in-memory store and caused popup to always show "No email open."
// chrome.storage.session survives service worker restarts.

const BACKEND_URL = 'https://cognitomail-backend.onrender.com';

// ── Message router ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Content script sends email data → we call the backend → cache result → return
  if (msg.type === 'ANALYZE_EMAIL') {
    const tabId = sender.tab?.id;
    analyzeEmail(msg.email)
      .then(result => {
        // Merge auth fields from the email into the result so popup can display them
        const enriched = {
          ...result,
          spf:   msg.email.spf   || 'none',
          dkim:  msg.email.dkim  || 'none',
          dmarc: msg.email.dmarc || 'none',
        };

        // Cache in session storage — survives service worker termination
        const cacheEntry = { result: enriched, email: msg.email };
        chrome.storage.session.set({ [`tab_${tabId}`]: cacheEntry });

        sendResponse({ ok: true, result: enriched });
      })
      .catch(err => {
        sendResponse({ ok: false, error: err.message });
      });
    return true; // keep message channel open for async response
  }

  // Popup asks for the latest result for its tab
  if (msg.type === 'GET_RESULT') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (!tabId) {
        sendResponse({ result: null });
        return;
      }
      chrome.storage.session.get([`tab_${tabId}`], (data) => {
        const entry = data[`tab_${tabId}`];
        sendResponse({ result: entry?.result || null });
      });
    });
    return true;
  }

  // Popup or content sends user feedback
  if (msg.type === 'SEND_FEEDBACK') {
    sendFeedback(msg.payload)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  // Clear result when user navigates away from an email
  if (msg.type === 'CLEAR_RESULT') {
    const tabId = sender.tab?.id;
    if (tabId) chrome.storage.session.remove([`tab_${tabId}`]);
  }
  // No return needed — synchronous, no async response
});

// Clean up stored results when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`tab_${tabId}`]);
});

// ── Backend calls ────────────────────────────────────────────────────────────
async function analyzeEmail(emailData) {
  const resp = await fetch(`${BACKEND_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(emailData),
    signal: AbortSignal.timeout(10000),
  });
  if (!resp.ok) throw new Error(`Backend error: ${resp.status}`);
  return await resp.json();
}

async function sendFeedback(payload) {
  await fetch(`${BACKEND_URL}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5000),
  });
}
