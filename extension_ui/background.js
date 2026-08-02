// background.js
// Receives analysis results from content.js and stores them
// so popup.html can retrieve the latest result for the active tab.

const BACKEND_URL = 'https://cognitomail-backend.onrender.com'; // change to your Render URL when deployed

// Store: tabId → last analysis result
const tabResults = {};

// Listen for messages from content.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Content script sends email data → we call the backend → return result
  if (msg.type === 'ANALYZE_EMAIL') {
    const tabId = sender.tab?.id;
    analyzeEmail(msg.email, tabId)
      .then(result => {
        if (tabId) tabResults[tabId] = result;
        sendResponse({ ok: true, result });
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
      sendResponse({ result: tabResults[tabId] || null });
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
    if (tabId) delete tabResults[tabId];
  }
});

// Clean up stored results when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
});

async function analyzeEmail(emailData, tabId) {
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
