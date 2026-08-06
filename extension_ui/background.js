// background.js — CognitoMail (stable)
const BACKEND_URL = "https://cognitomail-backend.onrender.com";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ANALYZE_EMAIL") {
    const tabId = sender.tab?.id;
    analyzeEmail(msg.email)
      .then((result) => {
        const enriched = {
          ...result,
          spf: msg.email.spf || "none",
          dkim: msg.email.dkim || "none",
          dmarc: msg.email.dmarc || "none",
        };
        if (tabId != null) {
          chrome.storage.session.set({ [`tab_${tabId}`]: { result: enriched, email: msg.email } });
        }
        sendResponse({ ok: true, result: enriched });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err.message || String(err) });
      });
    return true; // async
  }

  if (msg.type === "GET_RESULT") {
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

  if (msg.type === "SEND_FEEDBACK") {
    sendFeedback(msg.payload)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === "CLEAR_RESULT") {
    const tabId = sender.tab?.id;
    if (tabId != null) chrome.storage.session.remove([`tab_${tabId}`]);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`tab_${tabId}`]);
});

async function analyzeEmail(emailData) {
  const resp = await fetch(`${BACKEND_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(emailData),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Backend error ${resp.status}: ${text.slice(0, 120)}`);
  }
  return await resp.json();
}

async function sendFeedback(payload) {
  await fetch(`${BACKEND_URL}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5000),
  });
}
