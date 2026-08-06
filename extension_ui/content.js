// content.js — CognitoMail v1.1
// Robust Gmail + Outlook email detection
console.log("[CognitoMail] content script loaded —", location.href);

(function () {
  "use strict";

  let lastEmailSignature = null;
  let isAnalysing = false;
  let debounceTimer = null;
  let isInjecting = false;
  let lastUrl = location.href;

  const DEBOUNCE_MS = 600;

  // ── Helpers ────────────────────────────────────────────────────────────────

  function qs(sel, root = document) {
    try { return root.querySelector(sel); } catch { return null; }
  }
  function qsa(sel, root = document) {
    try { return Array.from(root.querySelectorAll(sel)); } catch { return []; }
  }

  function text(el) {
    return el ? (el.innerText || el.textContent || "").trim() : "";
  }

  // ── Observer ───────────────────────────────────────────────────────────────

  const observer = new MutationObserver(() => {
    if (isInjecting) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(onDomSettled, DEBOUNCE_MS);
  });

  function startObserving() {
    if (!document.body) return;
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startObserving);
  } else {
    startObserving();
  }

  // Also react to SPA navigation (Gmail / Outlook)
  window.addEventListener("hashchange", () => {
    lastEmailSignature = null;
    isAnalysing = false;
    removePanel();
    setTimeout(onDomSettled, 400);
  });

  // Catch clicks on email rows (helps when MutationObserver is slow)
  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!target) return;
    // Gmail list row or Outlook message list item
    if (
      target.closest(".zA") ||          // Gmail conversation row
      target.closest("[role='listitem']") ||
      target.closest("[data-convid]") ||
      target.closest("[aria-label*='Message']")
    ) {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(onDomSettled, 700);
    }
  }, true);

  // ── Main settle handler ────────────────────────────────────────────────────

  function onDomSettled() {
    if (isAnalysing) return;

    // URL change cleanup
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      lastEmailSignature = null;
      isAnalysing = false;
      removePanel();
      try {
        chrome.runtime.sendMessage({ type: "CLEAR_RESULT" });
      } catch (_) {}
    }

    const emailData = extractEmailData();
    if (!emailData) {
      lastEmailSignature = null;
      return;
    }

    const sig = (emailData.subject + "||" + emailData.sender + "||" + emailData.body.slice(0, 80)).toLowerCase();
    if (sig === lastEmailSignature) return;

    lastEmailSignature = sig;
    console.log("[CognitoMail] New email detected:", emailData.subject.slice(0, 60));
    triggerAnalysis(emailData);
  }

  // ── Extraction router ──────────────────────────────────────────────────────

  function extractEmailData() {
    const host = location.hostname;
    if (host === "mail.google.com") return extractGmail();
    if (host.includes("outlook") || host.includes("office.com") || host.includes("office365")) {
      return extractOutlook();
    }
    return null;
  }

  // ── Gmail extraction (multi-strategy, resilient) ───────────────────────────

  function extractGmail() {
    // Must be in a conversation view (not just the inbox list)
    const isConversation =
      location.hash.includes("/") ||                     // classic /#inbox/xxx
      !!qs("[data-thread-perm-id]") ||
      !!qs("[data-legacy-thread-id]") ||
      !!qs("h2.hP") ||
      !!qs(".ha h2") ||
      !!qs('[role="main"] h2');

    if (!isConversation) {
      console.debug("[CognitoMail] Gmail: no open conversation");
      return null;
    }

    // Subject
    const subjectEl =
      qs("h2.hP") ||
      qs("[data-thread-perm-id] h2") ||
      qs(".ha h2") ||
      qs('[role="main"] h2') ||
      qs(".a98.iY h2") ||
      qs("h2[data-thread-perm-id]") ||
      qs('[role="main"] .hP');

    const subject = text(subjectEl);
    if (!subject) {
      console.debug("[CognitoMail] Gmail: subject not found");
      return null;
    }

    // Body – prefer the expanded message body
    let bodyEl =
      qs(".a3s.aiL") ||
      qs(".ii.gt .a3s") ||
      qs(".a3s") ||
      qs('[role="main"] .ii.gt') ||
      qs(".Am.Al.editable") ||           // rare
      qs('[role="main"] .adP.adO');

    // Fallback: longest meaningful text block inside main
    if (!bodyEl) {
      const candidates = qsa('[role="main"] div[dir="ltr"], [role="main"] div[dir="auto"], [role="main"] .ii');
      let best = null, bestLen = 0;
      for (const el of candidates) {
        const t = text(el);
        if (t.length > bestLen && t.length > 40) {
          best = el;
          bestLen = t.length;
        }
      }
      bodyEl = best;
    }

    if (!bodyEl) {
      console.debug("[CognitoMail] Gmail: body not found");
      return null;
    }

    const body = text(bodyEl);
    if (body.length < 5) return null;

    // Sender
    let sender = "unknown";
    const senderEl =
      qs(".gD") ||
      qs("[email]") ||
      qs(".go") ||
      qs("[data-hovercard-id]") ||
      qs(".yW span[email]") ||
      qs(".qu .go .g2");

    if (senderEl) {
      sender =
        senderEl.getAttribute("email") ||
        senderEl.getAttribute("data-hovercard-id") ||
        senderEl.getAttribute("data-email") ||
        text(senderEl);
    }

    // Last-resort scan
    if (!sender || sender === "unknown") {
      const spans = qsa('[role="main"] span[email], [role="main"] a[email], [role="main"] span[data-hovercard-id]');
      for (const s of spans) {
        const e = s.getAttribute("email") || s.getAttribute("data-hovercard-id");
        if (e && e.includes("@")) {
          sender = e;
          break;
        }
      }
    }

    console.debug("[CognitoMail] Gmail extracted:", { subject: subject.slice(0, 40), sender, bodyLen: body.length });

    return {
      sender: sender || "unknown",
      subject,
      body,
      urls: extractUrls(bodyEl.innerHTML || body),
      spf: extractAuth("spf"),
      dkim: extractAuth("dkim"),
      dmarc: extractAuth("dmarc"),
    };
  }

  // ── Outlook extraction ─────────────────────────────────────────────────────

  function extractOutlook() {
    // Reading pane must be open
    const subjectEl =
      qs('[data-testid="subject"]') ||
      qs('[aria-label="Subject"]') ||
      qs(".allowTextSelection") ||
      qs('[role="heading"][aria-level="1"]') ||
      qs("div[data-automationid='Subject']") ||
      qs(".rps_b1e8") ||                     // older class
      qs('[class*="Subject"]');

    const senderEl =
      qs('[data-testid="senderName"]') ||
      qs('[aria-label*="From"]') ||
      qs(".OZZZK") ||
      qs('[class*="PersonName"]') ||
      qs("span[title*='@']") ||
      qs('[data-automationid="From"]');

    const bodyEl =
      qs('[data-testid="emailBodyContainer"]') ||
      qs('[aria-label="Message body"]') ||
      qs(".Wr[role='document']") ||
      qs('[role="document"]') ||
      qs(".rps_1f8f") ||
      qs("div[class*='UniqueMessageBody']") ||
      qs("div[class*='MessageBody']");

    if (!subjectEl || !bodyEl) {
      console.debug("[CognitoMail] Outlook: missing subject or body", {
        subject: !!subjectEl,
        body: !!bodyEl,
        sender: !!senderEl,
      });
      return null;
    }

    const subject = text(subjectEl);
    const body = text(bodyEl);
    if (!subject || body.length < 5) return null;

    let sender = text(senderEl) || "unknown";
    // Try to get email from title attribute
    if (senderEl) {
      const title = senderEl.getAttribute("title") || senderEl.getAttribute("aria-label") || "";
      const m = title.match(/[\w.+-]+@[\w.-]+\.\w+/);
      if (m) sender = m[0];
    }

    console.debug("[CognitoMail] Outlook extracted:", { subject: subject.slice(0, 40), sender, bodyLen: body.length });

    return {
      sender,
      subject,
      body,
      urls: extractUrls(bodyEl.innerHTML || body),
      spf: "none",
      dkim: "none",
      dmarc: "none",
    };
  }

  // ── Auth helpers (Gmail only) ──────────────────────────────────────────────

  function extractAuth(protocol) {
    const detailSpans = qsa(".aZy, .ajz, [data-tooltip], .ajT");
    for (const span of detailSpans) {
      const t = (text(span) + " " + (span.getAttribute("data-tooltip") || "")).toLowerCase();
      if (t.includes(protocol)) {
        if (t.includes("pass")) return "pass";
        if (t.includes("fail") || t.includes("softfail")) return "fail";
      }
    }
    return "none";
  }

  function extractUrls(html) {
    const matches = (html || "").match(/https?:\/\/[^\s"'<>]+/g) || [];
    return [...new Set(matches)].slice(0, 20);
  }

  // ── Analysis pipeline ──────────────────────────────────────────────────────

  function triggerAnalysis(emailData) {
    isAnalysing = true;
    safeInject(() => injectLoadingPanel());

    const safetyRelease = setTimeout(() => {
      if (isAnalysing) {
        isAnalysing = false;
        safeInject(() =>
          injectErrorPanel("CognitoMail: request timed out. Is the Render service awake?")
        );
      }
    }, 18000);

    try {
      chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: emailData }, (response) => {
        clearTimeout(safetyRelease);
        isAnalysing = false;

        if (chrome.runtime.lastError) {
          safeInject(() =>
            injectErrorPanel("CognitoMail: background not responding. Reload the tab.")
          );
          return;
        }
        if (!response || !response.ok) {
          safeInject(() =>
            injectErrorPanel(
              response?.error || "CognitoMail: backend unreachable. Check Render."
            )
          );
          return;
        }
        safeInject(() => injectResultPanel(response.result, emailData));
      });
    } catch (e) {
      clearTimeout(safetyRelease);
      isAnalysing = false;
      console.debug("[CognitoMail] context invalidated");
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
      }, 250);
    }
  }

  function removePanel() {
    const old = document.getElementById("cognitomail-panel-container");
    if (old) old.remove();
  }

  // ── Panel placement ────────────────────────────────────────────────────────

  function getPanelContainer() {
    let c = document.getElementById("cognitomail-panel-container");
    if (c) return c;

    c = document.createElement("div");
    c.id = "cognitomail-panel-container";
    c.style.cssText = "margin:16px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;z-index:9999;";

    // Prefer placing after the email body
    const gmailBody =
      qs(".a3s.aiL") ||
      qs(".a3s") ||
      qs('[role="main"] .ii.gt');

    if (gmailBody && gmailBody.parentNode) {
      gmailBody.parentNode.insertBefore(c, gmailBody.nextSibling);
      return c;
    }

    const outlookBody =
      qs('[data-testid="emailBodyContainer"]') ||
      qs('[role="document"]');

    if (outlookBody && outlookBody.parentNode) {
      outlookBody.parentNode.insertBefore(c, outlookBody.nextSibling);
      return c;
    }

    // Fallback – top of main content
    const main = qs('[role="main"]') || document.body;
    main.prepend(c);
    return c;
  }

  // ── UI panels (unchanged styling) ──────────────────────────────────────────

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
    const score = data.risk_score ?? 0;
    const colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";
    const verdictClass =
      score >= 70 ? "cgm-verdict-high" : score >= 40 ? "cgm-verdict-med" : "cgm-verdict-low";

    const flagsHTML =
      (data.flags || [])
        .map((f) => `<div class="cgm-flag">${f}</div>`)
        .join("") ||
      '<div class="cgm-flag cgm-flag-ok">No significant phishing signals detected.</div>';

    const authChip = (label, val) => {
      const cls =
        val === "pass" ? "cgm-auth-pass" : val === "fail" ? "cgm-auth-fail" : "cgm-auth-unknown";
      return `<span class="cgm-auth ${cls}">${label}: ${(val || "none").toUpperCase()}</span>`;
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
          <span class="cgm-badge ${verdictClass}">${data.verdict || "Analysed"}</span>
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
              <div class="cgm-method-badge">${data.method === "ml" ? "🤖 ML Model" : "📋 Rule-based"}</div>
              ${
                data.confidence != null
                  ? `<div class="cgm-conf">Confidence: ${Math.round(data.confidence * 100)}%</div>`
                  : ""
              }
            </div>
          </div>

          <div class="cgm-section-label">Findings</div>
          <div class="cgm-flags">${flagsHTML}</div>

          <div class="cgm-section-label" style="margin-top:10px">Authentication</div>
          <div class="cgm-auth-row">
            ${authChip("SPF", emailData.spf)}
            ${authChip("DKIM", emailData.dkim)}
            ${authChip("DMARC", emailData.dmarc)}
          </div>

          <div class="cgm-feedback-row">
            <span>Was this verdict correct?</span>
            <button class="cgm-fb-btn cgm-fb-yes" data-label="${predictedLabel}" data-correct="1">👍 Yes</button>
            <button class="cgm-fb-btn cgm-fb-no"  data-label="${predictedLabel}" data-correct="0">👎 No</button>
          </div>
        </div>
      </div>`;

    c.querySelectorAll(".cgm-fb-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const predicted = parseInt(btn.dataset.label);
        const isCorrect = parseInt(btn.dataset.correct);
        const correctLabel = isCorrect ? predicted : predicted === 1 ? 0 : 1;
        try {
          chrome.runtime.sendMessage({
            type: "SEND_FEEDBACK",
            payload: {
              email: emailData,
              predicted_label: predicted,
              correct_label: correctLabel,
            },
          });
        } catch (_) {}
        const row = c.querySelector(".cgm-feedback-row");
        if (row)
          row.innerHTML =
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

  // Kick once after load
  setTimeout(onDomSettled, 1200);
})();