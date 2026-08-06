// content.js — CognitoMail v1.3
// Gmail + Outlook detection | detailed panel | VirusTotal | side risk badge
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
  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
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

  window.addEventListener("hashchange", () => {
    lastEmailSignature = null;
    isAnalysing = false;
    removePanel();
    removeSideBadge();
    setTimeout(onDomSettled, 400);
  });

  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!target) return;
    if (
      target.closest(".zA") ||
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

    if (location.href !== lastUrl) {
      lastUrl = location.href;
      lastEmailSignature = null;
      isAnalysing = false;
      removePanel();
      removeSideBadge();
      try { chrome.runtime.sendMessage({ type: "CLEAR_RESULT" }); } catch (_) {}
    }

    const emailData = extractEmailData();
    if (!emailData) {
      lastEmailSignature = null;
      return;
    }

    const sig = (
      emailData.subject + "||" + emailData.sender + "||" + emailData.body.slice(0, 80)
    ).toLowerCase();
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

  // ── Gmail ──────────────────────────────────────────────────────────────────

  function extractGmail() {
    const isConversation =
      location.hash.includes("/") ||
      !!qs("[data-thread-perm-id]") ||
      !!qs("[data-legacy-thread-id]") ||
      !!qs("h2.hP") ||
      !!qs(".ha h2") ||
      !!qs('[role="main"] h2');

    if (!isConversation) {
      console.debug("[CognitoMail] Gmail: no open conversation");
      return null;
    }

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

    let bodyEl =
      qs(".a3s.aiL") ||
      qs(".ii.gt .a3s") ||
      qs(".a3s") ||
      qs('[role="main"] .ii.gt') ||
      qs(".Am.Al.editable") ||
      qs('[role="main"] .adP.adO');

    if (!bodyEl) {
      const candidates = qsa(
        '[role="main"] div[dir="ltr"], [role="main"] div[dir="auto"], [role="main"] .ii'
      );
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

    if (!sender || sender === "unknown") {
      const spans = qsa(
        '[role="main"] span[email], [role="main"] a[email], [role="main"] span[data-hovercard-id]'
      );
      for (const s of spans) {
        const e = s.getAttribute("email") || s.getAttribute("data-hovercard-id");
        if (e && e.includes("@")) {
          sender = e;
          break;
        }
      }
    }

    // Parse "Name <email@domain>" if needed
    if (sender && sender.includes("<") && sender.includes("@")) {
      const m = sender.match(/<([^>]+@[^>]+)>/);
      if (m) sender = m[1].trim();
    }

    console.debug("[CognitoMail] Gmail extracted:", {
      subject: subject.slice(0, 40),
      sender,
      bodyLen: body.length,
    });

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

  // ── Outlook ────────────────────────────────────────────────────────────────

  function extractOutlook() {
    const subjectEl =
      qs('[data-testid="subject"]') ||
      qs('[aria-label="Subject"]') ||
      qs(".allowTextSelection") ||
      qs('[role="heading"][aria-level="1"]') ||
      qs("div[data-automationid='Subject']") ||
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
      qs("div[class*='UniqueMessageBody']") ||
      qs("div[class*='MessageBody']");

    if (!subjectEl || !bodyEl) {
      console.debug("[CognitoMail] Outlook: missing subject or body");
      return null;
    }

    const subject = text(subjectEl);
    const body = text(bodyEl);
    if (!subject || body.length < 5) return null;

    let sender = text(senderEl) || "unknown";
    if (senderEl) {
      const title = senderEl.getAttribute("title") || senderEl.getAttribute("aria-label") || "";
      const m = title.match(/[\w.+-]+@[\w.-]+\.\w+/);
      if (m) sender = m[0];
    }
    if (sender.includes("<") && sender.includes("@")) {
      const m = sender.match(/<([^>]+@[^>]+)>/);
      if (m) sender = m[1].trim();
    }

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

  // ── Analysis ───────────────────────────────────────────────────────────────

  function triggerAnalysis(emailData) {
    isAnalysing = true;
    safeInject(() => {
      injectLoadingPanel();
      injectSideBadgeLoading();
    });

    const safetyRelease = setTimeout(() => {
      if (isAnalysing) {
        isAnalysing = false;
        safeInject(() => {
          injectErrorPanel("CognitoMail: request timed out. Is the Render service awake?");
          removeSideBadge();
        });
      }
    }, 20000);

    try {
      chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: emailData }, (response) => {
        clearTimeout(safetyRelease);
        isAnalysing = false;

        if (chrome.runtime.lastError) {
          safeInject(() => {
            injectErrorPanel("CognitoMail: background not responding. Reload the tab.");
            removeSideBadge();
          });
          return;
        }
        if (!response || !response.ok) {
          safeInject(() => {
            injectErrorPanel(response?.error || "CognitoMail: backend unreachable. Check Render.");
            removeSideBadge();
          });
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
    try { fn(); }
    finally {
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

  function removeSideBadge() {
    const b = document.getElementById("cognitomail-side-badge");
    if (b) b.remove();
  }

  // ── Panel placement ────────────────────────────────────────────────────────

  function getPanelContainer() {
    let c = document.getElementById("cognitomail-panel-container");
    if (c) return c;

    c = document.createElement("div");
    c.id = "cognitomail-panel-container";
    c.style.cssText =
      "margin:16px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;z-index:9999;";

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

    const main = qs('[role="main"]') || document.body;
    main.prepend(c);
    return c;
  }

  // ── Side badge ─────────────────────────────────────────────────────────────

  function injectSideBadgeLoading() {
    removeSideBadge();
    const badge = document.createElement("div");
    badge.id = "cognitomail-side-badge";
    badge.className = "cgm-side-loading";
    badge.innerHTML = `
      <div class="cgm-side-spinner"></div>
      <div class="cgm-side-label">Scanning…</div>
      <div class="cgm-side-sub">CognitoMail</div>
    `;
    document.body.appendChild(badge);
  }

  function injectSideBadge(data) {
    removeSideBadge();
    const score = data.risk_score ?? 0;
    const colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";
    const label =
      data.verdict ||
      (score >= 70 ? "Phishing" : score >= 40 ? "Suspicious" : "Likely Safe");

    const badge = document.createElement("div");
    badge.id = "cognitomail-side-badge";
    badge.innerHTML = `
      <div class="cgm-side-score" style="color:${colour}">${score}</div>
      <div class="cgm-side-label">${escapeHtml(label)}</div>
      <div class="cgm-side-sub">CognitoMail</div>
    `;
    document.body.appendChild(badge);
  }

  // ── Loading panel ──────────────────────────────────────────────────────────

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
            <span>Analysing email — ML, auth, URLs &amp; VirusTotal…</span>
          </div>
          <div class="cgm-skeleton"></div>
          <div class="cgm-skeleton" style="width:70%"></div>
          <div class="cgm-skeleton" style="width:50%"></div>
        </div>
      </div>`;
  }

  // ── Result panel ───────────────────────────────────────────────────────────

  function injectResultPanel(data, emailData) {
    const c = getPanelContainer();
    const score = data.risk_score ?? 0;
    const colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";
    const verdictClass =
      score >= 70 ? "cgm-verdict-high" : score >= 40 ? "cgm-verdict-med" : "cgm-verdict-low";

    const flagsHTML =
      (data.flags || [])
        .map((f) => `<div class="cgm-flag">${escapeHtml(f)}</div>`)
        .join("") ||
      '<div class="cgm-flag cgm-flag-ok">No significant phishing signals detected.</div>';

    const authChip = (label, val) => {
      const cls =
        val === "pass" ? "cgm-auth-pass" : val === "fail" ? "cgm-auth-fail" : "cgm-auth-unknown";
      return `<span class="cgm-auth ${cls}">${label}: ${(val || "none").toUpperCase()}</span>`;
    };

    const d = data.details || {};
    const vt = data.virustotal || {};
    const domain = data.sender_domain || d.sender_domain || "—";

    // VirusTotal block (supports multi-domain shape from new backend)
    let vtHTML = "";
    if (vt.available) {
      const mal = vt.max_malicious ?? (vt.reports && vt.reports[0] && vt.reports[0].malicious) ?? vt.malicious ?? 0;
      const sus = vt.max_suspicious ?? (vt.reports && vt.reports[0] && vt.reports[0].suspicious) ?? vt.suspicious ?? 0;
      const harm = vt.harmless ?? (vt.reports && vt.reports[0] && vt.reports[0].harmless) ?? "—";
      const rep = vt.reputation ?? (vt.reports && vt.reports[0] && vt.reports[0].reputation) ?? "—";
      const worst = vt.worst_domain || domain;
      const queried = (vt.queried || [domain]).join(", ");
      const malColor = mal > 0 ? "#ea4335" : "#00c9a7";
      const susColor = sus > 0 ? "#f9ab00" : "#9aa0b4";

      vtHTML = `
        <div class="cgm-vt-grid">
          <div class="cgm-vt-item"><span class="cgm-vt-label">Sender domain</span><span class="cgm-vt-value">${escapeHtml(domain)}</span></div>
          <div class="cgm-vt-item"><span class="cgm-vt-label">Checked</span><span class="cgm-vt-value">${escapeHtml(queried)}</span></div>
          <div class="cgm-vt-item"><span class="cgm-vt-label">Worst domain</span><span class="cgm-vt-value">${escapeHtml(worst || "—")}</span></div>
          <div class="cgm-vt-item"><span class="cgm-vt-label">Malicious</span><span class="cgm-vt-value" style="color:${malColor};font-weight:700">${mal}</span></div>
          <div class="cgm-vt-item"><span class="cgm-vt-label">Suspicious</span><span class="cgm-vt-value" style="color:${susColor}">${sus}</span></div>
          <div class="cgm-vt-item"><span class="cgm-vt-label">Reputation</span><span class="cgm-vt-value">${rep}</span></div>
        </div>`;
    } else {
      const reason = vt.reason || "unavailable";
      vtHTML = `
        <div class="cgm-vt-fallback">
          Domain: <b>${escapeHtml(domain)}</b><br>
          <span style="color:#9aa0b4;font-size:11px">VirusTotal: ${escapeHtml(reason)}</span>
        </div>`;
    }

    const signals = [
      ["URLs found", d.url_count ?? 0],
      ["IP-based URL", d.has_ip_based_url ? "Yes" : "No"],
      ["Suspicious TLDs", d.suspicious_tld_count ?? 0],
      ["Non-HTTPS links", d.http_url_count ?? 0],
      ["Urgency (subject)", d.subject_urgency_words ?? 0],
      ["Urgency (body)", d.urgency_word_count ?? 0],
      ["Credential words", d.credential_word_count ?? 0],
      ["Brand mentions", d.brand_impersonation_count ?? 0],
      ["Reward words", d.reward_word_count ?? 0],
      ["Hidden elements", d.hidden_text_elements ?? 0],
      ["HTML forms", d.html_form_elements ?? 0],
      ["Redirect links", d.redirect_link_count ?? 0],
    ];

    const signalsHTML = signals
      .map(([label, val]) => {
        const highlight =
          (typeof val === "number" && val > 0) || val === "Yes"
            ? 'style="color:#f9ab00;font-weight:600"'
            : "";
        return `<div class="cgm-signal"><span>${label}</span><span ${highlight}>${val}</span></div>`;
      })
      .join("");

    const predictedLabel = score >= 50 ? 1 : 0;
    const methodLabel = (data.method || "ml").includes("rules")
      ? "🤖 ML + Rules"
      : data.method === "ml"
        ? "🤖 ML Model"
        : "📋 Rule-based";

    c.innerHTML = `
      <div class="cgm-panel">
        <div class="cgm-header">
          <div class="cgm-logo">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>
            </svg>
            CognitoMail
          </div>
          <span class="cgm-badge ${verdictClass}">${escapeHtml(data.verdict || "Analysed")}</span>
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
              <div class="cgm-method-badge">${methodLabel}</div>
              ${
                data.confidence != null
                  ? `<div class="cgm-conf">Confidence: ${Math.round(data.confidence * 100)}%</div>`
                  : ""
              }
              ${
                data.rule_boost
                  ? `<div class="cgm-conf">Rule boost: +${data.rule_boost}</div>`
                  : ""
              }
            </div>
          </div>

          <div class="cgm-section-label">Findings</div>
          <div class="cgm-flags">${flagsHTML}</div>

          <div class="cgm-section-label" style="margin-top:12px">Authentication</div>
          <div class="cgm-auth-row">
            ${authChip("SPF", emailData.spf)}
            ${authChip("DKIM", emailData.dkim)}
            ${authChip("DMARC", emailData.dmarc)}
          </div>

          <div class="cgm-section-label" style="margin-top:12px">VirusTotal</div>
          ${vtHTML}

          <div class="cgm-section-label" style="margin-top:12px">Threat signals</div>
          <div class="cgm-signals-grid">${signalsHTML}</div>

          <div class="cgm-feedback-row">
            <span>Was this verdict correct?</span>
            <button class="cgm-fb-btn cgm-fb-yes" data-label="${predictedLabel}" data-correct="1">👍 Yes</button>
            <button class="cgm-fb-btn cgm-fb-no"  data-label="${predictedLabel}" data-correct="0">👎 No</button>
          </div>
        </div>
      </div>`;

    injectSideBadge(data);

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
          <div style="font-size:12px;color:#9aa0b4;line-height:1.6">${escapeHtml(msg)}</div>
          <div style="margin-top:8px;font-size:11px;background:#0d1117;border-radius:6px;padding:8px;color:#00c9a7;font-family:monospace">
            Check your Render deployment is running
          </div>
        </div>
      </div>`;
  }

  setTimeout(onDomSettled, 1200);
})();