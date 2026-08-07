// content.js — CognitoMail v1.3
// Gmail + Outlook | panel | VirusTotal | side badge | active-learning feedback
console.log("[CognitoMail] content script loaded —", location.href);

(function () {
  "use strict";

  let lastEmailSignature = null;
  let isAnalysing = false;
  let debounceTimer = null;
  let isInjecting = false;
  let lastUrl = location.href;

  const DEBOUNCE_MS = 600;

  function qs(sel, root) {
    root = root || document;
    try { return root.querySelector(sel); } catch (e) { return null; }
  }
  function qsa(sel, root) {
    root = root || document;
    try { return Array.from(root.querySelectorAll(sel)); } catch (e) { return []; }
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

  const observer = new MutationObserver(function () {
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

  window.addEventListener("hashchange", function () {
    lastEmailSignature = null;
    isAnalysing = false;
    removePanel();
    removeSideBadge();
    setTimeout(onDomSettled, 400);
  });

  document.addEventListener("click", function (e) {
    var target = e.target;
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

  function onDomSettled() {
    if (isAnalysing) return;

    if (location.href !== lastUrl) {
      lastUrl = location.href;
      lastEmailSignature = null;
      isAnalysing = false;
      removePanel();
      removeSideBadge();
      try { chrome.runtime.sendMessage({ type: "CLEAR_RESULT" }); } catch (e) {}
    }

    var emailData = extractEmailData();
    if (!emailData) {
      lastEmailSignature = null;
      return;
    }

    var sig = (
      emailData.subject + "||" + emailData.sender + "||" + emailData.body.slice(0, 80)
    ).toLowerCase();
    if (sig === lastEmailSignature) return;

    lastEmailSignature = sig;
    console.log("[CognitoMail] New email detected:", emailData.subject.slice(0, 60));
    triggerAnalysis(emailData);
  }

  function extractEmailData() {
    var host = location.hostname;
    if (host === "mail.google.com") return extractGmail();
    if (host.indexOf("outlook") !== -1 || host.indexOf("office.com") !== -1 || host.indexOf("office365") !== -1) {
      return extractOutlook();
    }
    return null;
  }

  function extractGmail() {
    var isConversation =
      location.hash.indexOf("/") !== -1 ||
      !!qs("[data-thread-perm-id]") ||
      !!qs("[data-legacy-thread-id]") ||
      !!qs("h2.hP") ||
      !!qs(".ha h2") ||
      !!qs('[role="main"] h2');

    if (!isConversation) return null;

    var subjectEl =
      qs("h2.hP") ||
      qs("[data-thread-perm-id] h2") ||
      qs(".ha h2") ||
      qs('[role="main"] h2') ||
      qs(".a98.iY h2") ||
      qs('[role="main"] .hP');

    var subject = text(subjectEl);
    if (!subject) return null;

    var bodyEl =
      qs(".a3s.aiL") ||
      qs(".ii.gt .a3s") ||
      qs(".a3s") ||
      qs('[role="main"] .ii.gt') ||
      qs('[role="main"] .adP.adO');

    if (!bodyEl) {
      var candidates = qsa('[role="main"] div[dir="ltr"], [role="main"] div[dir="auto"], [role="main"] .ii');
      var best = null, bestLen = 0, i, t;
      for (i = 0; i < candidates.length; i++) {
        t = text(candidates[i]);
        if (t.length > bestLen && t.length > 40) {
          best = candidates[i];
          bestLen = t.length;
        }
      }
      bodyEl = best;
    }

    if (!bodyEl) return null;
    var body = text(bodyEl);
    if (body.length < 5) return null;

    var sender = "unknown";
    var senderEl =
      qs(".gD") ||
      qs("[email]") ||
      qs(".go") ||
      qs("[data-hovercard-id]") ||
      qs(".yW span[email]");

    if (senderEl) {
      sender =
        senderEl.getAttribute("email") ||
        senderEl.getAttribute("data-hovercard-id") ||
        senderEl.getAttribute("data-email") ||
        text(senderEl);
    }

    if (!sender || sender === "unknown") {
      var spans = qsa('[role="main"] span[email], [role="main"] a[email], [role="main"] span[data-hovercard-id]');
      for (i = 0; i < spans.length; i++) {
        var e = spans[i].getAttribute("email") || spans[i].getAttribute("data-hovercard-id");
        if (e && e.indexOf("@") !== -1) {
          sender = e;
          break;
        }
      }
    }

    if (sender && sender.indexOf("<") !== -1 && sender.indexOf("@") !== -1) {
      var m = sender.match(/<([^>]+@[^>]+)>/);
      if (m) sender = m[1].trim();
    }

    return {
      sender: sender || "unknown",
      subject: subject,
      body: body,
      urls: extractUrls(bodyEl.innerHTML || body),
      spf: extractAuth("spf"),
      dkim: extractAuth("dkim"),
      dmarc: extractAuth("dmarc"),
    };
  }

  function extractOutlook() {
    var subjectEl =
      qs('[data-testid="subject"]') ||
      qs('[aria-label="Subject"]') ||
      qs(".allowTextSelection") ||
      qs('[role="heading"][aria-level="1"]');

    var senderEl =
      qs('[data-testid="senderName"]') ||
      qs('[aria-label*="From"]') ||
      qs(".OZZZK") ||
      qs("span[title*='@']");

    var bodyEl =
      qs('[data-testid="emailBodyContainer"]') ||
      qs('[aria-label="Message body"]') ||
      qs('[role="document"]');

    if (!subjectEl || !bodyEl) return null;

    var subject = text(subjectEl);
    var body = text(bodyEl);
    if (!subject || body.length < 5) return null;

    var sender = text(senderEl) || "unknown";
    if (senderEl) {
      var title = senderEl.getAttribute("title") || senderEl.getAttribute("aria-label") || "";
      var mm = title.match(/[\w.+-]+@[\w.-]+\.\w+/);
      if (mm) sender = mm[0];
    }
    if (sender.indexOf("<") !== -1 && sender.indexOf("@") !== -1) {
      var m2 = sender.match(/<([^>]+@[^>]+)>/);
      if (m2) sender = m2[1].trim();
    }

    return {
      sender: sender,
      subject: subject,
      body: body,
      urls: extractUrls(bodyEl.innerHTML || body),
      spf: "none",
      dkim: "none",
      dmarc: "none",
    };
  }

  function extractAuth(protocol) {
    var detailSpans = qsa(".aZy, .ajz, [data-tooltip], .ajT");
    for (var i = 0; i < detailSpans.length; i++) {
      var span = detailSpans[i];
      var t = (text(span) + " " + (span.getAttribute("data-tooltip") || "")).toLowerCase();
      if (t.indexOf(protocol) !== -1) {
        if (t.indexOf("pass") !== -1) return "pass";
        if (t.indexOf("fail") !== -1 || t.indexOf("softfail") !== -1) return "fail";
      }
    }
    return "none";
  }

  function extractUrls(html) {
    var matches = (html || "").match(/https?:\/\/[^\s"'<>]+/g) || [];
    return Array.from(new Set(matches)).slice(0, 20);
  }

  function triggerAnalysis(emailData) {
    isAnalysing = true;
    safeInject(function () {
      injectLoadingPanel();
      injectSideBadgeLoading();
    });

    var safetyRelease = setTimeout(function () {
      if (isAnalysing) {
        isAnalysing = false;
        safeInject(function () {
          injectErrorPanel("CognitoMail: request timed out. Is the Render service awake?");
          removeSideBadge();
        });
      }
    }, 20000);

    try {
      chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", email: emailData }, function (response) {
        clearTimeout(safetyRelease);
        isAnalysing = false;

        if (chrome.runtime.lastError) {
          safeInject(function () {
            injectErrorPanel("CognitoMail: background not responding. Reload the tab.");
            removeSideBadge();
          });
          return;
        }
        if (!response || !response.ok) {
          safeInject(function () {
            injectErrorPanel((response && response.error) || "CognitoMail: backend unreachable. Check Render.");
            removeSideBadge();
          });
          return;
        }
        safeInject(function () {
          injectResultPanel(response.result, emailData);
        });
      });
    } catch (e) {
      clearTimeout(safetyRelease);
      isAnalysing = false;
    }
  }

  function safeInject(fn) {
    isInjecting = true;
    observer.disconnect();
    try { fn(); }
    finally {
      setTimeout(function () {
        isInjecting = false;
        startObserving();
      }, 250);
    }
  }

  function removePanel() {
    var old = document.getElementById("cognitomail-panel-container");
    if (old) old.remove();
  }

  function removeSideBadge() {
    var b = document.getElementById("cognitomail-side-badge");
    if (b) b.remove();
  }

  function getPanelContainer() {
    var c = document.getElementById("cognitomail-panel-container");
    if (c) return c;

    c = document.createElement("div");
    c.id = "cognitomail-panel-container";
    c.style.cssText =
      "margin:16px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;z-index:9999;";

    var gmailBody = qs(".a3s.aiL") || qs(".a3s") || qs('[role="main"] .ii.gt');
    if (gmailBody && gmailBody.parentNode) {
      gmailBody.parentNode.insertBefore(c, gmailBody.nextSibling);
      return c;
    }

    var outlookBody = qs('[data-testid="emailBodyContainer"]') || qs('[role="document"]');
    if (outlookBody && outlookBody.parentNode) {
      outlookBody.parentNode.insertBefore(c, outlookBody.nextSibling);
      return c;
    }

    var main = qs('[role="main"]') || document.body;
    main.prepend(c);
    return c;
  }

  function injectSideBadgeLoading() {
    removeSideBadge();
    var badge = document.createElement("div");
    badge.id = "cognitomail-side-badge";
    badge.className = "cgm-side-loading";
    badge.innerHTML =
      '<div class="cgm-side-spinner"></div>' +
      '<div class="cgm-side-label">Scanning…</div>' +
      '<div class="cgm-side-sub">CognitoMail</div>';
    document.body.appendChild(badge);
  }

  function injectSideBadge(data) {
    removeSideBadge();
    var score = data.risk_score != null ? data.risk_score : 0;
    var colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";
    var label =
      data.verdict ||
      (score >= 70 ? "Phishing" : score >= 40 ? "Suspicious" : "Likely Safe");

    var badge = document.createElement("div");
    badge.id = "cognitomail-side-badge";
    badge.innerHTML =
      '<div class="cgm-side-score" style="color:' + colour + '">' + score + "</div>" +
      '<div class="cgm-side-label">' + escapeHtml(label) + "</div>" +
      '<div class="cgm-side-sub">CognitoMail</div>';
    document.body.appendChild(badge);
  }

  function injectLoadingPanel() {
    var c = getPanelContainer();
    c.innerHTML =
      '<div class="cgm-panel cgm-loading">' +
        '<div class="cgm-header">' +
          '<div class="cgm-logo">' +
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none">' +
              '<path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>' +
            "</svg> CognitoMail" +
          "</div>" +
          '<span class="cgm-badge cgm-badge-scanning">Scanning…</span>' +
        "</div>" +
        '<div class="cgm-body">' +
          '<div class="cgm-scan-row">' +
            '<div class="cgm-spinner"></div>' +
            "<span>Analysing email — ML, auth, URLs &amp; VirusTotal…</span>" +
          "</div>" +
          '<div class="cgm-skeleton"></div>' +
          '<div class="cgm-skeleton" style="width:70%"></div>' +
          '<div class="cgm-skeleton" style="width:50%"></div>' +
        "</div>" +
      "</div>";
  }

  function injectResultPanel(data, emailData) {
    var c = getPanelContainer();
    var score = data.risk_score != null ? data.risk_score : 0;
    var colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";
    var verdictClass =
      score >= 70 ? "cgm-verdict-high" : score >= 40 ? "cgm-verdict-med" : "cgm-verdict-low";

    var flagsHTML = (data.flags || [])
      .map(function (f) { return '<div class="cgm-flag">' + escapeHtml(f) + "</div>"; })
      .join("") ||
      '<div class="cgm-flag cgm-flag-ok">No significant phishing signals detected.</div>';

    function authChip(label, val) {
      var cls =
        val === "pass" ? "cgm-auth-pass" : val === "fail" ? "cgm-auth-fail" : "cgm-auth-unknown";
      return '<span class="cgm-auth ' + cls + '">' + label + ": " + (val || "none").toUpperCase() + "</span>";
    }

    var d = data.details || {};
    var vt = data.virustotal || {};
    var domain = data.sender_domain || d.sender_domain || "—";

    var vtHTML = "";
    if (vt.available) {
      var mal = vt.max_malicious != null ? vt.max_malicious : (vt.malicious != null ? vt.malicious : 0);
      var sus = vt.max_suspicious != null ? vt.max_suspicious : (vt.suspicious != null ? vt.suspicious : 0);
      var rep = vt.reputation != null ? vt.reputation : "—";
      var worst = vt.worst_domain || domain;
      var queried = (vt.queried || [domain]).join(", ");
      var malColor = mal > 0 ? "#ea4335" : "#00c9a7";
      var susColor = sus > 0 ? "#f9ab00" : "#9aa0b4";

      vtHTML =
        '<div class="cgm-vt-grid">' +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Sender domain</span><span class="cgm-vt-value">' + escapeHtml(domain) + "</span></div>" +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Checked</span><span class="cgm-vt-value">' + escapeHtml(queried) + "</span></div>" +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Worst domain</span><span class="cgm-vt-value">' + escapeHtml(worst || "—") + "</span></div>" +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Malicious</span><span class="cgm-vt-value" style="color:' + malColor + ';font-weight:700">' + mal + "</span></div>" +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Suspicious</span><span class="cgm-vt-value" style="color:' + susColor + '">' + sus + "</span></div>" +
          '<div class="cgm-vt-item"><span class="cgm-vt-label">Reputation</span><span class="cgm-vt-value">' + rep + "</span></div>" +
        "</div>";
    } else {
      var reason = vt.reason || "unavailable";
      vtHTML =
        '<div class="cgm-vt-fallback">' +
          "Domain: <b>" + escapeHtml(domain) + "</b><br>" +
          '<span style="color:#9aa0b4;font-size:11px">VirusTotal: ' + escapeHtml(reason) + "</span>" +
        "</div>";
    }

    var signals = [
      ["URLs found", d.url_count != null ? d.url_count : 0],
      ["IP-based URL", d.has_ip_based_url ? "Yes" : "No"],
      ["Suspicious TLDs", d.suspicious_tld_count != null ? d.suspicious_tld_count : 0],
      ["Non-HTTPS links", d.http_url_count != null ? d.http_url_count : 0],
      ["Urgency (subject)", d.subject_urgency_words != null ? d.subject_urgency_words : 0],
      ["Urgency (body)", d.urgency_word_count != null ? d.urgency_word_count : 0],
      ["Credential words", d.credential_word_count != null ? d.credential_word_count : 0],
      ["Brand mentions", d.brand_impersonation_count != null ? d.brand_impersonation_count : 0],
      ["Reward words", d.reward_word_count != null ? d.reward_word_count : 0],
      ["Hidden elements", d.hidden_text_elements != null ? d.hidden_text_elements : 0],
      ["HTML forms", d.html_form_elements != null ? d.html_form_elements : 0],
      ["Redirect links", d.redirect_link_count != null ? d.redirect_link_count : 0],
    ];

    var signalsHTML = signals.map(function (pair) {
      var label = pair[0], val = pair[1];
      var highlight =
        (typeof val === "number" && val > 0) || val === "Yes"
          ? ' style="color:#f9ab00;font-weight:600"'
          : "";
      return '<div class="cgm-signal"><span>' + label + "</span><span" + highlight + ">" + val + "</span></div>";
    }).join("");

    var predictedLabel = score >= 50 ? 1 : 0;
    var methodStr = data.method || "ml";
    var methodLabel =
      methodStr.indexOf("rules") !== -1
        ? "ML + Rules"
        : methodStr === "ml"
          ? "ML Model"
          : "Rule-based";

    var reviewHint = data.needs_review
      ? '<div class="cgm-review-hint">Uncertain prediction — your feedback is especially useful</div>'
      : "";

    var confHtml =
      data.confidence != null
        ? '<div class="cgm-conf">Confidence: ' + Math.round(data.confidence * 100) + "%</div>"
        : "";
    var boostHtml =
      data.rule_boost
        ? '<div class="cgm-conf">Rule boost: +' + data.rule_boost + "</div>"
        : "";

    c.innerHTML =
      '<div class="cgm-panel">' +
        '<div class="cgm-header">' +
          '<div class="cgm-logo">' +
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none">' +
              '<path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>' +
            "</svg> CognitoMail" +
          "</div>" +
          '<span class="cgm-badge ' + verdictClass + '">' + escapeHtml(data.verdict || "Analysed") + "</span>" +
        "</div>" +
        '<div class="cgm-body">' +
          '<div class="cgm-score-row">' +
            '<div class="cgm-score-wrap">' +
              '<svg class="cgm-gauge" viewBox="0 0 80 80">' +
                '<circle cx="40" cy="40" r="32" fill="none" stroke="#1e2433" stroke-width="7"/>' +
                '<circle cx="40" cy="40" r="32" fill="none" stroke="' + colour + '" stroke-width="7"' +
                  ' stroke-dasharray="' + Math.round(score * 2.01) + ' 201"' +
                  ' stroke-linecap="round" transform="rotate(-90 40 40)"/>' +
              "</svg>" +
              '<div class="cgm-score-num" style="color:' + colour + '">' + score + "</div>" +
            "</div>" +
            '<div class="cgm-score-meta">' +
              '<div class="cgm-score-label">Risk Score</div>' +
              '<div class="cgm-score-sublabel">out of 100</div>' +
              '<div class="cgm-method-badge">' + methodLabel + "</div>" +
              confHtml + boostHtml +
            "</div>" +
          "</div>" +
          '<div class="cgm-section-label">Findings</div>' +
          '<div class="cgm-flags">' + flagsHTML + "</div>" +
          '<div class="cgm-section-label" style="margin-top:12px">Authentication</div>' +
          '<div class="cgm-auth-row">' +
            authChip("SPF", emailData.spf) +
            authChip("DKIM", emailData.dkim) +
            authChip("DMARC", emailData.dmarc) +
          "</div>" +
          '<div class="cgm-section-label" style="margin-top:12px">VirusTotal</div>' +
          vtHTML +
          '<div class="cgm-section-label" style="margin-top:12px">Threat signals</div>' +
          '<div class="cgm-signals-grid">' + signalsHTML + "</div>" +
          reviewHint +
          '<div class="cgm-feedback-row">' +
            "<span>Was this verdict correct?</span>" +
            '<button class="cgm-fb-btn cgm-fb-yes" data-label="' + predictedLabel + '" data-correct="1">Yes</button>' +
            '<button class="cgm-fb-btn cgm-fb-no" data-label="' + predictedLabel + '" data-correct="0">No</button>' +
          "</div>" +
        "</div>" +
      "</div>";

    injectSideBadge(data);

    var buttons = c.querySelectorAll(".cgm-fb-btn");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var predicted = parseInt(this.getAttribute("data-label"), 10);
        var isCorrect = parseInt(this.getAttribute("data-correct"), 10);
        var correctLabel = isCorrect ? predicted : predicted === 1 ? 0 : 1;
        try {
          chrome.runtime.sendMessage({
            type: "SEND_FEEDBACK",
            payload: {
              email: emailData,
              predicted_label: predicted,
              correct_label: correctLabel,
              uncertainty: data.uncertainty != null ? data.uncertainty : null,
              needs_review: !!data.needs_review,
              p_phishing: data.p_phishing != null ? data.p_phishing : (data.confidence != null ? data.confidence : null),
            },
          });
        } catch (err) {}
        var row = c.querySelector(".cgm-feedback-row");
        if (row) {
          row.innerHTML =
            '<span style="color:#00c9a7;font-weight:600">Feedback recorded — thank you!</span>';
        }
        var hint = c.querySelector(".cgm-review-hint");
        if (hint) hint.remove();
      });
    }
  }

  function injectErrorPanel(msg) {
    var c = getPanelContainer();
    c.innerHTML =
      '<div class="cgm-panel cgm-error">' +
        '<div class="cgm-header">' +
          '<div class="cgm-logo">' +
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none">' +
              '<path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#00c9a7"/>' +
            "</svg> CognitoMail" +
          "</div>" +
          '<span class="cgm-badge" style="background:#3a1a1a;color:#ea4335">Offline</span>' +
        "</div>" +
        '<div class="cgm-body">' +
          '<div style="font-size:12px;color:#9aa0b4;line-height:1.6">' +
            escapeHtml(msg) +
          "</div>" +
          '<div style="margin-top:8px;font-size:11px;background:#0d1117;border-radius:6px;padding:8px;color:#00c9a7;font-family:monospace">' +
            "Check your Render deployment is running" +
          "</div>" +
        "</div>" +
      "</div>";
  }

  setTimeout(onDomSettled, 1200);
})();