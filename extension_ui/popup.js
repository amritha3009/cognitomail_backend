// popup.js
let currentResult = null;
let currentEmail = null;

function showScreen(id) {
  document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
}

function authClass(val) {
  return val === "pass" ? "auth-pass" : val === "fail" ? "auth-fail" : "auth-unknown";
}

function renderResult(data) {
  currentResult = data;
  const score = data.risk_score ?? 0;
  const circumference = 201;
  const colour = score >= 70 ? "#ea4335" : score >= 40 ? "#f9ab00" : "#00c9a7";

  const fill = document.getElementById("gaugeFill");
  fill.setAttribute("stroke", colour);
  setTimeout(() => {
    fill.setAttribute(
      "stroke-dasharray",
      `${Math.round((score * circumference) / 100)} ${circumference}`
    );
  }, 60);

  document.getElementById("scoreNum").textContent = score;
  document.getElementById("scoreNum").style.color = colour;

  const pill = document.getElementById("verdictPill");
  pill.textContent = data.verdict || "Analysed";
  pill.className =
    "verdict-pill " +
    (score >= 70 ? "verdict-high" : score >= 40 ? "verdict-med" : "verdict-low");

  const chip = document.getElementById("methodChip");
  chip.innerHTML =
    data.method === "ml"
      ? "🤖 ML Model" +
        (data.confidence != null ? ` · ${Math.round(data.confidence * 100)}% confidence` : "")
      : "📋 Rule-based fallback";

  const flags = data.flags || [];
  const flagsEl = document.getElementById("flagsContainer");
  if (flags.length === 0) {
    flagsEl.innerHTML = '<div class="flag flag-safe">No significant phishing signals detected.</div>';
  } else {
    flagsEl.innerHTML = flags.map((f) => `<div class="flag">${f}</div>`).join("");
  }

  const spf = data.spf || "none";
  const dkim = data.dkim || "none";
  const dmarc = data.dmarc || "none";
  document.getElementById("authRow").innerHTML = [
    ["SPF", spf],
    ["DKIM", dkim],
    ["DMARC", dmarc],
  ]
    .map(
      ([label, val]) =>
        `<span class="auth-chip ${authClass(val)}">${label}: ${val.toUpperCase()}</span>`
    )
    .join("");

  document.getElementById("footerText").textContent =
    `Analysed just now · ${data.method === "ml" ? "ML" : "Rules"} · v1.1`;

  showScreen("screen-result");
}

function setupFeedback() {
  const row = document.getElementById("feedbackRow");

  document.getElementById("fbYes").onclick = () => {
    if (!currentResult) return;
    const predicted = currentResult.risk_score >= 50 ? 1 : 0;
    sendFeedback(predicted, predicted);
    row.innerHTML =
      '<span style="color:#00c9a7;font-weight:600">✓ Feedback recorded — thank you!</span>';
  };

  document.getElementById("fbNo").onclick = () => {
    if (!currentResult) return;
    const predicted = currentResult.risk_score >= 50 ? 1 : 0;
    const correct = predicted === 1 ? 0 : 1;
    sendFeedback(predicted, correct);
    row.innerHTML =
      '<span style="color:#00c9a7;font-weight:600">✓ Feedback recorded — thank you!</span>';
  };
}

function sendFeedback(predictedLabel, correctLabel) {
  try {
    chrome.runtime.sendMessage({
      type: "SEND_FEEDBACK",
      payload: {
        email: currentEmail || {},
        predicted_label: predictedLabel,
        correct_label: correctLabel,
      },
    });
  } catch (e) {
    console.debug("[CognitoMail] Could not send feedback");
  }
}

function loadResult() {
  showScreen("screen-loading");

  setTimeout(() => {
    const auth = document.getElementById("step-auth");
    const urls = document.getElementById("step-urls");
    const ml = document.getElementById("step-ml");
    if (auth) auth.className = "loading-step done";
    if (urls) urls.className = "loading-step done";
    if (ml) ml.className = "loading-step active";
  }, 400);

  try {
    chrome.runtime.sendMessage({ type: "GET_RESULT" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        showScreen("screen-idle");
        return;
      }

      const result = response.result;
      if (!result) {
        showScreen("screen-idle");
        return;
      }
      if (result.error) {
        document.getElementById("errorMsg").textContent = result.error;
        showScreen("screen-error");
        return;
      }

      renderResult(result);
      setupFeedback();
    });
  } catch (e) {
    showScreen("screen-idle");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("refreshBtn");
  if (btn) btn.addEventListener("click", loadResult);
  loadResult();
});