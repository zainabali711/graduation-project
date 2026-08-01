document.addEventListener("DOMContentLoaded", function () {
  initSidebarNav();
  initScanForm();
  initDomainForm();
  animateBars();
  initResultCharts();
  initHistoryTabs();
  initHistorySearch();
  initAuthUI();
});

function initSidebarNav() {
  const toggle = document.getElementById("navToggle");
  const overlay = document.getElementById("navOverlay");
  const sidebar = document.getElementById("sidebar");
  if (!toggle || !sidebar) return;

  function setOpen(open) {
    document.body.classList.toggle("nav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    sidebar.setAttribute("aria-hidden", open ? "false" : "true");
    if (overlay) {
      if (open) {
        overlay.hidden = false;
      } else {
        // Allow fade-out before hiding from a11y tree
        window.setTimeout(function () {
          if (!document.body.classList.contains("nav-open")) {
            overlay.hidden = true;
          }
        }, 280);
      }
    }
  }

  function toggleNav() {
    setOpen(!document.body.classList.contains("nav-open"));
  }

  toggle.addEventListener("click", function (e) {
    e.stopPropagation();
    toggleNav();
  });

  if (overlay) {
    overlay.addEventListener("click", function () {
      setOpen(false);
    });
  }

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(false);
  });

  // Close after navigating via a sidebar link
  sidebar.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      setOpen(false);
    });
  });
}

function initScanForm() {
  const form = document.getElementById("scanForm");
  const urlInput = document.getElementById("urlInput");
  const submitBtn = document.getElementById("submitBtn");

  if (!form || !urlInput) return;

  form.addEventListener("submit", function (e) {
    const url = urlInput.value.trim();
    if (!url) {
      e.preventDefault();
      showFormError("Please enter a valid URL");
      return;
    }

    const testUrl = url.startsWith("http") ? url : "https://" + url;
    try {
      // eslint-disable-next-line no-new
      new URL(testUrl);
    } catch (err) {
      e.preventDefault();
      showFormError("Invalid URL format");
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.classList.add("loading");
    }
  });
}

function initDomainForm() {
  const form = document.getElementById("domainForm");
  const domainInput = document.getElementById("domainInput");
  const submitBtn = document.getElementById("domainSubmitBtn");

  if (!form || !domainInput) return;

  form.addEventListener("submit", function (e) {
    const domain = domainInput.value.trim();
    if (!domain) {
      e.preventDefault();
      showDomainFormError("Please enter a valid domain");
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.classList.add("loading");
    }

    // Show page-level scanning status while WHOIS/DNS/SSL run
    let status = document.getElementById("domainLoadingStatus");
    if (!status) {
      status = document.createElement("p");
      status.id = "domainLoadingStatus";
      status.className = "domain-loading-status";
      status.setAttribute("aria-live", "polite");
      form.insertAdjacentElement("afterend", status);
    }
    status.innerHTML =
      '<span class="domain-loading-spinner" aria-hidden="true"></span>' +
      "<span>Inspecting domain… fetching IP, WHOIS &amp; SSL</span>";
  });
}

function showDomainFormError(msg) {
  const form = document.getElementById("domainForm");
  if (!form) return;

  let alertEl = form.parentElement.querySelector(".alert-error");
  if (!alertEl) {
    alertEl = document.createElement("div");
    alertEl.className = "alert-error";
    alertEl.setAttribute("role", "alert");
    form.parentElement.insertBefore(alertEl, form);
  }
  alertEl.textContent = msg;
}

function showFormError(msg) {
  const form = document.getElementById("scanForm");
  if (!form) return;

  let alertEl = document.querySelector(".alert-error");
  if (!alertEl) {
    alertEl = document.createElement("div");
    alertEl.className = "alert-error";
    alertEl.setAttribute("role", "alert");
    form.parentElement.insertBefore(alertEl, form);
  }
  alertEl.textContent = msg;
}

function animateBars() {
  requestAnimationFrame(function () {
    document
      .querySelectorAll(".conf-fill, .xai-fill, .metric-bar-fill")
      .forEach(function (el) {
        const width = parseFloat(el.getAttribute("data-width") || "0");
        el.style.width = Math.max(0, Math.min(100, width)) + "%";
      });
  });
}

function initResultCharts() {
  const data = window.URL_SHIELD_RESULT;
  if (!data || typeof Chart === "undefined") return;

  const donutEl = document.getElementById("probDonut");
  if (!donutEl) return;

  let malicious = Math.max(0, Number(data.malicious) || 0);
  let benign = Math.max(0, Number(data.benign) || 0);
  const sum = malicious + benign;
  if (sum <= 0) {
    malicious = 50;
    benign = 50;
  } else if (Math.abs(sum - 100) > 0.01) {
    malicious = (malicious / sum) * 100;
    benign = (benign / sum) * 100;
  } else {
    benign = 100 - malicious;
  }

  new Chart(donutEl, {
    type: "doughnut",
    data: {
      labels: ["Benign", "Malicious"],
      datasets: [
        {
          data: [benign, malicious],
          backgroundColor: ["#10B981", "#EF4444"],
          borderWidth: 0,
          hoverOffset: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: "78%",
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
      animation: {
        animateRotate: true,
        duration: 1100,
      },
      elements: {
        arc: { borderWidth: 0 },
      },
    },
  });
}

function initHistoryTabs() {
  const tabs = document.querySelectorAll("[data-history-tab]");
  const panels = document.querySelectorAll("[data-history-panel]");
  if (!tabs.length || !panels.length) return;

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      const target = tab.getAttribute("data-history-tab");
      tabs.forEach(function (t) {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      panels.forEach(function (panel) {
        panel.classList.toggle(
          "active",
          panel.getAttribute("data-history-panel") === target
        );
      });
    });
  });
}

function initHistorySearch() {
  const input = document.getElementById("historySearch");
  if (!input) return;

  input.addEventListener("input", function () {
    const q = input.value.trim().toLowerCase();
    const activePanel = document.querySelector(".history-panel.active");
    if (!activePanel) return;

    activePanel.querySelectorAll("tbody tr").forEach(function (row) {
      const text = (row.textContent || "").toLowerCase();
      row.style.display = text.includes(q) ? "" : "none";
    });
  });
}

function initAuthUI() {
  const tabs = document.querySelectorAll("[data-auth-tab]");
  const forms = document.querySelectorAll("[data-auth-form]");

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      const mode = tab.getAttribute("data-auth-tab");
      tabs.forEach(function (t) {
        t.classList.toggle("active", t === tab);
      });
      forms.forEach(function (form) {
        const show = form.getAttribute("data-auth-form") === mode;
        form.hidden = !show;
        form.classList.toggle("active", show);
      });
    });
  });

  document.querySelectorAll(".password-toggle").forEach(function (toggle) {
    toggle.addEventListener("click", function () {
      const targetId = toggle.getAttribute("data-password-target");
      const pass = document.getElementById(targetId);
      if (!pass) return;
      const showing = pass.type === "text";
      pass.type = showing ? "password" : "text";
      toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    });
  });
}
