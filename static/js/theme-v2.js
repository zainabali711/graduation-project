/* CyberScan v2 visual layer: pointer tilt, radar parallax, scroll reveal.
   Never adds, removes or moves elements: it only sets inline CSS variables
   and data-v2-* attributes that theme-v2.css reads. */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  if (reduceMotion) return;

  var TILT_SELECTOR = [
    ".metric-card",
    ".domain-info-card",
    ".feature-chip",
    ".dns-example-chip",
    ".home-elite .elite-svc",
    ".home-elite .elite-stat",
    ".cm-cell",
    ".donut-wrap"
  ].join(",");

  var REVEAL_SELECTOR = [
    ".panel",
    ".metric-card",
    ".feature-chip",
    ".home-elite .elite-svc",
    ".home-elite .elite-step",
    ".home-elite .elite-stat",
    ".home-elite .elite-table-wrap",
    ".history-table-wrap",
    ".dns-examples"
  ].join(",");

  function initTilt() {
    if (!finePointer) return;
    var MAX = 7;
    document.querySelectorAll(TILT_SELECTOR).forEach(function (el) {
      el.addEventListener("pointermove", function (e) {
        var r = el.getBoundingClientRect();
        if (!r.width || !r.height) return;
        var x = (e.clientX - r.left) / r.width - 0.5;
        var y = (e.clientY - r.top) / r.height - 0.5;
        el.setAttribute("data-v2-tilting", "");
        el.style.setProperty("--v2-ry", (x * MAX).toFixed(2) + "deg");
        el.style.setProperty("--v2-rx", (-y * MAX).toFixed(2) + "deg");
      });
      el.addEventListener("pointerleave", function () {
        el.removeAttribute("data-v2-tilting");
        el.style.removeProperty("--v2-ry");
        el.style.removeProperty("--v2-rx");
      });
    });
  }

  /* The radar floor on Home and Sign in leans toward the pointer */
  function initRadarParallax() {
    if (!finePointer) return;
    var pairs = [
      [".home-elite .elite-hero", ".home-elite .elite-radar"],
      [".auth-elite-brand", ".auth-elite .elite-radar"]
    ];
    pairs.forEach(function (pair) {
      var area = document.querySelector(pair[0]);
      var radar = document.querySelector(pair[1]);
      if (!area || !radar) return;
      area.addEventListener("pointermove", function (e) {
        var r = area.getBoundingClientRect();
        var x = (e.clientX - r.left) / r.width - 0.5;
        var y = (e.clientY - r.top) / r.height - 0.5;
        radar.style.setProperty("--v2-px", x.toFixed(3));
        radar.style.setProperty("--v2-py", y.toFixed(3));
      });
      area.addEventListener("pointerleave", function () {
        radar.style.setProperty("--v2-px", "0");
        radar.style.setProperty("--v2-py", "0");
      });
    });
  }

  /* Elements already on screen are left alone, so nothing visible ever blinks */
  function initReveal() {
    if (!("IntersectionObserver" in window)) return;
    var fold = window.innerHeight;
    var pending = [];
    document.querySelectorAll(REVEAL_SELECTOR).forEach(function (el) {
      if (el.parentElement && el.parentElement.closest("[data-v2-reveal]")) return;
      var r = el.getBoundingClientRect();
      if (!r.width && !r.height) return;
      if (r.top < fold - 40) return;
      el.setAttribute("data-v2-reveal", "pending");
      pending.push(el);
    });
    if (!pending.length) return;

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        observer.unobserve(el);
        el.setAttribute("data-v2-reveal", "shown");
        window.setTimeout(function () { el.removeAttribute("data-v2-reveal"); }, 800);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });

    pending.forEach(function (el) { observer.observe(el); });
  }

  function init() {
    initTilt();
    initRadarParallax();
    initReveal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
