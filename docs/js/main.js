/* nice_scan landing — interactions: install tabs, copy, mobile drawer.
   No scroll-driven reveals; the only non-user motion is the hero
   transcript settle (CSS, once, reduced-motion aware). */

(function () {
  "use strict";

  var toast = document.getElementById("toast");
  var toastTimer = null;

  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toast.classList.remove("show");
    }, 1800);
  }

  /* Install tabs */
  var tabBtns = Array.prototype.slice.call(document.querySelectorAll(".tab-btn"));
  tabBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      tabBtns.forEach(function (b) {
        var on = b === btn;
        b.setAttribute("aria-selected", on ? "true" : "false");
      });
      document.querySelectorAll("#install .tab-panel pre").forEach(function (pre) {
        pre.hidden = pre.id !== "code-" + btn.dataset.tab;
      });
    });
  });

  /* Copy buttons */
  function bindCopy(btn, getText) {
    btn.addEventListener("click", function () {
      var text = getText();
      if (!text) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () { showToast("Copied"); },
          function () { showToast("Copy failed — select the text manually"); }
        );
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); showToast("Copied"); }
        catch (e) { showToast("Copy failed — select the text manually"); }
        document.body.removeChild(ta);
      }
    });
  }

  document.querySelectorAll("pre[data-copy], [data-cmd]").forEach(function (el) {
    bindCopy(el, function () { return el.dataset.cmd || el.textContent.trim(); });
  });

  /* The install-tabs panel copies whichever command is visible. */
  var installCopy = document.querySelector("#install > .code-tabs .tab-panel > .copy");
  if (installCopy) {
    bindCopy(installCopy, function () {
      var visible = document.querySelector("#install .tab-panel pre:not([hidden]) code");
      return visible ? visible.textContent.replace(/^[#\s]*[^\n]*\n/, "").trim() : "";
    });
  }

  /* Mobile drawer */
  var menuBtn = document.querySelector(".menu-btn");
  var drawer = document.getElementById("nav-drawer");
  if (menuBtn && drawer) {
    menuBtn.addEventListener("click", function () {
      var open = menuBtn.getAttribute("aria-expanded") === "true";
      menuBtn.setAttribute("aria-expanded", open ? "false" : "true");
      drawer.hidden = open;
    });
    drawer.addEventListener("click", function (e) {
      if (e.target.closest("a")) {
        menuBtn.setAttribute("aria-expanded", "false");
        drawer.hidden = true;
      }
    });
  }
})();
