document.addEventListener("DOMContentLoaded", function () {
  const toggle = document.getElementById("adminNavToggle");
  const overlay = document.getElementById("adminNavOverlay");
  const sidebar = document.getElementById("adminSidebar");
  if (!toggle || !sidebar) return;

  if (window.matchMedia("(max-width: 900px)").matches) {
    sidebar.setAttribute("aria-hidden", "true");
  }

  function setOpen(open) {
    document.body.classList.toggle("admin-nav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    sidebar.setAttribute("aria-hidden", open ? "false" : "true");
    if (overlay) {
      if (open) {
        overlay.hidden = false;
      } else {
        window.setTimeout(function () {
          if (!document.body.classList.contains("admin-nav-open")) {
            overlay.hidden = true;
          }
        }, 280);
      }
    }
  }

  toggle.addEventListener("click", function (e) {
    e.stopPropagation();
    setOpen(!document.body.classList.contains("admin-nav-open"));
  });

  if (overlay) {
    overlay.addEventListener("click", function () {
      setOpen(false);
    });
  }

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(false);
  });

  sidebar.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      if (window.matchMedia("(max-width: 900px)").matches) {
        setOpen(false);
      }
    });
  });
});
