/* aegis project site - no dependencies, no build step. */
(function () {
  "use strict";

  /* --- theme: follow the system, allow an override ---------------------- */
  var KEY = "aegis-theme";
  try {
    var saved = localStorage.getItem(KEY);
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (e) { /* private mode: stay on the system preference */ }

  function currentTheme() {
    var set = document.documentElement.getAttribute("data-theme");
    if (set) return set;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  document.addEventListener("click", function (ev) {
    var toggle = ev.target.closest && ev.target.closest(".theme-toggle");
    if (!toggle) return;
    var next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem(KEY, next); } catch (e) {}
  });

  /* --- mobile navigation ------------------------------------------------ */
  var navToggle = document.querySelector(".nav-toggle");
  var nav = document.querySelector(".nav");
  if (navToggle && nav) {
    navToggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", function (ev) {
      if (ev.target.tagName === "A") {
        nav.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* --- copy buttons ----------------------------------------------------- */
  document.querySelectorAll(".code").forEach(function (block) {
    var head = block.querySelector(".code-head");
    var pre = block.querySelector("pre");
    if (!head || !pre || head.querySelector(".copy")) return;

    var btn = document.createElement("button");
    btn.className = "copy";
    btn.type = "button";
    btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      var text = pre.innerText;
      var done = function () {
        btn.textContent = "Copied";
        btn.classList.add("done");
        setTimeout(function () {
          btn.textContent = "Copy";
          btn.classList.remove("done");
        }, 1600);
      };
      var fallback = function () {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); done(); } catch (e) {}
        document.body.removeChild(ta);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else {
        fallback();
      }
    });
    head.appendChild(btn);
  });

  /* --- tiny syntax highlighter -------------------------------------------
     Deliberately simple: comments and strings are set aside first, then
     keywords and numbers are coloured in what remains. Good enough for the
     YAML, JSON and shell snippets on this site, and it cannot break the page
     if it gets something wrong.                                            */
  var KEYWORDS = {
    yaml: /\b(server|users|targets|secrets|inject|headers|query|body|name|password|allow_any|id|description|base_url|methods|paths|rate_limit|timeout|follow_redirects|listen|public_url|max_response_bytes|request_timeout|token_ttl|code_ttl|login_rate_limit)\b(?=\s*:)/g,
    shell: /\b(docker|curl|go|export|cat|chmod|mkdir|git|EOF)\b/g,
    json: /&quot;(error|message|status|target|body|headers|truncated|duration_ms|targets|allow_any|id|description|base_url|methods|paths|injected|redacted|user|url|method|ts|event|level|rate_limit|client_id|bytes)&quot;(?=\s*:)/g
  };

  // Placeholders live in the Unicode private use area and contain no digits
  // or ASCII letters, so the keyword and number passes cannot match inside
  // one and corrupt the restore. Written as escapes to keep this file ASCII.
  var PU_START = 0xE100;
  var PLACEHOLDER = new RegExp("[\\uE100-\\uEFFF]", "g");

  document.querySelectorAll("pre[data-lang]").forEach(function (pre) {
    var lang = pre.getAttribute("data-lang");
    var slots = [];

    function stash(html) {
      slots.push(html);
      return String.fromCharCode(PU_START + slots.length - 1);
    }

    var out = pre.textContent
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

    // Comments first, so a # inside a string is never mistaken for one.
    out = out.replace(/(^|\n)([^\n]*?)(#[^\n]*)/g, function (m, nl, before, comment) {
      if ((before.match(/&quot;/g) || []).length % 2 === 1) return m;
      return nl + before + stash('<span class="t-com">' + comment + "</span>");
    });

    out = out.replace(/(&quot;(?:(?!&quot;)[\s\S])*&quot;)/g, function (m) {
      return stash('<span class="t-str">' + m + "</span>");
    });

    if (KEYWORDS[lang]) {
      out = out.replace(KEYWORDS[lang], function (m) {
        return '<span class="t-key">' + m + "</span>";
      });
    }
    out = out.replace(/\b(\d[\d_.]*)\b/g, '<span class="t-num">$1</span>');

    out = out.replace(PLACEHOLDER, function (ch) {
      return slots[ch.charCodeAt(0) - PU_START];
    });
    pre.innerHTML = out;
  });

  /* --- table of contents highlighting ----------------------------------- */
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = byId[entry.target.id];
        if (!link) return;
        if (entry.isIntersecting) {
          links.forEach(function (a) { a.classList.remove("active"); });
          link.classList.add("active");
        }
      });
    }, { rootMargin: "-88px 0px -70% 0px", threshold: 0 });

    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) observer.observe(el);
    });
  }

  /* --- year -------------------------------------------------------------- */
  document.querySelectorAll("[data-year]").forEach(function (el) {
    el.textContent = String(new Date().getFullYear());
  });
})();
