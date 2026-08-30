(function () {
  var SCRIPT = document.currentScript;
  var API = (SCRIPT && SCRIPT.getAttribute("data-api-url")) || "";
  if (!API && SCRIPT && SCRIPT.src) {
    try {
      API = new URL(SCRIPT.src).origin;
    } catch (err) {
      API = window.location.origin;
    }
  }
  var SITE_KEY = (SCRIPT && SCRIPT.getAttribute("data-site-key")) || "";
  var TOKEN = (SCRIPT && SCRIPT.getAttribute("data-token")) || "";
  var TITLE = (SCRIPT && SCRIPT.getAttribute("data-title")) || "";
  var WELCOME = (SCRIPT && SCRIPT.getAttribute("data-welcome")) || "";

  function loadCss() {
    var href = API.replace(/\/$/, "") + "/static/widget.css";
    if ([].some.call(document.styleSheets, function (sheet) { return sheet.href === href; })) {
      return;
    }
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    document.head.appendChild(link);
  }

  function bubble(role, text) {
    var el = document.createElement("div");
    el.className = "authinject-bubble " + role;
    el.textContent = text;
    return el;
  }

  function init(options) {
    options = options || {};
    API = options.apiUrl || API;
    SITE_KEY = options.siteKey || SITE_KEY;
    TOKEN = options.token || TOKEN;
    TITLE = options.title || TITLE || "Assistant";
    WELCOME = options.welcome || WELCOME || "Ask a question about the knowledge base.";
    loadCss();

    var root = document.createElement("div");
    root.className = "authinject-root";
    root.innerHTML =
      '<button type="button" class="authinject-launcher" aria-label="Open chat">✦</button>' +
      '<section class="authinject-panel" role="dialog" aria-label="Chat">' +
      '  <div class="authinject-header">' + TITLE + "<small>Authorization-first RAG</small></div>" +
      '  <div class="authinject-log"></div>' +
      '  <form class="authinject-form">' +
      '    <input type="text" placeholder="Ask a question" autocomplete="off" />' +
      "    <button type=\"submit\">Send</button>" +
      "  </form>" +
      "</section>";
    document.body.appendChild(root);

    var panel = root.querySelector(".authinject-panel");
    var log = root.querySelector(".authinject-log");
    var form = root.querySelector(".authinject-form");
    var input = form.querySelector("input");
    var history = [];

    log.appendChild(bubble("assistant", WELCOME));

    root.querySelector(".authinject-launcher").addEventListener("click", function () {
      panel.classList.toggle("open");
      if (panel.classList.contains("open")) input.focus();
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var message = input.value.trim();
      if (!message) return;
      input.value = "";
      log.appendChild(bubble("user", message));
      log.scrollTop = log.scrollHeight;
      var headers = { "content-type": "application/json" };
      if (TOKEN) headers.authorization = "Bearer " + TOKEN;
      if (SITE_KEY) headers["x-site-key"] = SITE_KEY;
      fetch(API.replace(/\/$/, "") + "/chat", {
        method: "POST",
        headers: headers,
        body: JSON.stringify({ message: message, history: history }),
      })
        .then(function (res) {
          if (!res.ok) throw new Error("Chat request failed (" + res.status + ")");
          return res.json();
        })
        .then(function (body) {
          var reply = body.reply || "";
          history.push({ role: "user", content: message });
          history.push({ role: "assistant", content: reply });
          if (history.length > 16) history = history.slice(-16);
          log.appendChild(bubble("assistant", reply));
          log.scrollTop = log.scrollHeight;
        })
        .catch(function (err) {
          log.appendChild(bubble("assistant", "Could not reach the assistant. " + err.message));
        });
    });
  }

  window.AuthInjectChat = { init: init };
  if (SCRIPT && SCRIPT.getAttribute("data-auto") !== "false") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () { init(); });
    } else {
      init();
    }
  }
})();
