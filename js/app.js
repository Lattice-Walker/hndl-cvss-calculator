// HNDL-adjusted CVSS v4.0 calculator.
// Scoring is delegated to FIRST's vendored implementation in js/cvss-v4/
// (globals: expectedMetricOrder, cvssConfig, cvssLookup_global, maxSeverity,
// macroVector, cvss_score). Everything here is wrapped in an IIFE because the
// vendored code assigns undeclared globals and must not collide with ours.
(function () {
  "use strict";

  if (typeof cvss_score !== "function" || typeof macroVector !== "function") {
    document.getElementById("results").insertAdjacentHTML("afterbegin",
      "<p><strong>The vendored CVSS v4.0 scoring files in js/cvss-v4/ failed to load.</strong></p>");
    return;
  }

  var ORDER = expectedMetricOrder;
  var BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
  var HARV_ALLOWED = BASE.concat(["CR"]);

  var DEFAULTS = {
    dep: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    harv: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H",
    dl: 30,
    mt: 4,
    qt: 15
  };
  var SENSITIVITY_QT = [10, 15, 20];

  var HARV_NOTES = {
    AT: "Set to None where traffic crosses international transit or a jurisdiction in which bulk collection is a standing practice.",
    SC: "Raise to High where harvested sessions carry credentials, long-lived tokens or key material."
  };
  var E_NOTE = "The absence of a present-day quantum decryption capability is the premise of the threat, not a mitigation of it.";

  var state = {};

  // ---- CVSS vectors -------------------------------------------------------

  function blankSelection() {
    var sel = {};
    Object.keys(ORDER).forEach(function (k) { sel[k] = "X"; });
    return sel;
  }

  // Returns a full selection object, or null if the vector is not a valid
  // CVSS v4.0 vector. Metrics outside `allowed` are dropped.
  function parseVector(str, allowed) {
    if (!str) return null;
    var parts = String(str).trim().split("/");
    if (parts.shift() !== "CVSS:4.0") return null;
    var sel = blankSelection();
    var seen = {};
    for (var i = 0; i < parts.length; i++) {
      var kv = parts[i].split(":");
      var k = kv[0], v = kv[1];
      if (kv.length !== 2 || !ORDER[k] || ORDER[k].indexOf(v) < 0 || seen[k]) return null;
      seen[k] = true;
      if (!allowed || allowed.indexOf(k) >= 0) sel[k] = v;
    }
    for (var j = 0; j < BASE.length; j++) {
      if (!seen[BASE[j]]) return null;
    }
    return sel;
  }

  function vectorString(sel) {
    var out = "CVSS:4.0";
    Object.keys(ORDER).forEach(function (k) {
      if (sel[k] !== "X") out += "/" + k + ":" + sel[k];
    });
    return out;
  }

  function score(sel) {
    return cvss_score(sel, cvssLookup_global, maxSeverity, macroVector(sel));
  }

  // ---- HNDL transformation ------------------------------------------------

  function temporal(dl, mt, qt) {
    var g = dl + mt - qt;
    var t = g <= 0 ? 0 : (qt > 0 ? Math.min(1, g / qt) : 1);
    return { g: g, t: t };
  }

  function round1(x) {
    return Math.round((x + Number.EPSILON) * 10) / 10;
  }

  function hndl(sDep, sHarv, t) {
    return round1(Math.max(sDep, t * sHarv));
  }

  function band(s) {
    if (s === 0) return "None";
    if (s < 4) return "Low";
    if (s < 7) return "Medium";
    if (s < 9) return "High";
    return "Critical";
  }

  function fmtYears(n) {
    return String(Math.round(n * 100) / 100);
  }

  // ---- Rendering ----------------------------------------------------------

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (a) { node.setAttribute(a, attrs[a]); });
    }
    if (text != null) node.textContent = text;
    return node;
  }

  // options: [{label, value, tooltip}]
  function metricRow(which, key, label, tooltip, options, note) {
    var row = el("div", { "class": "metric" });
    row.appendChild(el("div", { "class": "metric-label", title: tooltip || "" }, label + ":"));
    var opts = el("div", { "class": "options" });
    options.forEach(function (o) {
      var b = el("button", {
        type: "button",
        "data-which": which,
        "data-key": key,
        "data-value": o.value,
        title: o.tooltip || "",
        "aria-pressed": "false"
      }, o.label);
      opts.appendChild(b);
    });
    row.appendChild(opts);
    if (note) {
      var n = el("div", { "class": "note" });
      n.appendChild(el("b", null, "Guidance: "));
      n.appendChild(document.createTextNode(note));
      row.appendChild(n);
    }
    return row;
  }

  function configOptions(metricData) {
    return Object.keys(metricData.options).map(function (label) {
      var o = metricData.options[label];
      return { label: label, value: o.value, tooltip: o.tooltip };
    });
  }

  // Renders every metric group of one top-level cvssConfig section.
  function renderConfigSection(container, which, sectionName, notes) {
    var groups = cvssConfig[sectionName].metric_groups;
    Object.keys(groups).forEach(function (groupName) {
      if (groupName) container.appendChild(el("div", { "class": "group-title" }, groupName));
      var metrics = groups[groupName];
      Object.keys(metrics).forEach(function (label) {
        var m = metrics[label];
        container.appendChild(metricRow(which, m.short, label, m.tooltip, configOptions(m), notes && notes[m.short]));
      });
    });
  }

  function details(title, sections, which) {
    var d = el("details");
    d.appendChild(el("summary", null, title));
    var inner = el("div");
    sections.forEach(function (s) { renderConfigSection(inner, which, s); });
    d.appendChild(inner);
    return d;
  }

  function buildForm() {
    renderConfigSection(document.getElementById("dep-base"), "dep", "Base Metrics");
    var extra = document.getElementById("dep-extra");
    extra.appendChild(details("Supplemental Metrics", ["Supplemental Metrics"], "dep"));
    extra.appendChild(details("Environmental Metrics",
      ["Environmental (Modified Base Metrics)", "Environmental (Security Requirements)"], "dep"));
    extra.appendChild(details("Threat Metrics", ["Threat Metrics"], "dep"));

    var harv = document.getElementById("harv-base");
    renderConfigSection(harv, "harv", "Base Metrics", HARV_NOTES);

    harv.appendChild(el("div", { "class": "group-title" }, "Environmental and Threat"));
    var cr = cvssConfig["Environmental (Security Requirements)"].metric_groups[""]["Confidentiality Requirements (CR)"];
    var crOpts = configOptions(cr);
    var crOrder = ["X", "L", "M", "H"];
    crOpts.sort(function (a, b) { return crOrder.indexOf(a.value) - crOrder.indexOf(b.value); });
    harv.appendChild(metricRow("harv", "CR", "Confidentiality Requirements (CR)", cr.tooltip, crOpts));

    var eRow = el("div", { "class": "metric" });
    eRow.appendChild(el("div", { "class": "metric-label" }, "Exploit Maturity (E):"));
    eRow.appendChild(el("div", { "class": "locked" }, "Not Defined (X)"));
    var eNote = el("div", { "class": "note" });
    eNote.appendChild(el("b", null, "Locked: "));
    eNote.appendChild(document.createTextNode(E_NOTE));
    eRow.appendChild(eNote);
    harv.appendChild(eRow);

    var strip = document.getElementById("strip");
    SENSITIVITY_QT.forEach(function (qt) {
      strip.appendChild(el("div", { "data-qt": String(qt) }));
    });
  }

  // ---- State and URL ------------------------------------------------------

  function resetState() {
    state.dep = parseVector(DEFAULTS.dep);
    state.harv = parseVector(DEFAULTS.harv, HARV_ALLOWED);
    state.dl = DEFAULTS.dl;
    state.mt = DEFAULTS.mt;
    state.qt = DEFAULTS.qt;
  }

  function readYears(v) {
    var n = parseFloat(v);
    return isFinite(n) && n >= 0 ? n : null;
  }

  function hashString() {
    return "#dep=" + vectorString(state.dep) +
      "&harv=" + vectorString(state.harv) +
      "&dl=" + fmtYears(state.dl) +
      "&mt=" + fmtYears(state.mt) +
      "&qt=" + fmtYears(state.qt);
  }

  function readHash() {
    var h = window.location.hash.replace(/^#/, "");
    if (!h) return;
    var params = {};
    h.split("&").forEach(function (pair) {
      var i = pair.indexOf("=");
      if (i > 0) {
        try { params[pair.slice(0, i)] = decodeURIComponent(pair.slice(i + 1)); } catch (e) { /* ignore */ }
      }
    });
    var dep = parseVector(params.dep);
    var harv = parseVector(params.harv, HARV_ALLOWED);
    if (dep) state.dep = dep;
    if (harv) state.harv = harv;
    ["dl", "mt", "qt"].forEach(function (k) {
      var n = readYears(params[k]);
      if (n !== null) state[k] = n;
    });
  }

  function writeHash() {
    var h = hashString();
    if (window.location.hash === h) return;
    try {
      history.replaceState(null, "", h);
    } catch (e) {
      window.location.hash = h;
    }
  }

  function syncInputs() {
    ["dl", "mt", "qt"].forEach(function (k) {
      var input = document.getElementById(k);
      input.value = fmtYears(state[k]);
      input.removeAttribute("aria-invalid");
    });
  }

  // ---- Output -------------------------------------------------------------

  function setText(id, text) {
    document.getElementById(id).textContent = text;
  }

  function refresh() {
    var buttons = document.querySelectorAll("button[data-key]");
    for (var i = 0; i < buttons.length; i++) {
      var b = buttons[i];
      var sel = state[b.getAttribute("data-which")];
      b.setAttribute("aria-pressed", String(sel[b.getAttribute("data-key")] === b.getAttribute("data-value")));
    }

    var sDep = score(state.dep);
    var sHarv = score(state.harv);
    var tmp = temporal(state.dl, state.mt, state.qt);
    var sHndl = hndl(sDep, sHarv, tmp.t);
    var bandName = band(sHndl);

    // Section C
    setText("g-out", fmtYears(tmp.g));
    setText("t-rule", tmp.g <= 0 ? "0 (G ≤ 0)" : "min(1, G / QT)");
    setText("t-out", tmp.t.toFixed(2));
    setText("verdict", tmp.g <= 0
      ? "Mosca's inequality is satisfied — no HNDL exposure"
      : "Exposure gap: " + fmtYears(tmp.g) + " years");

    var cells = document.querySelectorAll("#strip > div");
    var results = SENSITIVITY_QT.map(function (qt) {
      var t = temporal(state.dl, state.mt, qt).t;
      return { qt: qt, t: t, s: hndl(sDep, sHarv, t) };
    });
    var worst = Math.max.apply(null, results.map(function (r) { return r.s; }));
    results.forEach(function (r, idx) {
      var c = cells[idx];
      c.className = r.s === worst ? "worst" : "";
      c.innerHTML = "";
      c.appendChild(el("div", null, "QT = " + r.qt + " yr, T = " + r.t.toFixed(2)));
      var line = el("div");
      line.appendChild(el("span", { "class": "s" }, r.s.toFixed(1)));
      line.appendChild(document.createTextNode(" " + band(r.s)));
      c.appendChild(line);
      if (r.s === worst) c.appendChild(el("div", null, "Worst case"));
    });

    // Results panel
    setText("hndl-score", sHndl.toFixed(1));
    setText("hndl-band", bandName);
    document.getElementById("headline").className = "headline band-" + bandName.toLowerCase();
    setText("dep-score", sDep.toFixed(1));
    setText("harv-score", sHarv.toFixed(1));
    setText("t-score", tmp.t.toFixed(2));

    var depVec = vectorString(state.dep);
    var harvVec = vectorString(state.harv);
    setText("dep-vector", depVec);
    setText("harv-vector", harvVec);
    document.getElementById("dep-link").href = "https://www.first.org/cvss/calculator/4.0#" + depVec;
    document.getElementById("harv-link").href = "https://www.first.org/cvss/calculator/4.0#" + harvVec;
    setText("ext-string", "HNDL:1.0/DL:" + fmtYears(state.dl) +
      "/MT:" + fmtYears(state.mt) +
      "/QT:" + fmtYears(state.qt) +
      "/T:" + tmp.t.toFixed(2) +
      "/SH:" + sHarv.toFixed(1) +
      "/SA:" + sHndl.toFixed(1));

    writeHash();
  }

  // ---- Clipboard ----------------------------------------------------------

  function fallbackCopy(text) {
    var ta = el("textarea", { readonly: "" });
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  function copyText(text, button) {
    var label = button.textContent;
    function done(ok) {
      button.textContent = ok ? "Copied" : "Copy failed";
      setTimeout(function () { button.textContent = label; }, 1200);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { done(true); },
        function () { done(fallbackCopy(text)); });
    } else {
      done(fallbackCopy(text));
    }
  }

  // ---- Wiring -------------------------------------------------------------

  function init() {
    buildForm();
    resetState();
    readHash();
    syncInputs();

    document.querySelector("main").addEventListener("click", function (e) {
      var b = e.target.closest("button[data-key]");
      if (!b) return;
      state[b.getAttribute("data-which")][b.getAttribute("data-key")] = b.getAttribute("data-value");
      refresh();
    });

    ["dl", "mt", "qt"].forEach(function (k) {
      var input = document.getElementById(k);
      input.addEventListener("input", function () {
        var n = readYears(input.value);
        if (n === null) {
          input.setAttribute("aria-invalid", "true");
          return;
        }
        input.removeAttribute("aria-invalid");
        state[k] = n;
        refresh();
      });
      input.addEventListener("change", syncInputs);
    });

    document.getElementById("results").addEventListener("click", function (e) {
      var b = e.target.closest("button.copy");
      if (!b) return;
      if (b.id === "copy-record") {
        copyText([
          document.getElementById("dep-vector").textContent,
          document.getElementById("harv-vector").textContent,
          document.getElementById("ext-string").textContent
        ].join("\n"), b);
      } else {
        copyText(document.getElementById(b.getAttribute("data-copy")).textContent, b);
      }
    });

    window.addEventListener("hashchange", function () {
      resetState();
      readHash();
      syncInputs();
      refresh();
    });

    refresh();
  }

  init();
})();
