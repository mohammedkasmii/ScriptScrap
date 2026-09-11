"""Static bodies served by the fixture application.

Everything in this module is a fixed literal. Nothing here is generated at
runtime, nothing depends on the clock, the filesystem or the network, and no
value is derived from ``random``/``uuid``. The single dynamic value in the whole
fixture is the cross-origin base URL, which is substituted into
:data:`MAIN_PAGE_HTML` through the :data:`CROSS_ORIGIN_PLACEHOLDER` token at
render time (the port is OS-assigned, so it cannot be a literal).
"""

from __future__ import annotations

CROSS_ORIGIN_PLACEHOLDER = "__CROSS_ORIGIN__"
WEBSOCKET_PLACEHOLDER = "__WEBSOCKET_URL__"
DEAD_URL_PLACEHOLDER = "__DEAD_URL__"

# --------------------------------------------------------------------------- #
# Fixed identifiers. These are deliberately credential-shaped but entirely
# fake; they exist so redaction / credential-classification code paths have
# something to bite on.
# --------------------------------------------------------------------------- #
FIXTURE_VERSION_HEADER = "X-Fixture-Version"
FIXTURE_VERSION_VALUE = "1"
FIXTURE_SESSION_COOKIE = "fixture_session=FIXTURE_SESSION_TOKEN_0001; Path=/"
FIXTURE_CSRF_TOKEN = "FIXTURE_CSRF_TOKEN_0001"
FIXTURE_MISSION_ID = "M-FIXTURE-0001"

# --------------------------------------------------------------------------- #
# JSON bodies (byte-exact literals, never json.dumps, so two runs cannot drift)
# --------------------------------------------------------------------------- #
DOSSIER_JSON = (
    '{"dossierId": 44718, "missionId": "M-FIXTURE-0001", '
    '"assure": {"nom": "Benali", "prenom": "Alice"}, '
    '"garage": {"code": "GAR-0007", "libelle": "Garage Central"}}'
)

REFERENTIEL_JSON = (
    '{"items": [{"id": "GAR-0007", "label": "Garage Central"}, '
    '{"id": "GAR-0011", "label": "Garage Atlas"}, '
    '{"id": "GAR-0042", "label": "Garage Souss"}]}'
)

REDIRECTED_JSON = '{"status": "redirected", "finalStop": true}'

ERROR_JSON = '{"error": "fixture_error", "code": "E-FIXTURE-500"}'

NOT_FOUND_JSON = '{"error": "not_found", "code": "E-FIXTURE-404"}'

VALIDER_REFERENCE = "REF-FIXTURE-9001"

# Byte-identical payload served from two endpoints, to prove content-addressed
# deduplication stores one blob.
TWIN_JSON = '{"twin": true, "payload": "FIXTURE-TWIN-PAYLOAD-0001"}'

# The parse-time case, in its own file so a forensic sensor can observe the
# SOURCE before Firefox parses it. The function is declared and called in the
# same parse, which is exactly what an injected interval hook cannot catch:
# by the time any wrapper could replace the function, the call has happened.
EARLY_JS = """/* fixture: declaration and call in one parse */
function fixtureEarlyFunction(a, b) {
  return a + b;
}
window.fixtureEarlyFunction = fixtureEarlyFunction;
window.__fixtureEarlyResult = fixtureEarlyFunction(20, 22);
/* Mirrored into the DOM so a driver in either JS world can wait on it. */
try {
  document.documentElement.setAttribute(
    "data-fixture-early-result", String(window.__fixtureEarlyResult));
} catch (e) { /* documentElement may not exist yet in some load orders */ }

function fixtureLateFunction(a, b) {
  return a * b;
}
window.fixtureLateFunction = fixtureLateFunction;

fetch("/api/referentiel?type=garage");
"""

# --------------------------------------------------------------------------- #
# A 1x1 fully transparent RGBA PNG. Hardcoded bytes, not generated.
# --------------------------------------------------------------------------- #
BG_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\rIDATx\xdac````\x00\x00\x00\x05\x00\x01z\xa8WP"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

# --------------------------------------------------------------------------- #
# CSS
# --------------------------------------------------------------------------- #
APP_CSS = """/* ScriptScrap fixture stylesheet - same-origin, so document.styleSheets
   exposes cssRules to script running on the main page. */
:root {
  --fixture-accent: #204080;
  --fixture-muted: #6b7280;
}

body {
  font-family: "Fixture Sans", Helvetica, Arial, sans-serif;
  background-image: url(../img/bg.png);
  background-repeat: no-repeat;
  color: #111827;
  margin: 16px;
}

h1#titre {
  font-family: "Fixture Display", Georgia, serif;
  font-size: 20px;
  color: var(--fixture-accent);
}

#frm-dossier label {
  display: block;
  margin-top: 6px;
}

#frm-dossier input[type="text"],
#frm-dossier input[type="password"],
#frm-dossier textarea,
#frm-dossier select {
  border: 1px solid var(--fixture-accent);
  padding: 2px 4px;
}

#actions button {
  margin-right: 6px;
}

#resultat {
  border: 1px dashed var(--fixture-muted);
  min-height: 18px;
  padding: 4px;
}

#mutation-target .fixture-added {
  color: var(--fixture-accent);
}
"""

VENDOR_CSS = """/* ScriptScrap fixture cross-origin stylesheet.
   Served from a different port (different origin) with NO CORS headers, so
   reading document.styleSheets[i].cssRules for this sheet throws SecurityError
   on the main page. That is the whole point of this file. */
.vendor-banner {
  font-family: "Vendor Sans", Verdana, sans-serif;
  background-color: #f3f4f6;
  border-bottom: 2px solid #9ca3af;
  padding: 6px;
}

.vendor-banner strong {
  color: #7c2d12;
}
"""

# --------------------------------------------------------------------------- #
# JavaScript
# --------------------------------------------------------------------------- #
JQUERY_STUB_JS = """/*
 * MINIMAL jQuery STAND-IN - THIS IS NOT jQuery.
 * ---------------------------------------------------------------------------
 * Purpose: give a jQuery-events extractor exactly the surface it probes, so the
 * extractor can be tested without shipping the real library into the fixture.
 *
 * Implemented (and nothing more):
 *   jQuery(selector)        -> collection object with .each(fn) and .on(t, h)
 *   collection.on(t, h)     -> real addEventListener + records h in a registry
 *   collection.each(fn)     -> fn.call(el, index, el) over the matched nodes
 *   jQuery._data(el, 'events') -> {click: [{type, handler, ...}], ...} | undefined
 *
 * NOT implemented, deliberately: selector engine beyond
 * document.querySelectorAll, .off/.trigger/.one, delegated events, namespaces,
 * .ajax/.get/.post, .css/.attr/.val/.html/.text, effects/animation, Deferred,
 * $.fn plugin extension, noConflict, DOM traversal, and chaining beyond the two
 * methods above.
 */
(function (global) {
  "use strict";

  var FIXTURE_STUB = "minimal-jquery-stand-in";
  var registry = new WeakMap();

  function record(el, type, handler) {
    var events = registry.get(el);
    if (!events) {
      events = {};
      registry.set(el, events);
    }
    if (!events[type]) {
      events[type] = [];
    }
    events[type].push({
      type: type,
      handler: handler,
      namespace: "",
      guid: events[type].length + 1,
      origin: FIXTURE_STUB
    });
  }

  function Collection(nodes) {
    this.length = nodes.length;
    for (var i = 0; i < nodes.length; i += 1) {
      this[i] = nodes[i];
    }
  }

  Collection.prototype.each = function (fn) {
    for (var i = 0; i < this.length; i += 1) {
      fn.call(this[i], i, this[i]);
    }
    return this;
  };

  Collection.prototype.on = function (type, handler) {
    for (var i = 0; i < this.length; i += 1) {
      this[i].addEventListener(type, handler, false);
      record(this[i], type, handler);
    }
    return this;
  };

  function jQuery(selector) {
    if (selector === null || selector === undefined) {
      return new Collection([]);
    }
    if (selector.nodeType === 1 || selector.nodeType === 9) {
      return new Collection([selector]);
    }
    return new Collection(document.querySelectorAll(String(selector)));
  }

  jQuery.fixtureStub = FIXTURE_STUB;

  jQuery._data = function (el, key) {
    if (key !== "events") {
      return undefined;
    }
    return registry.get(el);
  };

  global.jQuery = jQuery;
  global.$ = jQuery;
})(window);
"""

APP_JS = """/*
 * ScriptScrap fixture page script.
 * Deterministic and fully event-driven: no timers, no polling, no animation,
 * no clock reads. Once the initial /api/referentiel fetch settles the page is
 * quiescent until a user event arrives.
 */

/* Parse-time hook-timing case: a classic function declaration, exported onto
   window, and invoked ONCE while the script is still being parsed. An
   interval-installed runtime hook cannot possibly observe this call. */
function calculerMontantFixture(base, taux) {
  return base * taux;
}
window.calculerMontantFixture = calculerMontantFixture;
window.__fixtureParseTimeCall = calculerMontantFixture(100, 1.2);

/* Same shape, but only ever invoked from #btn-calculer - i.e. after load, so an
   interval-installed hook CAN observe it. */
function recalculerFixture(base, taux) {
  return base * taux;
}
window.recalculerFixture = recalculerFixture;

(function () {
  "use strict";

  function byId(id) {
    return document.getElementById(id);
  }

  function setResultat(text) {
    byId("resultat").textContent = text;
  }

  function chargerDossier() {
    return fetch("/api/dossier?id=44718", {
      method: "GET",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        /* Dependency-correlation case: the missionId seen in this RESPONSE is
           stashed and later re-sent in the /api/valider REQUEST body. */
        byId("mission").value = data.missionId;
        setResultat("dossier=" + data.dossierId + " mission=" + data.missionId);
      });
  }

  function validerDossier() {
    var payload = {
      missionId: byId("mission").value,
      montant: calculerMontantFixture(200, 1.5)
    };
    return fetch("/api/valider", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        setResultat("valide=" + data.status + " reference=" + data.reference);
      });
  }

  function envoyerFormulaire() {
    var body =
      "nom=" +
      encodeURIComponent(byId("nom").value) +
      "&ville=" +
      encodeURIComponent(byId("ville").value) +
      "&__RequestVerificationToken=" +
      encodeURIComponent(byId("csrf").value);
    return fetch("/api/form", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        setResultat("form=" + data.status);
      });
  }

  function suivreRedirection() {
    return fetch("/api/redirect", { method: "GET" })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        setResultat("redirect=" + data.status + " final=" + data.finalStop);
      });
  }

  function declencherErreur() {
    return fetch("/api/error", { method: "GET" })
      .then(function (response) {
        return response.json().then(function (data) {
          setResultat("erreur=" + response.status + " code=" + data.code);
        });
      });
  }

  function ajouterChamp() {
    var form = byId("frm-dossier");
    if (!byId("champ-dynamique")) {
      var champ = document.createElement("input");
      champ.type = "text";
      champ.id = "champ-dynamique";
      champ.name = "dynamique";
      champ.value = "valeur-dynamique";
      form.appendChild(champ);
    }
    var cible = byId("mutation-target");
    var ajout = document.createElement("div");
    ajout.className = "fixture-added";
    ajout.textContent = "mutation-" + (cible.children.length + 1);
    cible.appendChild(ajout);
  }

  function calculer() {
    byId("montant").textContent = String(recalculerFixture(200, 1.5));
  }

  function peuplerGarages() {
    return fetch("/api/referentiel?type=garage", {
      method: "GET",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        var select = byId("garage");
        for (var i = 0; i < data.items.length; i += 1) {
          var option = document.createElement("option");
          option.value = data.items[i].id;
          option.textContent = data.items[i].label;
          select.appendChild(option);
        }
      });
  }

  function attacherShadow() {
    var host = byId("shadow-host");
    if (!host || host.shadowRoot) {
      return;
    }
    var root = host.attachShadow({ mode: "open" });
    var form = document.createElement("form");
    form.id = "shadow-form";

    var input = document.createElement("input");
    input.type = "text";
    input.id = "shadow-input";
    input.name = "shadowNom";
    form.appendChild(input);

    var select = document.createElement("select");
    select.id = "shadow-select";
    select.name = "shadowChoix";
    var valeurs = [
      ["sh-1", "Ombre Une"],
      ["sh-2", "Ombre Deux"]
    ];
    for (var i = 0; i < valeurs.length; i += 1) {
      var option = document.createElement("option");
      option.value = valeurs[i][0];
      option.textContent = valeurs[i][1];
      select.appendChild(option);
    }
    form.appendChild(select);
    root.appendChild(form);
  }

  function enregistrerHandlersJQuery() {
    if (!window.jQuery) {
      return;
    }
    window.jQuery("#ville").on("change", function () {
      setResultat("ville=" + byId("ville").value);
    });
    window.jQuery("#accord").on("click", function () {
      setResultat("accord=" + byId("accord").checked);
    });
    window.jQuery("#frm-dossier").each(function () {
      this.setAttribute("data-fixture-jquery", "1");
    });
  }

  function initFixture() {
    byId("btn-charger").addEventListener("click", chargerDossier);
    byId("btn-valider").addEventListener("click", validerDossier);
    byId("btn-form").addEventListener("click", envoyerFormulaire);
    byId("btn-redirect").addEventListener("click", suivreRedirection);
    byId("btn-erreur").addEventListener("click", declencherErreur);
    byId("btn-ajouter").addEventListener("click", ajouterChamp);
    byId("btn-calculer").addEventListener("click", calculer);

    // --- M2 sensor exercises ------------------------------------------
    byId("btn-graphql").addEventListener("click", envoyerGraphQL);
    byId("btn-ws").addEventListener("click", ouvrirWebSocket);
    byId("btn-sse").addEventListener("click", ouvrirSSE);
    byId("btn-console").addEventListener("click", ecrireConsole);
    byId("btn-exception").addEventListener("click", declencherException);
    byId("btn-requete-morte").addEventListener("click", requeteImpossible);
    byId("btn-stockage").addEventListener("click", ecrireStockage);
    byId("btn-beacon").addEventListener("click", envoyerBeacon);
    byId("btn-popup").addEventListener("click", ouvrirPopup);
    byId("btn-route").addEventListener("click", changerRoute);
    byId("btn-telecharger").addEventListener("click", telecharger);

    // --- M3 inference exercises ---------------------------------------
    byId("btn-items").addEventListener("click", chargerItems);
    byId("btn-appliquer").addEventListener("click", appliquerItem);
    byId("btn-etat-liste").addEventListener("click", allerListe);
    byId("btn-etat-detail").addEventListener("click", allerDetail);
    byId("btn-etat-resume").addEventListener("click", allerResume);
    rendreBoutonInstable();

    byId("btn-icon").addEventListener("click", function () {
      setResultat("icone");
    });
    initialiserCombobox();

    attacherShadow();
    enregistrerHandlersJQuery();
    peuplerGarages();
    window.__fixtureReady = true;
    /* Readiness is also published to the DOM, because the DOM is the only
       thing a driver can see from EITHER JavaScript world. A `window` global
       is invisible to an isolated-world `wait_for_function`, which is how a
       browser update silently turned every readiness wait in the harness into
       a 30-second timeout. */
    document.documentElement.setAttribute("data-fixture-ready", "true");
  }

  /* ---------------------------------------------------------------- *
   * M2 sensor exercises. Each one drives exactly one observation path.
   * All values are fixed so two runs behave identically.
   * ---------------------------------------------------------------- */

  function envoyerGraphQL() {
    // A named mutation with variables: the operation, not the URL, is the
    // identity a GraphQL recogniser must retain.
    return fetch("/api/graphql", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operationName: "ValiderItem",
        query: "mutation ValiderItem($id: ID!, $note: String) " +
               "{ validerItem(id: $id, note: $note) { id statut } }",
        variables: { id: "ITEM-0001", note: "fixture" }
      })
    }).then(function (r) { return r.json(); })
      .then(function (data) {
        byId("resultat").textContent = "graphql:" + data.data.validerItem.statut;
      });
  }

  function ouvrirWebSocket() {
    var url = window.__fixtureWsUrl;
    if (!url) return;
    var socket = new WebSocket(url);
    window.__fixtureSocket = socket;
    socket.addEventListener("open", function () {
      socket.send("fixture-ping");
      socket.send(JSON.stringify({ type: "subscribe", channel: "items" }));
    });
    socket.addEventListener("message", function (ev) {
      var el = byId("ws-log");
      el.textContent = el.textContent + "[" + ev.data + "]";
      if (String(ev.data).indexOf("fixture-done") !== -1) socket.close();
    });
  }

  function ouvrirSSE() {
    var source = new EventSource("/api/sse");
    window.__fixtureSse = source;
    source.addEventListener("message", function (ev) {
      byId("sse-log").textContent += "[m:" + ev.data + "]";
    });
    source.addEventListener("progression", function (ev) {
      byId("sse-log").textContent += "[p:" + ev.data + "]";
    });
    source.addEventListener("fin", function () {
      byId("sse-log").textContent += "[fin]";
      source.close();
    });
  }

  function ecrireConsole() {
    console.log("fixture log message");
    console.info("fixture info message");
    console.warn("fixture warn message");
    console.error("fixture error message");
  }

  function declencherException() {
    // Thrown asynchronously so it becomes an uncaught page error rather than
    // an exception the click handler swallows.
    setTimeout(function () {
      throw new Error("fixture uncaught exception");
    }, 0);
  }

  function requeteImpossible() {
    // A high loopback port with nothing listening: same host, so the request
    // stays in scope, and not a browser-blocked "bad port", so the request is
    // actually attempted and fails at the network layer.
    return fetch(window.__fixtureDeadUrl, { mode: "no-cors" })
      .catch(function () { byId("resultat").textContent = "requete-echouee"; });
  }

  function ecrireStockage() {
    window.localStorage.setItem("fixtureToken", "LOCAL-FIXTURE-0001");
    window.localStorage.setItem("fixtureCounter", "42");
    window.sessionStorage.setItem("fixtureSession", "SESSION-FIXTURE-0001");
    window.localStorage.removeItem("fixtureCounter");
  }

  function envoyerBeacon() {
    if (navigator.sendBeacon) {
      navigator.sendBeacon("/api/beacon", "fixture-beacon-payload");
    }
  }

  function ouvrirPopup() {
    window.__fixturePopup = window.open("/page2?popup=1", "fixturePopup");
  }

  function changerRoute() {
    history.pushState({ etape: 2 }, "", "/#/etape/2");
    history.replaceState({ etape: 3 }, "", "/#/etape/3");
  }

  /* ---------------------------------------------------------------- *
   * M3 inference exercises. Each seeds one thing the analysis layer
   * must get right -- including two it must REJECT.
   * ---------------------------------------------------------------- */

  function chargerItems() {
    // Sibling paths, so endpoint templating has evidence to work from.
    var ids = [101, 102, 103];
    return ids.reduce(function (chain, id) {
      return chain.then(function () {
        return fetch("/api/items/" + id).then(function (r) { return r.json(); })
          .then(function (item) {
            window.__fixtureItems = window.__fixtureItems || {};
            window.__fixtureItems[id] = item;
            byId("items-log").textContent += "[" + item.reference + "]";
          });
      });
    }, Promise.resolve());
  }

  function appliquerItem() {
    var item = (window.__fixtureItems || {})[101];
    if (!item) return;
    // itemReference <- reference: a name-similarity dependency.
    // statut "OK" and actif 1 are COMMON values that must NOT correlate.
    return fetch("/api/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        itemReference: item.reference,
        statut: item.statut,
        actif: 1
      })
    }).then(function (r) { return r.json(); })
      .then(function (d) { byId("resultat").textContent = "applique:" + d.applied; });
  }

  function allerListe()  { history.pushState({}, "", "#/liste"); marquerEtat("liste"); }
  function allerDetail() { history.pushState({}, "", "#/detail/101"); marquerEtat("detail"); }
  function allerResume() { history.pushState({}, "", "#/resume"); marquerEtat("resume"); }

  function marquerEtat(nom) {
    byId("etat").textContent = nom;
  }

  var compteurInstable = 0;
  function rendreBoutonInstable() {
    // Same logical control, regenerated id every render: the case where an id
    // locator scores badly and a semantic one does not.
    compteurInstable += 1;
    var hote = byId("zone-instable");
    hote.innerHTML = "";
    var bouton = document.createElement("button");
    bouton.type = "button";
    bouton.id = "ctl00_generated_" + compteurInstable + "_a1b2c3d4";
    bouton.setAttribute("aria-label", "Action instable");
    bouton.textContent = "Action instable";
    bouton.addEventListener("click", rendreBoutonInstable);
    hote.appendChild(bouton);
  }

  function initialiserCombobox() {
    var combo = byId("agent-combo");
    var list = byId("agent-list");
    if (!combo || !list) {
      return;
    }
    combo.addEventListener("click", function () {
      var open = combo.getAttribute("aria-expanded") === "true";
      combo.setAttribute("aria-expanded", open ? "false" : "true");
      list.hidden = open;
    });
    list.querySelectorAll('[role="option"]').forEach(function (option) {
      option.addEventListener("click", function () {
        list.querySelectorAll('[role="option"]').forEach(function (other) {
          other.setAttribute("aria-selected", "false");
        });
        option.setAttribute("aria-selected", "true");
        combo.setAttribute("aria-activedescendant", option.id);
        combo.setAttribute("aria-expanded", "false");
        combo.textContent = option.textContent;
        list.hidden = true;
        setResultat("agent=" + option.getAttribute("data-value"));
      });
    });
  }

  function telecharger() {
    // A real navigation to an attachment response, so Playwright raises a
    // download event rather than a navigation.
    var a = document.createElement("a");
    a.href = "/api/telecharger";
    a.download = "fixture-rapport.txt";
    document.body.appendChild(a);
    a.click();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initFixture);
  } else {
    initFixture();
  }
})();
"""

# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
MAIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture</title>
<link rel="stylesheet" href="/assets/app.css">
<link rel="stylesheet" href="__CROSS_ORIGIN__/vendor.css">
<style>
#actions { margin-top: 12px; }
#montant { font-weight: bold; }
.fixture-inline { border: 1px solid #204080; padding: 2px; }
</style>
</head>
<body>
<h1 id="titre">ScriptScrap Fixture</h1>

<form id="frm-dossier" method="GET" action="/page2">
  <label for="nom">Nom</label>
  <input type="text" id="nom" name="nom" value="">

  <label for="notes">Notes</label>
  <textarea id="notes" name="notes" rows="3" cols="30"></textarea>

  <label for="accord"><input type="checkbox" id="accord" name="accord" value="oui"> Accord</label>

  <label for="type-bris"><input type="radio" id="type-bris" name="typeSinistre" value="bris"> Bris</label>
  <label for="type-choc"><input type="radio" id="type-choc" name="typeSinistre" value="choc"> Choc</label>

  <label for="ville">Ville</label>
  <select id="ville" name="ville">
    <option value="cas">Casablanca</option>
    <option value="rab">Rabat</option>
    <option value="mar">Marrakech</option>
  </select>

  <label for="garage">Garage</label>
  <select id="garage" name="garage"></select>

  <input type="hidden" id="csrf" name="__RequestVerificationToken" value="FIXTURE_CSRF_TOKEN_0001">
  <input type="hidden" id="mission" name="missionId" value="">

  <label for="champ-desactive">Desactive</label>
  <input type="text" id="champ-desactive" name="desactive" value="valeur-fixe" disabled>

  <label for="champ-lecture">Lecture</label>
  <input type="text" id="champ-lecture" name="lecture" value="lecture-seule" readonly>

  <label for="pw">Mot de passe</label>
  <label for="courriel">Courriel</label>
  <input type="email" id="courriel" name="courriel" value="">

  <input type="password" id="pw" name="pw" value="">

  <label for="justificatif">Justificatif</label>
  <input type="file" id="justificatif" name="justificatif">

  <button type="submit" id="btn-submit">Envoyer</button>
</form>

<!-- A button whose click lands on a decorative child: the observer must
     normalise the icon/span target up to the button. data-testid is the most
     stable locator a page can offer, so one control carries it. -->
<button type="button" id="btn-icon" data-testid="icon-action">
  <svg viewBox="0 0 8 8" width="8" height="8"><path d="M0 0h8v8H0z"></path></svg>
  <span class="btn-icon-label">Action icone</span>
</button>

<!-- A custom ARIA combobox: no native <select> value, only accessible state.
     Offline analysis connects the trigger to the listbox it controls and to
     the option the operator selects. -->
<div id="combo-wrap">
  <span id="combo-label">Agent</span>
  <div id="agent-combo" role="combobox" aria-expanded="false"
       aria-controls="agent-list" aria-haspopup="listbox"
       aria-labelledby="combo-label" tabindex="0">Choisir un agent</div>
  <ul id="agent-list" role="listbox" aria-labelledby="combo-label" hidden>
    <li role="option" id="opt-agent-1" data-value="ag-1">Agent Un</li>
    <li role="option" id="opt-agent-2" data-value="ag-2">Agent Deux</li>
  </ul>
</div>

<div id="actions">
  <button type="button" id="btn-charger">Charger</button>
  <button type="button" id="btn-valider">Valider</button>
  <button type="button" id="btn-form">Formulaire</button>
  <button type="button" id="btn-redirect">Redirection</button>
  <button type="button" id="btn-erreur">Erreur</button>
  <button type="button" id="btn-ajouter">Ajouter</button>
  <button type="button" id="btn-calculer">Calculer</button>
  <button type="button" id="btn-graphql">GraphQL</button>
  <button type="button" id="btn-ws">WebSocket</button>
  <button type="button" id="btn-sse">SSE</button>
  <button type="button" id="btn-console">Console</button>
  <button type="button" id="btn-exception">Exception</button>
  <button type="button" id="btn-requete-morte">Requete morte</button>
  <button type="button" id="btn-stockage">Stockage</button>
  <button type="button" id="btn-beacon">Beacon</button>
  <button type="button" id="btn-popup">Popup</button>
  <button type="button" id="btn-route">Route SPA</button>
  <button type="button" id="btn-telecharger">Telecharger</button>
  <button type="button" id="btn-items">Charger items</button>
  <button type="button" id="btn-appliquer">Appliquer</button>
  <button type="button" id="btn-etat-liste">Etat liste</button>
  <button type="button" id="btn-etat-detail">Etat detail</button>
  <button type="button" id="btn-etat-resume">Etat resume</button>
</div>

<div id="zone-instable"></div>

<div id="logs">
  <span id="ws-log"></span>
  <span id="sse-log"></span>
  <span id="items-log"></span>
  <span id="etat"></span>
</div>

<div id="resultat"></div>
<p>Montant: <span id="montant"></span></p>

<div id="shadow-host"></div>
<div id="mutation-target"></div>

<iframe id="frame-outer" src="/frame/outer" width="420" height="220" title="frame externe"></iframe>

<script>
window.__fixtureWsUrl = "__WEBSOCKET_URL__";
window.__fixtureDeadUrl = "__DEAD_URL__";
</script>
<script src="/assets/jquery-stub.js"></script>
<script src="/assets/app.js"></script>
</body>
</html>
"""

PAGE2_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Page 2</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h1 id="titre-page2">Page 2</h1>
<p id="page2-note">Cible d'une navigation complete depuis #btn-submit.</p>

<form id="frm-page2" method="GET" action="/page2">
  <label for="p2-reference">Reference</label>
  <input type="text" id="p2-reference" name="reference" value="REF-FIXTURE-9001">
  <label for="p2-etat">Etat</label>
  <select id="p2-etat" name="etat">
    <option value="ouvert">Ouvert</option>
    <option value="clos">Clos</option>
  </select>
  <button type="submit" id="btn-page2-submit">Confirmer</button>
</form>

<script>
/* Parse-time call on the navigation target too: the observer must re-install
   its hooks after a full document swap, and even then this call is already
   gone. */
function page2ParseTimeFixture(base) {
  return base * 2;
}
window.page2ParseTimeFixture = page2ParseTimeFixture;
window.__page2ParseTimeCall = page2ParseTimeFixture(21);
</script>
</body>
</html>
"""

# A form with id-less radio and checkbox groups (controls sharing a name but no
# id) plus a genuinely anonymous form (no id, no name). Exercises radio-group
# aggregation, distinct same-named checkboxes, and anonymous-form event
# attribution (DOM inventory + input + submit resolving to one entry).
CHOICES_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Choices</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h1 id="choices-title">Choices</h1>

<form id="prefs-form" onsubmit="return false;">
  <fieldset>
    <legend>Plan</legend>
    <label><input type="radio" name="plan" value="basic"> Basic</label>
    <label><input type="radio" name="plan" value="pro" checked> Pro</label>
    <label><input type="radio" name="plan" value="max"> Max</label>
  </fieldset>
  <fieldset>
    <legend>Toppings</legend>
    <label><input type="checkbox" name="topping" value="cheese"> Cheese</label>
    <label><input type="checkbox" name="topping" value="olives"> Olives</label>
    <label><input type="checkbox" name="topping" value="ham"> Ham</label>
  </fieldset>
  <button type="submit" id="prefs-submit">Save preferences</button>
</form>

<!-- A genuinely anonymous form: no id and no name attribute. -->
<form onsubmit="return false;">
  <label>Note <input type="text" name="note"></label>
  <button type="submit" id="anon-submit">Save note</button>
</form>

<script>
document.documentElement.setAttribute("data-fixture-choices-ready", "true");
</script>
</body>
</html>
"""


# Two routes that serve DIFFERENT documents carrying the SAME form id, so a
# same-tab navigation between them proves the catalog does not merge them.
def _same_id_form_page(title, route, field_label, field_name, next_route,
                       next_label):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - {title}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h1>{title}</h1>
<form id="entity-form" method="POST" action="{route}">
  <label>{field_label} <input type="text" id="entity-field" name="{field_name}"></label>
  <button type="submit" id="entity-submit">Submit</button>
</form>
<a id="go-next" href="{next_route}">{next_label}</a>
<script>
document.documentElement.setAttribute("data-fixture-entity-ready", "true");
</script>
</body>
</html>
"""


CLAIMS_NEW_HTML = _same_id_form_page(
    "New Claim", "/claims/new", "Claim reference", "claim_ref",
    "/customers/new", "Go to new customer")
CUSTOMERS_NEW_HTML = _same_id_form_page(
    "New Customer", "/customers/new", "Customer name", "customer_name",
    "/claims/new", "Go to new claim")


FRAME_OUTER_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Frame Outer</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h2 id="titre-outer">Frame externe</h2>

<form id="frm-outer" method="GET" action="/frame/outer">
  <label for="outer-champ">Champ externe</label>
  <input type="text" id="outer-champ" name="outerChamp" value="">
  <button type="submit" id="btn-outer-submit">Outer</button>
</form>

<iframe id="frame-inner" src="/frame/inner" width="320" height="90" title="frame interne"></iframe>
</body>
</html>
"""

FRAME_INNER_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Frame Inner</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h3 id="titre-inner">Frame interne</h3>
<input type="text" id="inner-champ" name="innerChamp" value="">
<select id="inner-select" name="innerSelect">
  <option value="in-1">Interne Un</option>
  <option value="in-2">Interne Deux</option>
</select>
</body>
</html>
"""

TABLE_PAGE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Table</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<h1 id="titre-table">Dossiers</h1>

<input type="search" id="table-filter" name="filtre"
       placeholder="Filtrer les dossiers" aria-controls="dossiers">

<table id="dossiers" aria-label="Dossiers">
  <caption>Dossiers ouverts</caption>
  <thead>
    <tr>
      <th id="col-id" data-sort="id">Reference</th>
      <th id="col-client" data-sort="client">Client</th>
      <th id="col-montant" data-sort="montant">Montant</th>
      <th id="col-actions">Actions</th>
    </tr>
  </thead>
  <tbody id="dossiers-body">
    <tr data-id="D-1001"><td>D-1001</td><td>Alpha</td><td>1200</td>
      <td><button type="button" class="row-edit" data-id="D-1001">Editer</button></td></tr>
    <tr data-id="D-1002"><td>D-1002</td><td>Beta</td><td>800</td>
      <td><button type="button" class="row-edit" data-id="D-1002">Editer</button></td></tr>
    <tr data-id="D-1003"><td>D-1003</td><td>Gamma</td><td>450</td>
      <td><button type="button" class="row-edit" data-id="D-1003">Editer</button></td></tr>
  </tbody>
</table>

<div id="pagination">
  <button type="button" id="prev-page" aria-controls="dossiers">Precedent</button>
  <span id="page-indicator">Page 1</span>
  <button type="button" id="next-page" aria-controls="dossiers">Suivant</button>
</div>
<div id="table-status"></div>

<script>
(function () {
  "use strict";
  var page = 1;
  function status(text) { document.getElementById("table-status").textContent = text; }
  document.getElementById("table-filter").addEventListener("input", function (ev) {
    var term = ev.target.value.toLowerCase();
    var rows = document.querySelectorAll("#dossiers-body tr");
    for (var i = 0; i < rows.length; i += 1) {
      rows[i].hidden = term && rows[i].textContent.toLowerCase().indexOf(term) === -1;
    }
    status("filtre=" + term);
  });
  var headers = document.querySelectorAll("#dossiers thead th[data-sort]");
  for (var h = 0; h < headers.length; h += 1) {
    headers[h].addEventListener("click", function (ev) {
      status("tri=" + ev.currentTarget.getAttribute("data-sort"));
    });
  }
  var edits = document.querySelectorAll(".row-edit");
  for (var e = 0; e < edits.length; e += 1) {
    edits[e].addEventListener("click", function (ev) {
      status("editer=" + ev.currentTarget.getAttribute("data-id"));
    });
  }
  document.getElementById("next-page").addEventListener("click", function () {
    page += 1; document.getElementById("page-indicator").textContent = "Page " + page;
  });
  document.getElementById("prev-page").addEventListener("click", function () {
    if (page > 1) { page -= 1; }
    document.getElementById("page-indicator").textContent = "Page " + page;
  });
  document.documentElement.setAttribute("data-fixture-table-ready", "true");
})();
</script>
</body>
</html>
"""

OPENS_POPUP_PAGE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>ScriptScrap Fixture - Opens Popup</title></head>
<body>
<h1 id="titre-opener">Ouverture automatique</h1>
<script>
/* Opens a popup DURING this page's initial load, so coverage started before
   the first navigation must still catch it. */
window.__fixtureAutoPopup = window.open("/page2?auto=1", "autopopup");
document.documentElement.setAttribute("data-fixture-opener-ready", "true");
</script>
</body>
</html>
"""

INTERACTIONS_PAGE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>ScriptScrap Fixture - Interactions</title>
<link rel="stylesheet" href="/assets/app.css">
<style>
#menu { display: none; }
#menu.open { display: block; }
#virt-wrap { height: 180px; overflow: auto; border: 1px solid #999; width: 320px; }
#virt-spacer { position: relative; }
#drop-target { border: 2px dashed #999; padding: 10px; min-height: 24px; }
</style>
</head>
<body>
<h1 id="titre-interactions">Interactions</h1>

<!-- Hover-opened menu: the trigger declares aria-haspopup, and the menu shows
     on hover. The probe records the hover on the menu trigger. -->
<div id="menu-region">
  <button type="button" id="menu-trigger" aria-haspopup="menu"
          aria-controls="menu">Actions</button>
  <ul id="menu" role="menu" aria-labelledby="menu-trigger">
    <li role="menuitem" id="menu-open">Ouvrir</li>
    <li role="menuitem" id="menu-archive">Archiver</li>
  </ul>
</div>

<!-- A JavaScript dialog: confirm(). The automation layer intercepts it; the
     recorder observes type/message and dismisses. -->
<button type="button" id="btn-confirm">Confirmer une action</button>
<div id="confirm-result"></div>

<!-- Drag and drop. Playwright cannot drive native HTML5 DnD, so a button lets
     the page fire the real DragEvent sequence a browser produces during a drag;
     the probe observes the same listener path either way. -->
<div id="drag-src" draggable="true" data-item="dossier-7">Dossier 7</div>
<div id="drop-target" aria-label="Corbeille">Deposer ici</div>
<button type="button" id="sim-drag">Glisser vers la corbeille</button>
<div id="drop-result"></div>

<!-- A genuinely virtualized table: only a window of rows is in the DOM, and
     which rows are rendered changes on scroll. -->
<div id="virt-wrap" aria-label="Grand tableau">
  <div id="virt-spacer">
    <table id="virt-table" role="grid" aria-label="Grand tableau">
      <caption>Grand tableau</caption>
      <thead><tr><th>Ref</th><th>Client</th><th>Montant</th></tr></thead>
      <tbody id="virt-body"></tbody>
    </table>
  </div>
</div>

<script>
(function () {
  "use strict";
  // Hover menu.
  var trigger = document.getElementById("menu-trigger");
  var menu = document.getElementById("menu");
  trigger.addEventListener("mouseover", function () { menu.classList.add("open"); });
  trigger.addEventListener("focus", function () { menu.classList.add("open"); });

  // Dialog.
  document.getElementById("btn-confirm").addEventListener("click", function () {
    var ok = window.confirm("Proceder a l'archivage ?");
    document.getElementById("confirm-result").textContent = "confirm=" + ok;
  });

  // Drag and drop.
  var src = document.getElementById("drag-src");
  var target = document.getElementById("drop-target");
  src.addEventListener("dragstart", function (ev) {
    ev.dataTransfer.setData("text/plain", src.getAttribute("data-item"));
  });
  target.addEventListener("dragover", function (ev) { ev.preventDefault(); });
  target.addEventListener("drop", function (ev) {
    ev.preventDefault();
    document.getElementById("drop-result").textContent =
      "drop=" + ev.dataTransfer.getData("text/plain");
  });
  document.getElementById("sim-drag").addEventListener("click", function () {
    var dt = new DataTransfer();
    dt.setData("text/plain", src.getAttribute("data-item"));
    src.dispatchEvent(new DragEvent("dragstart",
      { bubbles: true, cancelable: true, dataTransfer: dt }));
    target.dispatchEvent(new DragEvent("drop",
      { bubbles: true, cancelable: true, dataTransfer: dt }));
    src.dispatchEvent(new DragEvent("dragend",
      { bubbles: true, cancelable: true, dataTransfer: dt }));
  });

  // Virtualized table: 60 rows of data, ~12 rendered at a time.
  var DATA = [];
  for (var i = 1; i <= 60; i += 1) {
    DATA.push({ id: "V-" + i, client: "Client " + i, montant: i * 10 });
  }
  var ROW_H = 24, WINDOW = 12;
  var body = document.getElementById("virt-body");
  var spacer = document.getElementById("virt-spacer");
  var wrap = document.getElementById("virt-wrap");
  spacer.style.height = (DATA.length * ROW_H) + "px";
  function render() {
    var start = Math.floor(wrap.scrollTop / ROW_H);
    var end = Math.min(DATA.length, start + WINDOW);
    var html = "";
    for (var j = start; j < end; j += 1) {
      var d = DATA[j];
      html += '<tr data-id="' + d.id + '" style="position:absolute;top:' +
        (j * ROW_H) + 'px"><td>' + d.id + '</td><td>' + d.client +
        '</td><td>' + d.montant + '</td></tr>';
    }
    body.innerHTML = html;
  }
  wrap.addEventListener("scroll", render);
  render();
  document.documentElement.setAttribute("data-fixture-interactions-ready", "true");
})();
</script>
</body>
</html>
"""

NOT_FOUND_HTML = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>ScriptScrap Fixture - 404</title></head>
<body><h1 id="titre-404">404</h1><p id="note-404">Route inconnue.</p></body>
</html>
"""


def render_main_page(
    cross_origin_url: str, websocket_url: str = "", dead_url: str = ""
) -> str:
    """Return the main page with the per-run URLs substituted in.

    These URLs are the only text in the page that varies between runs; their
    ports are OS-assigned. Everything else is fixed.
    """
    return (
        MAIN_PAGE_HTML
        .replace(CROSS_ORIGIN_PLACEHOLDER, cross_origin_url)
        .replace(WEBSOCKET_PLACEHOLDER, websocket_url)
        .replace(DEAD_URL_PLACEHOLDER, dead_url)
    )
