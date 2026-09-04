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

# --------------------------------------------------------------------------- #
# Fixed identifiers. These are deliberately credential-shaped but entirely
# fake; they exist so redaction / credential-classification code paths have
# something to bite on.
# --------------------------------------------------------------------------- #
FIXTURE_VERSION_HEADER = "X-Fixture-Version"
FIXTURE_VERSION_VALUE = "1"
FIXTURE_SESSION_COOKIE = "fixture_session=FIXTURE-SESSION-0001; Path=/"
FIXTURE_CSRF_TOKEN = "FIXTURE-CSRF-TOKEN-0001"
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

    attacherShadow();
    enregistrerHandlersJQuery();
    peuplerGarages();
    window.__fixtureReady = true;
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

  <input type="hidden" id="csrf" name="__RequestVerificationToken" value="FIXTURE-CSRF-TOKEN-0001">
  <input type="hidden" id="mission" name="missionId" value="">

  <label for="champ-desactive">Desactive</label>
  <input type="text" id="champ-desactive" name="desactive" value="valeur-fixe" disabled>

  <label for="champ-lecture">Lecture</label>
  <input type="text" id="champ-lecture" name="lecture" value="lecture-seule" readonly>

  <label for="pw">Mot de passe</label>
  <input type="password" id="pw" name="pw" value="">

  <button type="submit" id="btn-submit">Envoyer</button>
</form>

<div id="actions">
  <button type="button" id="btn-charger">Charger</button>
  <button type="button" id="btn-valider">Valider</button>
  <button type="button" id="btn-form">Formulaire</button>
  <button type="button" id="btn-redirect">Redirection</button>
  <button type="button" id="btn-erreur">Erreur</button>
  <button type="button" id="btn-ajouter">Ajouter</button>
  <button type="button" id="btn-calculer">Calculer</button>
</div>

<div id="resultat"></div>
<p>Montant: <span id="montant"></span></p>

<div id="shadow-host"></div>
<div id="mutation-target"></div>

<iframe id="frame-outer" src="/frame/outer" width="420" height="220" title="frame externe"></iframe>

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

NOT_FOUND_HTML = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>ScriptScrap Fixture - 404</title></head>
<body><h1 id="titre-404">404</h1><p id="note-404">Route inconnue.</p></body>
</html>
"""


def render_main_page(cross_origin_url: str) -> str:
    """Return the main page with the cross-origin base URL substituted in."""
    return MAIN_PAGE_HTML.replace(CROSS_ORIGIN_PLACEHOLDER, cross_origin_url)
