import asyncio
import json
import hashlib
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox

OUTPUT_DIR = Path("v13_investigation_output")

NOISY_ENDPOINTS = {
    "iadvize.com", "usejimo.com", "iconify.design", "privacy-center.org",
    "error-js", "utilisation-log", "events/log", "dynatrace", "google-analytics"
}

STATIC_MEDIA_EXTENSIONS = {
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".woff", ".ttf", ".css", ".png", ".jpg"
}

# ============================================================
# ACTIVE INTROSPECTION INJECTIONS
# ============================================================
HOOK_AND_OBSERVER_JS = """
(() => {
    window.functionHookLogs = [];
    window.domMutations = [];

    // 1. Time-Travel DOM Mutation Observer
    window.addEventListener('DOMContentLoaded', () => {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((m) => {
                if (m.target && (m.target.id || m.target.className)) {
                    window.domMutations.push({
                        time: Date.now(),
                        type: m.type,
                        targetId: m.target.id || m.target.className || m.target.tagName,
                        addedNodes: m.addedNodes ? m.addedNodes.length : 0
                    });
                }
            });
        });
        observer.observe(document.body, { childList: true, subtree: true, attributes: true });
    });

    // 2. Monkey Patching MCMA Legacy Math Formulas
    function hookMCMAFunction(funcName) {
        if (typeof window[funcName] === 'function' && !window[funcName].isHooked) {
            const original = window[funcName];
            window[funcName] = function(...args) {
                const result = original.apply(this, args);
                window.functionHookLogs.push({
                    function: funcName,
                    arguments: args,
                    returned: result,
                    timestamp: Date.now()
                });
                return result;
            };
            window[funcName].isHooked = true;
        }
    }

    // Interval to hook functions even if loaded later via AJAX
    setInterval(() => {
        ['DevisCalculerMontantCharge', 'CalculerMntArrete', 'CalculerMontantVetuste', 'ValiderDevis', 'CalculerMontantDommage'].forEach(hookMCMAFunction);
    }, 2000);
})();
"""

DOM_PROBE_JS = """
(() => {
    function querySelectorAllDeep(selector, root = document) {
        let results = Array.from(root.querySelectorAll(selector));
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (node.shadowRoot) {
                results = results.concat(querySelectorAllDeep(selector, node.shadowRoot));
            }
        }
        return results;
    }

    const parseElement = (el) => {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || "").toLowerCase();
        const base = {
            tag, type,
            name: el.name || el.getAttribute("name") || null,
            id: el.id || null,
            placeholder: el.placeholder || el.getAttribute("placeholder") || null,
        };

        if (tag === "select") {
            base.options = Array.from(el.options).map(o => ({
                value: o.value, text: (o.text || "").trim()
            }));
        } else if (["checkbox", "radio"].includes(type)) {
            base.value = el.value;
            base.checked = el.checked;
        } else if (el.value !== undefined) {
            base.value = el.value;
        }
        return base;
    };

    const forms = querySelectorAllDeep("form").map((form, idx) => ({
        index: idx,
        id: form.id || null,
        action: form.action || window.location.href,
        method: (form.method || "GET").toUpperCase(),
        fields: querySelectorAllDeep("input, select, textarea, button", form).map(parseElement)
    }));

    return { forms };
})();
"""

class WebHarvester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.endpoints = {}
        self.network_log = []
        self.dom_snapshots = []
        self.value_origins = {}
        self.value_dependencies = []
        self.openapi_paths = {}
        
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.visual_dir = OUTPUT_DIR / "visual_traces"
        self.visual_dir.mkdir(parents=True, exist_ok=True)
        self.step_counter = 1

    async def route_filter(self, route):
        url = route.request.url.lower()
        parsed = urlparse(url)
        if any(parsed.path.endswith(ext) for ext in STATIC_MEDIA_EXTENSIONS):
            await route.abort()
            return
        await route.continue_()

    async def capture_visual_state(self, page):
        """Captures full-page screenshots and fully-styled offline HTML."""
        timestamp = datetime.now().strftime("%H%M%S")
        file_prefix = self.visual_dir / f"step_{self.step_counter:03d}_{timestamp}"
        
        try:
            # 1. Take the visual screenshot
            await page.screenshot(path=f"{file_prefix}.png", full_page=True)
            
            # 2. Inject JS to embed CSS stylesheets and preserve typed input values
            html_content = await page.evaluate("""async () => {
                // Fetch and inline all external stylesheets
                const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
                for (let link of links) {
                    try {
                        const res = await fetch(link.href);
                        let css = await res.text();
                        
                        // Fix relative paths inside the CSS (like background images or fonts)
                        const baseUrl = new URL(link.href);
                        css = css.replace(/url\\((?!['"]?(?:data:|https:|http:))['"]?([^'"\\)]*)['"]?\\)/gi, (match, urlPath) => {
                            return `url('${new URL(urlPath, baseUrl).href}')`;
                        });
                        
                        const style = document.createElement('style');
                        style.textContent = css;
                        link.replaceWith(style);
                    } catch (e) {}
                }
                
                // Ensure typed text and checkboxes are hardcoded into the HTML attributes
                document.querySelectorAll('input, textarea').forEach(el => {
                    if (el.tagName === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio')) {
                        if (el.checked) el.setAttribute('checked', 'checked');
                        else el.removeAttribute('checked');
                    } else {
                        el.setAttribute('value', el.value);
                    }
                });
                
                return document.documentElement.outerHTML;
            }""")
            
            # 3. Inject a <base> tag so relative <img> tags load from the live server offline
            base_tag = f'<base href="{page.url}">'
            if "<head>" in html_content:
                html_content = html_content.replace("<head>", f"<head>\n    {base_tag}", 1)
            else:
                html_content = f"{base_tag}\n{html_content}"

            Path(f"{file_prefix}.html").write_text(html_content, encoding="utf-8")
            self.step_counter += 1
            
        except Exception as e:
            pass # Suppress transient errors if page navigates while saving

    async def handle_request(self, request):
        if request.resource_type in ["xhr", "fetch", "document"] and request.method != "OPTIONS":
            url = request.url
            method = request.method.upper()
            
            if any(noise in url for noise in NOISY_ENDPOINTS):
                return

            headers = await request.all_headers()
            post_data = request.post_data
            parsed_json = None
            
            if post_data:
                try: 
                    parsed_json = json.loads(post_data)
                except Exception: 
                    pass

            url_path = urlparse(url).path or "/"
            key = (method, url_path)
            
            if key not in self.endpoints:
                self.endpoints[key] = {
                    "method": method, 
                    "url": url,
                    "headers": headers, 
                    "sample_payloads": [], 
                    "statuses": set(),
                    "response_samples": []
                }

            if parsed_json and len(self.endpoints[key]["sample_payloads"]) < 2:
                self.endpoints[key]["sample_payloads"].append(parsed_json)
            elif post_data and not parsed_json and len(self.endpoints[key]["sample_payloads"]) < 2:
                self.endpoints[key]["sample_payloads"].append(post_data) # Capture raw forms/multipart

            self.network_log.append({
                "time": datetime.now().isoformat(), 
                "method": method,
                "url": url, 
                "headers": headers,
                "body": parsed_json or post_data
            })
            
            print(f"[API ->] {method:6} {url_path}")
            
            if isinstance(parsed_json, (dict, list)):
                self._correlate_dependencies(parsed_json, method, url_path)

            self._build_openapi_request(method, url_path, parsed_json or post_data)

    async def handle_response(self, response):
        req = response.request
        if req.resource_type in ["xhr", "fetch", "document"] and req.method != "OPTIONS":
            url_path = urlparse(req.url).path or "/"
            key = (req.method.upper(), url_path)
            
            if key in self.endpoints:
                self.endpoints[key]["statuses"].add(response.status)

            try:
                resp_text = await response.text()
                try:
                    data = json.loads(resp_text)
                    self._map_response_tokens(data, req.method.upper(), url_path)
                    
                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 2:
                        self.endpoints[key]["response_samples"].append(data)
                except json.JSONDecodeError:
                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 1:
                        self.endpoints[key]["response_samples"].append(resp_text[:500] + "...")
                        
                self._build_openapi_response(req.method.upper(), url_path, response.status, data if 'data' in locals() else resp_text[:500])
            except Exception:
                pass

    # ==========================================
    # DATA CORRELATION & OPENAPI
    # ==========================================
    def _map_response_tokens(self, data, method, path, prefix=""):
        if isinstance(data, dict):
            for k, v in data.items(): 
                self._map_response_tokens(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]): 
                self._map_response_tokens(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            val = str(data)
            if 3 <= len(val) <= 120:
                h = hashlib.sha1(val.encode("utf-8", errors="ignore")).hexdigest()
                self.value_origins[h] = {"origin_endpoint": f"{method} {path}", "field": prefix}

    def _correlate_dependencies(self, data, method, path, prefix=""):
        if isinstance(data, dict):
            for k, v in data.items(): 
                self._correlate_dependencies(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]): 
                self._correlate_dependencies(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            h = hashlib.sha1(str(data).encode("utf-8", errors="ignore")).hexdigest()
            origin = self.value_origins.get(h)
            if origin:
                link = {"source": origin, "consumer": {"endpoint": f"{method} {path}", "field": prefix}}
                if link not in self.value_dependencies:
                    self.value_dependencies.append(link)

    def _build_openapi_request(self, method, path, payload):
        if path not in self.openapi_paths:
            self.openapi_paths[path] = {}
        
        m_lower = method.lower()
        if m_lower not in self.openapi_paths[path]:
            self.openapi_paths[path][m_lower] = {
                "summary": f"Auto-captured {path}",
                "responses": {}
            }
            
        if payload:
            content_type = "application/json" if isinstance(payload, (dict, list)) else "application/x-www-form-urlencoded"
            self.openapi_paths[path][m_lower]["requestBody"] = {
                "content": {
                    content_type: {
                        "schema": {"type": "object"},
                        "example": payload
                    }
                }
            }

    def _build_openapi_response(self, method, path, status, payload):
        m_lower = method.lower()
        if path in self.openapi_paths and m_lower in self.openapi_paths[path]:
            content_type = "application/json" if isinstance(payload, (dict, list)) else "text/html"
            self.openapi_paths[path][m_lower]["responses"][str(status)] = {
                "description": "Auto-captured response",
                "content": {
                    content_type: {
                        "example": payload
                    }
                }
            }

    # ==========================================
    # FINAL EXPORT ENGINES
    # ==========================================
    async def scan_all_frames(self, page):
        results = []
        for frame in page.frames:
            try:
                dom = await frame.evaluate(DOM_PROBE_JS)
                results.append({"frame_url": frame.url, "data": dom})
            except Exception: 
                pass
        self.dom_snapshots.append({"time": datetime.now().isoformat(), "frames": results})

    async def extract_active_introspection(self, page):
        """Pulls Hooks, Dropdowns, and jQuery events before closing."""
        print("\n[*] Dumping Dropdown Catalogs & jQuery Events...")
        
        self.catalogs = await page.evaluate("""() => {
            let dict = {};
            document.querySelectorAll('select').forEach(sel => {
                let options = [];
                sel.querySelectorAll('option').forEach(opt => {
                    options.push({id: opt.value, label: opt.innerText.trim()});
                });
                if(sel.id || sel.name) dict[sel.id || sel.name] = options;
            });
            return dict;
        }""")

        self.jquery_events = await page.evaluate("""() => {
            let eventsMap = {};
            if (window.jQuery) {
                window.jQuery('*').each(function() {
                    let ev_data = window.jQuery._data(this, 'events');
                    if (ev_data) {
                        let id = this.id ? '#' + this.id : (this.className ? '.' + this.className : this.tagName);
                        eventsMap[id] = Object.keys(ev_data);
                    }
                });
            }
            return eventsMap;
        }""")

        self.js_hooks = await page.evaluate("window.functionHookLogs || []")
        self.mutations = await page.evaluate("window.domMutations || []")

    def generate_httpx_code(self) -> str:
        code_blocks = [
            "import httpx", "import asyncio", "import json\n",
            "# Auto-generated clean microservice API client\n"
        ]
        for idx, ((method, path), meta) in enumerate(self.endpoints.items()):
            fn_name = re.sub(r"[^a-zA-Z0-9_]+", "_", f"{method.lower()}_{path.strip('/')}") or f"req_{idx}"
            clean_headers = {k: v for k, v in meta["headers"].items() if not k.startswith(":") and k.lower() not in ["content-length", "host"]}
            sample_body = meta["sample_payloads"][0] if meta["sample_payloads"] else None
            body_arg = f"json.loads('''{json.dumps(sample_body)}''')" if isinstance(sample_body, dict) else "None"

            fn = f"""
async def {fn_name}(payload: dict = None, custom_headers: dict = None):
    url = "{meta['url']}"
    headers = {json.dumps(clean_headers, indent=4)}
    if custom_headers: headers.update(custom_headers)
    async with httpx.AsyncClient(verify=False) as client:
        res = await client.{method.lower()}(url, headers=headers, json=payload if payload is not None else {body_arg})
        return res.json() if "application/json" in res.headers.get("content-type", "") else res.text
"""
            code_blocks.append(fn.strip() + "\n")
        return "\n".join(code_blocks)

    def export(self):
        (OUTPUT_DIR / "network_traffic.json").write_text(json.dumps(self.network_log, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "dom_structure.json").write_text(json.dumps(self.dom_snapshots, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "api_dependencies.json").write_text(json.dumps(self.value_dependencies, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "generated_client.py").write_text(self.generate_httpx_code(), encoding="utf-8")
        
        # New Introspection Dumps
        (OUTPUT_DIR / "dropdown_catalogs.json").write_text(json.dumps(getattr(self, 'catalogs', {}), indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "jquery_events.json").write_text(json.dumps(getattr(self, 'jquery_events', {}), indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "js_hooks_and_mutations.json").write_text(json.dumps({"function_calls": getattr(self, 'js_hooks', []), "dom_mutations": getattr(self, 'mutations', [])}, indent=2), encoding="utf-8")

        # OpenAPI Spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "MCMA Auto-Synthesized API", "version": "1.0"},
            "paths": self.openapi_paths
        }
        (OUTPUT_DIR / "mcma_openapi_spec.json").write_text(json.dumps(openapi_spec, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"\n🏆 All 8 data files & visual traces exported to ./{OUTPUT_DIR.name}/")

async def background_dom_scanner(page, engine):
    last_hash = ""
    await engine.capture_visual_state(page)
    while True:
        await asyncio.sleep(2.0)
        try:
            content = await page.content()
            curr_hash = hashlib.md5(content.encode("utf-8")).hexdigest()
            if curr_hash != last_hash:
                last_hash = curr_hash
                await engine.scan_all_frames(page)
                await engine.capture_visual_state(page)
        except Exception:
            pass

async def main():
    target_url = input("Enter Target Portal URL: ").strip()
    if not target_url.startswith("http"): target_url = "https://" + target_url

    engine = WebHarvester(target_url)

    print("\n🦊 [CAMOUFOX] Booting active introspection engine...")
    try:
        async with AsyncCamoufox(headless=False, humanize=True, os="windows", geoip=False, enable_cache=True) as browser:
            page = await browser.new_page(locale="fr-FR", timezone_id="Europe/Paris")
            
            # Add early Hooks and Observers
            await page.add_init_script(HOOK_AND_OBSERVER_JS)
            
            await page.route("**/*", engine.route_filter)
            page.on("request", engine.handle_request)
            page.on("response", engine.handle_response)

            print(f"🚀 Infiltrating {target_url}...")
            await page.goto(target_url, wait_until="load")

            scanner_task = asyncio.create_task(background_dom_scanner(page, engine))

            print("\n" + "=" * 60)
            print("🟢 AUTOMATIC SPY IS ACTIVE")
            print("1. Interact with the website normally (process a Garage Conventionné dossier).")
            print("2. The script captures full bodies, OpenAPI specs, and JS functions automatically.")
            print("3. Press ENTER in this terminal ONLY when you are done.")
            print("=" * 60 + "\n")

            await asyncio.to_thread(input, "")
            scanner_task.cancel()
            
            # Final dump of hidden in-memory state
            await engine.extract_active_introspection(page)
            
    except Exception as e:
        print(f"\n⚠️ Session interrupted: {e}")
    finally:
        engine.export()

if __name__ == "__main__":
    asyncio.run(main())