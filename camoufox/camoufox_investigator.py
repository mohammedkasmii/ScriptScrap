import asyncio
import json
import hashlib
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox

OUTPUT_DIR = Path("v12_camoufox_output")

# Third-party chat and error logging noise to ignore in the final code export
NOISY_ENDPOINTS = {
    "iadvize.com", "usejimo.com", "iconify.design", "privacy-center.org",
    "error-js", "utilisation-log", "events/log"
}

# Only block heavy media to avoid tripping anti-bot JS integrity checks.
STATIC_MEDIA_EXTENSIONS = {
    ".mp3", ".mp4", ".wav", ".avi", ".mov"
}

# ============================================================
# DEEP DOM PROBE (Forms, Iframes, Custom Comboboxes)
# ============================================================
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

    const standaloneInputs = querySelectorAllDeep("body input:not(form input), body select:not(form select)")
        .map(parseElement);

    const customPickers = querySelectorAllDeep('[role="combobox"], [role="listbox"], [class*="select"]')
        .map(el => ({
            tag: el.tagName.toLowerCase(),
            role: el.getAttribute("role"),
            id: el.id || null,
            name: el.getAttribute("name") || null,
            currentText: (el.innerText || el.textContent || "").trim().slice(0, 100)
        }));

    return { forms, standaloneInputs, customPickers };
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
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # Visual Snapshot Storage
        self.visual_dir = OUTPUT_DIR / "visual_traces"
        self.visual_dir.mkdir(parents=True, exist_ok=True)
        self.step_counter = 1

    async def route_filter(self, route):
        """Only blocks heavy media to avoid tripping anti-bot JS integrity checks."""
        url = route.request.url.lower()
        parsed = urlparse(url)
        
        if any(parsed.path.endswith(ext) for ext in STATIC_MEDIA_EXTENSIONS):
            await route.abort()
            return
            
        await route.continue_()

    async def capture_visual_state(self, page):
        """Captures full-page screenshots and raw HTML files for offline visual recreation."""
        timestamp = datetime.now().strftime("%H%M%S")
        file_prefix = self.visual_dir / f"step_{self.step_counter:03d}_{timestamp}"
        
        try:
            await page.screenshot(path=f"{file_prefix}.png", full_page=True)
            html_content = await page.content()
            Path(f"{file_prefix}.html").write_text(html_content, encoding="utf-8")
            print(f"📸 [VISUAL TRACE] Saved Screenshot & HTML -> Step {self.step_counter:03d}")
            self.step_counter += 1
        except Exception:
            pass

    async def handle_request(self, request):
        if request.resource_type in ["xhr", "fetch"] and request.method != "OPTIONS":
            url = request.url
            method = request.method.upper()
            
            if any(noise in url for noise in NOISY_ENDPOINTS):
                return

            headers = await request.all_headers()
            post_data = request.post_data
            parsed_json = None
            
            if post_data and "application/json" in headers.get("content-type", "").lower():
                try: 
                    parsed_json = json.loads(post_data)
                except Exception: 
                    parsed_json = post_data

            url_path = urlparse(url).path or "/"
            key = (method, url_path)
            
            if key not in self.endpoints:
                self.endpoints[key] = {
                    "method": method, 
                    "url": url,
                    "headers": headers, 
                    "sample_payloads": [], 
                    "statuses": set()
                }

            if parsed_json and len(self.endpoints[key]["sample_payloads"]) < 2:
                self.endpoints[key]["sample_payloads"].append(parsed_json)

            self.network_log.append({
                "time": datetime.now().isoformat(), 
                "method": method,
                "url": url, 
                "body": parsed_json or post_data
            })
            
            print(f"[API ->] {method:6} {url_path}")
            
            if isinstance(parsed_json, (dict, list)):
                self._correlate_dependencies(parsed_json, method, url_path)

    async def handle_response(self, response):
        req = response.request
        if req.resource_type in ["xhr", "fetch"] and req.method != "OPTIONS":
            url_path = urlparse(req.url).path or "/"
            key = (req.method.upper(), url_path)
            if key in self.endpoints:
                self.endpoints[key]["statuses"].add(response.status)

            headers = await response.all_headers()
            if "application/json" in headers.get("content-type", "").lower():
                try:
                    data = await response.json()
                    self._map_response_tokens(data, req.method.upper(), url_path)
                except Exception:
                    pass

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
                    print(f"  [CHAIN LINK] {origin['origin_endpoint']} ({origin['field']}) -> {method} {path} ({prefix})")

    async def scan_all_frames(self, page):
        results = []
        for idx, frame in enumerate(page.frames):
            try:
                dom = await frame.evaluate(DOM_PROBE_JS)
                results.append({"frame_url": frame.url, "data": dom})
            except Exception: 
                pass
            
        self.dom_snapshots.append({"time": datetime.now().isoformat(), "frames": results})

    def generate_httpx_code(self) -> str:
        code_blocks = [
            "import httpx",
            "import asyncio",
            "import json\n",
            "# Auto-generated clean microservice API client\n"
        ]
        for idx, ((method, path), meta) in enumerate(self.endpoints.items()):
            fn_name = re.sub(r"[^a-zA-Z0-9_]+", "_", f"{method.lower()}_{path.strip('/')}") or f"req_{idx}"
            clean_headers = {
                k: v for k, v in meta["headers"].items() 
                if not k.startswith(":") and k.lower() not in ["content-length", "host"]
            }
            
            sample_body = meta["sample_payloads"][0] if meta["sample_payloads"] else None
            body_arg = f"json.loads('''{json.dumps(sample_body)}''')" if sample_body else "None"

            fn = f"""
async def {fn_name}(payload: dict = None, custom_headers: dict = None):
    url = "{meta['url']}"
    headers = {json.dumps(clean_headers, indent=4)}
    if custom_headers:
        headers.update(custom_headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        res = await client.{method.lower()}(
            url, 
            headers=headers, 
            json=payload if payload is not None else {body_arg}
        )
        try:
            return res.json()
        except Exception:
            return res.text
"""
            code_blocks.append(fn.strip() + "\n")
        return "\n".join(code_blocks)

    def export(self):
        (OUTPUT_DIR / "network_traffic.json").write_text(json.dumps(self.network_log, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "dom_structure.json").write_text(json.dumps(self.dom_snapshots, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "api_dependencies.json").write_text(json.dumps(self.value_dependencies, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "generated_client.py").write_text(self.generate_httpx_code(), encoding="utf-8")
        
        md = [
            "# Investigation Report",
            f"**Target:** `{self.target_url}`",
            f"**Generated:** `{datetime.now().isoformat()}`\n",
            "## Discovered Business APIs\n"
        ]
        for (m, p), meta in self.endpoints.items():
            statuses = ", ".join(str(s) for s in sorted(meta["statuses"])) or "None"
            md.append(f"### `{m}` `{p}`")
            md.append(f"- **URL:** `{meta['url']}`")
            md.append(f"- **Statuses:** `{statuses}`")
            if meta["sample_payloads"]:
                md.append("```json")
                md.append(json.dumps(meta["sample_payloads"][0], indent=2))
                md.append("```")
            md.append("")

        (OUTPUT_DIR / "INVESTIGATION_REPORT.md").write_text("\n".join(md), encoding="utf-8")
        print(f"\n🏆 All 5 data files & visual traces exported to ./{OUTPUT_DIR.name}/")

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

    print("\n🦊 [CAMOUFOX] Booting engine-level anti-detect browser...")
    
    try:
        async with AsyncCamoufox(
            headless=False,
            humanize=True,
            os="windows",
            geoip=False,
            enable_cache=True
        ) as browser:
            
            page = await browser.new_page(
                locale="fr-FR",
                timezone_id="Europe/Paris"
            )
            
            await page.route("**/*", engine.route_filter)
            page.on("request", engine.handle_request)
            page.on("response", engine.handle_response)

            print(f"🚀 Infiltrating {target_url}...")
            await page.goto(target_url, wait_until="load")
            await page.wait_for_timeout(2000)

            scanner_task = asyncio.create_task(background_dom_scanner(page, engine))

            print("\n" + "=" * 60)
            print("🟢 AUTOMATIC SPY IS ACTIVE")
            print("1. Interact with the website normally.")
            print("2. The script captures DOM, Visuals & APIs automatically.")
            print("3. Press ENTER in this terminal ONLY when you are done.")
            print("=" * 60 + "\n")

            await asyncio.to_thread(input, "")
            scanner_task.cancel()
            
    except Exception as e:
        print(f"\n⚠️ Session interrupted: {e}")
    finally:
        engine.export()

if __name__ == "__main__":
    asyncio.run(main())