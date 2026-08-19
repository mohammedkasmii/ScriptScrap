import asyncio
import json
import hashlib
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qsl

from playwright.async_api import async_playwright

OUTPUT_DIR = Path("titan_scraped_output")

# ============================================================
# 1. NETWORK BLOCKLIST (Tracker/Analytics Nullifier)
# ============================================================

TRACKER_DOMAINS = {
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "doubleclick.net", "adtrafficquality.google", "googlesyndication.com",
    "criteo.com", "criteo.net", "openx.net", "crwdcntrl.net", "id5-sync.com",
    "facebook.net", "facebook.com", "segment.io", "hotjar.com", "sentry.io",
    "clarity.ms", "datadoghq.com", "branch.io", "appsflyer.com"
}

STATIC_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".map"
}

# ============================================================
# 2. INJECTED JAVASCRIPT: DEEP DOM & SHADOW ROOT EXTRACTION
# ============================================================

TITAN_DOM_PROBE = """
(() => {
    // 1. Recursive Shadow DOM & DOM walker
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

    // 2. Parse Standard Inputs & Hidden CSRF Tokens
    const parseElement = (el) => {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || "").toLowerCase();
        const base = {
            tag,
            type,
            name: el.name || el.getAttribute("name") || null,
            id: el.id || null,
            placeholder: el.placeholder || el.getAttribute("placeholder") || null,
            required: el.required ?? false,
            disabled: el.disabled ?? false
        };

        if (tag === "select") {
            base.options = Array.from(el.options).map(o => ({
                value: o.value,
                text: (o.text || "").trim(),
                selected: o.selected
            }));
            base.options_count = el.options.length;
        } else if (["checkbox", "radio"].includes(type)) {
            base.value = el.value;
            base.checked = el.checked;
        } else if (el.value !== undefined) {
            base.value = el.value;
        }
        return base;
    };

    // 3. Extract Forms
    const forms = querySelectorAllDeep("form").map((form, idx) => ({
        index: idx,
        id: form.id || null,
        name: form.getAttribute("name") || null,
        action: form.action || window.location.href,
        method: (form.method || "GET").toUpperCase(),
        fields: querySelectorAllDeep("input, select, textarea, button", form).map(parseElement)
    }));

    // 4. Extract Standalone Inputs (loose elements in SPAs)
    const standaloneInputs = querySelectorAllDeep("body input:not(form input), body select:not(form select), body textarea:not(form textarea)")
        .map(parseElement);

    // 5. Extract Modern Custom UI Dropdowns (React-Select, Vue Comboboxes, AntD)
    const customPickers = querySelectorAllDeep('[role="combobox"], [role="listbox"], [class*="select"], [class*="dropdown"]')
        .map((el, idx) => ({
            index: idx,
            tag: el.tagName.toLowerCase(),
            role: el.getAttribute("role"),
            id: el.id || null,
            name: el.getAttribute("name") || null,
            className: el.className || null,
            currentText: (el.innerText || el.textContent || "").trim().slice(0, 150),
            dataset: Object.assign({}, el.dataset)
        }));

    return { forms, standaloneInputs, customPickers };
})();
"""

# ============================================================
# 3. TITAN HARVESTER ENGINE
# ============================================================

class TitanHarvester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.scope_domain = urlparse(target_url).netloc.lower()
        self.endpoints = {}
        self.network_log = []
        self.dom_snapshots = []
        self.value_origins = {}
        self.value_dependencies = []
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    async def route_filter(self, route):
        """Kills third-party tracking, analytics, and static media before network transfer."""
        url = route.request.url.lower()
        parsed = urlparse(url)
        host = parsed.hostname or ""

        # Block analytics & advertising domains
        if any(d in host for d in TRACKER_DOMAINS):
            await route.abort()
            return

        # Block heavy media files to maximize speed
        if any(parsed.path.endswith(ext) for ext in STATIC_EXTENSIONS):
            await route.abort()
            return

        await route.continue_()

    async def handle_request(self, request):
        if request.resource_type in ["xhr", "fetch"]:
            method = request.method.upper()
            url = request.url
            headers = {}
            try:
                headers = await request.all_headers()
            except Exception:
                pass

            post_data = request.post_data
            parsed_json = None
            if post_data and "application/json" in headers.get("content-type", "").lower():
                try:
                    parsed_json = json.loads(post_data)
                except Exception:
                    parsed_json = post_data

            record = {
                "timestamp": datetime.now().isoformat(),
                "method": method,
                "url": url,
                "path": urlparse(url).path or "/",
                "headers": headers,
                "body": parsed_json if parsed_json else post_data
            }

            key = (method, urlparse(url).path)
            if key not in self.endpoints:
                self.endpoints[key] = {
                    "method": method,
                    "url": url,
                    "path": urlparse(url).path,
                    "headers": headers,
                    "sample_payloads": [],
                    "response_statuses": set()
                }

            if parsed_json and len(self.endpoints[key]["sample_payloads"]) < 5:
                self.endpoints[key]["sample_payloads"].append(parsed_json)

            self.network_log.append(record)
            print(f"[API ->] {method:6} {urlparse(url).path}")

            # Check if this request body reuses values discovered in previous responses
            if parsed_json and isinstance(parsed_json, (dict, list)):
                self._correlate_dependencies(parsed_json, method, urlparse(url).path)

    async def handle_response(self, response):
        request = response.request
        if request.resource_type in ["xhr", "fetch"]:
            key = (request.method.upper(), urlparse(request.url).path)
            if key in self.endpoints:
                self.endpoints[key]["response_statuses"].add(response.status)

            # Extract response payload for dependency chaining
            headers = {}
            try:
                headers = await response.all_headers()
            except Exception:
                pass

            if "application/json" in headers.get("content-type", "").lower():
                try:
                    data = await response.json()
                    self._map_response_tokens(data, request.method.upper(), urlparse(request.url).path)
                except Exception:
                    pass

    def _map_response_tokens(self, data, method, path, prefix=""):
        """Indexes leaf string/number tokens from API responses for dependency mapping."""
        if isinstance(data, dict):
            for k, v in data.items():
                self._map_response_tokens(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]):
                self._map_response_tokens(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            val_str = str(data)
            if 3 <= len(val_str) <= 120:
                h = hashlib.sha1(val_str.encode("utf-8", errors="ignore")).hexdigest()
                self.value_origins[h] = {
                    "origin_endpoint": f"{method} {path}",
                    "field_path": prefix
                }

    def _correlate_dependencies(self, data, method, path, prefix=""):
        """Checks whether the current request body uses values discovered in earlier responses."""
        if isinstance(data, dict):
            for k, v in data.items():
                self._correlate_dependencies(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]):
                self._correlate_dependencies(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            val_str = str(data)
            h = hashlib.sha1(val_str.encode("utf-8", errors="ignore")).hexdigest()
            origin = self.value_origins.get(h)
            if origin and len(self.value_dependencies) < 100:
                link = {
                    "source": origin,
                    "consumer": {
                        "endpoint": f"{method} {path}",
                        "field_path": prefix
                    }
                }
                if link not in self.value_dependencies:
                    self.value_dependencies.append(link)
                    print(f"  [CHAIN DETECTED] {origin['origin_endpoint']} ({origin['field_path']}) -> {method} {path} ({prefix})")

    async def scan_all_frames(self, page):
        """Extracts deep DOM state across the top frame and all embedded iframes."""
        print("[*] Running Deep DOM & Shadow Root Sweep across all frames...")
        frame_results = []
        total_forms = 0
        total_pickers = 0

        for idx, frame in enumerate(page.frames):
            try:
                dom_data = await frame.evaluate(TITAN_DOM_PROBE)
                total_forms += len(dom_data["forms"])
                total_pickers += len(dom_data["customPickers"])
                frame_results.append({
                    "frame_index": idx,
                    "frame_url": frame.url,
                    "data": dom_data
                })
            except Exception:
                pass

        try:
            storage = await page.evaluate("""() => ({
                localStorage: Object.assign({}, window.localStorage),
                sessionStorage: Object.assign({}, window.sessionStorage),
                cookies: document.cookie
            })""")
        except Exception:
            storage = {}

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "page_url": page.url,
            "frames": frame_results,
            "storage": storage
        }
        self.dom_snapshots.append(snapshot)
        print(f"[+] Harvested {total_forms} forms and {total_pickers} custom UI comboboxes across {len(page.frames)} frames.")

    def generate_httpx_code(self) -> str:
        """Generates clean, executable Python httpx code for all mapped endpoints."""
        code_blocks = [
            "import httpx",
            "import asyncio",
            "import json",
            "",
            "BASE_HEADERS = {",
            '    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",',
            '    "accept": "application/json, text/plain, */*",',
            "}",
            ""
        ]

        for idx, ((method, path), meta) in enumerate(self.endpoints.items()):
            fn_name = re.sub(r"[^a-zA-Z0-9_]+", "_", f"{method.lower()}_{path.strip('/')}") or f"root_{idx}"
            clean_headers = {
                k: v for k, v in meta["headers"].items()
                if not k.startswith(":") and k.lower() not in ["content-length", "host"]
            }

            sample_body = meta["sample_payloads"][0] if meta["sample_payloads"] else None
            body_arg = f"json.loads('''{json.dumps(sample_body)}''')" if sample_body else "None"

            fn_code = f"""
async def {fn_name}(payload: dict = None, custom_headers: dict = None):
    url = "{meta['url']}"
    headers = {{**BASE_HEADERS, **{json.dumps(clean_headers, indent=8)}}}
    if custom_headers:
        headers.update(custom_headers)
        
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.{method.lower()}(
            url,
            headers=headers,
            json=payload if payload is not None else {body_arg}
        )
        try:
            return response.json()
        except Exception:
            return response.text
"""
            code_blocks.append(fn_code.strip())
            code_blocks.append("")

        return "\n".join(code_blocks)

    def write_reports(self):
        """Writes JSON datasets, dependency graphs, generated code, and Markdown documentation."""
        (OUTPUT_DIR / "network_traffic.json").write_text(
            json.dumps(self.network_log, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (OUTPUT_DIR / "dom_structure.json").write_text(
            json.dumps(self.dom_snapshots, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (OUTPUT_DIR / "field_dependencies.json").write_text(
            json.dumps(self.value_dependencies, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        endpoints_serializable = {
            f"{m} {p}": {
                "url": meta["url"],
                "response_statuses": sorted(meta["response_statuses"]),
                "sample_payloads": meta["sample_payloads"]
            }
            for (m, p), meta in self.endpoints.items()
        }
        (OUTPUT_DIR / "endpoints_map.json").write_text(
            json.dumps(endpoints_serializable, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Write generated Python client
        (OUTPUT_DIR / "generated_api_client.py").write_text(self.generate_httpx_code(), encoding="utf-8")

        # Generate Master Markdown Report with Mermaid Dependency Graph
        md = [
            "# Titan Engine Investigation Report",
            f"**Target URL:** `{self.target_url}`  ",
            f"**Generated:** `{datetime.now().isoformat()}`  ",
            "",
            "## Discovered Business Endpoints",
            ""
        ]

        for (method, path), meta in self.endpoints.items():
            statuses = ", ".join(str(s) for s in sorted(meta["response_statuses"])) or "None"
            md.append(f"### `{method}` `{path}`")
            md.append(f"- **Full URL:** `{meta['url']}`")
            md.append(f"- **Observed HTTP Statuses:** `{statuses}`")
            if meta["sample_payloads"]:
                md.append("- **Sample Request Schema:**")
                md.append("```json")
                md.append(json.dumps(meta["sample_payloads"][0], indent=2))
                md.append("```")
            md.append("")

        if self.value_dependencies:
            md.append("## Field Dependency Flow (Data Chains)")
            md.append("```mermaid")
            md.append("graph TD")
            for idx, link in enumerate(self.value_dependencies):
                src = f"{link['source']['origin_endpoint']}\\n({link['source']['field_path']})"
                dst = f"{link['consumer']['endpoint']}\\n({link['consumer']['field_path']})"
                md.append(f'    Node{idx}A["{src}"] --> Node{idx}B["{dst}"]')
            md.append("```")
            md.append("")

        (OUTPUT_DIR / "INVESTIGATION_REPORT.md").write_text("\n".join(md), encoding="utf-8")
        print(f"\n[+] Output files generated in ./{OUTPUT_DIR.name}/")

# ============================================================
# 4. RUNNER & INTERACTION PROBE
# ============================================================

async def main():
    print("=" * 65)
    print("             TITAN INVESTIGATOR & HARVESTER (V11)            ")
    print("=" * 65)

    target_url = input("Enter Target Portal URL: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    engine = TitanHarvester(target_url)

    async with async_playwright() as p:
        # Launch Chromium with anti-bot automation flags disabled
        browser = await p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox"
            ]
        )
        context = await browser.new_context(
            viewport={"width": 1366, "height": 768},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )

        page = await context.new_page()

        # Wire socket-level ad-blocking & API capture
        await page.route("**/*", engine.route_filter)
        page.on("request", engine.handle_request)
        page.on("response", engine.handle_response)

        print(f"[*] Navigating to {target_url}...")
        await page.goto(target_url, wait_until="domcontentloaded")
        await page.wait_for_timeout(2000)

        # Initial baseline capture
        await engine.scan_all_frames(page)

        print("\n" + "=" * 65)
        print("TITAN READY — Perform operations in the browser.")
        print("  [s]  Run deep DOM & iframe sweep (do this on each new step)")
        print("  [q]  Finish session and generate reports & Python httpx client")
        print("=" * 65 + "\n")

        while True:
            cmd = await asyncio.to_thread(input, "Command (s=sweep, q=quit): ")
            cmd_clean = cmd.strip().lower()
            if cmd_clean == "q":
                break
            elif cmd_clean == "s":
                await engine.scan_all_frames(page)

        engine.write_reports()
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())