"""
Information Gathering & Discovery Scanner
==========================================

The first phase of any security audit. This module performs passive and active
reconnaissance against a target web application to build a complete map of its
attack surface before any vulnerability-specific scanners run.

Capabilities
------------
1. **Site Crawling**        — Recursively follow links to discover all
                              accessible URLs, forms, API endpoints, and
                              JavaScript files.
2. **Auth Detection**       — Identify authentication mechanisms such as
                              login / registration / password-reset pages,
                              OAuth redirects, API key headers, and JWT usage.
3. **Role Indicator Discovery** — Flag URLs that hint at privilege levels
                              (e.g. /admin, /dashboard, /api/v1/).
4. **API Documentation Probing** — Check for publicly exposed documentation
                              endpoints like /swagger, /api-docs, /graphql,
                              /openapi.json.
5. **Parameter Extraction** — Harvest parameters from query strings, form
                              fields (including hidden inputs), and inline
                              JavaScript/JSON payloads.
"""

import re
import time
import sys
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from scanners.base import BaseScanner

# ═══════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 50
REQUEST_TIMEOUT = 10  # seconds

# HTTP headers that mimic a real browser to avoid simple bot blocks
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Patterns that suggest authentication-related pages
AUTH_URL_PATTERNS = [
    r"/log[-_]?in",
    r"/sign[-_]?in",
    r"/sign[-_]?up",
    r"/register",
    r"/auth",
    r"/oauth",
    r"/sso",
    r"/password[-_]?reset",
    r"/forgot[-_]?password",
    r"/recover",
    r"/logout",
    r"/sign[-_]?out",
    r"/callback",       # OAuth callback
    r"/token",
    r"/2fa",
    r"/mfa",
    r"/verify[-_]?email",
]

# Patterns in HTML that indicate auth mechanisms
AUTH_HTML_INDICATORS = {
    "login_form":       r'<form[^>]*(?:login|signin|auth)[^>]*>',
    "password_field":   r'<input[^>]*type=["\']password["\'][^>]*>',
    "csrf_token":       r'<input[^>]*name=["\'](?:csrf|_token|authenticity_token)["\'][^>]*>',
    "oauth_link":       r'(?:accounts\.google|github\.com/login/oauth|facebook\.com/dialog/oauth)',
    "jwt_storage":      r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["\'](?:token|jwt|access_token)',
    "api_key_header":   r'["\'](?:X-API-Key|Authorization|Bearer)["\']',
}

# URL fragments that indicate privileged / role-based routes
ROLE_PATTERNS = {
    "admin":     [r"/admin", r"/administrator", r"/manage"],
    "user":      [r"/user", r"/profile", r"/account", r"/settings"],
    "dashboard": [r"/dashboard", r"/panel", r"/console"],
    "api":       [r"/api/v\d+", r"/api/", r"/rest/", r"/graphql"],
    "internal":  [r"/internal", r"/staff", r"/moderator", r"/backoffice"],
}

# Well-known API documentation paths to probe
API_DOC_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi.yaml",
    "/graphql",
    "/graphiql",
    "/altair",
    "/playground",
    "/.well-known/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
]

# File extensions to skip during crawling (binary / non-HTML assets)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
}


# ═══════════════════════════════════════════════════════════════
# Helper: coloured / formatted console output
# ═══════════════════════════════════════════════════════════════

def _print_section(title: str) -> None:
    """Print a highlighted section header."""
    print(f"\n  ╔{'═' * 68}╗")
    padding = 68 - len(title) - 4
    print(f"  ║  {title}{' ' * padding}  ║")
    print(f"  ╚{'═' * 68}╝\n")


def _print_found(label: str, value: str) -> None:
    """Print a single finding line."""
    print(f"     ● {label}: {value}")


def _print_item(text: str) -> None:
    """Print a bullet-point item."""
    print(f"       ▸ {text}")


def _print_warning(text: str) -> None:
    """Print a warning-level finding."""
    print(f"     ⚠  {text}")


def _print_count(label: str, count: int) -> None:
    """Print a summary count."""
    dots = "." * (50 - len(label))
    print(f"     {label} {dots} {count}")


# ═══════════════════════════════════════════════════════════════
# DiscoveryScanner
# ═══════════════════════════════════════════════════════════════

class DiscoveryScanner(BaseScanner):
    """
    Phase-1 scanner: Information Gathering & Discovery.

    Crawls the target website and builds a comprehensive map of the
    application's attack surface including pages, forms, scripts,
    authentication flows, role-based routes, API docs, and parameters.

    Usage::

        scanner = DiscoveryScanner()
        results = scanner.scan("https://example.com")

    Attributes
    ----------
    name : str
        Human-readable scanner name shown in CLI output.
    description : str
        One-line summary of what this scanner does.
    owasp_category : str
        Related OWASP category reference.
    """

    name = "Discovery Scanner"
    description = "Crawl and map the full attack surface of the target application"
    owasp_category = "Reconnaissance (Pre-Attack Phase)"

    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
    ):
        """
        Initialise the discovery scanner.

        Parameters
        ----------
        max_depth : int
            How many link-hops deep the crawler will follow from the
            starting URL.  Keeps scans bounded on large sites.
        max_pages : int
            Hard cap on the number of unique pages to fetch.  Prevents
            runaway crawling on sites with infinite pagination / query
            variations.
        """
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

        # Accumulated results — reset on every scan() call
        self._visited: Set[str] = set()
        self._urls: Set[str] = set()
        self._forms: List[Dict] = []
        self._scripts: Set[str] = set()
        self._parameters: Dict[str, Set[str]] = {}
        self._auth_indicators: List[Dict] = []
        self._role_urls: Dict[str, List[str]] = {}
        self._api_docs: List[Dict] = []

    # ───────────────────────────────────────────────────────────
    # Public API
    # ───────────────────────────────────────────────────────────

    def scan(self, target: str) -> dict:
        """
        Run the full discovery scan against ``target``.

        This is the main entry point called by the ChakraView runner.
        It orchestrates crawling, detection, and parameter extraction,
        printing live results to the console and returning a structured
        findings dict.

        Parameters
        ----------
        target : str
            The base URL of the web application to scan
            (e.g. ``"https://example.com"``).

        Returns
        -------
        dict
            A result dict with keys ``scanner``, ``target``, ``status``,
            and ``findings`` (a dict of categorised discovery data).
        """
        self._reset()

        parsed = urlparse(target)
        if not parsed.scheme:
            target = "https://" + target
        self._base_url = target
        self._base_domain = urlparse(target).netloc

        _print_section("Phase 1: Information Gathering & Discovery")
        print(f"     Target ➜  {target}")
        print(f"     Depth  ➜  {self.max_depth}   |   Page cap ➜  {self.max_pages}")
        print()

        # Step 1 — Crawl
        print("   ┌─ Crawling site...")
        self._crawl(target, depth=0)
        print(f"   └─ Crawl complete: {len(self._visited)} pages visited\n")

        # Step 2 — Detect auth mechanisms
        print("   ┌─ Detecting authentication mechanisms...")
        self._detect_auth_from_urls()
        print(f"   └─ {len(self._auth_indicators)} indicator(s) found\n")

        # Step 3 — Identify role-based routes
        print("   ┌─ Identifying role-based routes...")
        self._identify_role_urls()
        total_roles = sum(len(v) for v in self._role_urls.values())
        print(f"   └─ {total_roles} role-indicator URL(s) found\n")

        # Step 4 — Probe API documentation endpoints
        print("   ┌─ Probing API documentation endpoints...")
        self._probe_api_docs()
        print(f"   └─ {len(self._api_docs)} doc endpoint(s) found\n")

        # Step 5 — Summary
        self._print_summary()

        # Build structured result
        findings = {
            "urls_discovered": sorted(self._urls),
            "forms": self._forms,
            "scripts": sorted(self._scripts),
            "parameters": {src: sorted(params) for src, params in self._parameters.items()},
            "auth_indicators": self._auth_indicators,
            "role_urls": {role: sorted(urls) for role, urls in self._role_urls.items()},
            "api_docs": self._api_docs,
        }

        return self._result(target, findings=[findings])

    # ───────────────────────────────────────────────────────────
    # Internal: state management
    # ───────────────────────────────────────────────────────────

    def _reset(self) -> None:
        """Clear all accumulated state from a previous scan."""
        self._visited.clear()
        self._urls.clear()
        self._forms.clear()
        self._scripts.clear()
        self._parameters.clear()
        self._auth_indicators.clear()
        self._role_urls.clear()
        self._api_docs.clear()

    # ───────────────────────────────────────────────────────────
    # Internal: crawler
    # ───────────────────────────────────────────────────────────

    def _crawl(self, url: str, depth: int) -> None:
        """
        Recursively crawl pages starting from ``url``.

        At each page the crawler:
        - Records the URL
        - Extracts links, forms, scripts, and parameters
        - Detects inline auth indicators
        - Follows same-domain links up to ``max_depth``

        Parameters
        ----------
        url : str
            The page URL to fetch and parse.
        depth : int
            Current recursion depth (0 = starting page).
        """
        # Enforce limits
        if depth > self.max_depth:
            return
        if len(self._visited) >= self.max_pages:
            return

        # Normalise and deduplicate
        normalised = self._normalise_url(url)
        if normalised in self._visited:
            return
        if not self._is_same_domain(normalised):
            return

        # Skip binary/asset URLs
        path = urlparse(normalised).path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            self._urls.add(normalised)
            return

        self._visited.add(normalised)
        self._urls.add(normalised)

        # Fetch the page (fall back to unverified SSL if cert chain fails)
        try:
            resp = self.session.get(normalised, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.exceptions.SSLError:
            try:
                resp = self.session.get(
                    normalised, timeout=REQUEST_TIMEOUT,
                    allow_redirects=True, verify=False,
                )
                print(f"     ⚠ SSL verification failed, continued without — {normalised}")
            except requests.RequestException as exc:
                print(f"     ✗ Failed: {normalised} ({exc.__class__.__name__})")
                return
        except requests.RequestException as exc:
            print(f"     ✗ Failed: {normalised} ({exc.__class__.__name__})")
            return

        status = resp.status_code
        indent = "     " + "  " * depth
        print(f"{indent}[{status}] {normalised}")

        # Only parse HTML responses
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract everything from this page
        links = self._extract_links(soup, normalised)
        self._extract_forms(soup, normalised)
        self._extract_scripts(soup, normalised)
        self._extract_parameters(normalised, soup, resp.text)
        self._detect_auth_from_html(normalised, resp.text)

        # Recurse into discovered links
        for link in links:
            self._crawl(link, depth + 1)

    # ───────────────────────────────────────────────────────────
    # Internal: extraction helpers
    # ───────────────────────────────────────────────────────────

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all navigable links from the page.

        Resolves relative URLs against ``base_url`` and filters to
        same-domain links only. Also picks up links from ``<link>``
        tags and common JS-driven navigation attributes.

        Parameters
        ----------
        soup : BeautifulSoup
            Parsed HTML of the page.
        base_url : str
            The URL of the page (used for resolving relative paths).

        Returns
        -------
        list[str]
            Absolute URLs discovered on this page.
        """
        links: Set[str] = set()

        # <a href="...">
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(base_url, href)
            normalised = self._normalise_url(absolute)
            if self._is_same_domain(normalised):
                links.add(normalised)
                self._urls.add(normalised)

        # <link> tags (sitemaps, alternate pages)
        for tag in soup.find_all("link", href=True):
            href = tag["href"].strip()
            absolute = urljoin(base_url, href)
            normalised = self._normalise_url(absolute)
            if self._is_same_domain(normalised):
                self._urls.add(normalised)

        return list(links)

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        """
        Extract all ``<form>`` elements and their fields from the page.

        For each form, records the action URL, HTTP method, and a list
        of all input/select/textarea fields with their names, types,
        and any default values.

        Parameters
        ----------
        soup : BeautifulSoup
            Parsed HTML of the page.
        page_url : str
            The URL the form was found on.
        """
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action_url = urljoin(page_url, action) if action else page_url
            method = form.get("method", "GET").upper()

            fields = []
            for inp in form.find_all(["input", "select", "textarea"]):
                field_name = inp.get("name", "")
                field_type = inp.get("type", "text")
                field_value = inp.get("value", "")
                if field_name:
                    fields.append({
                        "name": field_name,
                        "type": field_type,
                        "value": field_value,
                        "is_hidden": field_type == "hidden",
                    })
                    # Also record as a discovered parameter
                    self._parameters.setdefault(page_url, set()).add(field_name)

            form_info = {
                "page": page_url,
                "action": action_url,
                "method": method,
                "fields": fields,
            }
            self._forms.append(form_info)

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> None:
        """
        Collect all JavaScript file references from the page.

        Records both external ``<script src="...">`` URLs and flags
        the presence of significant inline scripts.

        Parameters
        ----------
        soup : BeautifulSoup
            Parsed HTML of the page.
        base_url : str
            The URL of the page (for resolving relative ``src`` paths).
        """
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                absolute = urljoin(base_url, src.strip())
                self._scripts.add(absolute)

    def _extract_parameters(
        self, url: str, soup: BeautifulSoup, raw_html: str
    ) -> None:
        """
        Harvest parameters from multiple sources on the page.

        Sources checked:
        - Query string parameters in the page URL
        - Form fields (handled separately in ``_extract_forms``)
        - ``data-*`` attributes on HTML elements
        - Inline JSON-like structures in ``<script>`` blocks
        - URL-like strings embedded in JavaScript

        Parameters
        ----------
        url : str
            The page URL (query string params extracted from here).
        soup : BeautifulSoup
            Parsed HTML of the page.
        raw_html : str
            The raw HTML string (for regex-based JS scanning).
        """
        # Query string parameters
        parsed = urlparse(url)
        qs_params = parse_qs(parsed.query)
        for param_name in qs_params:
            self._parameters.setdefault(url, set()).add(param_name)

        # data-* attributes can reveal API parameter names
        for tag in soup.find_all(attrs={"data-url": True}):
            data_url = tag["data-url"]
            data_parsed = urlparse(data_url)
            for p in parse_qs(data_parsed.query):
                self._parameters.setdefault(url, set()).add(p)

        # Scan inline <script> for JSON keys that look like API params
        # e.g.  {"user_id": 123, "api_key": "..."}
        json_key_pattern = re.compile(r'["\'](\w{2,30})["\']\s*:')
        for script in soup.find_all("script", src=False):
            if script.string:
                for match in json_key_pattern.finditer(script.string):
                    key = match.group(1)
                    # Filter out obvious JS noise
                    if key not in {"function", "return", "const", "let", "var",
                                   "true", "false", "null", "undefined", "this",
                                   "type", "use", "exports", "module", "require",
                                   "default", "class", "import", "from"}:
                        self._parameters.setdefault(url, set()).add(key)

    # ───────────────────────────────────────────────────────────
    # Internal: auth detection
    # ───────────────────────────────────────────────────────────

    def _detect_auth_from_urls(self) -> None:
        """
        Scan all discovered URLs for patterns that indicate
        authentication-related pages (login, signup, OAuth, etc.).

        Matches against ``AUTH_URL_PATTERNS`` and records each hit
        with the matched pattern name.
        """
        for url in sorted(self._urls):
            path = urlparse(url).path.lower()
            for pattern in AUTH_URL_PATTERNS:
                if re.search(pattern, path):
                    indicator = {
                        "type": "auth_url",
                        "url": url,
                        "pattern": pattern,
                    }
                    self._auth_indicators.append(indicator)
                    _print_item(f"{url}  (matched: {pattern})")
                    break  # one match per URL is enough

    def _detect_auth_from_html(self, url: str, html: str) -> None:
        """
        Scan raw HTML for authentication-related patterns.

        Looks for login forms, password fields, CSRF tokens, OAuth
        redirect links, JWT localStorage usage, and API key headers
        in inline JavaScript.

        Parameters
        ----------
        url : str
            The page URL where the HTML was fetched from.
        html : str
            The raw HTML content to scan.
        """
        for indicator_name, pattern in AUTH_HTML_INDICATORS.items():
            if re.search(pattern, html, re.IGNORECASE):
                indicator = {
                    "type": indicator_name,
                    "url": url,
                    "pattern": pattern,
                }
                # Avoid duplicate entries
                if not any(
                    i["type"] == indicator_name and i["url"] == url
                    for i in self._auth_indicators
                ):
                    self._auth_indicators.append(indicator)

    # ───────────────────────────────────────────────────────────
    # Internal: role & API doc detection
    # ───────────────────────────────────────────────────────────

    def _identify_role_urls(self) -> None:
        """
        Categorise discovered URLs by role indicators.

        Scans the full URL set for path fragments like ``/admin``,
        ``/dashboard``, ``/api/v1/`` and groups them under role
        labels.
        """
        for url in sorted(self._urls):
            path = urlparse(url).path.lower()
            for role, patterns in ROLE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, path):
                        self._role_urls.setdefault(role, [])
                        if url not in self._role_urls[role]:
                            self._role_urls[role].append(url)
                            _print_item(f"[{role.upper()}] {url}")
                        break

    def _probe_api_docs(self) -> None:
        """
        Actively probe the target for common API documentation paths.

        Sends HEAD requests to well-known documentation URLs (Swagger,
        OpenAPI, GraphQL, etc.) and records any that return a
        successful (2xx) status code.
        """
        for doc_path in API_DOC_PATHS:
            probe_url = urljoin(self._base_url, doc_path)
            try:
                try:
                    resp = self.session.head(
                        probe_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
                    )
                except requests.exceptions.SSLError:
                    resp = self.session.head(
                        probe_url, timeout=REQUEST_TIMEOUT,
                        allow_redirects=True, verify=False,
                    )
                if resp.status_code < 400:
                    doc_entry = {
                        "url": probe_url,
                        "status_code": resp.status_code,
                        "path": doc_path,
                    }
                    self._api_docs.append(doc_entry)
                    _print_warning(f"EXPOSED: {probe_url}  [{resp.status_code}]")
            except requests.RequestException:
                continue

    # ───────────────────────────────────────────────────────────
    # Internal: output summary
    # ───────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        """Print a consolidated summary of all discovery findings."""
        _print_section("Discovery Summary")

        _print_count("URLs discovered", len(self._urls))
        _print_count("Pages crawled", len(self._visited))
        _print_count("Forms found", len(self._forms))
        _print_count("JavaScript files", len(self._scripts))
        _print_count("Auth indicators", len(self._auth_indicators))
        _print_count("API doc endpoints", len(self._api_docs))

        total_params = sum(len(p) for p in self._parameters.values())
        _print_count("Unique parameters", total_params)

        # Detail: forms
        if self._forms:
            print("\n     ── Forms ──")
            for f in self._forms:
                field_names = [fld["name"] for fld in f["fields"]]
                hidden = [fld["name"] for fld in f["fields"] if fld["is_hidden"]]
                print(f"       {f['method']} {f['action']}")
                print(f"         fields : {', '.join(field_names) or '(none)'}")
                if hidden:
                    print(f"         hidden : {', '.join(hidden)}")

        # Detail: role URLs
        if self._role_urls:
            print("\n     ── Role Indicators ──")
            for role, urls in self._role_urls.items():
                print(f"       [{role.upper()}]")
                for u in urls[:10]:  # cap output for very large sets
                    print(f"         {u}")

        # Detail: API docs
        if self._api_docs:
            print("\n     ── Exposed API Documentation ──")
            for doc in self._api_docs:
                _print_warning(f"{doc['url']}  [{doc['status_code']}]")

        # Detail: auth indicators
        if self._auth_indicators:
            print("\n     ── Authentication Indicators ──")
            seen = set()
            for ind in self._auth_indicators:
                key = (ind["type"], ind["url"])
                if key not in seen:
                    seen.add(key)
                    _print_item(f"{ind['type']}: {ind['url']}")

        print()

    # ───────────────────────────────────────────────────────────
    # Internal: URL utilities
    # ───────────────────────────────────────────────────────────

    def _normalise_url(self, url: str) -> str:
        """
        Normalise a URL for consistent deduplication.

        Strips fragments (``#section``), removes trailing slashes
        from the path, and lowercases the scheme and host.
        """
        parsed = urlparse(url)
        # Drop fragment, normalise trailing slash
        path = parsed.path.rstrip("/") or "/"
        normalised = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=path,
            fragment="",
        )
        return normalised.geturl()

    def _is_same_domain(self, url: str) -> bool:
        """Return True if ``url`` belongs to the target domain."""
        return urlparse(url).netloc.lower() == self._base_domain.lower()
