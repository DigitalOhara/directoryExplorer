"""
Lightweight technology fingerprinting and passive recon helpers.
"""

import hashlib
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


TECH_SIGNATURES: Dict[str, List[str]] = {
    "WordPress":    ["wp-content", "wp-includes", "wp-json", "WordPress"],
    "Joomla":       ["Joomla!", "/components/com_", "/modules/mod_"],
    "Drupal":       ["Drupal", "drupal.js", "/sites/default/"],
    "Magento":      ["Mage.Cookies", "MAGE_", "/skin/frontend/"],
    "Django":       ["csrftoken", "csrfmiddlewaretoken", "__django_context"],
    "Laravel":      ["laravel_session", "XSRF-TOKEN", "Laravel"],
    "Rails":        ["_rails_session", "X-Request-Id", "actionpack"],
    "ASP.NET":      ["ASP.NET", "X-AspNet-Version", "__VIEWSTATE", "ASPNET"],
    "PHP":          ["X-Powered-By: PHP", ".php"],
    "Node.js":      ["X-Powered-By: Express", "connect.sid"],
    "Apache":       ["Apache/", "Server: Apache"],
    "Nginx":        ["nginx/", "Server: nginx"],
    "IIS":          ["Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "Cloudflare":   ["CF-RAY", "cloudflare"],
    "AWS":          ["x-amz-", "AmazonS3", "awselb"],
}

FAVICON_HASHES: Dict[str, str] = {
    "-297558949":  "Grafana",
    "708578229":   "Jenkins",
    "-875986553":  "Jira",
    "1110248758":  "Kibana",
    "522352439":   "GitLab",
    "-1279384951": "Confluence",
}


def _mmh3_hash(data: bytes) -> int:
    """MurmurHash3 32-bit — used by Shodan for favicon hashing."""
    try:
        import mmh3
        return mmh3.hash(data)
    except ImportError:
        # Fallback: simple signed CRC32
        import struct, zlib
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return struct.unpack(">i", struct.pack(">I", crc))[0]


def fingerprint_target(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    proxy: Optional[str] = None,
) -> Dict:
    """
    Perform lightweight fingerprinting of target.
    Returns a dict with detected technologies, server info, and favicon hash.
    """
    result = {
        "url": url,
        "server": None,
        "technologies": [],
        "favicon_hash": None,
        "favicon_tech": None,
        "robots_txt": False,
        "sitemap_xml": False,
        "error": None,
    }

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests library not available"
        return result

    session = requests.Session()
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; directoryExplorer/1.0)"}
    if headers:
        req_headers.update(headers)

    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        resp = session.get(
            url, headers=req_headers, timeout=timeout,
            proxies=proxies, allow_redirects=True, verify=False
        )

        server_header = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")
        result["server"] = server_header or powered_by or "Unknown"

        all_indicators = (
            resp.text[:4096]
            + " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        )

        for tech, sigs in TECH_SIGNATURES.items():
            if any(sig.lower() in all_indicators.lower() for sig in sigs):
                if tech not in result["technologies"]:
                    result["technologies"].append(tech)

        # Robots.txt check
        robots_url = urljoin(url.rstrip("/") + "/", "robots.txt")
        try:
            r = session.get(
                robots_url, headers=req_headers, timeout=5,
                proxies=proxies, allow_redirects=False, verify=False
            )
            result["robots_txt"] = r.status_code == 200
        except Exception:
            pass

        # Sitemap.xml check
        sitemap_url = urljoin(url.rstrip("/") + "/", "sitemap.xml")
        try:
            r = session.get(
                sitemap_url, headers=req_headers, timeout=5,
                proxies=proxies, allow_redirects=False, verify=False
            )
            result["sitemap_xml"] = r.status_code == 200
        except Exception:
            pass

        # Favicon hash
        favicon_url = urljoin(url.rstrip("/") + "/", "favicon.ico")
        try:
            fr = session.get(
                favicon_url, headers=req_headers, timeout=5,
                proxies=proxies, allow_redirects=True, verify=False
            )
            if fr.status_code == 200 and fr.content:
                fhash = str(_mmh3_hash(fr.content))
                result["favicon_hash"] = fhash
                result["favicon_tech"] = FAVICON_HASHES.get(fhash)
        except Exception:
            pass

    except requests.exceptions.RequestException as exc:
        result["error"] = str(exc)

    return result


def parse_robots_txt(url: str, timeout: int = 10, proxy: Optional[str] = None) -> List[str]:
    """Fetch and parse robots.txt, returning disallowed paths."""
    if not REQUESTS_AVAILABLE:
        return []

    robots_url = urljoin(url.rstrip("/") + "/", "robots.txt")
    paths: List[str] = []

    try:
        import requests as req
        resp = req.get(
            robots_url,
            timeout=timeout,
            proxies={"http": proxy, "https": proxy} if proxy else None,
            verify=False,
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/":
                            paths.append(path)
    except Exception:
        pass

    return paths
