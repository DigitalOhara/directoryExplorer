"""
Built-in wordlist and sensitive-file checks.
"""

import tempfile
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

DEFAULT_WORDLIST: List[str] = [
    # Administration
    "admin", "administrator", "administration", "manage", "management",
    "manager", "moderator", "webmaster", "sysadmin",
    # Authentication
    "login", "logout", "signin", "signout", "signup", "register",
    "auth", "authentication", "oauth", "sso", "forgot-password",
    "reset-password", "change-password", "2fa", "mfa",
    # Dashboards & panels
    "dashboard", "panel", "controlpanel", "cp", "cpanel", "plesk",
    "portal", "console", "cockpit", "back-office", "backoffice",
    # APIs
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "swagger", "openapi", "docs", "documentation",
    # Common app paths
    "app", "apps", "application", "applications",
    "user", "users", "account", "accounts", "profile", "profiles",
    "settings", "preferences", "config", "configuration",
    "search", "results", "reports", "report", "export",
    # Uploads / media
    "upload", "uploads", "files", "file", "media", "images", "image",
    "img", "photos", "photo", "avatar", "thumbnails",
    # Static assets
    "assets", "static", "public", "resources", "res",
    "js", "css", "fonts", "icons", "svg",
    "vendor", "lib", "libs", "library", "libraries",
    # Development / staging
    "dev", "development", "staging", "stage", "uat", "qa", "test",
    "testing", "demo", "sandbox", "preview", "beta",
    # Infrastructure
    "internal", "private", "secure", "secret", "hidden",
    "server", "services", "service", "microservice",
    "health", "healthcheck", "status", "ping", "metrics",
    "monitor", "monitoring", "alerts",
    # Database
    "database", "db", "sql", "mysql", "postgres", "mongodb",
    "redis", "phpmyadmin", "adminer", "dbadmin",
    # Backups / archives
    "backup", "backups", "archive", "archives",
    "old", "bak", "copy", "tmp", "temp",
    # Source control
    "git", "svn", "cvs", "hg",
    # E-commerce / CMS
    "shop", "store", "cart", "checkout", "payment", "billing",
    "invoice", "order", "orders", "product", "products",
    "blog", "news", "posts", "post", "articles", "article",
    "wp-admin", "wp-content", "wp-includes", "wp-json",
    "joomla", "drupal", "magento", "typo3",
    # Support / help
    "support", "help", "faq", "contact", "feedback",
    "ticket", "tickets", "helpdesk",
    # Versioning / well-known
    ".well-known", ".well-known/security.txt",
    ".well-known/acme-challenge",
    # Common paths
    "cgi-bin", "cgi", "scripts", "bin", "includes",
    "inc", "common", "shared", "components",
    "home", "index", "main", "default",
    "404", "500", "error", "errors",
    # Cloud / infrastructure
    "aws", "azure", "gcp", "cloud", "cdn",
    "proxy", "reverse-proxy", "gateway", "load-balancer",
    # Monitoring
    "kibana", "grafana", "prometheus", "jaeger",
    "elastic", "elasticsearch",
]

SENSITIVE_FILES: List[str] = [
    # Environment & secrets
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.old",
    # Source control
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".git/index", ".git/packed-refs",
    ".gitignore", ".gitmodules",
    ".svn/entries", ".svn/wc.db",
    # IDE / OS
    ".DS_Store", "Thumbs.db", ".idea/workspace.xml",
    # Web server
    "web.config", ".htaccess", ".htpasswd",
    "nginx.conf", "apache.conf",
    # Application config
    "config.php", "config.yml", "config.yaml", "config.json",
    "settings.py", "settings.php", "settings.yml",
    "database.yml", "database.php",
    "wp-config.php", "wp-config.php.bak",
    "configuration.php", "local.xml",
    "application.properties", "application.yml",
    "appsettings.json",
    # Certificates / keys
    "id_rsa", "id_rsa.pub", "id_dsa", "id_ecdsa",
    "server.key", "server.crt", "server.pem",
    "private.pem", "private.key",
    "*.pfx", "*.p12",
    # Package management
    "composer.json", "composer.lock",
    "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum",
    # Container / deployment
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", ".dockerignore",
    "kubernetes.yml", "k8s.yml",
    "Vagrantfile",
    # CI/CD
    ".travis.yml", ".circleci/config.yml",
    ".github/workflows/main.yml",
    "Jenkinsfile", ".gitlab-ci.yml",
    # Archives / backups
    "backup.zip", "backup.tar.gz", "backup.tar",
    "dump.sql", "database.sql", "db.sql",
    "backup.sql", "data.sql",
    "site.tar.gz", "www.zip", "html.zip",
    # Informational
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt",
    "CHANGELOG.md", "CHANGELOG.txt",
    "README.md", "README.txt",
    "LICENSE", "LICENSE.txt",
    # Log files
    "error.log", "access.log", "debug.log",
    "app.log", "application.log",
    "phpinfo.php", "info.php", "test.php",
    # Misc
    "phpMyAdmin", "phpmyadmin",
    "adminer.php", "adminer",
    "console", "actuator", "actuator/health",
    "actuator/env", "actuator/mappings",
    "trace", "heapdump",
]


# Known installation paths for dirsearch's dicc.txt, checked in order.
_DICC_SEARCH_PATHS: List[str] = [
    "/usr/lib/python3/dist-packages/dirsearch/db/dicc.txt",
    "/usr/local/lib/python3/dist-packages/dirsearch/db/dicc.txt",
    "/usr/share/dirsearch/db/dicc.txt",
    "/opt/dirsearch/db/dicc.txt",
]


def find_dicc_txt() -> Optional[str]:
    """
    Return the path to dirsearch's dicc.txt if it can be found, else None.
    Checks fixed known paths first, then falls back to a glob over all
    Python dist-packages trees.
    """
    import glob

    for path in _DICC_SEARCH_PATHS:
        if Path(path).is_file():
            return path

    # Glob fallback: handles non-standard Python prefix installs
    for pattern in (
        "/usr/**/dirsearch/db/dicc.txt",
        "/opt/**/dirsearch/db/dicc.txt",
        str(Path.home() / "**" / "dirsearch" / "db" / "dicc.txt"),
    ):
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return matches[0]

    return None


@dataclass
class WordlistResult:
    path: str
    is_temp: bool   # True → caller must delete after use; False → real file, do not delete


def build_combined_wordlist(
    custom_path: Optional[str] = None,
) -> WordlistResult:
    """
    Resolve the wordlist all tools will use.

    Fast path — no temp file created:
      • No -w given → return dicc.txt path directly (is_temp=False)

    Merge path — temp file created (is_temp=True):
      • Custom -w supplied → custom entries + any SENSITIVE_FILES not already present

    Extension expansion is intentionally NOT done here; every tool wrapper
    applies extensions natively via its own -x / -e / --extensions flag.
    """
    import sys

    dicc = find_dicc_txt()

    # ── Fast path: no custom wordlist → use dicc.txt directly ─────────────────
    if not custom_path:
        if dicc:
            print(f"[*] Wordlist: {dicc}  ({_count_lines(dicc)} entries)", file=sys.stderr)
            return WordlistResult(path=dicc, is_temp=False)
        # No dicc.txt anywhere → fall back to built-in list written once as temp
        print(
            f"[*] dicc.txt not found — using built-in wordlist ({len(DEFAULT_WORDLIST)} entries)",
            file=sys.stderr,
        )
        return WordlistResult(path=_write_temp(DEFAULT_WORDLIST + SENSITIVE_FILES), is_temp=True)

    # ── Merge path: custom wordlist provided ───────────────────────────────────
    custom_file = Path(custom_path)
    if not custom_file.is_file():
        print(
            f"[!] Custom wordlist not found: {custom_path} — falling back to dicc.txt / built-in",
            file=sys.stderr,
        )
        return build_combined_wordlist()   # recurse without custom_path

    entries = _read_wordlist(custom_file)
    print(f"[*] Wordlist: {custom_path}  ({len(entries)} entries, custom)", file=sys.stderr)

    # Append sensitive files not already present in the custom list
    entries_set = set(entries)
    for sf in SENSITIVE_FILES:
        if sf not in entries_set:
            entries.append(sf)

    return WordlistResult(path=_write_temp(entries), is_temp=True)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _read_wordlist(path) -> List[str]:
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip()
            if word and not word.startswith("#"):
                entries.append(word)
    return entries


def _write_temp(entries: List[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="de_wordlist_"
    )
    tmp.write("\n".join(entries) + "\n")
    tmp.close()
    return tmp.name


def _count_lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0
