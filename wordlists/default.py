"""
Built-in wordlist and sensitive-file checks.
"""

import tempfile
import os
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


def build_combined_wordlist(
    custom_path: Optional[str] = None,
    extensions: Optional[List[str]] = None,
) -> str:
    """
    Build the wordlist used by all tools.

    Priority order:
      1. Custom wordlist supplied via -w / --wordlist  (if given)
      2. dirsearch's dicc.txt                          (if found on disk)
      3. Built-in DEFAULT_WORDLIST + SENSITIVE_FILES   (always-available fallback)

    When dicc.txt or a custom wordlist is used, SENSITIVE_FILES entries are
    appended so sensitive-file checks are always included regardless of source.
    The result is written to a temporary file whose path is returned.
    The caller is responsible for deleting the temp file.
    """
    import sys

    entries: List[str] = []
    source: str = "built-in"

    if custom_path:
        custom_file = Path(custom_path)
        if custom_file.is_file():
            with open(custom_file, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        entries.append(word)
            source = str(custom_file)
        else:
            print(
                f"[!] Custom wordlist not found: {custom_path} — falling back to dicc.txt / built-in",
                file=sys.stderr,
            )

    if not entries:
        dicc = find_dicc_txt()
        if dicc:
            with open(dicc, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        entries.append(word)
            source = dicc
            print(f"[*] Using dirsearch wordlist: {dicc} ({len(entries)} entries)", file=sys.stderr)
        else:
            entries = list(DEFAULT_WORDLIST)
            source = "built-in"
            print(
                "[*] dicc.txt not found — using built-in wordlist "
                f"({len(entries)} entries)",
                file=sys.stderr,
            )

    # Always append sensitive files (deduplicated below)
    entries.extend(SENSITIVE_FILES)

    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for entry in entries:
        if entry not in seen:
            seen.add(entry)
            unique.append(entry)

    # Expand with extensions for extension-less entries
    if extensions:
        base_entries = list(unique)
        for word in base_entries:
            if "." not in word.split("/")[-1]:
                for ext in extensions:
                    ext = ext.lstrip(".")
                    candidate = f"{word}.{ext}"
                    if candidate not in seen:
                        seen.add(candidate)
                        unique.append(candidate)

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="de_wordlist_"
    )
    tmp.write("\n".join(unique) + "\n")
    tmp.close()
    return tmp.name
