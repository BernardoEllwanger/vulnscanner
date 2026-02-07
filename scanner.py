#!/usr/bin/env python3
"""
Scanner de Vulnerabilidades Web
Uso autorizado apenas em sites próprios ou com permissão explícita.
"""

import argparse
import base64
import hashlib
import html
import json
import os
import re
import ssl
import socket
import time
import uuid
from collections import defaultdict
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "BAIXO": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRÍTICO": Fore.RED,
    "ALTO": Fore.LIGHTRED_EX,
    "MÉDIO": Fore.YELLOW,
    "BAIXO": Fore.CYAN,
    "INFO": Fore.WHITE,
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "MÉDIO",
    "X-Content-Type-Options": "MÉDIO",
    "X-Frame-Options": "MÉDIO",
    "Strict-Transport-Security": "ALTO",
    "Referrer-Policy": "BAIXO",
    "Permissions-Policy": "BAIXO",
    "X-XSS-Protection": "BAIXO",
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

ALWAYS_CHECK_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/.htpasswd", "/.aws/credentials", "/.ssh/id_rsa",
]

SENSITIVE_PATTERNS = [
    r'\.env$', r'\.git/', r'\.htpasswd', r'\.htaccess',
    r'wp-config\.php', r'config\.(php|yml|json|yaml)$',
    r'database\.(yml|sql)$', r'\.sqlite3?$',
    r'backup\.(zip|tar\.gz|sql|rar)$', r'dump\.sql$',
    r'phpinfo\.php$', r'\.aws/', r'\.ssh/',
    r'docker-compose\.yml$', r'Dockerfile$',
    r'\.pem$', r'\.key$', r'\.crt$',
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

SQLI_PAYLOADS = [
    "'", "''",
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    '" OR "1"="1',
    "1' ORDER BY 1--", "1' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int, @@version)--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning.*mysql",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"microsoft ole db provider", r"odbc.*driver",
    r"syntax error.*postgresql", r"pg_query\(\)",
    r"org\.postgresql\.util\.psqlexception", r"sqlite3\.operationalerror",
    r"sqlexception", r"oracle.*error", r"ora-\d{5}",
    r"sql server.*error", r"microsoft sql native client",
    r"invalid column name", r"column.*does not exist",
    r"unterminated.*string", r"jdbc\.sqlserver",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "url", "next",
    "return", "return_url", "returnUrl", "returnTo", "goto",
    "destination", "dest", "continue", "target", "link", "rurl",
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class VulnScanner:
    def __init__(self, target_url, token=None, login_url=None, username=None,
                 password=None, log_callback=None):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.scheme = self.parsed.scheme

        # Log callback: para web usa callback customizado, para CLI usa print com cores
        self._external_log = log_callback
        if log_callback:
            self._log = log_callback
        else:
            self._log = self._cli_log

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnScanner/2.0 (Authorized Security Test)"})
        self.session.verify = True

        self.has_auth = False
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
            self.has_auth = True

        if login_url and username and password:
            self._login(login_url, username, password)
            self.has_auth = True

        self.visited = set()
        self.forms = []
        self.findings = []
        self.api_endpoints = set()
        self.js_urls = set()

        self.baseline_status = None
        self.baseline_length = 0
        self.baseline_hash = ""
        self.baseline_text_stripped = ""

        self._js_texts = {}  # url -> JS source text (cache para form discovery)
        self.dynamic_form_sources = {}  # action_url -> "html" | "dynamic"

    def _cli_log(self, msg, level="info"):
        """Log para modo CLI com cores."""
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "finding": "", "banner": Fore.CYAN,
        }
        color = colors.get(level, "")
        print(f"{color}{msg}{Style.RESET_ALL}")

    # -- Autenticação -------------------------------------------------------

    def _login(self, login_url, username, password):
        self._log(f"[*] Tentando login em {login_url}...", "info")
        try:
            resp = self.session.get(login_url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            form = soup.find("form")
            if not form:
                self._log(f"[!] Nenhum formulário encontrado em {login_url}", "warning")
                return

            action = urljoin(login_url, form.get("action", login_url))
            data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                itype = (inp.get("type") or "text").lower()
                if itype == "hidden":
                    data[name] = inp.get("value", "")
                elif itype in ("text", "email"):
                    data[name] = username
                elif itype == "password":
                    data[name] = password

            resp = self.session.post(action, data=data, timeout=10, allow_redirects=True)
            if resp.status_code < 400:
                self._log(f"[+] Login realizado (status {resp.status_code})", "success")
            else:
                self._log(f"[!] Login retornou status {resp.status_code}", "warning")
        except Exception as e:
            self._log(f"[!] Erro no login: {e}", "error")

    # -- Baseline -----------------------------------------------------------

    def _get_baseline_response(self):
        random_path = f"/_{uuid.uuid4().hex[:12]}_nonexistent"
        try:
            resp = self.session.get(self.target + random_path, timeout=10, allow_redirects=True)
            self.baseline_status = resp.status_code
            self.baseline_length = len(resp.text)
            self.baseline_hash = hashlib.md5(resp.text.encode()).hexdigest()
            self.baseline_text_stripped = re.sub(r'\s+', '', resp.text)
        except Exception:
            pass

    def _is_real_content(self, resp, path=""):
        if resp.status_code in (403, 500, 501, 502, 503):
            return True
        if resp.status_code in (301, 302, 303, 307, 308, 404):
            return False
        if not self.baseline_hash:
            return resp.status_code == 200 and len(resp.content) > 0

        resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
        if resp_hash == self.baseline_hash:
            return False

        if self.baseline_length > 0:
            ratio = len(resp.text) / self.baseline_length
            if 0.90 <= ratio <= 1.10:
                stripped = re.sub(r'\s+', '', resp.text)
                similarity = SequenceMatcher(None, self.baseline_text_stripped[:2000],
                                             stripped[:2000]).quick_ratio()
                if similarity > 0.85:
                    return False

        content_type = resp.headers.get("Content-Type", "")
        if path and "text/html" in content_type:
            config_exts = ('.json', '.yml', '.yaml', '.xml', '.sql', '.env',
                           '.php', '.config', '.key', '.pem', '.crt', '.sqlite3')
            if any(path.endswith(ext) for ext in config_exts):
                return False

        return True

    # -- JS URL extraction --------------------------------------------------

    def _extract_js_urls(self, page_url, soup):
        js_texts = []

        for script in soup.find_all("script", src=True):
            src = urljoin(page_url, script["src"])
            if src in self.js_urls or urlparse(src).netloc != self.domain:
                continue
            self.js_urls.add(src)
            try:
                resp = self.session.get(src, timeout=10)
                if resp.status_code == 200:
                    js_texts.append(resp.text)
                    self._js_texts[src] = resp.text
            except Exception:
                continue

        for script in soup.find_all("script", src=False):
            if script.string:
                js_texts.append(script.string)

        found_urls = set()
        for js in js_texts:
            for m in re.finditer(r'''fetch\s*\(\s*["']([^"']+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''axios\.\w+\s*\(\s*["']([^"']+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''\$\.\w+\s*\(\s*["']([^"']+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''["'](/api/[^"'\s]+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''path\s*:\s*["'](/[^"']+)["']''', js):
                found_urls.add(m.group(1))
            for m in re.finditer(r'''["'](/[a-zA-Z][a-zA-Z0-9_\-/]*(?:\.[a-zA-Z]{2,4})?)["']''', js):
                path = m.group(1)
                if not re.match(r'^/[/\\*\d]', path) and len(path) > 2:
                    found_urls.add(path)

        for raw_url in found_urls:
            full_url = urljoin(page_url, raw_url)
            parsed = urlparse(full_url)
            if parsed.netloc != self.domain:
                continue
            if '/api/' in raw_url or re.search(r'\.\w+$', raw_url) is None:
                self.api_endpoints.add(full_url)

        return found_urls

    # -- Crawling -----------------------------------------------------------

    def crawl(self, url=None, depth=0, max_depth=3):
        if url is None:
            url = self.target
        if depth > max_depth or url in self.visited:
            return
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            return

        self.visited.add(url)
        try:
            resp = self.session.get(url, timeout=10)
            if resp.url != url:
                self.visited.add(resp.url)
        except Exception:
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        self._extract_js_urls(url, soup)

        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", url))
            method = (form.get("method") or "GET").upper()
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    val = inp.get("value", "")
                    itype = (inp.get("type") or "text").lower()
                    if itype == "hidden":
                        fields[name] = val
                    elif itype == "password":
                        fields[name] = "test123"
                    elif itype == "email":
                        fields[name] = "test@test.com"
                    elif itype == "number":
                        fields[name] = "1"
                    else:
                        fields[name] = val or "test"
            if fields:
                self.forms.append((url, method, action, fields))

        urls_to_follow = set()
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if urlparse(link).netloc == self.domain:
                urls_to_follow.add(link)

        for elem in soup.find_all(attrs={"onclick": True}):
            for m in re.finditer(r'''["']([^"']*(?:/[^"']+))["']''', elem["onclick"]):
                link = urljoin(url, m.group(1))
                if urlparse(link).netloc == self.domain:
                    urls_to_follow.add(link)

        for attr in ("data-href", "data-url", "data-link", "data-src"):
            for elem in soup.find_all(attrs={attr: True}):
                link = urljoin(url, elem[attr]).split("#")[0]
                if urlparse(link).netloc == self.domain:
                    urls_to_follow.add(link)

        for tag in soup.find_all(["iframe", "embed", "object"], src=True):
            link = urljoin(url, tag["src"]).split("#")[0]
            if urlparse(link).netloc == self.domain:
                urls_to_follow.add(link)

        for link in urls_to_follow:
            self.crawl(link, depth + 1, max_depth)

    # -- Dynamic Form Discovery (SPA) --------------------------------------

    FORM_FIELD_INDICATORS = {
        'name', 'email', 'phone', 'telefone', 'address', 'endereco',
        'password', 'senha', 'cpf', 'cnpj', 'data_nascimento', 'birth',
        'username', 'usuario', 'login', 'comment', 'comentario',
        'message', 'mensagem', 'description', 'descricao', 'titulo', 'title',
        'first_name', 'last_name', 'nome', 'sobrenome', 'city', 'cidade',
        'state', 'estado', 'zip', 'cep', 'country', 'pais',
        'rg', 'sexo', 'gender', 'age', 'idade', 'profissao', 'occupation',
        'cro', 'crm', 'especialidade', 'specialty', 'observacao', 'notes',
    }

    def _analyze_json_for_form_fields(self, data):
        """Analisa resposta JSON para detectar estruturas de formulário."""
        fields = {}

        if isinstance(data, dict):
            keys_lower = {k.lower() for k in data.keys()}
            overlap = keys_lower & self.FORM_FIELD_INDICATORS
            if len(overlap) >= 2 or (len(overlap) >= 1 and len(data) <= 10):
                for key, val in data.items():
                    if isinstance(val, (str, int, float, type(None))):
                        fields[key] = str(val) if val else "test"

            for nested_key in ('fields', 'schema', 'form', 'data'):
                if nested_key in data and isinstance(data[nested_key], (dict, list)):
                    nested = data[nested_key]
                    if isinstance(nested, dict):
                        nested_lower = {k.lower() for k in nested.keys()}
                        if nested_lower & self.FORM_FIELD_INDICATORS:
                            for k, v in nested.items():
                                if isinstance(v, (str, int, float, type(None))):
                                    fields[k] = str(v) if v else "test"
                    elif isinstance(nested, list) and nested and isinstance(nested[0], dict):
                        for item in nested:
                            name = item.get('name') or item.get('field') or item.get('key')
                            if name:
                                fields[name] = item.get('default', 'test')

        elif isinstance(data, list) and data and isinstance(data[0], dict):
            sample = data[0]
            keys_lower = {k.lower() for k in sample.keys()}
            overlap = keys_lower & self.FORM_FIELD_INDICATORS
            if len(overlap) >= 2:
                for key, val in sample.items():
                    if isinstance(val, (str, int, float, type(None))):
                        fields[key] = str(val) if val else "test"

        return fields if len(fields) >= 2 else {}

    def _discover_dynamic_forms(self):
        """Descobre formulários carregados via JS/AJAX em SPAs."""
        self._log("[*] Buscando formulários dinâmicos (SPA)...", "info")
        dynamic_count = 0

        # Fase A: chamar API endpoints e analisar JSON
        for api_url in list(self.api_endpoints):
            try:
                resp = self.session.get(api_url, timeout=10)
                ct = resp.headers.get("Content-Type", "")
                if "application/json" not in ct:
                    continue
                data = resp.json()
                fields = self._analyze_json_for_form_fields(data)
                if fields:
                    self.forms.append((api_url, "POST", api_url, fields))
                    self.dynamic_form_sources[api_url] = "dynamic"
                    dynamic_count += 1
                    self._log(f"  [+] Formulário dinâmico: {api_url} ({len(fields)} campos)", "success")
            except Exception:
                continue

        # Fase B: buscar padrões de formulário no JS
        form_js_patterns = [
            r'new\s+FormData',
            r'\.submit\s*\(',
            r'handleSubmit|onSubmit',
            r'document\.createElement\s*\(\s*["\'](?:form|input)["\']',
            r'getElementById\s*\(\s*["\'][^"\']*form[^"\']*["\']',
            r'querySelector\s*\(\s*["\'][^"\']*form[^"\']*["\']',
        ]
        for js_url, js_text in self._js_texts.items():
            has_form_pattern = any(re.search(p, js_text) for p in form_js_patterns)
            if not has_form_pattern:
                continue
            # Extrair endpoints POST próximos aos padrões de form
            post_matches = re.finditer(
                r'''(?:fetch|axios\.post|\.post)\s*\(\s*["']([^"']+)["']''', js_text
            )
            for m in post_matches:
                endpoint = m.group(1)
                full_url = urljoin(self.target, endpoint)
                parsed = urlparse(full_url)
                if parsed.netloc != self.domain:
                    continue
                if full_url not in self.dynamic_form_sources:
                    # Tentar GET no endpoint para descobrir campos
                    try:
                        resp = self.session.get(full_url, timeout=10)
                        ct = resp.headers.get("Content-Type", "")
                        if "application/json" in ct:
                            data = resp.json()
                            fields = self._analyze_json_for_form_fields(data)
                            if fields:
                                self.forms.append((js_url, "POST", full_url, fields))
                                self.dynamic_form_sources[full_url] = "dynamic"
                                dynamic_count += 1
                                self._log(f"  [+] Formulário via JS: {full_url} ({len(fields)} campos)", "success")
                    except Exception:
                        continue

        self._log(f"[+] {dynamic_count} formulário(s) dinâmico(s) encontrado(s)", "success")

    # -- Findings -----------------------------------------------------------

    def _add(self, severity, category, **details):
        self.findings.append((severity, category, details))

    # -- 1. Security Headers ------------------------------------------------

    def check_headers(self):
        self._log("[*] Verificando Security Headers...", "info")
        try:
            resp = self.session.get(self.target, timeout=10)
        except Exception as e:
            self._add("ALTO", "Erro de Conexão", url=self.target, detalhe=str(e))
            return

        for header, sev in SECURITY_HEADERS.items():
            if header.lower() not in {h.lower() for h in resp.headers}:
                self._add(sev, "Header de Segurança Ausente",
                          url=self.target, header=header,
                          detalhe=f"O header '{header}' não está presente na resposta.")

        for header in INFO_HEADERS:
            val = resp.headers.get(header)
            if val:
                self._add("BAIXO", "Information Disclosure (Header)",
                          url=self.target, header=header, valor=val,
                          detalhe=f"O header '{header}' revela informação: {val}")

    # -- 2. SSL/TLS ---------------------------------------------------------

    def check_ssl(self):
        self._log("[*] Verificando SSL/TLS...", "info")
        hostname = self.domain.split(":")[0]

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError as e:
            self._add("ALTO", "Certificado SSL Inválido", url=self.target, detalhe=str(e))
        except (socket.timeout, ConnectionRefusedError, OSError):
            self._add("ALTO", "HTTPS Indisponível",
                      url=self.target, detalhe="Não foi possível conectar na porta 443.")

        http_url = f"http://{self.domain}"
        try:
            resp = requests.get(http_url, timeout=5, allow_redirects=False, verify=False)
            if resp.status_code not in (301, 302, 307, 308):
                self._add("MÉDIO", "Sem Redirecionamento HTTP→HTTPS",
                          url=http_url, detalhe="O site não redireciona de HTTP para HTTPS.")
            elif "https" not in (resp.headers.get("Location", "") or "").lower():
                self._add("MÉDIO", "Redirecionamento HTTP não aponta para HTTPS",
                          url=http_url, location=resp.headers.get("Location", ""),
                          detalhe="O redirect não aponta para uma URL HTTPS.")
        except Exception:
            pass

    # -- 3. Information Disclosure ------------------------------------------

    def check_info_disclosure(self):
        self._log("[*] Verificando Information Disclosure...", "info")

        for path in ALWAYS_CHECK_PATHS:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and self._is_real_content(resp, path):
                    snippet = resp.text[:200].replace("\n", " ").strip()
                    self._add("ALTO", "Arquivo Sensível Exposto",
                              url=url, status=resp.status_code,
                              content_type=resp.headers.get("Content-Type", ""),
                              detalhe="Arquivo acessível publicamente.", trecho=snippet)
            except Exception:
                continue

        try:
            resp = self.session.get(self.target + "/robots.txt", timeout=5)
            if resp.status_code == 200 and self._is_real_content(resp, "/robots.txt"):
                self._add("INFO", "robots.txt encontrado",
                          url=self.target + "/robots.txt", detalhe="Arquivo robots.txt acessível.")
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        dpath = line.split(":", 1)[1].strip()
                        if dpath and dpath != "/":
                            durl = urljoin(self.target, dpath)
                            try:
                                r2 = self.session.get(durl, timeout=5)
                                if r2.status_code == 200 and self._is_real_content(r2, dpath):
                                    self._add("MÉDIO", "Path do robots.txt acessível",
                                              url=durl, status=r2.status_code,
                                              detalhe=f"O path '{dpath}' listado como Disallow está acessível.")
                            except Exception:
                                continue
        except Exception:
            pass

        try:
            resp = self.session.get(self.target + "/sitemap.xml", timeout=5)
            if resp.status_code == 200 and self._is_real_content(resp, "/sitemap.xml"):
                self._add("INFO", "sitemap.xml encontrado",
                          url=self.target + "/sitemap.xml", detalhe="Arquivo sitemap.xml acessível.")
                for m in re.finditer(r'<loc>\s*(.*?)\s*</loc>', resp.text):
                    loc_url = m.group(1)
                    if urlparse(loc_url).netloc == self.domain:
                        self.visited.add(loc_url)
        except Exception:
            pass

        all_urls = self.visited | self.api_endpoints
        for url in all_urls:
            path = urlparse(url).path
            for pattern in SENSITIVE_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    try:
                        resp = self.session.get(url, timeout=5)
                        if resp.status_code == 200 and self._is_real_content(resp, path):
                            snippet = resp.text[:200].replace("\n", " ").strip()
                            self._add("ALTO", "Arquivo Sensível Descoberto (via crawler)",
                                      url=url, content_type=resp.headers.get("Content-Type", ""),
                                      detalhe="Arquivo sensível encontrado pelo crawler.", trecho=snippet)
                    except Exception:
                        continue
                    break

        dirs_to_check = {"/", "/images/", "/uploads/", "/static/", "/assets/", "/files/", "/media/"}
        for url in list(self.visited)[:50]:
            path = urlparse(url).path
            if "/" in path:
                parent = path.rsplit("/", 1)[0] + "/"
                if parent != "/":
                    dirs_to_check.add(parent)

        for path in dirs_to_check:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=5)
                if "Index of" in resp.text or "Directory listing" in resp.text:
                    self._add("MÉDIO", "Directory Listing Habilitado", url=url,
                              detalhe="O servidor está listando o conteúdo do diretório.")
            except Exception:
                continue

    # -- 4. XSS Refletido --------------------------------------------------

    def check_xss(self):
        self._log("[*] Verificando XSS Refletido...", "info")
        tested = set()

        for page_url, method, action, fields in self.forms:
            for field_name in fields:
                for payload in XSS_PAYLOADS:
                    key = (action, field_name, payload)
                    if key in tested:
                        continue
                    tested.add(key)
                    test_data = dict(fields)
                    test_data[field_name] = payload
                    try:
                        if method == "GET":
                            resp = self.session.get(action, params=test_data, timeout=10)
                        else:
                            resp = self.session.post(action, data=test_data, timeout=10)
                        if payload in resp.text:
                            self._add("CRÍTICO", "XSS Refletido", url=action, método=method,
                                      parâmetro=field_name, payload=payload,
                                      detalhe="O payload foi refletido na resposta sem sanitização.")
                            break
                    except Exception:
                        continue

        for url in self.visited:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    key = (url, param_name, payload)
                    if key in tested:
                        continue
                    tested.add(key)
                    new_params = dict(params)
                    new_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                    try:
                        resp = self.session.get(test_url, timeout=10)
                        if payload in resp.text:
                            self._add("CRÍTICO", "XSS Refletido", url=test_url,
                                      parâmetro=param_name, payload=payload,
                                      detalhe="O payload foi refletido na resposta sem sanitização.")
                            break
                    except Exception:
                        continue

    # -- 5. SQL Injection ---------------------------------------------------

    def check_sqli(self):
        self._log("[*] Verificando SQL Injection...", "info")
        tested = set()

        def _check(resp_text, url, param, payload, method="GET"):
            lower = resp_text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                match = re.search(pattern, lower)
                if match:
                    self._add("CRÍTICO", "SQL Injection", url=url, método=method,
                              parâmetro=param, payload=payload, evidência=match.group(0),
                              detalhe="Erro de banco de dados detectado na resposta.")
                    return True
            return False

        for page_url, method, action, fields in self.forms:
            for field_name in fields:
                for payload in SQLI_PAYLOADS:
                    key = (action, field_name, payload)
                    if key in tested:
                        continue
                    tested.add(key)
                    test_data = dict(fields)
                    test_data[field_name] = payload
                    try:
                        if method == "GET":
                            resp = self.session.get(action, params=test_data, timeout=10)
                        else:
                            resp = self.session.post(action, data=test_data, timeout=10)
                        if _check(resp.text, action, field_name, payload, method):
                            break
                    except Exception:
                        continue

        for url in self.visited:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            for param_name in params:
                for payload in SQLI_PAYLOADS:
                    key = (url, param_name, payload)
                    if key in tested:
                        continue
                    tested.add(key)
                    new_params = dict(params)
                    new_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                    try:
                        resp = self.session.get(test_url, timeout=10)
                        if _check(resp.text, test_url, param_name, payload):
                            break
                    except Exception:
                        continue

    # -- 6. Open Redirect ---------------------------------------------------

    def check_open_redirect(self):
        self._log("[*] Verificando Open Redirect...", "info")
        evil_url = "https://evil.com"

        for url in self.visited:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                if param_name.lower() in [p.lower() for p in REDIRECT_PARAMS]:
                    new_params = dict(params)
                    new_params[param_name] = evil_url
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                    try:
                        resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if evil_url in location:
                            self._add("MÉDIO", "Open Redirect", url=test_url,
                                      parâmetro=param_name, redireciona_para=location,
                                      detalhe="O site redireciona para um domínio externo arbitrário.")
                    except Exception:
                        continue

        for param in REDIRECT_PARAMS:
            test_url = f"{self.target}/?{param}={evil_url}"
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if evil_url in location:
                    self._add("MÉDIO", "Open Redirect", url=test_url, parâmetro=param,
                              redireciona_para=location,
                              detalhe="O site redireciona para um domínio externo arbitrário.")
            except Exception:
                continue

    # -- 7. Cookies ---------------------------------------------------------

    def check_cookies(self):
        self._log("[*] Verificando Cookies...", "info")
        try:
            resp = self.session.get(self.target, timeout=10)
        except Exception:
            return

        for cookie in self.session.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite")
            if issues:
                self._add("MÉDIO" if "Secure" in issues or "HttpOnly" in issues else "BAIXO",
                          "Cookie Inseguro", url=self.target, cookie=cookie.name,
                          flags_ausentes=", ".join(issues),
                          detalhe=f"O cookie '{cookie.name}' não possui as flags: {', '.join(issues)}.")

        for header_val in resp.headers.get("Set-Cookie", "").split(","):
            if not header_val.strip():
                continue
            cookie_name = header_val.strip().split("=")[0]
            lower = header_val.lower()
            issues = []
            if "secure" not in lower:
                issues.append("Secure")
            if "httponly" not in lower:
                issues.append("HttpOnly")
            if "samesite" not in lower:
                issues.append("SameSite")
            if issues:
                self._add("MÉDIO" if "HttpOnly" in issues else "BAIXO",
                          "Cookie Inseguro (via Set-Cookie header)", url=self.target,
                          cookie=cookie_name, flags_ausentes=", ".join(issues),
                          detalhe=f"O cookie '{cookie_name}' não possui as flags: {', '.join(issues)}.")

    # -- 8. JWT Analysis ----------------------------------------------------

    def check_jwt(self):
        self._log("[*] Analisando JWT Token...", "info")
        auth_header = self.session.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return

        token = auth_header[7:]
        parts = token.split(".")
        if len(parts) != 3:
            self._add("INFO", "Token não é JWT",
                      detalhe="O Bearer token não tem o formato JWT.")
            return

        def _b64(s):
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            return base64.urlsafe_b64decode(s)

        try:
            header = json.loads(_b64(parts[0]))
            payload = json.loads(_b64(parts[1]))
        except Exception as e:
            self._add("MÉDIO", "JWT Malformado", detalhe=f"Não foi possível decodificar: {e}")
            return

        alg = header.get("alg", "").lower()
        if alg == "none":
            self._add("CRÍTICO", "JWT com Algoritmo 'none'",
                      header=json.dumps(header, indent=2),
                      detalhe="O JWT usa algoritmo 'none', permitindo falsificação de tokens.")
        elif alg in ("hs256", "hs384", "hs512"):
            self._add("INFO", "JWT usa algoritmo simétrico", algoritmo=header.get("alg"),
                      detalhe=f"O JWT usa {header.get('alg')}.")

        exp = payload.get("exp")
        if exp is None:
            self._add("MÉDIO", "JWT sem Expiração",
                      detalhe="O token JWT não tem claim 'exp'.")
        elif isinstance(exp, (int, float)) and exp < time.time():
            self._add("MÉDIO", "JWT Expirado",
                      expiração=time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(exp)),
                      detalhe="O token JWT está expirado mas ainda está sendo usado.")

        sensitive = [k for k in payload
                     if any(s in k.lower() for s in ("pass", "secret", "key", "token", "credit"))]
        if sensitive:
            self._add("ALTO", "JWT contém dados sensíveis no payload",
                      campos_sensíveis=", ".join(sensitive),
                      detalhe="O payload do JWT contém campos que podem expor dados sensíveis.")

        self._add("INFO", "JWT Payload Decodificado", algoritmo=header.get("alg", "?"),
                  payload=json.dumps(payload, indent=2, default=str),
                  detalhe="Conteúdo decodificado do JWT para análise.")

    # -- 9. CORS ------------------------------------------------------------

    def check_cors(self):
        self._log("[*] Verificando CORS...", "info")
        evil_origin = "https://evil.com"

        urls_to_test = [self.target] + list(self.api_endpoints)[:5]
        for url in urls_to_test:
            try:
                resp = self.session.get(url, timeout=10, headers={"Origin": evil_origin})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*":
                    sev = "ALTO" if creds == "true" else "MÉDIO"
                    self._add(sev, "CORS Permissivo (wildcard)", url=url,
                              access_control_allow_origin="*",
                              allow_credentials=creds or "não definido",
                              detalhe="O servidor permite requisições de qualquer origem.")
                elif evil_origin in acao:
                    sev = "CRÍTICO" if creds == "true" else "ALTO"
                    self._add(sev, "CORS Reflete Origem Arbitrária", url=url,
                              origin_enviado=evil_origin, access_control_allow_origin=acao,
                              allow_credentials=creds or "não definido",
                              detalhe="O servidor reflete a origem do atacante.")
            except Exception:
                continue

    # -- 10. HTTP Method Tampering ------------------------------------------

    def check_http_methods(self):
        self._log("[*] Verificando HTTP Method Tampering...", "info")
        dangerous = ["PUT", "DELETE", "PATCH", "TRACE"]
        urls = list(self.api_endpoints)[:10] or [self.target]

        for url in urls:
            try:
                resp = self.session.options(url, timeout=5)
                allow = resp.headers.get("Allow", "")
                if allow:
                    allowed = [m.strip().upper() for m in allow.split(",")]
                    bad = [m for m in allowed if m in dangerous]
                    if bad:
                        self._add("MÉDIO", "Métodos HTTP Perigosos Permitidos", url=url,
                                  métodos_permitidos=", ".join(bad), header_allow=allow,
                                  detalhe=f"O endpoint permite: {', '.join(bad)}")
            except Exception:
                pass

            for method in dangerous:
                try:
                    resp = self.session.request(method, url, timeout=5,
                                                json={} if method in ("PUT", "PATCH") else None)
                    if resp.status_code not in (405, 404, 501, 403):
                        self._add("MÉDIO", "Método HTTP Inesperado Aceito", url=url,
                                  método=method, status=resp.status_code,
                                  detalhe=f"O endpoint aceitou {method} (status {resp.status_code}).")
                except Exception:
                    continue

    # -- 11. IDOR -----------------------------------------------------------

    def check_idor(self):
        self._log("[*] Verificando IDOR...", "info")
        tested = 0
        max_tests = 10

        for url in list(self.visited | self.api_endpoints):
            if tested >= max_tests:
                break
            parsed = urlparse(url)
            path = parsed.path

            for match in re.finditer(r'/(\d+)(?:/|$)', path):
                if tested >= max_tests:
                    break
                original_id = int(match.group(1))
                if original_id == 0:
                    continue
                try:
                    original_resp = self.session.get(url, timeout=10)
                    if original_resp.status_code != 200:
                        continue
                except Exception:
                    continue

                for delta in [1, -1]:
                    new_id = original_id + delta
                    if new_id < 0:
                        continue
                    new_path = path[:match.start(1)] + str(new_id) + path[match.end(1):]
                    new_url = urlunparse(parsed._replace(path=new_path))
                    try:
                        test_resp = self.session.get(new_url, timeout=10)
                        if (test_resp.status_code == 200
                                and self._is_real_content(test_resp, new_path)
                                and test_resp.text != original_resp.text
                                and len(test_resp.text) > 100):
                            self._add("ALTO", "IDOR - Referência Direta Insegura",
                                      url_original=url, url_testada=new_url,
                                      id_original=original_id, id_testado=new_id,
                                      detalhe="Foi possível acessar dados de outro objeto alterando o ID.")
                            tested += 1
                            break
                    except Exception:
                        continue
                tested += 1

            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                if tested >= max_tests:
                    break
                for val in values:
                    if not val.isdigit():
                        continue
                    original_id = int(val)
                    if original_id == 0:
                        continue
                    try:
                        original_resp = self.session.get(url, timeout=10)
                        if original_resp.status_code != 200:
                            continue
                    except Exception:
                        continue
                    for delta in [1, -1]:
                        new_id = original_id + delta
                        if new_id < 0:
                            continue
                        new_params = dict(params)
                        new_params[param_name] = [str(new_id)]
                        test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                        try:
                            test_resp = self.session.get(test_url, timeout=10)
                            if (test_resp.status_code == 200
                                    and self._is_real_content(test_resp)
                                    and test_resp.text != original_resp.text
                                    and len(test_resp.text) > 100):
                                self._add("ALTO", "IDOR - Referência Direta Insegura",
                                          url_original=url, url_testada=test_url,
                                          parâmetro=param_name, id_original=original_id,
                                          id_testado=new_id,
                                          detalhe="Foi possível acessar dados alterando o ID no parâmetro.")
                                tested += 1
                                break
                        except Exception:
                            continue
                    tested += 1

    # -- 12. Broken Access Control ------------------------------------------

    def check_broken_access_control(self):
        self._log("[*] Verificando Broken Access Control...", "info")
        if not self.has_auth:
            self._log("[!] Pulando: nenhuma autenticação configurada.", "warning")
            return

        unauth = requests.Session()
        unauth.headers.update({"User-Agent": "VulnScanner/2.0 (Authorized Security Test)"})
        unauth.verify = True

        skip_kw = ("login", "signin", "sign-in", "register", "signup", "sign-up",
                    "forgot", "reset", "public", "home", "about", "contact")
        protected = set()
        for url in self.visited | self.api_endpoints:
            path = urlparse(url).path.lower()
            if url in (self.target, self.target + "/"):
                continue
            if any(kw in path for kw in skip_kw):
                continue
            protected.add(url)

        tested = 0
        for url in list(protected)[:20]:
            try:
                resp = unauth.get(url, timeout=10, allow_redirects=False)
                if resp.status_code == 200 and self._is_real_content(resp, urlparse(url).path):
                    auth_resp = self.session.get(url, timeout=10)
                    if (auth_resp.status_code == 200 and len(resp.text) > 100
                            and SequenceMatcher(None, resp.text[:1000],
                                                auth_resp.text[:1000]).quick_ratio() > 0.5):
                        self._add("ALTO", "Broken Access Control", url=url,
                                  status_sem_auth=resp.status_code,
                                  detalhe="Este endpoint retorna conteúdo sem autenticação.")
                        tested += 1
                elif resp.status_code == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "application/json" in ct and len(resp.text) > 2:
                        self._add("ALTO", "Broken Access Control (API)", url=url,
                                  status_sem_auth=resp.status_code, content_type=ct,
                                  detalhe="Este endpoint de API retorna dados JSON sem autenticação.")
                        tested += 1
            except Exception:
                continue
            if tested >= 15:
                break

    # -- 13. Privilege Escalation -------------------------------------------

    def check_privilege_escalation(self):
        self._log("[*] Verificando Escalação de Privilégios...", "info")
        tested = 0
        max_tests = 20

        admin_paths = ["/admin", "/admin/", "/administrator", "/manager",
                       "/dashboard/admin", "/api/admin", "/api/users",
                       "/api/admin/users", "/api/config", "/api/settings"]

        for path in admin_paths:
            if tested >= max_tests:
                break
            url = self.target + path
            if url in self.visited:
                continue
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and self._is_real_content(resp, path):
                    self._add("ALTO", "Possível Painel Admin Acessível", url=url,
                              status=resp.status_code, detalhe=f"O path '{path}' retorna conteúdo real.")
                    tested += 1
            except Exception:
                continue

        role_params = [("role", "admin"), ("role", "administrator"),
                       ("admin", "true"), ("admin", "1"),
                       ("is_admin", "true"), ("is_admin", "1"),
                       ("user_type", "admin"), ("privilege", "admin")]

        for url in list(self.api_endpoints)[:10]:
            if tested >= max_tests:
                break
            parsed = urlparse(url)
            for pname, pval in role_params:
                if tested >= max_tests:
                    break
                ep = parse_qs(parsed.query)
                ep[pname] = [pval]
                test_url = urlunparse(parsed._replace(query=urlencode(ep, doseq=True)))
                try:
                    resp = self.session.get(test_url, timeout=5)
                    if resp.status_code == 200 and self._is_real_content(resp, parsed.path):
                        orig = self.session.get(url, timeout=5)
                        if resp.text != orig.text and len(resp.text) > 100:
                            self._add("ALTO", "Possível Escalação de Privilégio", url=test_url,
                                      parâmetro=f"{pname}={pval}",
                                      detalhe="A adição do parâmetro de admin alterou a resposta.")
                            tested += 1
                            break
                except Exception:
                    continue

    # -- Structured Results -------------------------------------------------

    def get_structured_results(self):
        """Retorna todos os dados do scan como dict serializável."""
        return {
            "target": self.target,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
            "stats": {
                "pages_found": len(self.visited),
                "forms_found": len(self.forms),
                "api_endpoints_found": len(self.api_endpoints),
                "js_files_analyzed": len(self.js_urls),
                "total_findings": len(self.findings),
            },
            "discovery": {
                "pages": sorted(self.visited),
                "api_endpoints": sorted(self.api_endpoints),
                "js_files": sorted(self.js_urls),
                "forms": [
                    {"page_url": url, "method": method, "action": action, "fields": fields,
                     "source": self.dynamic_form_sources.get(action, "html")}
                    for url, method, action, fields in self.forms
                ],
            },
            "findings": [
                {"severity": sev, "category": cat, "details": details}
                for sev, cat, details in sorted(
                    self.findings, key=lambda f: SEVERITY_ORDER.get(f[0], 99))
            ],
        }

    # -- Relatório ----------------------------------------------------------

    def _print_findings(self):
        if not self.findings:
            self._log("=" * 60, "success")
            self._log("  Nenhuma vulnerabilidade encontrada!", "success")
            self._log("=" * 60, "success")
            return

        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f[0], 99))
        self._log("=" * 60, "info")
        self._log(f"  RESULTADOS - {len(self.findings)} vulnerabilidade(s) encontrada(s)", "info")
        self._log("=" * 60, "info")

        for severity, category, details in sorted_findings:
            self._log(f"[{severity}] {category}", "finding")
            for key, val in details.items():
                self._log(f"  {key}: {val}", "finding")
            self._log("", "finding")

    def generate_report(self, output_dir=".", report_id=None):
        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f[0], 99))

        severity_colors_html = {
            "CRÍTICO": "#dc3545", "ALTO": "#e8590c",
            "MÉDIO": "#ffc107", "BAIXO": "#0dcaf0", "INFO": "#6c757d",
        }

        counts = defaultdict(int)
        for sev, _, _ in self.findings:
            counts[sev] += 1

        rows = ""
        for severity, category, details in sorted_findings:
            color = severity_colors_html.get(severity, "#6c757d")
            details_html = ""
            for k, v in details.items():
                val_str = str(v)[:500]
                details_html += f"<strong>{html.escape(str(k))}:</strong> <code>{html.escape(val_str)}</code><br>"
            rows += f"""
            <tr>
                <td><span class="badge" style="background:{color};color:#fff;padding:4px 10px;border-radius:4px">{html.escape(severity)}</span></td>
                <td>{html.escape(category)}</td>
                <td style="font-size:0.9em">{details_html}</td>
            </tr>"""

        summary_items = ""
        for sev in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
            c = counts.get(sev, 0)
            color = severity_colors_html.get(sev, "#6c757d")
            summary_items += f'<span style="color:{color};font-weight:bold;margin-right:20px">{sev}: {c}</span>'

        report_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Relatório - {html.escape(self.target)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #8b949e; }}
  .summary {{ background: #161b22; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #30363d; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; color: #8b949e; text-align: left; padding: 12px; }}
  td {{ padding: 12px; border-top: 1px solid #30363d; vertical-align: top; word-break: break-all; }}
  tr:hover {{ background: #1c2128; }}
  .badge {{ display: inline-block; min-width: 70px; text-align: center; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
  .footer {{ margin-top: 30px; color: #484f58; font-size: 0.85em; text-align: center; }}
  .stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 15px; }}
  .stat-card {{ background: #21262d; padding: 10px 18px; border-radius: 6px; }}
  .stat-card strong {{ color: #58a6ff; }}
</style>
</head>
<body>
<div class="container">
  <h1>Relatório de Vulnerabilidades</h1>
  <p><strong>Alvo:</strong> {html.escape(self.target)}</p>
  <p><strong>Data:</strong> {time.strftime('%d/%m/%Y %H:%M:%S')}</p>
  <div class="stats">
    <div class="stat-card"><strong>{len(self.visited)}</strong> páginas</div>
    <div class="stat-card"><strong>{len(self.forms)}</strong> formulários</div>
    <div class="stat-card"><strong>{len(self.api_endpoints)}</strong> API endpoints</div>
    <div class="stat-card"><strong>{len(self.js_urls)}</strong> arquivos JS</div>
  </div>
  <div class="summary">
    <h2>Resumo</h2>
    <p>{summary_items}</p>
    <p><strong>Total: {len(self.findings)} vulnerabilidade(s)</strong></p>
  </div>
  <table>
    <thead><tr><th style="width:100px">Severidade</th><th style="width:220px">Categoria</th><th>Detalhes</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="3" style="text-align:center;color:#3fb950">Nenhuma vulnerabilidade encontrada!</td></tr>'}</tbody>
  </table>
  <div class="footer"><p>VulnScanner | Uso autorizado apenas.</p></div>
</div>
</body>
</html>"""

        if report_id is None:
            report_id = time.strftime('%Y%m%d_%H%M%S')

        os.makedirs(output_dir, exist_ok=True)

        html_path = os.path.join(output_dir, f"scan_{report_id}.html")
        json_path = os.path.join(output_dir, f"scan_{report_id}.json")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.get_structured_results(), f, ensure_ascii=False, indent=2)

        self._log(f"[+] Relatório salvo em: {html_path}", "success")
        return report_id

    # -- Execução -----------------------------------------------------------

    def run(self):
        auth_type = 'Bearer Token' if 'Authorization' in self.session.headers else \
                    'Session/Cookies' if self.has_auth else 'Nenhuma'
        self._log("=" * 60, "banner")
        self._log("  VulnScanner - Scanner de Vulnerabilidades Web", "banner")
        self._log(f"  Alvo: {self.target}", "banner")
        self._log(f"  Auth: {auth_type}", "banner")
        self._log("=" * 60, "banner")

        self._log("[*] Iniciando crawling inteligente (profundidade 3)...", "info")
        self.crawl()
        self._log(f"[+] {len(self.visited)} página(s) encontrada(s)", "success")
        self._log(f"[+] {len(self.forms)} formulário(s) encontrado(s)", "success")
        self._log(f"[+] {len(self.api_endpoints)} API endpoint(s) descoberto(s) via JS", "success")
        self._log(f"[+] {len(self.js_urls)} arquivo(s) JS analisado(s)", "success")

        self._discover_dynamic_forms()

        self._log("[*] Estabelecendo baseline de resposta...", "info")
        self._get_baseline_response()

        self.check_headers()
        self.check_ssl()
        self.check_cookies()
        self.check_jwt()
        self.check_cors()
        self.check_info_disclosure()
        self.check_xss()
        self.check_sqli()
        self.check_open_redirect()
        self.check_http_methods()
        self.check_idor()
        self.check_broken_access_control()
        self.check_privilege_escalation()

        self._print_findings()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scanner de Vulnerabilidades Web - Uso autorizado apenas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python scanner.py https://meusite.com
  python scanner.py https://meusite.com --token "eyJhbGciOi..."
  python scanner.py https://meusite.com --login-url https://meusite.com/login -u admin -p senha123
        """,
    )
    parser.add_argument("url", help="URL alvo para escanear")
    parser.add_argument("--token", "-t", help="Bearer token para autenticação")
    parser.add_argument("--login-url", help="URL da página de login")
    parser.add_argument("--username", "-u", help="Usuário para login")
    parser.add_argument("--password", "-p", help="Senha para login")

    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    print(f"\n{Fore.YELLOW}[!] AVISO: Use este scanner apenas em sites que você possui")
    print(f"    ou tem autorização explícita para testar.{Style.RESET_ALL}")

    scanner = VulnScanner(
        target_url=args.url, token=args.token,
        login_url=args.login_url, username=args.username, password=args.password,
    )
    scanner.run()
    scanner.generate_report()


if __name__ == "__main__":
    main()
