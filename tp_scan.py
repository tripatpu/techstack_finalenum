#!/usr/bin/env python3
"""
tp_scan.py — memory-optimized true-positive scanner built on top of ProjectDiscovery httpx.

Design
------
httpx (Go) does all the network work: fast, concurrent, HTTP/2, streaming JSONL.
This script:
  1. shells out to httpx with the right probe flags and streams its JSONL to disk
  2. reads that JSONL **line by line** (never json.load the whole file) so memory
     stays flat regardless of input size (millions of URLs are fine)
  3. classifies each record into true-positive buckets by tech stack and by
     response body type (json / yaml / txt / metrics), using cheap signals
     httpx already gives us (content_type, tech, server, status, body_preview)
     plus a tiny bounded read of the body only when a bucket needs confirmation.

Usage
-----
  # from a file of URLs (output of your brute step)
  python3 tp_scan.py -l urls.txt -o results/

  # or pipe them in
  cat urls.txt | python3 tp_scan.py -o results/

  # tune concurrency / rate to respect program limits
  python3 tp_scan.py -l urls.txt -o results/ --threads 40 --rate 120

Outputs (JSONL, one object per line, streamed — never buffered):
  results/all.jsonl            raw httpx records (live hosts only)
  results/tech.jsonl           records with a confirmed tech-stack tag
  results/json_endpoints.jsonl endpoints returning real JSON
  results/yaml_endpoints.jsonl endpoints returning YAML
  results/txt_endpoints.jsonl  endpoints returning plaintext
  results/metrics.jsonl        Prometheus/OpenMetrics exposition endpoints
  results/summary.txt          human-readable counts per bucket/tech

Requires: httpx in PATH  (go install github.com/projectdiscovery/httpx/cmd/httpx@latest)
Only stdlib otherwise.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

# --------------------------------------------------------------------------- #
# httpx invocation
# --------------------------------------------------------------------------- #
# Probes chosen to be cheap but discriminating. body-preview gives us the first
# N chars so most classification needs zero extra requests.
HTTPX_PROBES = [
    "-json",            # JSONL output (one obj per line) -> stream-friendly
    "-silent",
    "-sc",              # status_code
    "-cl",              # content_length
    "-ct",              # content_type
    "-title",
    "-server",          # webserver header
    "-td",              # tech-detect (wappalyzer)
    "-location",
    "-method",
    # NOTE: body inclusion is added in build_httpx_cmd exactly once, with a value.
    # Do NOT also pass the boolean alias -bp here — passing the same flag twice
    # (and mixing boolean + valued forms) can make httpx emit broken/empty JSON,
    # which silently produces zero classified results downstream.
]


def build_httpx_cmd(args):
    cmd = [args.httpx_bin] + HTTPX_PROBES + [
        "-threads", str(args.threads),
        "-rate-limit", str(args.rate),
        "-timeout", str(args.timeout),
        "-retries", str(args.retries),
        "-mc", args.match_codes,          # only keep interesting status codes
        # Response body for content sniffing. -body-preview gives the first N
        # (html-stripped) chars as field "body_preview". If you need the full raw
        # body instead, pass --extra "-irr" (adds "body"/"response").
        "-body-preview", str(args.preview_len),
    ]
    if args.follow_redirects:
        cmd.append("-follow-redirects")
    if args.no_fallback:
        cmd.append("-no-fallback")
    if args.list:
        cmd += ["-l", args.list]
    if args.extra:
        cmd += args.extra.split()
    return cmd


# --------------------------------------------------------------------------- #
# Classification signals
# --------------------------------------------------------------------------- #

# Tech-stack fingerprints. Each entry: (bucket_tag, [substring signals]).
# Signals are matched case-insensitively against a combined haystack built from
# httpx fields (tech list + server + title + url path + body preview). Cheap and
# order-independent; first match wins for the primary tag, but we record all hits.
TECH_SIGNATURES = [
    ("prometheus",   ["# help ", "# type ", "go_gc_duration_seconds", "promhttp",
                      "prometheus_build_info", "prometheus_tsdb_", "server: prometheus"]),
    ("node_exporter",["node_cpu_seconds_total", "node_filesystem_", "node_exporter_build_info"]),
    ("grafana",      ["x-grafana", "grafana_boot", "grafana-app", '"grafanaversion"',
                      "grafanabootdata", "server: grafana"]),
    ("minio",        ["x-minio", "x-amz-request-id", "x-amz-bucket-region",
                      "server: minio", "<code>accessdenied</code>", "minio console"]),
    ("kubernetes",   ["kube-apiserver", "k8s.io", '"kind":"status"', "x-kubernetes",
                      '"apiversion":"v1"', "componentstatus"]),
    ("kubelet",      ["cadvisor_version_info", "kubelet_", "container_cpu_usage_seconds"]),
    ("docker",       ["docker/", "moby/", '"apiversion"', "x-docker",
                      "docker-distribution", '"containers":', "server: docker"]),
    ("docker_registry", ["docker-distribution-api-version", "registry/2.0",
                      '{"repositories":[']),
    ("jira",         ["x-arequestid", "x-ausername", "com.atlassian.jira",
                      "secure/dashboard.jspa", "x-seraph-loginreason", "jira.webresources"]),
    ("confluence",   ["x-confluence-request-time", "confluence-request-time",
                      "com.atlassian.confluence"]),
    ("servicedesk",  ["rest/servicedeskapi", "x-ausername", "servicedesk.webresources"]),
    ("nginx",        ["server: nginx", "active connections:"]),  # stub_status marker
    ("apache",       ["server: apache", "mod_status", "apache server status",
                      "apache/2."]),
    ("php",          ["x-powered-by: php", "phpsessid", "<title>phpinfo()",
                      "set-cookie: phpmyadmin"]),
    ("phpmyadmin",   ["pmaabsoluteuri", "phpmyadmin sql dump", "pma_", "phpmyadmin.css",
                      "<title>phpmyadmin"]),
    ("spring_boot",  ["whitelabel error page", "x-application-context",
                      '"_links":{"self"', 'vnd.spring-boot.actuator']),
    ("elasticsearch",['"cluster_name"', '"lucene_version"', '"number_of_nodes"',
                      "you know, for search"]),
    ("kibana",       ["kbn-name", "kbn-version", "kbn-license-sig"]),
    ("vault",        ["x-vault-", '"sealed":', '"initialized":true', "hashicorp vault"]),
    ("consul",       ["x-consul-", '"consulindex"', "x-consul-index"]),
    ("traefik",      ["x-traefik", '"entrypoints":', "traefik-"]),
    ("gitlab",       ["x-gitlab-", "gitlab-runner", "gon.gitlab_url"]),
    ("jenkins",      ["x-jenkins", "x-hudson", "hudson.model", "jenkins-session"]),
    ("swagger",      ["swagger-ui", '"swagger":"2', '"openapi":"3', "swagger-ui-bundle"]),
    ("graphql",      ['"__schema"', '"data":{"__typename"', "graphiql",
                      '{"errors":[{"message":"must provide query']),
    ("wordpress",    ["wp-content/", "wp-json/", "x-redirect-by: wordpress",
                      "/wp-includes/"]),
    ("django",       ["csrftoken", "__admin_media_prefix__", "csrfmiddlewaretoken"]),
    ("keycloak",     ["kc-", '"realm":', "auth/realms/", "keycloak-identity"]),
]

# Sensitive/high-value content markers -> flag on top of tech tag.
SENSITIVE_MARKERS = [
    ("aws_key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key",  re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt",          re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")),
    ("env_secret",   re.compile(r"(?i)(secret|password|passwd|api[_-]?key|token)\s*[=:]\s*\S{6,}")),
    ("db_conn",      re.compile(r"(?i)(mongodb|postgres|postgresql|mysql|redis)://[^\s\"']+")),
    ("git_config",   re.compile(r"\[core\][\s\S]*repositoryformatversion")),
]

# Prometheus / OpenMetrics exposition-format detector (very high precision).
METRICS_LINE = re.compile(r"(?m)^#\s+(?:HELP|TYPE)\s+\w", re.MULTILINE)
METRICS_SAMPLE = re.compile(r"(?m)^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?\s+[-+]?[0-9.eE]+")


def extract_body(rec):
    """Pull the response body from a httpx JSON record, tolerant of version/flag
    differences. httpx may store it under different keys depending on which body
    flag was used:
      -body-preview        -> "body_preview"
      -irr / -include-response / -sr -> "body" and/or "response" (raw, may include
                              the response headers as a prefixed block)
    We also strip a leading raw-HTTP header block if present so classifiers see
    just the body text.
    """
    for key in ("body_preview", "body", "response", "raw", "response_body"):
        val = rec.get(key)
        if val:
            s = val if isinstance(val, str) else str(val)
            # If this looks like a raw HTTP response (starts with "HTTP/1" or has a
            # header block), split on the first blank line and keep the body part.
            if s.startswith("HTTP/") or ("\r\n\r\n" in s[:2048]):
                parts = s.split("\r\n\r\n", 1)
                if len(parts) == 2:
                    s = parts[1]
                else:
                    parts = s.split("\n\n", 1)
                    if len(parts) == 2:
                        s = parts[1]
            return s
    return ""


def build_haystacks(rec, body):
    """Return (strong, weak) lowercase haystacks.

    strong = signals that come from the SERVER's response: httpx tech-detect list,
             Server header, title, content-type, and the body. A match here is
             trustworthy.
    weak   = the URL/path/input only. A match here means the path is *named* after
             a tech (e.g. /prometheus/metrics, /blog/grafana-tips) which is NOT
             evidence the tech is actually there — it must be corroborated by a
             strong signal or a matching body type before we trust it.
    """
    strong_parts = []
    for k in ("title", "webserver", "content_type", "server"):
        v = rec.get(k)
        if v:
            strong_parts.append(str(v))
    tech = rec.get("tech")
    if isinstance(tech, list):
        strong_parts.extend(tech)
    # httpx may include response headers as a dict/list with -irh
    hdrs = rec.get("header") or rec.get("headers")
    if isinstance(hdrs, dict):
        strong_parts.extend(f"{k}: {v}" for k, v in hdrs.items())
    elif isinstance(hdrs, str):
        strong_parts.append(hdrs)
    if body:
        strong_parts.append(body)

    weak_parts = []
    for k in ("url", "input", "path", "location"):
        v = rec.get(k)
        if v:
            weak_parts.append(str(v))

    return ("\n".join(strong_parts).lower(), "\n".join(weak_parts).lower())


def classify_tech(strong, weak):
    """Return (confirmed, weak_only) tag lists.

    confirmed  = matched in the strong (response) haystack — trustworthy.
    weak_only  = matched ONLY in the URL/path — needs corroboration before use.
    """
    confirmed, weak_only = [], []
    for tag, signals in TECH_SIGNATURES:
        if any(s in strong for s in signals):
            confirmed.append(tag)
        elif any(s in weak for s in signals):
            weak_only.append(tag)
    return confirmed, weak_only


# httpx's own wappalyzer output (the record "tech" list) is authoritative. Map
# its product names to our bucket tags so a wappalyzer hit counts as a strong,
# confirmed signal even when our raw markers don't fire.
HTTPX_TECH_MAP = {
    "prometheus": "prometheus", "node exporter": "node_exporter", "grafana": "grafana",
    "minio": "minio", "kubernetes": "kubernetes", "docker": "docker",
    "docker registry": "docker_registry", "jira": "jira", "atlassian jira": "jira",
    "confluence": "confluence", "jira service management": "servicedesk",
    "nginx": "nginx", "apache": "apache", "apache http server": "apache",
    "php": "php", "phpmyadmin": "phpmyadmin", "spring boot": "spring_boot",
    "spring": "spring_boot", "elasticsearch": "elasticsearch", "kibana": "kibana",
    "vault": "vault", "hashicorp vault": "vault", "consul": "consul",
    "traefik": "traefik", "gitlab": "gitlab", "jenkins": "jenkins",
    "swagger": "swagger", "swagger ui": "swagger", "graphql": "graphql",
    "wordpress": "wordpress", "django": "django", "keycloak": "keycloak",
}


def classify_tech_full(rec, strong, weak):
    """Combine raw-marker matching with httpx wappalyzer names. Returns
    (confirmed, weak_only) where wappalyzer hits are always confirmed (strong)."""
    confirmed, weak_only = classify_tech(strong, weak)
    tech_list = rec.get("tech")
    if isinstance(tech_list, list):
        for name in tech_list:
            tag = HTTPX_TECH_MAP.get(str(name).strip().lower())
            if tag and tag not in confirmed:
                confirmed.append(tag)
                if tag in weak_only:
                    weak_only.remove(tag)
    return confirmed, weak_only


def sniff_body_type(rec, body):
    """
    Return one of: 'metrics', 'json', 'yaml', 'txt', or None.
    Uses content_type first (cheap), then a bounded body sniff for confirmation
    so we don't trust content_type alone (misconfigured servers lie constantly).
    """
    ct = (rec.get("content_type") or "").lower()
    url = (rec.get("url") or rec.get("input") or "").lower().split("?")[0]
    b = (body or "").strip()

    # 1. Prometheus/OpenMetrics exposition — highest precision, check first.
    if ("openmetrics" in ct or "text/plain" in ct or not ct) and b:
        if METRICS_LINE.search(b) or (b.startswith("#") and METRICS_SAMPLE.search(b)):
            return "metrics"

    # 2. JSON — confirm it actually parses (bounded) rather than trusting header.
    if "json" in ct or b[:1] in "{[":
        if _looks_like_json(b):
            return "json"

    # 3. Known-plaintext file extensions and formats win before the YAML kv
    #    heuristic — robots.txt / .txt / .log / .csv etc. use "key: value"-ish
    #    lines that would otherwise false-positive as YAML.
    PLAINTEXT_EXT = (".txt", ".log", ".csv", ".md", ".ini", ".conf", ".cfg", ".properties")
    KNOWN_TXT = ("robots.txt", "security.txt", "humans.txt", "ads.txt", ".well-known/")
    if url.endswith(PLAINTEXT_EXT) or any(k in url for k in KNOWN_TXT):
        if b and _mostly_printable(b):
            return "txt"

    # 4. YAML — explicit header, .yml/.yaml extension, or structural sniff.
    if ("yaml" in ct or "yml" in ct or url.endswith((".yml", ".yaml"))
            or _looks_like_yaml(b)):
        return "yaml"

    # 5. Generic plaintext fallback — but require real substance. A lone comment
    #    line or a near-empty body on a path NOT ending in a plaintext extension is
    #    almost always a placeholder/soft response, not a finding. Exception:
    #    health/status endpoints legitimately return short tokens ("ok", "UP").
    if ("text/plain" in ct or ct == "") and b and _mostly_printable(b):
        stripped = b.strip()
        non_comment = [ln for ln in stripped.splitlines()
                       if ln.strip() and not ln.lstrip().startswith("#")]
        is_known_txt_path = url.endswith(PLAINTEXT_EXT) or any(k in url for k in KNOWN_TXT)
        HEALTH_PATH = ("health", "healthz", "livez", "readyz", "ready", "live",
                       "ping", "status", "alive", "-/healthy", "-/ready")
        is_health_path = any(url.rstrip("/").endswith(h) for h in HEALTH_PATH)
        HEALTH_TOKENS = ("ok", "up", "healthy", "ready", "alive", "pong", "true",
                         "running", "ok\n", "success")
        is_health_token = stripped.lower() in HEALTH_TOKENS or \
            (len(stripped) <= 20 and is_health_path)
        # accept if: known txt path, health endpoint w/ token, >=2 substantive
        # lines, or a single long substantive line (>=40 chars).
        if (is_known_txt_path or is_health_token or len(non_comment) >= 2
                or (len(non_comment) == 1 and len(non_comment[0]) >= 40)):
            return "txt"
        return None

    return None


def _looks_like_json(b):
    if not b or b[0] not in "{[":
        return False
    snippet = b[:4096]  # bounded — never parse megabytes
    try:
        json.loads(snippet)
        return True
    except Exception:
        # partial preview may be truncated; accept clear structural start + key:val
        return bool(re.match(r'^\s*[\[{]\s*["\d\[{tfn-]', snippet))


def _looks_like_yaml(b):
    if not b:
        return False
    lines = b[:1024].splitlines()
    kv = sum(1 for ln in lines if re.match(r"^[A-Za-z0-9_.-]+\s*:\s*", ln))
    doc = any(ln.strip() in ("---", "...") for ln in lines)
    return doc or kv >= 2


def _mostly_printable(b):
    sample = b[:512]
    if not sample:
        return False
    printable = sum(1 for c in sample if c.isprintable() or c in "\n\r\t")
    return printable / len(sample) > 0.9


def scan_sensitive(body):
    if not body:
        return []
    hits = []
    sample = body[:8192]  # bounded scan
    for tag, rx in SENSITIVE_MARKERS:
        if rx.search(sample):
            hits.append(tag)
    return hits


# --------------------------------------------------------------------------- #
# False-positive hardening
# --------------------------------------------------------------------------- #
# A 200 OK means almost nothing on its own: soft-404 pages, SPA catch-all routes,
# WAF interstitials and login walls all return 200 with HTML. We score each
# candidate on multiple independent signals and reject low-confidence noise.

SOFT_404_MARKERS = [
    "not found", "404", "page not found", "does not exist", "no encontrado",
    "sign in", "log in", "login", "please authenticate", "authentication required",
    "access denied", "forbidden", "unauthorized", "session expired",
    "cloudflare", "attention required", "captcha", "are you human",
    "coming soon", "under construction", "default page", "it works!",
    "welcome to nginx", "apache2 ubuntu default", "test page",
]
# Content-type expected per body bucket — used to catch header/body mismatch.
EXPECTED_CT = {
    "metrics": ("text/plain", "openmetrics", "application/openmetrics"),
    "json":    ("json",),
    "yaml":    ("yaml", "yml", "text/plain", "text/vnd.yaml", "application/x-yaml"),
    "txt":     ("text/plain", "text/",),
}
LOGIN_WALL_SIGNS = [
    'name="password"', 'type="password"', 'name="username"', 'id="login"',
    "csrf", "oauth", "saml", "sso", "j_security_check", "signin", "sign-in",
]


def assess_true_positive(rec, body, btype, tech_hits, sens, strong_tech=None):
    """
    Return (is_tp, confidence[0..100], reasons[list]).
    Combines status code, content-type coherence, content-length sanity, and
    body-content evidence. Designed to reject the classic 200-OK false positives.
    strong_tech: tech tags confirmed by a response signal (Server/title/body/httpx),
                 as opposed to URL-path-only guesses — these justify keeping an
                 otherwise-empty health endpoint.
    """
    strong_tech = strong_tech or []
    reasons = []
    score = 0
    status = rec.get("status_code")
    ct = (rec.get("content_type") or "").lower()
    clen = rec.get("content_length")
    b = (body or "")
    bl = b.lower().strip()

    # --- status code weighting ---------------------------------------------
    if status == 200:
        score += 20; reasons.append("status:200")
    elif status in (401, 403):
        # auth-gated: interesting (endpoint exists) but not an open TP
        score += 10; reasons.append(f"status:{status}:auth-gated")
    elif status in (301, 302, 307, 308):
        score += 5; reasons.append(f"status:{status}:redirect")
    elif status in (500, 503):
        score += 8; reasons.append(f"status:{status}:server-error")
    elif status in (204,):
        score += 12; reasons.append("status:204:no-content")
    else:
        reasons.append(f"status:{status}")

    # --- empty body sanity --------------------------------------------------
    empty = (not bl) or (isinstance(clen, int) and clen == 0)
    if empty and btype != "metrics" and not strong_tech:
        # empty 200 with no server-confirmed tech -> almost always noise.
        # (A URL-path-only tech guess does NOT rescue an empty body.)
        reasons.append("empty-body")
        return (False, max(0, score - 15), reasons)

    # --- soft-404 / login wall / WAF detection ------------------------------
    is_htmlish = ("html" in ct) or bl.startswith("<!doctype") or bl.startswith("<html")
    soft_hit = next((m for m in SOFT_404_MARKERS if m in bl[:600]), None)
    login_hit = any(s in bl[:2000] for s in LOGIN_WALL_SIGNS)

    # If the body type we care about is data (metrics/json/yaml) but the page is
    # HTML, that's a strong soft-404/redirect-to-login signal.
    if btype in ("metrics", "json", "yaml") and is_htmlish:
        reasons.append("data-expected-but-html")
        score -= 25
    if soft_hit and btype != "txt":
        reasons.append(f"soft404:{soft_hit}")
        score -= 20
    if login_hit and not (sens or btype == "metrics"):
        reasons.append("login-wall")
        score -= 15

    # --- content-type coherence --------------------------------------------
    if btype:
        want = EXPECTED_CT.get(btype, ())
        if want and ct and not any(w in ct for w in want):
            reasons.append(f"ct-mismatch:{ct.split(';')[0]}")
            score -= 10
        elif want and any(w in ct for w in want):
            score += 15; reasons.append("ct-coherent")

    # --- positive body evidence per bucket ---------------------------------
    if btype == "metrics":
        # require at least one real HELP/TYPE line OR several metric samples;
        # a lone stray '#' is not enough.
        help_lines = len(re.findall(r"(?m)^#\s+(?:HELP|TYPE)\s+\w", b))
        sample_lines = len(re.findall(
            r"(?m)^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?\s+[-+]?[0-9.eE]", b))
        if help_lines >= 1 or sample_lines >= 3:
            score += 40; reasons.append(f"metrics-evidence:help={help_lines},samples={sample_lines}")
        else:
            reasons.append("weak-metrics-evidence")
            score -= 20
    elif btype == "json":
        score += 25; reasons.append("json-parsed")
    elif btype == "yaml":
        score += 15; reasons.append("yaml-structure")
    elif btype == "txt":
        score += 10; reasons.append("plaintext")

    # --- tech / sensitive corroboration ------------------------------------
    if tech_hits:
        strong_hits = [t for t in tech_hits if t in strong_tech]
        weak_hits = [t for t in tech_hits if t not in strong_tech]
        if strong_hits:
            score += min(30, 15 * len(strong_hits))
            reasons.append(f"tech-strong:{','.join(strong_hits)}")
        if weak_hits:
            score += min(10, 4 * len(weak_hits))
            reasons.append(f"tech-weak:{','.join(weak_hits)}")
    if sens:
        score += 25; reasons.append(f"sensitive:{','.join(sens)}")

    # --- content-length plausibility ---------------------------------------
    if isinstance(clen, int):
        if clen > 20:
            score += 5
        if btype == "json" and clen < 3:
            score -= 10; reasons.append("json-too-small")

    score = max(0, min(100, score))
    has_strong_tech = any(t in strong_tech for t in tech_hits)
    # Decision threshold:
    if status in (401, 403) and (has_strong_tech or sens):
        is_tp = True                      # auth-gated but server-confirmed
    elif btype == "metrics":
        is_tp = score >= 50
    elif btype in ("json", "yaml", "txt"):
        is_tp = score >= 45
    elif has_strong_tech:
        is_tp = score >= 35               # response-confirmed tech (e.g. empty health)
    elif tech_hits or sens:
        is_tp = score >= 40 and bool(sens)  # weak-only tech w/o body -> needs a secret
    else:
        is_tp = False
    return (is_tp, score, reasons)


# --------------------------------------------------------------------------- #
# Streaming pipeline
# --------------------------------------------------------------------------- #

class Writers:
    """Lazily-opened line writers so we don't create empty files or hold buffers."""
    def __init__(self, outdir):
        self.outdir = outdir
        self._fh = {}

    def write(self, name, obj):
        fh = self._fh.get(name)
        if fh is None:
            fh = open(os.path.join(self.outdir, name), "w", encoding="utf-8")
            self._fh[name] = fh
        fh.write(json.dumps(obj, separators=(",", ":")) + "\n")

    def close(self):
        for fh in self._fh.values():
            fh.close()


def process_stream(line_iter, writers, counters):
    """Consume httpx JSONL line-by-line. Flat memory: one record at a time.
    Every candidate is scored by assess_true_positive; only findings that clear
    the confidence bar land in the true-positive buckets. Low-confidence hits go
    to rejected.jsonl with their reasons so nothing is silently dropped."""
    for line in line_iter:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("failed"):
            continue

        counters["live"] += 1
        writers.write("all.jsonl", rec)

        body = extract_body(rec)
        if not body:
            counters["no_body"] += 1
        strong, weak = build_haystacks(rec, body)

        confirmed_tech, weak_tech = classify_tech_full(rec, strong, weak)
        btype = sniff_body_type(rec, body)
        sens = scan_sensitive(body)

        # Infra web-server tags (nginx/apache) are ubiquitous and not findings on
        # their own — they only corroborate. Strip them from the set that can
        # *drive* a finding.
        INFRA = {"nginx", "apache"}
        confirmed_meaningful = [t for t in confirmed_tech if t not in INFRA]

        # Corroboration rule: a URL-only ("weak") tech tag is trusted only if the
        # response itself backs it up — a real data body type, or a sensitive hit.
        # Otherwise a path merely NAMED after a tech (/prometheus/metrics,
        # /blog/grafana-tips) is dropped.
        corroborated = bool(btype in ("metrics", "json", "yaml")) or bool(sens)
        if corroborated:
            tech_hits = confirmed_meaningful + [t for t in weak_tech
                                                if t not in confirmed_meaningful]
        else:
            tech_hits = confirmed_meaningful

        # nothing meaningful detected -> skip (bare nginx/apache HTML soft-404)
        if not (tech_hits or btype or sens):
            continue

        is_tp, confidence, reasons = assess_true_positive(
            rec, body, btype, tech_hits, sens, strong_tech=confirmed_meaningful)
        if weak_tech and not corroborated:
            reasons.append(f"dropped-weak-tech:{','.join(weak_tech)}")

        rec_out = _slim(rec)
        rec_out["tp_confidence"] = confidence
        rec_out["tp_reasons"] = reasons
        if tech_hits:
            rec_out["tp_tech"] = tech_hits
        if btype:
            rec_out["tp_type"] = btype
        if sens:
            rec_out["tp_sensitive"] = sens

        if not is_tp:
            counters["rejected"] += 1
            writers.write("rejected.jsonl", rec_out)
            continue

        # --- confirmed true positives, routed by kind ---
        if tech_hits:
            writers.write("tech.jsonl", rec_out)
            for t in tech_hits:
                counters["tech"][t] += 1
        if btype:
            counters["btype"][btype] += 1
            fname = {
                "metrics": "metrics.jsonl",
                "json":    "json_endpoints.jsonl",
                "yaml":    "yaml_endpoints.jsonl",
                "txt":     "txt_endpoints.jsonl",
            }[btype]
            writers.write(fname, rec_out)
        if sens:
            counters["sensitive"] += 1
            writers.write("sensitive.jsonl", rec_out)
        counters["confirmed"] += 1


def _slim(rec):
    """Keep only the useful fields so output files stay small."""
    keep = ("url", "input", "status_code", "content_type", "content_length",
            "webserver", "title", "tech", "location", "method", "port", "scheme")
    return {k: rec[k] for k in keep if k in rec}


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Memory-optimized true-positive scanner over httpx JSONL.")
    ap.add_argument("-l", "--list", help="input file of URLs (else read stdin)")
    ap.add_argument("-o", "--out", default="tp_results", help="output directory")
    ap.add_argument("--httpx-bin", default="httpx", help="path to httpx binary")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--rate", type=int, default=150, help="requests/sec (respect program limits)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--preview-len", type=int, default=512, help="body-preview chars for sniffing")
    ap.add_argument("--match-codes", default="200,201,204,301,302,401,403,405,500",
                    help="httpx -mc list; keep interesting codes only")
    ap.add_argument("--follow-redirects", action="store_true")
    ap.add_argument("--no-fallback", action="store_true",
                    help="probe both http+https instead of auto-fallback")
    ap.add_argument("--extra", default="", help="extra raw flags passed to httpx")
    ap.add_argument("--from-jsonl", help="skip httpx; classify an existing httpx JSONL file")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    writers = Writers(args.out)
    counters = {"live": 0, "sensitive": 0, "confirmed": 0, "rejected": 0, "no_body": 0,
                "tech": Counter(), "btype": Counter()}

    try:
        if args.from_jsonl:
            # Re-classify an existing httpx run without re-scanning the network.
            with open(args.from_jsonl, "r", encoding="utf-8", errors="replace") as fh:
                process_stream(fh, writers, counters)
        else:
            if not shutil.which(args.httpx_bin):
                sys.exit(f"[!] httpx not found at '{args.httpx_bin}'. "
                         f"Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            cmd = build_httpx_cmd(args)
            stdin = None
            if not args.list:
                if sys.stdin.isatty():
                    sys.exit("[!] No -l file and nothing on stdin.")
                stdin = sys.stdin
            print(f"[*] httpx: {' '.join(cmd)}", file=sys.stderr)
            proc = subprocess.Popen(
                cmd,
                stdin=(stdin if stdin else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=1,               # line-buffered: true streaming
                text=True,
            )
            # Stream httpx stdout directly — never accumulate in memory.
            process_stream(proc.stdout, writers, counters)
            proc.wait()
    finally:
        writers.close()

    # Summary
    summary_path = os.path.join(args.out, "summary.txt")
    with open(summary_path, "w", encoding="utf-8") as s:
        s.write(f"live hosts:          {counters['live']}\n")
        s.write(f"records w/o body:    {counters['no_body']}\n")
        s.write(f"confirmed TPs:       {counters['confirmed']}\n")
        s.write(f"rejected (low-conf): {counters['rejected']}\n")
        s.write(f"sensitive hits:      {counters['sensitive']}\n\n")
        # Diagnostic: if most records had no body, content classification cannot
        # work. This is the #1 cause of "zero output" and it is almost always a
        # missing httpx body flag upstream.
        if counters["live"] and counters["no_body"] >= counters["live"] * 0.9:
            s.write("!! WARNING: ~all records had NO response body.\n")
            s.write("   Content classification (json/yaml/txt/metrics) needs the body.\n")
            s.write("   Re-run httpx WITH a body flag, e.g.:\n")
            s.write("     httpx -l urls.txt -json -sc -cl -ct -title -server -td \\\n")
            s.write("           -body-preview 512 -o httpx_out.jsonl\n")
            s.write("   then: tp_scan.py --from-jsonl httpx_out.jsonl -o results/\n\n")
        s.write("== response body types (confirmed) ==\n")
        for t, c in counters["btype"].most_common():
            s.write(f"  {t:10s} {c}\n")
        s.write("\n== tech stacks (confirmed true positives) ==\n")
        for t, c in counters["tech"].most_common():
            s.write(f"  {t:16s} {c}\n")
    with open(summary_path, "r", encoding="utf-8") as s:
        sys.stderr.write("\n" + s.read())
    print(f"\n[*] Results in {args.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
