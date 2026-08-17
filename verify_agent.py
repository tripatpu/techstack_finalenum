#!/usr/bin/env python3
"""
verify_agent.py — an INDEPENDENT auditor for a bug-bounty recon toolkit.

It does NOT import or trust the scanner's own logic. It re-derives expectations
from first principles and checks the deliverables against them, then reports
pass/fail with evidence and concrete gaps.

Three audits:
  A. WORDLIST COVERAGE  — does the path list cover the categories that actually
     pay out in bug bounty? Measures presence, depth, and blind spots.
  B. SCANNER CORRECTNESS — feed the scanner a synthetic "ground-truth" corpus
     where we KNOW the right answer for every record, then score precision/recall
     per bucket (tech, metrics, json, yaml, txt, sensitive). This catches both
     false negatives (missed finds) and false positives (noise).
  C. SCANNER PERFORMANCE — measure peak RSS and throughput as input scales, and
     verify memory stays flat (streaming) rather than growing with input size.

Usage:
  python3 verify_agent.py --wordlist PATH --scanner PATH [--report report.md]
"""

import argparse, json, os, re, resource, subprocess, sys, tempfile, time
from collections import Counter, defaultdict

# ===========================================================================
# AUDIT A — WORDLIST COVERAGE
# ===========================================================================
# Independent expectation model: categories that produce real bug-bounty payouts,
# each with representative probe substrings we EXPECT to find in a "complete" list.
# These were chosen from disclosed-report patterns, not copied from the generator.
COVERAGE_MODEL = {
    # --- observability / metrics ecosystem (expanded) ---
    "core_metrics":       ["metrics", "actuator/prometheus", "federate"],
    "prometheus_admin":   ["-/healthy", "-/ready", "-/reload", "api/v1/status/config"],
    "prometheus_api":     ["api/v1/query", "api/v1/targets", "api/v1/rules"],
    "prom_pprof":         ["debug/pprof/heap", "debug/pprof/goroutine"],
    "exporters":          ["node_exporter/metrics", "blackbox_exporter/metrics",
                           "redis_exporter/metrics", "cadvisor/metrics"],
    "pushgateway":        ["pushgateway/metrics", "metrics/job/"],
    "alertmanager":       ["alertmanager/api/v2/status", "alertmanager/api/v2/silences",
                           "alertmanager/api/v1/alerts"],
    "grafana_api":        ["grafana/api/health", "api/datasources", "api/admin/settings",
                           "api/dashboards/home"],
    "grafana_ssrf_lfi":   ["api/datasources/proxy/1", "public/plugins/graph/../../../../../../../../etc/passwd"],
    "thanos_cortex":      ["thanos/api/v1/query", "cortex/ring", "mimir/config"],
    "victoriametrics":    ["victoriametrics/metrics", "vmui/", "vm/api/v1/query"],
    "loki_tempo":         ["loki/api/v1/query", "loki/ready", "tempo/api/search"],
    "tracing":            ["jaeger/api/services", "zipkin/api/v2/services"],
    "graphite_influx":    ["graphite/render", "influxdb/query", "influxdb/debug/vars"],
    "tsdb_misc":          ["opentsdb/", "netdata/api/v1/info", "api/put"],
    "apm_beacons":        ["datadog/api/v1/series", "intake/v2/rum/events", "api/store/"],
    "k8s_metrics":        ["stats/summary", "apis/metrics.k8s.io/v1beta1/nodes",
                           "metrics/cadvisor"],
    "health_family":      ["healthz", "readyz", "livez", "health/liveness"],
    # --- original high-value bug bounty categories (retained) ---
    "secrets_env":        [".env", ".env.production", ".env.bak"],
    "git_exposure":       [".git/config", ".git/HEAD", ".git/logs/head"],
    "vcs_other":          [".svn/entries", ".hg/store", ".bzr"],
    "backups_archive":    ["backup.zip", "backup.sql", "dump.sql", "www.zip"],
    "cloud_creds":        [".aws/credentials", ".kube/config", "kubeconfig"],
    "iac_state":          ["terraform.tfstate", "docker-compose.yml", "values.yaml"],
    "spring_actuator":    ["actuator/env", "actuator/heapdump", "actuator/gateway/routes"],
    "spring_jolokia":     ["jolokia", "jolokia/list"],
    "swagger_openapi":    ["swagger.json", "openapi.json", "api-docs", "v3/api-docs"],
    "graphql":            ["graphql", "graphiql", "___graphql"],
    "k8s_api":            ["api/v1/namespaces", "healthz", "readyz", "openapi/v2"],
    "kubelet":            ["stats/summary", "pods", "runningpods"],
    "docker_registry":    ["v2/_catalog", "v2/tags/list", "containers/json"],
    "minio":              ["minio/health/live", "minio/admin/v3/info"],
    "phpmyadmin":         ["phpmyadmin/index.php", "phpmyadmin/setup/index.php"],
    "php_info":           ["phpinfo.php", "info.php"],
    "nginx_status":       ["nginx_status", "stub_status", "server-status"],
    "jira":               ["secure/dashboard.jspa", "rest/api/2/serverinfo",
                           "secure/querycomponent!default.jspa"],
    "jira_sd":            ["rest/servicedeskapi/info", "servicedesk/customer/portal/1"],
    "confluence_cve":     ["pages/createpage-entervariables.action", "template/aui/"],
    "weblogic_cve":       ["wls-wsat/coordinatorporttype", "_async/asyncresponseservice"],
    "f5_citrix_cve":      ["mgmt/tm/util/bash", "tmui/login.jsp", "vpns/cfg/smb.conf"],
    "exchange_cve":       ["autodiscover/autodiscover.json", "ecp/ddi/ddiservice.svc/getobject"],
    "vpn_cve":            ["dana-na/auth/url_default/welcome.cgi", "remote/login"],
    "laravel_cve":        ["_ignition/execute-solution", "storage/logs/laravel.log"],
    "wordpress":          ["wp-login.php", "wp-json/wp/v2/users", "xmlrpc.php"],
    "drupal":             ["user/login", "changelog.txt", "core/install.php"],
    "elasticsearch":      ["_cat/indices", "_cluster/health", "_search"],
    "vault_consul":       ["v1/sys/health", "v1/sys/seal-status", "consul/v1/kv/"],
    "jenkins":            ["script", "scripttext", "asynchpeople/"],
    "gitlab":             ["users/sign_in", "api/graphql", "explore/projects"],
    "wellknown":          [".well-known/security.txt", ".well-known/openid-configuration"],
    "traversal_lfi":      ["etc/passwd", "web-inf/web.xml", "proc/self/environ"],
    "aem":                ["crx/de/index.jsp", "system/console/bundles", "bin/querybuilder.json"],
}

# High-value categories whose absence is a serious gap (weighted).
CRITICAL = {
    "secrets_env", "git_exposure", "swagger_openapi", "graphql",
    "spring_actuator", "k8s_api", "docker_registry", "jira",
    "core_metrics", "prometheus_api", "grafana_api", "alertmanager",
    "exporters", "health_family",
}


def audit_wordlist(paths):
    """paths: str or list of str. Coverage is checked against the UNION of all
    supplied lists (a real toolkit uses several lists together). Probe matching
    is substring-based: a probe counts as covered if it appears anywhere inside
    any entry (handles :port/path prefixes, traversal prefixes, etc.)."""
    if isinstance(paths, str):
        paths = [paths]
    result = {"paths": paths, "categories": {}, "stats": {}}
    existing = [p for p in paths if p and os.path.exists(p)]
    if not existing:
        result["error"] = "no wordlist found"
        return result

    total = 0
    lowered_seen = set()       # unique full entries (lowered)
    dup = 0
    bad_format = 0
    scheme_or_host = 0
    lengths = []
    # We need substring search across all entries. To keep memory bounded on huge
    # lists we do a two-pass approach: pass 1 collects a big joined blob PER FILE
    # in chunks and tests probes incrementally, so we never hold all entries as
    # separate objects beyond the dedup set. For the sizes here (~250k) the set
    # is fine; the joined-haystack test is done per line to stay streaming.
    # lowercase probes so matching against lowered entries is truly case-insensitive
    probe_hits = {p.lower(): False for probes in COVERAGE_MODEL.values() for p in probes}
    pending = set(probe_hits)   # probes still unmatched — shrinks as we go

    n_len = 0
    len_sum = 0
    for path in existing:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                e = line.rstrip("\n")
                if not e:
                    continue
                total += 1
                low = e.lower()
                if low in lowered_seen:
                    dup += 1
                else:
                    lowered_seen.add(low)
                if "://" in e:
                    scheme_or_host += 1
                if e.startswith("/"):
                    bad_format += 1
                n_len += 1
                len_sum += len(e)
                # only test probes not yet found; remove on hit so the set shrinks
                if pending:
                    matched = [p for p in pending if p in low]
                    for p in matched:
                        probe_hits[p] = True
                        pending.discard(p)
    lengths = [len_sum / n_len] if n_len else [0]  # avg only, no per-line list

    for cat, probes in COVERAGE_MODEL.items():
        found = [p for p in probes if probe_hits[p.lower()]]
        result["categories"][cat] = {
            "expected": len(probes),
            "found": len(found),
            "missing": [p for p in probes if not probe_hits[p.lower()]],
            "critical": cat in CRITICAL,
        }

    covered = sum(1 for c in result["categories"].values() if c["found"] > 0)
    fully = sum(1 for c in result["categories"].values() if c["found"] == c["expected"])
    crit_gaps = [cat for cat, c in result["categories"].items()
                 if c["critical"] and c["found"] == 0]

    result["stats"] = {
        "total_entries": total,
        "unique_entries": len(lowered_seen),
        "duplicates": dup,
        "leading_slash": bad_format,
        "scheme_or_host_leak": scheme_or_host,
        "avg_len": round(lengths[0], 1) if lengths else 0,
        "categories_total": len(COVERAGE_MODEL),
        "categories_touched": covered,
        "categories_full": fully,
        "critical_gaps": crit_gaps,
    }
    return result


# ===========================================================================
# AUDIT B — SCANNER CORRECTNESS (precision / recall on labeled corpus)
# ===========================================================================
# Build a synthetic httpx-style JSONL where every record carries a hidden
# ground-truth label. We then run the scanner and check what it put in each
# bucket. The scanner never sees the labels.

def build_labeled_corpus(n_noise=2000):
    """Return (list_of_httpx_records, list_of_expected_labels_per_record)."""
    records = []
    labels = []  # each: dict(tech=set, btype=str|None, sensitive=set)

    def rec(url, ct, body, tech=None, server="", status=200, title=""):
        return {
            "url": url, "input": url, "status_code": status,
            "content_type": ct, "content_length": len(body),
            "webserver": server, "title": title,
            "tech": tech or [], "method": "GET",
            "body_preview": body[:512], "failed": False,
        }

    # --- POSITIVE cases with known labels ---
    cases = [
        # metrics
        (rec("https://a/metrics", "text/plain; version=0.0.4",
             "# HELP go_gc_duration_seconds x\n# TYPE go_gc_duration_seconds summary\ngo_gc_duration_seconds{quantile=\"0\"} 1e-05",
             ["Prometheus"]),
         {"tech": {"prometheus"}, "btype": "metrics", "sensitive": set()}),
        (rec("https://a/node/metrics", "text/plain",
             "# HELP node_cpu_seconds_total x\n# TYPE node_cpu_seconds_total counter\nnode_cpu_seconds_total{cpu=\"0\"} 12345.6"),
         {"tech": {"node_exporter", "prometheus"}, "btype": "metrics", "sensitive": set()}),
        # json
        (rec("https://a/api/users", "application/json",
             '{"users":[{"id":1,"name":"a"}]}', ["Nginx"], server="nginx"),
         {"tech": {"nginx"}, "btype": "json", "sensitive": set()}),
        (rec("https://a/v2/_catalog", "application/json",
             '{"repositories":["app","db"]}', server="registry"),
         {"tech": {"docker_registry"}, "btype": "json", "sensitive": set()}),
        (rec("https://a/actuator/env", "application/vnd.spring-boot.actuator.v3+json",
             '{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment"}]}',
             ["Spring"]),
         {"tech": {"spring_boot"}, "btype": "json", "sensitive": set()}),
        # yaml
        (rec("https://a/config.yml", "text/plain",
             "server:\n  host: 0.0.0.0\n  port: 8080\napi_key: LIVEsecret999"),
         {"tech": set(), "btype": "yaml", "sensitive": {"env_secret"}}),
        (rec("https://a/swagger.yaml", "application/yaml",
             "openapi: 3.0.0\ninfo:\n  title: API\npaths:\n  /x: {}"),
         {"tech": set(), "btype": "yaml", "sensitive": set()}),
        # txt (must NOT be yaml despite colons)
        (rec("https://a/robots.txt", "text/plain",
             "User-agent: *\nDisallow: /admin\nDisallow: /api"),
         {"tech": set(), "btype": "txt", "sensitive": set()}),
        (rec("https://a/.well-known/security.txt", "text/plain",
             "Contact: mailto:sec@x\nExpires: 2026-01-01T00:00:00Z"),
         {"tech": set(), "btype": "txt", "sensitive": set()}),
        # sensitive
        (rec("https://a/.env", "text/plain",
             "DB_PASSWORD=SuperSecret123\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
         {"tech": set(), "btype": "txt", "sensitive": {"aws_key", "env_secret"}}),
        (rec("https://a/.git/config", "text/plain",
             "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@x:y.git"),
         {"tech": set(), "btype": "txt", "sensitive": {"git_config"}}),
        (rec("https://a/id_rsa", "text/plain",
             "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"),
         {"tech": set(), "btype": "txt", "sensitive": {"private_key"}}),
        (rec("https://a/token", "application/json",
             '{"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"}'),
         {"tech": set(), "btype": "json", "sensitive": {"jwt"}}),
        # tech via markers
        (rec("https://a/secure/Dashboard.jspa", "text/html",
             "<html><title>System Dashboard - Jira</title>", ["Atlassian Jira"],
             server="nginx", title="System Dashboard - Jira"),
         {"tech": {"jira", "nginx"}, "btype": None, "sensitive": set()}),
        (rec("https://a/minio/health/live", "text/plain", "",
             server="MinIO", tech=["MinIO"]),
         {"tech": {"minio"}, "btype": None, "sensitive": set()}),
        (rec("https://a/healthz", "text/plain", "ok",
             tech=["Kubernetes"], server="kube-apiserver"),
         {"tech": {"kubernetes"}, "btype": "txt", "sensitive": set()}),
        (rec("https://a/", "text/html", "<html>phpMyAdmin login</html>",
             ["phpMyAdmin", "PHP"], server="Apache", title="phpMyAdmin"),
         {"tech": {"phpmyadmin", "php", "apache"}, "btype": None, "sensitive": set()}),
    ]
    for r, lab in cases:
        records.append(r); labels.append(lab)

    # --- NEGATIVE/noise: plain HTML pages that should NOT populate tech/type/sensitive
    for i in range(n_noise):
        r = rec(f"https://noise{i}/page", "text/html",
                "<html><body>Welcome to our marketing site</body></html>",
                server="cloudflare")
        records.append(r)
        labels.append({"tech": set(), "btype": None, "sensitive": set()})

    return records, labels


# Which tech tags the scanner emits that we treat as "expected noise-tolerant":
# server headers like nginx/apache legitimately tag many records; we score the
# *primary* high-value techs strictly and allow infra tags as non-penalized.
INFRA_TAGS = {"nginx", "apache"}


def run_scanner_on_corpus(scanner_path, records):
    tmpdir = tempfile.mkdtemp(prefix="verify_")
    corpus = os.path.join(tmpdir, "corpus.jsonl")
    with open(corpus, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    outdir = os.path.join(tmpdir, "out")
    subprocess.run([sys.executable, scanner_path, "--from-jsonl", corpus, "-o", outdir],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)

    def load(name):
        p = os.path.join(outdir, name)
        rows = []
        if os.path.exists(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
        return rows

    got = {
        "tech": {r["url"]: set(r.get("tp_tech", [])) for r in load("tech.jsonl")},
        "metrics": {r["url"] for r in load("metrics.jsonl")},
        "json": {r["url"] for r in load("json_endpoints.jsonl")},
        "yaml": {r["url"] for r in load("yaml_endpoints.jsonl")},
        "txt": {r["url"] for r in load("txt_endpoints.jsonl")},
        "sensitive": {r["url"]: set(r.get("tp_sensitive", [])) for r in load("sensitive.jsonl")},
    }
    return got, tmpdir


def score_correctness(records, labels, got):
    # Per-bucket confusion for body type
    btype_buckets = ["metrics", "json", "yaml", "txt"]
    conf = {b: Counter() for b in btype_buckets}  # tp, fp, fn
    for r, lab in zip(records, labels):
        url = r["url"]
        exp = lab["btype"]
        for b in btype_buckets:
            in_got = url in got[b]
            if exp == b and in_got:
                conf[b]["tp"] += 1
            elif exp == b and not in_got:
                conf[b]["fn"] += 1
            elif exp != b and in_got:
                conf[b]["fp"] += 1

    # Tech recall on high-value tags (ignore infra tags for recall strictness)
    tech_tp = tech_fn = 0
    tech_detail = []
    for r, lab in zip(records, labels):
        url = r["url"]
        exp_tech = {t for t in lab["tech"] if t not in INFRA_TAGS}
        got_tech = got["tech"].get(url, set())
        for t in exp_tech:
            if t in got_tech:
                tech_tp += 1
            else:
                tech_fn += 1
                tech_detail.append((url, t))

    # Sensitive precision/recall
    sens_tp = sens_fn = sens_fp = 0
    sens_detail = []
    for r, lab in zip(records, labels):
        url = r["url"]
        exp = lab["sensitive"]
        got_s = got["sensitive"].get(url, set())
        for t in exp:
            if t in got_s:
                sens_tp += 1
            else:
                sens_fn += 1
                sens_detail.append(("MISS", url, t))
        for t in got_s:
            if t not in exp:
                sens_fp += 1
                sens_detail.append(("FP", url, t))

    return {
        "btype": conf,
        "tech": {"tp": tech_tp, "fn": tech_fn, "misses": tech_detail},
        "sensitive": {"tp": sens_tp, "fn": sens_fn, "fp": sens_fp, "detail": sens_detail},
    }


# ===========================================================================
# AUDIT C — PERFORMANCE (flat-memory + throughput at scale)
# ===========================================================================
def audit_performance(scanner_path, sizes=(10000, 50000, 200000)):
    rows = []
    tmpdir = tempfile.mkdtemp(prefix="perf_")
    for n in sizes:
        corpus = os.path.join(tmpdir, f"c{n}.jsonl")
        with open(corpus, "w") as f:
            base = json.dumps({
                "url": "https://h/api", "status_code": 200,
                "content_type": "application/json", "body_preview": '{"ok":true}',
                "tech": ["Nginx"], "failed": False,
            })
            # vary url per line cheaply
            for i in range(n):
                f.write(base.replace('"https://h/api"', f'"https://h{i}/api"') + "\n")
        outdir = os.path.join(tmpdir, f"o{n}")
        t = time.time()
        p = subprocess.run([sys.executable, scanner_path, "--from-jsonl", corpus, "-o", outdir],
                           stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        el = time.time() - t
        # peak RSS of the child we just ran (RUSAGE_CHILDREN accumulates; take delta-ish)
        rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024.0  # MB
        rows.append({"n": n, "seconds": round(el, 2),
                     "rate": int(n / el) if el else 0, "peak_child_rss_mb": round(rss, 1)})
    return rows


# ===========================================================================
# AUDIT D — FALSE-POSITIVE RESISTANCE
# ===========================================================================
# Feed the scanner records that a naive "200 == hit" tool would wrongly flag.
# Every one of these MUST be rejected (absent from all true-positive buckets).
def build_fp_traps():
    def rec(url, ct, body, status=200, clen=None, tech=None, server="nginx"):
        b = body
        return {
            "url": url, "input": url, "status_code": status,
            "content_type": ct, "content_length": len(b) if clen is None else clen,
            "webserver": server, "title": "", "tech": tech or [],
            "method": "GET", "body_preview": b[:512], "failed": False,
        }, url

    traps = []
    # soft-404 HTML served with 200 at a metrics-looking path
    traps.append(rec("https://t/metrics", "text/html",
                     "<!doctype html><html><title>404 Not Found</title>"
                     "<body>The page you requested was not found</body></html>"))
    # SPA catch-all: every path returns the app shell with 200
    traps.append(rec("https://t/actuator/env", "text/html",
                     "<!doctype html><html><div id=app></div>"
                     "<script src=/main.js></script></html>", clen=4200))
    # login wall returned as 200
    traps.append(rec("https://t/api/admin", "text/html",
                     "<html><form>Please sign in"
                     "<input type=\"password\" name=\"password\"></form></html>", clen=1800))
    # WAF/Cloudflare interstitial
    traps.append(rec("https://t/api/v1/query", "text/html",
                     "<html><title>Attention Required! | Cloudflare</title>"
                     "Please enable cookies. Are you human?</html>", clen=2400,
                     server="cloudflare"))
    # empty 200
    traps.append(rec("https://t/health", "text/plain", "", clen=0))
    # metrics path but body is just a stray comment, not real exposition
    traps.append(rec("https://t/prometheus/metrics", "text/plain",
                     "# this page intentionally left blank"))
    # JSON content-type but body is an HTML error (header lies)
    traps.append(rec("https://t/config.json", "application/json",
                     "<html><body>500 Internal Server Error</body></html>", clen=120))
    # "default page" of a fresh web server
    traps.append(rec("https://t/status", "text/html",
                     "<html><body>Welcome to nginx! It works!</body></html>", clen=600))
    # marketing homepage that mentions the word 'grafana' but isn't
    traps.append(rec("https://t/blog/grafana-tips", "text/html",
                     "<html><body>Our blog post about grafana best practices</body>"
                     "</html>", clen=3000))
    return traps


def audit_fp_resistance(scanner_path):
    records = [r for r, _ in build_fp_traps()]
    urls = [u for _, u in build_fp_traps()]
    got, tmp = run_scanner_on_corpus(scanner_path, records)
    # a trap "leaks" if it shows up in any TP bucket
    tp_urls = set()
    for k in ("metrics", "json", "yaml", "txt"):
        tp_urls |= set(got[k])
    tp_urls |= set(got["tech"].keys())
    tp_urls |= set(got["sensitive"].keys())
    leaked = [u for u in urls if u in tp_urls]
    return {"total_traps": len(urls), "leaked": leaked,
            "rejected": len(urls) - len(leaked)}


# ===========================================================================
# REPORT
# ===========================================================================
def grade(cond):
    return "PASS" if cond else "FAIL"


def build_report(wl, corr, perf, fp):
    L = []
    L.append("# Independent Verification Report")
    L.append("_Generated by verify_agent.py — an auditor with its own detection "
             "model, independent of the scanner's logic._\n")

    # ---- A. Wordlist ----
    L.append("## A. Wordlist Coverage\n")
    if wl.get("error"):
        L.append(f"**ERROR:** {wl['error']}\n")
    else:
        s = wl["stats"]
        L.append(f"- Entries: **{s['total_entries']:,}** total, "
                 f"**{s['unique_entries']:,}** unique "
                 f"({s['duplicates']:,} case-insensitive dups)")
        L.append(f"- Format hygiene: leading-slash lines **{s['leading_slash']}**, "
                 f"scheme/host leaks **{s['scheme_or_host_leak']}** "
                 f"→ {grade(s['leading_slash']==0 and s['scheme_or_host_leak']==0)}")
        L.append(f"- Category coverage: **{s['categories_touched']}/{s['categories_total']}** "
                 f"touched, **{s['categories_full']}** fully covered")
        if s["critical_gaps"]:
            L.append(f"- **CRITICAL GAPS:** {', '.join(s['critical_gaps'])} → FAIL")
        else:
            L.append(f"- Critical categories: all present → PASS")
        L.append("\n### Category detail\n")
        L.append("| Category | Found/Expected | Critical | Missing probes |")
        L.append("|---|---|---|---|")
        for cat, c in sorted(wl["categories"].items(),
                             key=lambda kv: (not kv[1]["critical"], kv[0])):
            miss = ", ".join(c["missing"][:3]) + ("…" if len(c["missing"]) > 3 else "")
            star = "★" if c["critical"] else ""
            L.append(f"| {cat} {star} | {c['found']}/{c['expected']} | "
                     f"{'yes' if c['critical'] else ''} | {miss or '—'} |")
        L.append("")

    # ---- B. Correctness ----
    L.append("## B. Scanner Correctness (labeled corpus)\n")
    L.append("Body-type classification (precision on known-labeled endpoints):\n")
    L.append("| Bucket | TP | FP | FN | Verdict |")
    L.append("|---|---|---|---|---|")
    all_ok = True
    for b, c in corr["btype"].items():
        ok = c["fp"] == 0 and c["fn"] == 0
        all_ok &= ok
        L.append(f"| {b} | {c['tp']} | {c['fp']} | {c['fn']} | {grade(ok)} |")
    L.append("")
    t = corr["tech"]
    tech_ok = t["fn"] == 0
    L.append(f"Tech-stack recall (high-value tags): **{t['tp']} hit / {t['fn']} missed** "
             f"→ {grade(tech_ok)}")
    if t["misses"]:
        L.append("  - misses: " + ", ".join(f"{u.split('//')[-1]}→{tag}"
                                             for u, tag in t["misses"][:8]))
    s = corr["sensitive"]
    sens_ok = s["fn"] == 0 and s["fp"] == 0
    L.append(f"\nSensitive-marker detection: **{s['tp']} TP, {s['fp']} FP, {s['fn']} FN** "
             f"→ {grade(sens_ok)}")
    if s["detail"]:
        L.append("  - " + "; ".join(f"{k}:{u.split('//')[-1]}:{tag}"
                                    for k, u, tag in s["detail"][:8]))
    L.append("")

    # ---- C. Performance ----
    L.append("## C. Scanner Performance\n")
    L.append("| Records | Time (s) | Rate (rec/s) | Peak child RSS (MB) |")
    L.append("|---|---|---|---|")
    for r in perf:
        L.append(f"| {r['n']:,} | {r['seconds']} | {r['rate']:,} | {r['peak_child_rss_mb']} |")
    # flat-memory check: RSS at largest size should not be wildly larger than smallest
    if len(perf) >= 2:
        lo, hi = perf[0]["peak_child_rss_mb"], perf[-1]["peak_child_rss_mb"]
        growth = (hi / lo) if lo else 999
        input_growth = perf[-1]["n"] / perf[0]["n"]
        flat = growth < 2.0  # memory <2x while input grew Nx
        L.append(f"\nInput grew **{input_growth:.0f}×** ({perf[0]['n']:,}→{perf[-1]['n']:,}); "
                 f"peak RSS grew **{growth:.2f}×**. "
                 f"Flat-memory streaming → {grade(flat)}")
    L.append("")

    # ---- D. False-positive resistance ----
    L.append("## D. False-Positive Resistance\n")
    L.append(f"Fed **{fp['total_traps']}** classic false-positive traps "
             f"(soft-404 HTML at data paths, SPA catch-all, login walls, WAF "
             f"interstitials, empty 200s, header-lying JSON, default server pages).\n")
    fp_ok = len(fp["leaked"]) == 0
    L.append(f"- Rejected: **{fp['rejected']}/{fp['total_traps']}** → {grade(fp_ok)}")
    if fp["leaked"]:
        L.append(f"- **LEAKED (wrongly flagged):** "
                 + ", ".join(u.split('//')[-1] for u in fp["leaked"]))
    L.append("")

    # ---- Verdict ----
    L.append("## Overall Verdict\n")
    wl_ok = (not wl.get("error")) and not wl["stats"]["critical_gaps"] \
        and wl["stats"]["leading_slash"] == 0 and wl["stats"]["scheme_or_host_leak"] == 0
    verdicts = {
        "Wordlist coverage & hygiene": wl_ok,
        "Body-type classification": all_ok,
        "Tech-stack recall": tech_ok,
        "Sensitive detection": sens_ok,
        "False-positive resistance": fp_ok,
        "Flat-memory performance": (perf[-1]["peak_child_rss_mb"] / perf[0]["peak_child_rss_mb"] < 2.0)
        if len(perf) >= 2 else True,
    }
    for k, v in verdicts.items():
        L.append(f"- {k}: **{grade(v)}**")
    L.append("")
    return "\n".join(L), verdicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", required=True, nargs="+",
                    help="one or more wordlist files; coverage checked across the union")
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--report", default="verification_report.md")
    ap.add_argument("--perf-sizes", default="10000,50000,200000")
    args = ap.parse_args()

    print("[*] Audit A: wordlist coverage…", file=sys.stderr)
    wl = audit_wordlist(args.wordlist)

    print("[*] Audit B: scanner correctness on labeled corpus…", file=sys.stderr)
    records, labels = build_labeled_corpus()
    got, tmp = run_scanner_on_corpus(args.scanner, records)
    corr = score_correctness(records, labels, got)

    print("[*] Audit C: performance & flat-memory…", file=sys.stderr)
    sizes = tuple(int(x) for x in args.perf_sizes.split(","))
    perf = audit_performance(args.scanner, sizes)

    print("[*] Audit D: false-positive resistance…", file=sys.stderr)
    fp = audit_fp_resistance(args.scanner)

    report, verdicts = build_report(wl, corr, perf, fp)
    with open(args.report, "w") as f:
        f.write(report)
    print(report)
    print(f"\n[*] Report written to {args.report}", file=sys.stderr)
    # exit non-zero if any critical verdict failed
    sys.exit(0 if all(verdicts.values()) else 1)


if __name__ == "__main__":
    main()
