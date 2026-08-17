# Bug Bounty Recon Toolkit

Authorized security testing only. A wordlist + true-positive scanner + independent
verifier + PoC generator for endpoint discovery and triage.

## Layout

```
bb-recon-toolkit/
├── scripts/
│   ├── tp_scan.py             memory-optimized true-positive scanner (httpx wrapper + classifier)
│   ├── gen_poc.py             turns confirmed findings into PoC artifacts (poc.md, repro.sh, findings.jsonl)
│   └── verify_agent.py        independent auditor: coverage, correctness, FP-resistance, performance
├── wordlists/
│   ├── bugbounty_paths_wordlist.txt   ~252k path-only entries (CVEs, disclosures, observability, custom)
│   ├── observability_paths.txt        ~1.6k metrics/monitoring paths (Prometheus, Grafana, exporters, …)
│   └── portpath_fuzz_wordlist.txt     :port/path format for port+path fuzzing
└── docs/
    └── verification_report.md         latest independent verification (all checks PASS)
```

## Requirements

- Python 3.8+ (standard library only)
- [httpx](https://github.com/projectdiscovery/httpx) in PATH for live scanning:
  `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`

## Workflow

1) Fuzz for paths with your tool of choice (ffuf, feroxbuster, …) using a wordlist.
   The path-only lists are for `FUZZ`-on-path; the `:port/path` list is for
   port+path fuzzing.

2) Scan collected URLs for true positives (classifies tech stack + response type,
   scores confidence, rejects soft-404 / login-wall / SPA / header-lying noise):

   ```bash
   python3 scripts/tp_scan.py -l urls.txt -o results/ --threads 40 --rate 120
   # or re-classify an existing httpx JSONL without re-scanning:
   python3 scripts/tp_scan.py --from-jsonl httpx_out.jsonl -o results/
   ```

   Outputs (JSONL): tech.jsonl, metrics.jsonl, json_endpoints.jsonl,
   yaml_endpoints.jsonl, txt_endpoints.jsonl, sensitive.jsonl, rejected.jsonl,
   plus summary.txt. Each confirmed record carries `tp_confidence` and `tp_reasons`.

3) Generate PoC artifacts from confirmed findings (read-only GET reproductions):

   ```bash
   python3 scripts/gen_poc.py --results results/ --out poc/ --min-confidence 45 \
       --program "YourProgram (authorized)"
   ```

4) Verify the toolkit any time (exits non-zero on any failure — CI-friendly):

   ```bash
   python3 scripts/verify_agent.py \
       --wordlist wordlists/bugbounty_paths_wordlist.txt wordlists/portpath_fuzz_wordlist.txt \
       --scanner scripts/tp_scan.py \
       --report docs/verification_report.md
   ```

## Notes

- Respect program scope and rate limits. `--rate` defaults are aggressive for
  rate-limited targets; lower them. Filter wordlists to the fingerprinted stack to
  cut request volume and SIEM noise.
- The wordlist contains traversal/LFI probe entries (e.g. Grafana CVE-2021-43798).
  Only fire those against hosts your authorization explicitly covers.
- PoC `curl` commands are deliberately read-only. Keep them that way.
