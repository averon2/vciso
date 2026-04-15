"""
CVE Prioritizer
---------------
Fetches CVEs from CISA KEV and NVD, enriches with EPSS scores,
and outputs a prioritized list.

Sources:
  - CISA KEV  : known exploited vulnerabilities (highest signal)
  - NVD API   : recent CVEs with CVSS scores
  - FIRST EPSS: exploit prediction scores (0–1 probability)

Priority score = KEV (boolean) * 10 + EPSS * 5 + CVSS_normalized * 3

Usage examples:
  python cve_prioritizer.py                         # recent CVEs, no filter
  python cve_prioritizer.py --product openssh       # CVEs for a specific product
  python cve_prioritizer.py --product nginx --days 90 --min-cvss 7.0
  python cve_prioritizer.py --product apache --save apache_cves.json
"""

import argparse
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from tabulate import tabulate

# ── Cache ──────────────────────────────────────────────────────────────────────
CACHE_DIR = Path(__file__).parent / ".cve_cache"
CACHE_DIR.mkdir(exist_ok=True)
CACHE_TTL_HOURS = 6


def _cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.json"


def _load_cache(name: str):
    p = _cache_path(name)
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    age = datetime.now(timezone.utc) - datetime.fromisoformat(data["_cached_at"])
    if age > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return data["payload"]


def _save_cache(name: str, payload):
    p = _cache_path(name)
    p.write_text(json.dumps({"_cached_at": datetime.now(timezone.utc).isoformat(), "payload": payload}))


# ── Fetchers ───────────────────────────────────────────────────────────────────
def fetch_kev() -> dict[str, dict]:
    """Return dict of CVE ID -> KEV metadata (due date, notes, affected product)."""
    cached = _load_cache("kev")
    if cached is not None:
        return cached

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    result = {}
    for v in resp.json().get("vulnerabilities", []):
        result[v["cveID"]] = {
            "product": v.get("product", ""),
            "vendor": v.get("vendorProject", ""),
            "due_date": v.get("dueDate", ""),
            "notes": v.get("notes", ""),
            "action": v.get("requiredAction", ""),
        }
    _save_cache("kev", result)
    return result


def _parse_cve_item(item: dict) -> dict:
    """Parse a raw NVD CVE item into a flat dict."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No description",
    )

    # CVSS: prefer v3.1 > v3.0 > v2
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            entry = metrics[key][0].get("cvssData", {})
            cvss_score = entry.get("baseScore")
            cvss_vector = entry.get("vectorString", "")
            break

    # Fix / patch availability from references
    references = cve.get("references", [])
    patch_url = None
    has_fix = False
    for ref in references:
        tags = [t.lower() for t in ref.get("tags", [])]
        if any(t in tags for t in ("patch", "vendor advisory", "fix", "mitigation")):
            has_fix = True
            if patch_url is None:
                patch_url = ref.get("url", "")

    # Affected versions from configurations CPE data
    affected_versions = _extract_affected_versions(cve.get("configurations", []))

    # vuln status
    vuln_status = cve.get("vulnStatus", "")

    pub_date = cve.get("published", "")[:10]
    mod_date = cve.get("lastModified", "")[:10]

    return {
        "id": cve_id,
        "desc": desc,
        "cvss": cvss_score,
        "vector": cvss_vector,
        "published": pub_date,
        "last_modified": mod_date,
        "vuln_status": vuln_status,
        "has_fix": has_fix,
        "patch_url": patch_url or "",
        "affected_versions": affected_versions,
    }


def _extract_affected_versions(configurations: list) -> str:
    """Pull affected version ranges from CPE configuration data."""
    versions = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                parts = cpe_match.get("criteria", "").split(":")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 6:
                    version = parts[5]
                    v_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                    v_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                    if v_start or v_end:
                        rng = f"{v_start or '*'} – {v_end or '*'}"
                        versions.append(rng)
                    elif version and version not in ("-", "*"):
                        versions.append(version)
    # Deduplicate and limit length
    seen = []
    for v in versions:
        if v not in seen:
            seen.append(v)
    return ", ".join(seen[:5])


def fetch_nvd_recent(days: int = 30, max_results: int = 200) -> list[dict]:
    """Return recent CVEs from NVD (no product filter)."""
    cache_key = f"nvd_{days}d"
    cached = _load_cache(cache_key)
    if cached is not None:
        return cached

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": end.strftime(fmt),
        "resultsPerPage": min(max_results, 2000),
    }
    results = _nvd_fetch(params)
    _save_cache(cache_key, results)
    return results


def fetch_nvd_product(product: str, days: int = 365, max_results: int = 500) -> list[dict]:
    """Return CVEs from NVD matching a product keyword search, filtered client-side by date."""
    safe_key = re.sub(r"[^a-z0-9_]", "_", product.lower())
    cache_key = f"nvd_product_{safe_key}"
    cached = _load_cache(cache_key)
    if cached is not None:
        all_results = cached
    else:
        # NVD does not allow date params combined with keywordSearch — filter client-side
        params = {
            "keywordSearch": product,
            "resultsPerPage": min(max_results, 2000),
        }
        all_results = _nvd_fetch(params)
        _save_cache(cache_key, all_results)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    return [c for c in all_results if c["published"] >= cutoff]


def _nvd_fetch(params: dict) -> list[dict]:
    """Make a single NVD API call and return parsed CVE list."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    resp = requests.get(url, params=params, timeout=60)
    resp.raise_for_status()
    return [_parse_cve_item(item) for item in resp.json().get("vulnerabilities", [])]


def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Return EPSS scores for given CVE IDs (batched, cached)."""
    if not cve_ids:
        return {}

    cached = _load_cache("epss")
    cache = cached if cached is not None else {}

    missing = [c for c in cve_ids if c not in cache]
    if missing:
        batch_size = 30
        for i in range(0, len(missing), batch_size):
            batch = missing[i : i + batch_size]
            try:
                resp = requests.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": ",".join(batch)},
                    timeout=30,
                )
                resp.raise_for_status()
                for entry in resp.json().get("data", []):
                    cache[entry["cve"]] = float(entry.get("epss", 0))
            except Exception:
                pass
            if i + batch_size < len(missing):
                time.sleep(0.5)
        _save_cache("epss", cache)

    return {c: cache.get(c, 0.0) for c in cve_ids}


# ── Prioritization ─────────────────────────────────────────────────────────────
def priority_score(cvss: float | None, epss: float, in_kev: bool) -> float:
    cvss_norm = (cvss or 0) / 10.0
    return (10.0 if in_kev else 0.0) + epss * 5.0 + cvss_norm * 3.0


def severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "N/A"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def fix_label(has_fix: bool, vuln_status: str) -> str:
    if has_fix:
        return "YES"
    if vuln_status in ("Analyzed", "Modified"):
        return "CHECK"
    return "NO"


# ── Output ─────────────────────────────────────────────────────────────────────
def render_table(cves: list[dict], limit: int = 50):
    rows = []
    for c in cves[:limit]:
        rows.append([
            c["id"],
            c["published"],
            severity_label(c["cvss"]),
            f"{c['cvss']:.1f}" if c["cvss"] is not None else "—",
            f"{c['epss'] * 100:.1f}%",
            "YES" if c["kev"] else "",
            fix_label(c["has_fix"], c["vuln_status"]),
            f"{c['priority']:.2f}",
            c["desc"][:75],
        ])

    headers = ["CVE ID", "Published", "Severity", "CVSS", "EPSS%", "KEV", "Fix?", "Score", "Description"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))


def render_detail(cves: list[dict], limit: int = 10):
    """Detailed view for product searches — shows fix info and affected versions."""
    for i, c in enumerate(cves[:limit], 1):
        sev = severity_label(c["cvss"])
        cvss_str = f"{c['cvss']:.1f}" if c["cvss"] is not None else "N/A"
        kev_str = " [ACTIVELY EXPLOITED - KEV]" if c["kev"] else ""
        fix_str = fix_label(c["has_fix"], c["vuln_status"])

        print(f"\n{'-'*80}")
        print(f"#{i}  {c['id']}  |  {sev} (CVSS {cvss_str})  |  EPSS {c['epss']*100:.1f}%  |  Priority {c['priority']:.2f}{kev_str}")
        print(f"    Published : {c['published']}  |  Status: {c['vuln_status']}")
        print(f"    Fix       : {fix_str}", end="")
        if c["patch_url"]:
            print(f"  ->  {c['patch_url']}", end="")
        print()
        if c["affected_versions"]:
            print(f"    Versions  : {c['affected_versions']}")
        if c["kev"]:
            kev_meta = c.get("kev_meta", {})
            if kev_meta.get("action"):
                print(f"    Action    : {kev_meta['action']}")
            if kev_meta.get("due_date"):
                print(f"    CISA Due  : {kev_meta['due_date']}")
        # Wrap description
        desc = c["desc"]
        words = desc.split()
        line, lines = [], []
        for w in words:
            if sum(len(x) + 1 for x in line) + len(w) > 76:
                lines.append("    " + " ".join(line))
                line = [w]
            else:
                line.append(w)
        if line:
            lines.append("    " + " ".join(line))
        print("\n".join(lines))

    print(f"\n{'-'*80}")


def save_json(cves: list[dict], path: str):
    Path(path).write_text(json.dumps(cves, indent=2))
    print(f"\nSaved {len(cves)} CVEs to {path}")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Fetch and prioritize CVEs — optionally filtered to a specific product",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cve_prioritizer.py                          # recent CVEs (last 30 days)
  python cve_prioritizer.py --product openssh        # all CVEs for OpenSSH
  python cve_prioritizer.py --product nginx --days 90 --min-cvss 7.0
  python cve_prioritizer.py --product log4j --save log4j.json
        """,
    )
    parser.add_argument("--product", metavar="NAME", help="Product/software name to search for")
    parser.add_argument("--days", type=int, default=30, help="Lookback window in days (default: 30, product mode: 365)")
    parser.add_argument("--limit", type=int, default=50, help="Rows/items to display (default: 50)")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score filter")
    parser.add_argument("--kev-only", action="store_true", help="Show only KEV (actively exploited) entries")
    parser.add_argument("--detail", action="store_true", help="Detailed view with fix info (auto-enabled for --product)")
    parser.add_argument("--save", metavar="FILE", help="Save full results as JSON")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and re-fetch everything")
    args = parser.parse_args()

    if args.no_cache:
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()

    product_mode = bool(args.product)
    use_detail = args.detail or product_mode
    days = args.days if args.days != 30 or not product_mode else 365

    print(f"[1/4] Fetching CISA KEV list...")
    kev_map = fetch_kev()
    print(f"      {len(kev_map)} known-exploited CVEs loaded")

    if product_mode:
        print(f"[2/4] Searching NVD for '{args.product}' (last {days} days)...")
        nvd_cves = fetch_nvd_product(args.product, days=days)
    else:
        print(f"[2/4] Fetching NVD CVEs (last {days} days)...")
        nvd_cves = fetch_nvd_recent(days=days)
    print(f"      {len(nvd_cves)} CVEs retrieved")

    print(f"[3/4] Fetching EPSS scores...")
    ids = [c["id"] for c in nvd_cves]
    epss_map = fetch_epss(ids)

    print(f"[4/4] Scoring and sorting...\n")
    enriched = []
    for c in nvd_cves:
        if c["cvss"] is not None and c["cvss"] < args.min_cvss:
            continue
        in_kev = c["id"] in kev_map
        if args.kev_only and not in_kev:
            continue
        epss = epss_map.get(c["id"], 0.0)
        score = priority_score(c["cvss"], epss, in_kev)
        enriched.append({
            **c,
            "epss": epss,
            "kev": in_kev,
            "kev_meta": kev_map.get(c["id"], {}),
            "priority": score,
        })

    enriched.sort(key=lambda x: x["priority"], reverse=True)

    # Summary
    kev_count = sum(1 for c in enriched if c["kev"])
    critical = sum(1 for c in enriched if (c["cvss"] or 0) >= 9.0)
    high_epss = sum(1 for c in enriched if c["epss"] >= 0.1)
    with_fix = sum(1 for c in enriched if c["has_fix"])
    no_fix = sum(1 for c in enriched if not c["has_fix"] and (c["cvss"] or 0) >= 7.0)

    if product_mode:
        print(f"  Product    : {args.product}")
    print(f"  Total CVEs : {len(enriched)}")
    print(f"  In KEV     : {kev_count}  (actively exploited — patch immediately)")
    print(f"  Critical   : {critical}  (CVSS >= 9.0)")
    print(f"  High EPSS  : {high_epss}  (>= 10% exploit probability)")
    print(f"  Has Fix    : {with_fix}  |  High/Crit No Fix: {no_fix}\n")

    if not enriched:
        print("No CVEs found matching your criteria.")
        return

    if use_detail:
        render_detail(enriched, limit=args.limit)
    else:
        render_table(enriched, limit=args.limit)

    if args.save:
        save_json(enriched, args.save)


if __name__ == "__main__":
    main()
