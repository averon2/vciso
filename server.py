"""
CVE Prioritizer — Web Server
Serves the dark-mode frontend and exposes /api/scan
"""

import re
import sys
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

# Import shared logic from cve_prioritizer
sys.path.insert(0, str(Path(__file__).parent))
from cve_prioritizer import (
    fetch_kev,
    fetch_nvd_product,
    fetch_epss,
    priority_score,
    severity_label,
    fix_label,
)

app = Flask(__name__, static_folder="static")


# ── Version matching ──────────────────────────────────────────────────────────
def _parse_ver(v: str):
    """Parse version string into tuple of ints, ignoring non-numeric suffixes."""
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        return None


def version_affected(user_version: str, affected_str: str) -> bool | None:
    """
    Returns True if user_version falls within affected ranges.
    Returns None if we can't determine (no version data).
    """
    if not affected_str or not user_version:
        return None

    uv = _parse_ver(user_version)
    if uv is None:
        return None

    # Each segment is either "X.Y.Z" (exact) or "X – Y" (range)
    for segment in affected_str.split(","):
        segment = segment.strip()
        if " - " in segment or " \u2013 " in segment:
            parts = re.split(r"\s*[-\u2013]\s*", segment, maxsplit=1)
            lo_str, hi_str = parts[0].strip(), parts[1].strip()
            lo = _parse_ver(lo_str) if lo_str not in ("*", "") else None
            hi = _parse_ver(hi_str) if hi_str not in ("*", "") else None
            if (lo is None or uv >= lo) and (hi is None or uv <= hi):
                return True
        else:
            ev = _parse_ver(segment)
            if ev is not None and uv == ev:
                return True

    return False


# ── API ────────────────────────────────────────────────────────────────────────
@app.get("/api/scan")
def scan():
    product = (request.args.get("product") or "").strip()
    version = (request.args.get("version") or "").strip()

    if not product:
        return jsonify({"error": "product is required"}), 400

    try:
        kev_map = fetch_kev()
        nvd_cves = fetch_nvd_product(product)
        ids = [c["id"] for c in nvd_cves]
        epss_map = fetch_epss(ids)
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    enriched = []
    for c in nvd_cves:
        in_kev = c["id"] in kev_map
        epss = epss_map.get(c["id"], 0.0)
        score = priority_score(c["cvss"], epss, in_kev)

        # Version relevance
        ver_match = None
        if version:
            ver_match = version_affected(version, c.get("affected_versions", ""))

        enriched.append({
            "id": c["id"],
            "published": c["published"],
            "severity": severity_label(c["cvss"]),
            "cvss": c["cvss"],
            "epss": round(epss * 100, 2),
            "kev": in_kev,
            "kev_meta": kev_map.get(c["id"], {}),
            "fix": fix_label(c["has_fix"], c["vuln_status"]),
            "patch_url": c["patch_url"],
            "affected_versions": c["affected_versions"],
            "vuln_status": c["vuln_status"],
            "desc": c["desc"],
            "priority": round(score, 2),
            "version_affected": ver_match,  # True / False / None
        })

    enriched.sort(key=lambda x: (
        # If version given: affected vulns first, then unknown, then not-affected
        {"True": 0, "None": 1, "False": 2}.get(str(x["version_affected"]), 1),
        -x["priority"],
    ))

    stats = {
        "total": len(enriched),
        "kev": sum(1 for c in enriched if c["kev"]),
        "critical": sum(1 for c in enriched if (c["cvss"] or 0) >= 9.0),
        "high_epss": sum(1 for c in enriched if c["epss"] >= 10),
        "has_fix": sum(1 for c in enriched if c["fix"] == "YES"),
        "version_affected": sum(1 for c in enriched if c["version_affected"] is True) if version else None,
    }

    return jsonify({"product": product, "version": version, "stats": stats, "cves": enriched})


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    print("CVE Prioritizer running at http://localhost:5000")
    app.run(debug=False, port=5000)
