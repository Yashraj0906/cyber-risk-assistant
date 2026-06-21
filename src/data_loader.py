"""Data Loader Module

Loads all data sources needed for risk analysis:
- Local: 6 files from data/ folder (CSVs + threat report markdown)
- External: CISA KEV catalog (JSON from cisa.gov) and NIST SP 800-53 controls (JSON from NIST GitHub)

External data is cached in data/cache/ after first download to avoid repeated network calls.
NIST controls are parsed from the OSCAL JSON format into flat dicts with control_id, name, description, guidance.
"""
import os
import json
import pandas as pd
import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
CACHE_DIR = os.path.join(DATA_DIR, "cache")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"


def load_assets():
    return pd.read_csv(os.path.join(DATA_DIR, "assets.csv"))


def load_vulnerabilities():
    return pd.read_csv(os.path.join(DATA_DIR, "vulnerabilities.csv"))


def load_threat_intelligence():
    return pd.read_csv(os.path.join(DATA_DIR, "threat_intelligence.csv"))


def load_business_services():
    return pd.read_csv(os.path.join(DATA_DIR, "business_services.csv"))


def load_remediation_guidance():
    return pd.read_csv(os.path.join(DATA_DIR, "remediation_guidance.csv"))


def load_threat_report():
    path = os.path.join(DATA_DIR, "synthetic_threat_report.md")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _fetch_with_cache(url, cache_filename):
    """Download JSON from url, cache locally so we don't re-download every run."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, cache_filename)

    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    return data


def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog.
    Returns a DataFrame with columns: cveID, knownRansomwareCampaignUse, etc.
    """
    data = _fetch_with_cache(CISA_KEV_URL, "cisa_kev.json")
    return pd.DataFrame(data["vulnerabilities"])


def fetch_nist_controls():
    """Fetch NIST SP 800-53 Rev 5 controls from the OSCAL JSON catalog.
    Returns a list of dicts with: control_id, control_name, family, family_id, description, guidance.
    """
    data = _fetch_with_cache(NIST_URL, "nist_sp800_53.json")
    groups = data["catalog"]["groups"]

    controls = []
    for group in groups:
        family_id = group.get("id", "").upper()
        family_name = group.get("title", "")

        for control in group.get("controls", []):
            parsed = _parse_control(control, family_id, family_name)
            if parsed:
                controls.append(parsed)

            # control enhancements (sub-controls like AC-2(1))
            for enhancement in control.get("controls", []):
                parsed = _parse_control(enhancement, family_id, family_name)
                if parsed:
                    controls.append(parsed)

    return controls


def _parse_control(control, family_id, family_name):
    """Extract id, title, description and guidance from a single NIST control."""
    control_id = _get_label(control)
    title = control.get("title", "")

    parts = control.get("parts", [])
    description = ""
    guidance = ""

    for part in parts:
        if part.get("name") == "statement":
            description = _extract_prose(part)
        elif part.get("name") == "guidance":
            guidance = part.get("prose", "")

    if not description and not guidance:
        return None

    return {
        "control_id": control_id,
        "control_name": title,
        "family_id": family_id,
        "family_name": family_name,
        "description": description,
        "guidance": guidance,
    }


def _get_label(control):
    """Get the human-readable label like 'AC-2' from control props."""
    for prop in control.get("props", []):
        if prop.get("name") == "label" and "class" not in prop:
            return prop["value"]
    return control.get("id", "").upper()


def _extract_prose(part):
    """Recursively extract all prose text from a control's statement parts."""
    texts = []
    if part.get("prose"):
        texts.append(part["prose"])
    for sub in part.get("parts", []):
        texts.extend([_extract_prose(sub)])
    return " ".join(t for t in texts if t)


if __name__ == "__main__":
    print("Loading local data...")
    assets = load_assets()
    vulns = load_vulnerabilities()
    threat = load_threat_intelligence()
    biz = load_business_services()
    remediation = load_remediation_guidance()
    report = load_threat_report()

    print(f"  Assets: {len(assets)} rows")
    print(f"  Vulnerabilities: {len(vulns)} rows")
    print(f"  Threat Intel: {len(threat)} rows")
    print(f"  Business Services: {len(biz)} rows")
    print(f"  Remediation: {len(remediation)} rows")
    print(f"  Threat Report: {len(report)} chars")

    print("\nFetching CISA KEV...")
    kev = fetch_cisa_kev()
    print(f"  KEV entries: {len(kev)}")

    print("\nFetching NIST SP 800-53...")
    nist = fetch_nist_controls()
    print(f"  NIST controls: {len(nist)}")
    print(f"  Sample: {nist[1]['control_id']} - {nist[1]['control_name']}")
    print(f"  Description: {nist[1]['description'][:150]}...")
    print(f"  Guidance: {nist[1]['guidance'][:150]}...")
