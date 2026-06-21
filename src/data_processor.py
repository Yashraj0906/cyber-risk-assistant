"""Data Processor Module

Joins all data sources into a single enriched DataFrame (114 rows x 41 columns).

Join chain:
  vulnerabilities.csv (114 rows, main table)
    + assets.csv on asset_id -> adds asset_type, environment, internet_exposed, edr_installed
    + business_services.csv on business_service -> adds revenue_impact, compliance_scope, rto_hours
    + threat_intelligence.csv on CVE -> adds threat_actor, campaign_name, ransomware_association
    + CISA KEV on CVE -> adds kev_confirmed (bool), kev_ransomware (Known/Unknown)

Not all 114 vulns will have threat intel or KEV matches — that's expected.
The ones that DO match score higher in the risk scoring engine (Phase 2).
"""
import pandas as pd
from src.data_loader import (
    load_assets,
    load_vulnerabilities,
    load_threat_intelligence,
    load_business_services,
    fetch_cisa_kev,
)


def build_enriched_dataframe():
    """Join all data sources into a single enriched DataFrame.
    
    Join chain:
      vulnerabilities (114 rows)
        + assets (on asset_id) -> adds asset_type, environment, internet_exposed, etc.
        + business_services (on business_service via assets) -> adds revenue_impact, compliance_scope, etc.
        + threat_intelligence (on CVE) -> adds threat_actor, ransomware_association, etc.
        + CISA KEV (on CVE) -> adds kev_confirmed, kev_ransomware columns
    """
    vulns = load_vulnerabilities()
    assets = load_assets()
    threat = load_threat_intelligence()
    biz = load_business_services()
    kev = fetch_cisa_kev()

    # Step 1: vulns + assets on asset_id
    df = vulns.merge(assets, on="asset_id", how="left", suffixes=("", "_asset"))

    # Step 2: merge with business_services on business_service (comes from assets)
    df = df.merge(biz, on="business_service", how="left", suffixes=("", "_biz"))

    # Step 3: merge with threat_intelligence on CVE
    # threat_intel has matched_cve_or_control which can be a CVE or a NIST control ID
    # we only want CVE matches here
    threat_cve = threat[threat["matched_cve_or_control"].str.startswith("CVE-", na=False)]
    threat_cve = threat_cve.rename(columns={"matched_cve_or_control": "cve"})

    # a single CVE can have multiple threat intel matches, take the highest confidence one
    threat_cve = threat_cve.sort_values("confidence", ascending=False)
    threat_cve = threat_cve.drop_duplicates(subset=["cve"], keep="first")

    df = df.merge(
        threat_cve[["cve", "threat_actor", "campaign_name", "exploit_maturity",
                     "ransomware_association", "confidence", "summary"]],
        on="cve",
        how="left",
        suffixes=("", "_threat"),
    )

    # Step 4: cross-reference with CISA KEV on CVE
    kev_lookup = kev[["cveID", "knownRansomwareCampaignUse"]].rename(
        columns={"cveID": "cve", "knownRansomwareCampaignUse": "kev_ransomware"}
    )
    df = df.merge(kev_lookup, on="cve", how="left")
    df["kev_confirmed"] = df["kev_ransomware"].notna()
    df["kev_ransomware"] = df["kev_ransomware"].fillna("Unknown")

    return df


if __name__ == "__main__":
    df = build_enriched_dataframe()
    print(f"Enriched DataFrame: {df.shape[0]} rows x {df.shape[1]} columns")
    print(f"\nColumns: {list(df.columns)}")
    print(f"\nKEV confirmed: {df['kev_confirmed'].sum()} vulnerabilities")
    print(f"Has threat actor: {df['threat_actor'].notna().sum()} vulnerabilities")
    print(f"\nSample row:")
    row = df.loc[df["kev_confirmed"]].iloc[0]
    for col in ["vulnerability_name", "cve", "cvss", "asset_name", "internet_exposed",
                 "business_service", "threat_actor", "kev_confirmed", "kev_ransomware"]:
        print(f"  {col}: {row[col]}")
