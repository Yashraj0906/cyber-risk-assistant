"""Risk Scoring Engine

Scores each of the 114 vulnerabilities using weighted factors and returns the top 5.

The key design decision: CVSS is one factor among many (only 0-5 points out of ~100).
A CVSS-10 on an internal dev server with no active threat scores LOWER than
a CVSS-8 on an internet-facing production VPN with ransomware campaigns and KEV confirmation.

Scoring factors:
  Internet-exposed asset:     25 pts  (from assets.csv)
  Exploit available:          20 pts  (from vulnerabilities.csv + threat_intel exploit_maturity)
  Confirmed in CISA KEV:      15 pts  (from KEV cross-reference)
  Ransomware associated:      15 pts  (from threat_intel + KEV ransomware field)
  Critical business service:  10 pts  (from business_services.csv revenue_impact)
  Compliance scope:            5 pts  (from business_services.csv)
  No EDR installed:            5 pts  (from assets.csv)
  Production environment:      3 pts  (from assets.csv)
  CVSS normalized:           0-5 pts  (from vulnerabilities.csv)
  Customer-facing service:     2 pts  (from business_services.csv)

Output: Top 5 risks, each with a score breakdown and all supporting evidence.
"""
import pandas as pd
from src.data_processor import build_enriched_dataframe


def score_vulnerabilities(df):
    """Apply weighted scoring to each vulnerability row. Returns df with score columns added."""
    df = df.copy()

    # Internet-exposed: 25 pts
    df["pts_internet_exposed"] = (df["internet_exposed"] == "Yes").astype(int) * 25

    # Exploit available or weaponized: 20 pts
    df["pts_exploit"] = 0
    df.loc[df["exploit_available"] == "Yes", "pts_exploit"] = 15
    df.loc[df["exploit_maturity"] == "Weaponized", "pts_exploit"] = 20
    df.loc[df["exploit_maturity"] == "PoC Available", "pts_exploit"] = df["pts_exploit"].clip(lower=10)

    # KEV confirmed: 15 pts
    df["pts_kev"] = df["kev_confirmed"].astype(int) * 15

    # Ransomware associated: 15 pts (from either threat intel or KEV)
    df["pts_ransomware"] = 0
    df.loc[df["ransomware_association"] == "Yes", "pts_ransomware"] = 15
    df.loc[df["kev_ransomware"] == "Known", "pts_ransomware"] = 15

    # Critical business service: 10 pts
    df["pts_business"] = 0
    df.loc[df["revenue_impact"] == "Critical", "pts_business"] = 10
    df.loc[df["revenue_impact"] == "High", "pts_business"] = 7
    df.loc[df["revenue_impact"] == "Medium", "pts_business"] = 4

    # Compliance scope: 5 pts
    df["pts_compliance"] = 0
    df.loc[df["compliance_scope"].notna() & (df["compliance_scope"] != "None"), "pts_compliance"] = 5

    # No EDR: 5 pts (missing endpoint protection = higher risk)
    df["pts_no_edr"] = (df["edr_installed"] == "No").astype(int) * 5

    # Production environment: 3 pts
    df["pts_production"] = (df["environment"] == "Production").astype(int) * 3

    # CVSS normalized to 0-5 range
    df["pts_cvss"] = (df["cvss"].fillna(0) / 10 * 5).round(1)

    # Customer-facing: 2 pts
    df["pts_customer_facing"] = (df["customer_facing"] == "Yes").astype(int) * 2

    # Total score
    score_cols = [c for c in df.columns if c.startswith("pts_")]
    df["risk_score"] = df[score_cols].sum(axis=1)

    return df


def get_top_risks(df, n=5):
    """Score all vulnerabilities, rank them, return top n with evidence bundles."""
    scored = score_vulnerabilities(df)

    # sort by score desc, then cvss desc for tiebreaking, then days_open desc
    scored = scored.sort_values(
        by=["risk_score", "cvss", "days_open"],
        ascending=[False, False, False]
    )

    # deduplicate by CVE — keep only the highest scoring instance of each CVE
    # otherwise the same CVE on two VPN gateways would take up 2 of our top 5 slots
    scored = scored.drop_duplicates(subset=["cve"], keep="first")

    top = scored.head(n).copy()
    top["rank"] = range(1, n + 1)

    # build evidence bundles
    results = []
    score_cols = [c for c in top.columns if c.startswith("pts_")]

    for _, row in top.iterrows():
        breakdown = {col.replace("pts_", ""): row[col] for col in score_cols if row[col] > 0}

        results.append({
            "rank": row["rank"],
            "risk_score": row["risk_score"],
            "vulnerability_name": row["vulnerability_name"],
            "cve": row["cve"],
            "cvss": row["cvss"],
            "severity": row["severity"],
            "days_open": row["days_open"],
            "exploit_available": row["exploit_available"],
            "affected_component": row["affected_component"],
            "asset_name": row["asset_name"],
            "asset_type": row["asset_type"],
            "environment": row["environment"],
            "internet_exposed": row["internet_exposed"],
            "edr_installed": row["edr_installed"],
            "business_service": row["business_service"],
            "business_impact": row.get("business_impact", ""),
            "revenue_impact": row.get("revenue_impact", ""),
            "compliance_scope": row.get("compliance_scope", ""),
            "customer_facing": row.get("customer_facing", ""),
            "rto_hours": row.get("rto_hours", ""),
            "threat_actor": row.get("threat_actor", ""),
            "campaign_name": row.get("campaign_name", ""),
            "ransomware_association": row.get("ransomware_association", ""),
            "kev_confirmed": row["kev_confirmed"],
            "kev_ransomware": row["kev_ransomware"],
            "scoring_breakdown": breakdown,
        })

    return results


if __name__ == "__main__":
    df = build_enriched_dataframe()
    top5 = get_top_risks(df)

    for risk in top5:
        print(f"\nRisk #{risk['rank']}: {risk['asset_name']} / {risk['cve']} (Score: {risk['risk_score']})")
        print(f"  Vuln: {risk['vulnerability_name']} (CVSS: {risk['cvss']})")
        print(f"  Asset: {risk['asset_type']}, {risk['environment']}, Internet: {risk['internet_exposed']}")
        print(f"  Business: {risk['business_service']} ({risk['revenue_impact']})")
        print(f"  Threat: {risk['threat_actor'] or 'None'} | KEV: {risk['kev_confirmed']} | Ransomware: {risk['kev_ransomware']}")
        print(f"  Breakdown: {risk['scoring_breakdown']}")
