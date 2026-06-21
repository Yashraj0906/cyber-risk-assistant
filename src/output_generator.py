"""Output Generator Module

Takes a scored risk (from risk_scorer.py) + retrieved NIST controls (from rag_pipeline.py)
and uses the LLM to generate a plain-English explanation.

The LLM is instructed to:
  1. Explain WHY this risk is ranked at this position (using the scoring breakdown)
  2. Explain WHAT the NIST control recommends for remediation
  3. ONLY use data from the provided context (no hallucination from training data)

Output: a dict per risk with all structured data + LLM-generated explanation text.
"""
from src.llm_client import generate

SYSTEM_PROMPT = """You are a senior cybersecurity analyst writing a risk briefing for a CISO.
You must base your analysis ONLY on the data and NIST control text provided.
Do not use information from your training data about these vulnerabilities.
Be concise, specific, and actionable. Use bullet points where appropriate."""


def generate_risk_explanation(risk, nist_controls):
    """Generate a plain-English explanation for a single risk using the LLM.

    Args:
        risk: dict from risk_scorer.get_top_risks()
        nist_controls: list of dicts from rag_pipeline.retrieve_nist_guidance()
    
    Returns: string with the LLM-generated explanation
    """
    # format NIST controls for the prompt
    controls_text = ""
    for i, c in enumerate(nist_controls, 1):
        controls_text += f"\n  {i}. {c['control_id']} - {c['control_name']}\n"
        controls_text += f"     {c['document'][:500]}\n"

    prompt = f"""Analyze the following cybersecurity risk and provide:
1. A 2-3 sentence explanation of WHY this risk is dangerous (use the specific data below)
2. For each NIST control listed, a 1-2 sentence actionable remediation recommendation

RISK DATA:
  Rank: #{risk['rank']} (Score: {risk['risk_score']}/100)
  Vulnerability: {risk['vulnerability_name']} ({risk['cve']}, CVSS: {risk['cvss']})
  Asset: {risk['asset_name']} ({risk['asset_type']}, {risk['environment']})
  Internet Exposed: {risk['internet_exposed']}
  EDR Installed: {risk['edr_installed']}
  Business Service: {risk['business_service']} (Revenue Impact: {risk['revenue_impact']})
  Compliance: {risk['compliance_scope']}
  Threat Actor: {risk.get('threat_actor', 'None')} ({risk.get('campaign_name', 'None')})
  KEV Confirmed: {risk['kev_confirmed']} | Ransomware: {risk['kev_ransomware']}
  Scoring Breakdown: {risk['scoring_breakdown']}

RETRIEVED NIST CONTROLS:{controls_text}
"""

    return generate(prompt, system_prompt=SYSTEM_PROMPT)


def generate_all_explanations(risks, retrieve_fn):
    """Generate explanations for all top risks.

    Args:
        risks: list of risk dicts from risk_scorer.get_top_risks()
        retrieve_fn: function that takes a risk dict and returns NIST controls
    
    Returns: list of dicts with risk data + nist_controls + explanation
    """
    results = []

    for risk in risks:
        print(f"  Generating explanation for Risk #{risk['rank']}...")

        nist_controls = retrieve_fn(risk)
        explanation = generate_risk_explanation(risk, nist_controls)

        results.append({
            **risk,
            "nist_controls": [
                {
                    "control_id": c["control_id"],
                    "control_name": c["control_name"],
                    "family_name": c.get("family_name", ""),
                    "rerank_score": c.get("rerank_score", 0),
                }
                for c in nist_controls
            ],
            "explanation": explanation,
        })

    return results


if __name__ == "__main__":
    from src.data_processor import build_enriched_dataframe
    from src.risk_scorer import get_top_risks
    from src.rag_pipeline import retrieve_nist_guidance

    df = build_enriched_dataframe()
    top5 = get_top_risks(df)

    # test with just the first risk
    risk = top5[0]
    controls = retrieve_nist_guidance(risk)
    explanation = generate_risk_explanation(risk, controls)

    print(f"Risk #{risk['rank']}: {risk['vulnerability_name']}")
    print(f"\nControls: {[c['control_id'] for c in controls]}")
    print(f"\nExplanation:\n{explanation}")
