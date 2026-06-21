"""Streamlit Web App — AI-Powered Cyber Risk Assistant

Entry point for the web interface. Displays:
  - Top 5 risks ranked by multi-factor scoring (not just CVSS)
  - Scoring breakdown showing exactly which factors contributed and why
  - LLM-generated risk explanation grounded in retrieved NIST controls
  - NIST SP 800-53 remediation guidance retrieved via hybrid RAG pipeline

Run with: streamlit run app.py
"""
import streamlit as st
import json
import os
from src.data_processor import build_enriched_dataframe
from src.risk_scorer import get_top_risks
from src.rag_pipeline import retrieve_nist_guidance, initialize
from src.output_generator import generate_risk_explanation

st.set_page_config(
    page_title="TawasolPay Cyber Risk Assistant",
    layout="wide",
    initial_sidebar_state="expanded",
)

# all styling via HTML, no streamlit components that use Material icons
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200');
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="st-"] { font-family: 'Inter', sans-serif; }

    /* NUCLEAR: hide sidebar toggle across ALL Streamlit versions */
    [data-testid="collapsedControl"] { display: none !important; }
    [data-testid="stSidebarCollapseButton"] { display: none !important; }
    [data-testid="stSidebarNavCollapseButton"] { display: none !important; }
    section[data-testid="stSidebar"] button[kind="header"] { display: none !important; }
    section[data-testid="stSidebar"] > div:first-child > div > button { display: none !important; }
    .st-emotion-cache-zq5wmm { display: none !important; }

    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 32px; border-radius: 16px; margin-bottom: 16px; text-align: center;
    }
    .main-header h1 { color: #ffffff; font-size: 2rem; margin: 0; }
    .main-header p { color: #a0aec0; font-size: 1rem; margin-top: 8px; }

    .info-bar {
        display: flex; gap: 12px; flex-wrap: wrap; justify-content: center;
        margin-bottom: 20px;
    }
    .info-chip {
        background: #1a1a2e; border: 1px solid #2d2d44; border-radius: 8px;
        padding: 8px 16px; color: #cbd5e1; font-size: 0.85rem;
    }
    .info-chip strong { color: #818cf8; }

    .risk-header {
        padding: 16px 20px; border-radius: 12px; margin-bottom: 12px;
        display: flex; justify-content: space-between; align-items: center;
    }
    .risk-critical { background: linear-gradient(135deg, #7f1d1d, #991b1b); }
    .risk-high { background: linear-gradient(135deg, #78350f, #92400e); }
    .risk-medium { background: linear-gradient(135deg, #713f12, #854d0e); }
    .risk-header h3 { color: #fff; margin: 0; font-size: 1.1rem; }
    .risk-header .score { color: #fbbf24; font-size: 1.3rem; font-weight: 700; }

    .detail-card {
        background: #1a1a2e; border: 1px solid #2d2d44;
        border-radius: 10px; padding: 16px; margin-bottom: 8px;
    }
    .detail-card h4 {
        color: #818cf8; font-size: 0.85rem; text-transform: uppercase;
        letter-spacing: 0.5px; margin-bottom: 8px;
    }
    .detail-card p { color: #cbd5e1; font-size: 0.9rem; line-height: 1.6; }
    .breakdown-bar {
        background: #0f172a; border-radius: 6px; padding: 6px 10px; margin: 3px 0;
        display: flex; justify-content: space-between; border-left: 3px solid #818cf8;
    }
    .breakdown-bar .label { color: #94a3b8; font-size: 0.8rem; }
    .breakdown-bar .pts { color: #fbbf24; font-weight: 600; font-size: 0.8rem; }
    .nist-badge {
        display: inline-block; background: #1e3a5f; color: #93c5fd;
        padding: 4px 10px; border-radius: 6px; font-size: 0.8rem;
        font-weight: 600; margin: 2px;
    }
    .key-facts { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }
    .key-fact {
        background: #111827; border: 1px solid #1f2937;
        border-radius: 8px; padding: 10px 16px; min-width: 120px;
    }
    .key-fact .kf-label { color: #6b7280; font-size: 0.7rem; text-transform: uppercase; }
    .key-fact .kf-value { color: #f9fafb; font-size: 1rem; font-weight: 600; margin-top: 2px; }
    .ai-details {
        background: #111827; border: 1px solid #1f2937;
        border-radius: 10px; margin-bottom: 16px;
    }
    .ai-details summary {
        padding: 12px 16px; cursor: pointer; color: #93c5fd;
        font-weight: 600; font-size: 0.95rem; list-style: none;
    }
    .ai-details summary::-webkit-details-marker { display: none; }
    .ai-details summary::before { content: '+ '; }
    .ai-details[open] summary::before { content: '- '; }
    .ai-details .ai-content {
        padding: 0 16px 16px 16px; color: #cbd5e1;
        font-size: 0.9rem; line-height: 1.7;
    }
</style>
""", unsafe_allow_html=True)


def get_severity(score):
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    return "medium"


@st.cache_data(show_spinner=False)
def load_data():
    df = build_enriched_dataframe()
    return get_top_risks(df)


@st.cache_resource(show_spinner=False)
def init_rag():
    initialize()
    return True


def render_risk(risk, controls, explanation):
    sev_class = get_severity(risk["risk_score"])

    st.markdown(f"""
    <div class="risk-header risk-{sev_class}">
        <h3>#{risk['rank']}  {risk['vulnerability_name']}</h3>
        <span class="score">{risk['risk_score']} / 100</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="key-facts">
        <div class="key-fact"><div class="kf-label">CVE</div><div class="kf-value">{risk['cve']}</div></div>
        <div class="key-fact"><div class="kf-label">CVSS</div><div class="kf-value">{risk['cvss']}</div></div>
        <div class="key-fact"><div class="kf-label">Severity</div><div class="kf-value">{risk['severity']}</div></div>
        <div class="key-fact"><div class="kf-label">Asset</div><div class="kf-value">{risk['asset_name']}</div></div>
        <div class="key-fact"><div class="kf-label">Environment</div><div class="kf-value">{risk['environment']}</div></div>
        <div class="key-fact"><div class="kf-label">Days Open</div><div class="kf-value">{risk['days_open']}</div></div>
    </div>
    """, unsafe_allow_html=True)

    left, right = st.columns(2)

    with left:
        actor = risk.get('threat_actor') or 'No known actor'
        campaign = risk.get('campaign_name') or 'N/A'
        st.markdown(f"""<div class="detail-card">
            <h4>Asset & Business Context</h4>
            <p>
            <strong>Asset:</strong> {risk['asset_name']} ({risk['asset_type']})<br>
            <strong>Internet Exposed:</strong> {risk['internet_exposed']} &nbsp;|&nbsp; <strong>EDR:</strong> {risk['edr_installed']}<br>
            <strong>Business Service:</strong> {risk['business_service']}<br>
            <strong>Revenue Impact:</strong> {risk['revenue_impact']} &nbsp;|&nbsp; <strong>Compliance:</strong> {risk['compliance_scope']}<br>
            <strong>Customer Facing:</strong> {risk['customer_facing']}
            </p>
        </div>""", unsafe_allow_html=True)

        st.markdown(f"""<div class="detail-card">
            <h4>Threat Intelligence</h4>
            <p>
            <strong>Threat Actor:</strong> {actor}<br>
            <strong>Campaign:</strong> {campaign}<br>
            <strong>KEV Confirmed:</strong> {'Yes' if risk['kev_confirmed'] else 'No'}<br>
            <strong>Ransomware:</strong> {risk['kev_ransomware']}
            </p>
        </div>""", unsafe_allow_html=True)

    with right:
        breakdown = risk["scoring_breakdown"]
        bars = ""
        for factor, pts in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
            label = factor.replace("_", " ").title()
            bars += f'<div class="breakdown-bar"><span class="label">{label}</span><span class="pts">+{pts}</span></div>'

        st.markdown(f"""<div class="detail-card">
            <h4>Scoring Breakdown</h4>
            {bars}
        </div>""", unsafe_allow_html=True)

        badges = " ".join(
            f'<span class="nist-badge">{c["control_id"]} — {c["control_name"]}</span>'
            for c in controls
        )
        st.markdown(f"""<div class="detail-card">
            <h4>Retrieved NIST Controls</h4>
            {badges}
        </div>""", unsafe_allow_html=True)

    st.markdown(f"""
    <details class="ai-details">
        <summary>View AI Analysis & Remediation for Risk #{risk['rank']}</summary>
        <div class="ai-content">{explanation}</div>
    </details>
    """, unsafe_allow_html=True)

    st.markdown("---")


def main():
    # sidebar (static, no collapse button)
    with st.sidebar:
        logo_path = os.path.join(os.path.dirname(__file__), "hive_pro_logo.jpg")
        if os.path.exists(logo_path):
            st.image(logo_path, width='stretch')
        st.markdown("### How This Works")
        st.markdown("""
        This system ingests TawasolPay's cybersecurity data and automatically
        identifies the **top 5 most dangerous risks** based on real-world threat context,
        not just CVSS scores.
        """)

        st.markdown("---")
        st.markdown("### Data Ingested")
        st.markdown("- **60** Assets")
        st.markdown("- **114** Vulnerabilities")
        st.markdown("- **40** Threat Intel Records")
        st.markdown("- **20** Business Services")

        st.markdown("---")
        st.markdown("### External Sources")
        st.markdown("- CISA KEV Catalog (live)")
        st.markdown("- NIST SP 800-53 Rev 5 (1,016 controls)")

        st.markdown("---")
        st.markdown("### RAG Pipeline")
        st.markdown("""
        1. **BGE Embeddings** - dense semantic search
        2. **BM25** - sparse keyword search
        3. **Reciprocal Rank Fusion** - combines both
        4. **Cross-Encoder Reranking** - precise top-3
        """)

        st.markdown("---")
        st.markdown("### Retrieval Evaluation")
        try:
            eval_path = os.path.join(os.path.dirname(__file__), "eval", "eval_results.json")
            with open(eval_path) as f:
                eval_data = json.load(f)
            m = eval_data.get("retrieval_metrics", {})
            st.markdown(f"- **Hit Rate @3:** {m.get('hit_rate', 'N/A')}")
            st.markdown(f"- **MRR:** {m.get('mrr', 'N/A')}")
            st.markdown(f"- **Context Precision:** {m.get('context_precision', 'N/A')}")
        except (FileNotFoundError, json.JSONDecodeError):
            st.markdown("Run rag_evaluator.py to see metrics.")

    # header
    st.markdown("""
    <div class="main-header">
        <h1>TawasolPay — Cyber Risk Assessment</h1>
        <p>Multi-factor risk scoring + RAG-based NIST SP 800-53 remediation guidance</p>
    </div>
    """, unsafe_allow_html=True)

    # info bar (replaces sidebar)
    st.markdown("""
    <div class="info-bar">
        <div class="info-chip"><strong>60</strong> Assets</div>
        <div class="info-chip"><strong>114</strong> Vulnerabilities</div>
        <div class="info-chip"><strong>40</strong> Threat Intel</div>
        <div class="info-chip"><strong>20</strong> Business Services</div>
        <div class="info-chip"><strong>CISA KEV</strong> (live)</div>
        <div class="info-chip"><strong>NIST 800-53</strong> (1,016 controls)</div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Run Risk Analysis", type="primary", use_container_width=True):
        st.session_state["run_analysis"] = True
        st.session_state["results"] = None

    if not st.session_state.get("run_analysis", False):
        st.markdown("Click **Run Risk Analysis** to score 114 vulnerabilities, retrieve NIST guidance, and generate risk explanations.")
        return

    if st.session_state.get("results") is None:
        progress = st.empty()
        progress.markdown("Loading and enriching data...")
        top5 = load_data()

        progress.markdown("Initializing RAG pipeline...")
        init_rag()

        results = []
        for risk in top5:
            progress.markdown(f"Processing Risk #{risk['rank']}: {risk['vulnerability_name'][:50]}...")
            controls = retrieve_nist_guidance(risk)
            explanation = generate_risk_explanation(risk, controls)
            results.append((risk, controls, explanation))

        st.session_state["results"] = results
        progress.markdown("**Analysis complete.**")

    for risk, controls, explanation in st.session_state["results"]:
        render_risk(risk, controls, explanation)

    st.caption(
        "Data: CISA KEV (cisa.gov), NIST SP 800-53 Rev 5 (nist.gov), TawasolPay (synthetic). "
        "Models: Llama 3.3 70B (Groq), BAAI/bge-small-en-v1.5, cross-encoder/ms-marco-MiniLM-L-6-v2."
    )


if __name__ == "__main__":
    main()
