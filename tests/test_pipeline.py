"""Tests for the risk scoring and RAG pipeline.

Run with: python -m pytest tests/ -v
"""
import pytest
from src.data_processor import build_enriched_dataframe
from src.risk_scorer import score_vulnerabilities, get_top_risks


@pytest.fixture(scope="module")
def enriched_df():
    return build_enriched_dataframe()


@pytest.fixture(scope="module")
def top5(enriched_df):
    return get_top_risks(enriched_df)


class TestDataProcessor:
    def test_enriched_df_has_expected_rows(self, enriched_df):
        assert len(enriched_df) == 114

    def test_enriched_df_has_kev_columns(self, enriched_df):
        assert "kev_confirmed" in enriched_df.columns
        assert "kev_ransomware" in enriched_df.columns

    def test_enriched_df_has_threat_columns(self, enriched_df):
        assert "threat_actor" in enriched_df.columns
        assert "campaign_name" in enriched_df.columns

    def test_enriched_df_has_business_columns(self, enriched_df):
        assert "revenue_impact" in enriched_df.columns
        assert "compliance_scope" in enriched_df.columns


class TestRiskScorer:
    def test_returns_5_risks(self, top5):
        assert len(top5) == 5

    def test_scores_are_descending(self, top5):
        scores = [r["risk_score"] for r in top5]
        assert scores == sorted(scores, reverse=True)

    def test_top_risk_is_internet_exposed(self, top5):
        assert top5[0]["internet_exposed"] == "Yes"

    def test_all_top5_are_kev_confirmed(self, top5):
        for r in top5:
            assert r["kev_confirmed"] is True

    def test_score_breakdown_sums_to_total(self, top5):
        for r in top5:
            breakdown_sum = sum(r["scoring_breakdown"].values())
            assert abs(breakdown_sum - r["risk_score"]) < 0.1

    def test_each_risk_has_required_fields(self, top5):
        required = ["rank", "risk_score", "cve", "vulnerability_name",
                     "asset_name", "scoring_breakdown"]
        for r in top5:
            for field in required:
                assert field in r


class TestRAGPipeline:
    def test_retrieve_returns_controls(self, top5):
        from src.rag_pipeline import retrieve_nist_guidance
        controls = retrieve_nist_guidance(top5[0])
        assert len(controls) == 3

    def test_controls_have_required_fields(self, top5):
        from src.rag_pipeline import retrieve_nist_guidance
        controls = retrieve_nist_guidance(top5[0])
        for c in controls:
            assert "control_id" in c
            assert "control_name" in c
            assert "rerank_score" in c
